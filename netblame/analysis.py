"""Transforma amostras brutas em um diagnóstico: "ONDE na rota está a falha?".

O raciocínio é por eliminação, comparando quem falhou junto em cada ciclo:

* gateway **e** todos os alvos externos falham  -> problema local (cabo, placa, roteador)
* gateway responde, todos os externos falham    -> modem ou provedor (ISP)
* só o alvo do app falha                        -> rota até o serviço ou o próprio servidor
* perdas coincidem com CPU/RAM no limite        -> o PC não deu conta, não a rede

Cada regra gera um :class:`Finding` com severidade, explicação e conselho.
Os limiares estão em constantes no topo para ficarem fáceis de discutir e
ajustar - todos são heurísticas, não leis da física.
"""

from __future__ import annotations

import ipaddress
import statistics
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Literal, Optional

from netblame.i18n import Text, ms, num, same, secs
from netblame.models import HopStat, NicSnapshot, Session
from netblame.tracing import find_bad_hop, rate_limited_hops

Severity = Literal["critical", "warning", "info", "ok"]
# "ok" só existe quando não há critical/warning, e deve virar o veredito
# mesmo havendo observações informativas.
SEVERITY_RANK = {"critical": 0, "warning": 1, "ok": 2, "info": 3}

# -- limiares -------------------------------------------------------------
LOSS_WARN_PCT = 1.0  # perda a partir da qual um alvo é "instável"
APP_LOSS_PCT = 2.0  # perda mínima para culpar a rota de um app
APP_LOSS_RATIO = 3.0  # ... e quantas vezes maior que a da internet ela precisa ser
DNS_LOSS_PCT = 2.0
DNS_SLOW_MS = 150.0
CPU_STRESS_PCT = 90.0
RAM_STRESS_PCT = 95.0
PC_MIN_OVERLAP = 3  # ciclos com perda + máquina saturada
PC_OVERLAP_RATIO = 0.5  # fração dos ciclos com perda que precisa coincidir
SPIKE_RATIO = 4.0  # p95 > 4x a mediana...
SPIKE_MIN_MS = 20.0  # ...e pelo menos 20 ms acima dela (1 ms -> 5 ms não é pico)
JITTER_MS = 30.0
MIN_RTTS_FOR_LATENCY = 20
BLACKOUT_MIN_CYCLES = 2
NIC_DROPS_WARN = 50  # descartes durante a captura (o Windows conta ruído também)
UDP_LOSS_PCT = 2.0  # perda mínima do UDP para culpar o tratamento de UDP...
UDP_LOSS_RATIO = 3.0  # ...e quantas vezes maior que a do ICMP ao mesmo destino
UDP_RX_ERRORS_WARN = 5  # datagramas descartados pelo Windows durante a captura


@dataclass
class TargetStats:
    label: str
    role: str
    sent: int
    lost: int
    loss_pct: float
    mean: Optional[float]
    median: Optional[float]
    p95: Optional[float]
    max: Optional[float]
    jitter: Optional[float]


@dataclass
class Event:
    """Um apagão: ``cycles`` ciclos seguidos sem alcançar a internet."""

    start_cycle: int
    end_cycle: int
    start_t: float
    end_t: float
    scope: Literal["local", "upstream", "unknown"]
    stressed: bool = False  # a máquina estava saturada durante a maior parte dele

    @property
    def cycles(self) -> int:
        return self.end_cycle - self.start_cycle + 1

    @property
    def duration(self) -> float:
        return round(self.end_t - self.start_t, 1)


@dataclass
class Finding:
    severity: Severity
    category: str  # local | isp | route | pc | dns | udp | cable | bufferbloat | wifi | info | ok
    title: Text  # nas duas línguas: o relatório troca de idioma sem recalcular nada
    detail: Text
    advice: Text
    score: float = 0.0  # desempate dentro da mesma severidade (maior = mais importante)
    #: Estação do mapa do relatório onde o problema está: pc | home | isp | internet | app.
    #: None = deduzir pela categoria (ou, para observações gerais, nenhuma estação).
    node: Optional[str] = None


#: Estação padrão de cada categoria no mapa do caminho.
CATEGORY_NODE = {
    "pc": "pc", "local": "home", "cable": "home", "wifi": "home",
    "isp": "isp", "bufferbloat": "isp", "dns": "isp", "udp": "isp",
    "route": "app",
}


def finding_node(f: Finding) -> Optional[str]:
    """Em que estação do caminho (PC, casa, provedor, internet, servidor) o finding se encaixa."""
    return f.node or CATEGORY_NODE.get(f.category)


@dataclass
class Analysis:
    stats: dict[str, TargetStats]
    events: list[Event]
    findings: list[Finding]
    bad_hops: dict[str, Optional[HopStat]] = field(default_factory=dict)
    rate_limited: dict[str, list[int]] = field(default_factory=dict)
    stressed_cycles: set[int] = field(default_factory=set)

    @property
    def verdict(self) -> Finding:
        return self.findings[0]


# --------------------------------------------------------------------------
# Estatística
# --------------------------------------------------------------------------

def percentile(values: list[float], pct: float) -> float:
    """Percentil com interpolação linear (o mesmo método padrão do NumPy)."""
    s = sorted(values)
    if len(s) == 1:
        return s[0]
    k = (len(s) - 1) * pct / 100
    lo = int(k)
    hi = min(lo + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (k - lo)


def jitter(rtts: list[float]) -> Optional[float]:
    """Média da variação absoluta entre RTTs consecutivos (estilo RFC 3550, sem suavização).

    Perdas não entram na sequência: o jitter mede a instabilidade dos
    pacotes que chegaram, a perda é medida à parte.
    """
    if len(rtts) < 2:
        return None
    return statistics.fmean(abs(b - a) for a, b in zip(rtts, rtts[1:]))


def target_stats(session: Session) -> dict[str, TargetStats]:
    by_target: dict[str, list] = defaultdict(list)
    for s in sorted(session.samples, key=lambda x: x.cycle):
        by_target[s.target].append(s.rtt)
    out = {}
    for t in session.targets:
        values = by_target.get(t.label, [])
        rtts = [v for v in values if v is not None]
        sent, lost = len(values), sum(v is None for v in values)
        r = lambda x: None if x is None else round(x, 2)  # noqa: E731
        out[t.label] = TargetStats(
            label=t.label, role=t.role, sent=sent, lost=lost,
            loss_pct=round(100 * lost / sent, 2) if sent else 0.0,
            mean=r(statistics.fmean(rtts)) if rtts else None,
            median=r(statistics.median(rtts)) if rtts else None,
            p95=r(percentile(rtts, 95)) if rtts else None,
            max=r(max(rtts)) if rtts else None,
            jitter=r(jitter(rtts)),
        )
    return out


# --------------------------------------------------------------------------
# Apagões
# --------------------------------------------------------------------------

def _cycle_table(session: Session) -> dict[int, dict[str, Optional[float]]]:
    table: dict[int, dict[str, Optional[float]]] = defaultdict(dict)
    for s in session.samples:
        table[s.cycle][s.target] = s.rtt
    return table


def stressed_cycles(session: Session) -> set[int]:
    return {x.cycle for x in session.sys if x.cpu >= CPU_STRESS_PCT or x.ram >= RAM_STRESS_PCT}


def find_events(session: Session, min_cycles: int = BLACKOUT_MIN_CYCLES) -> list[Event]:
    """Agrupa ciclos sem internet em apagões e classifica cada um.

    Um ciclo é "sem internet" quando **todos** os alvos externos (internet e
    apps) falham. Se o gateway também falhou, o ciclo é local; se o gateway
    respondeu, o problema está depois dele (upstream). Sem alvo de gateway
    não dá para saber (unknown).

    O gateway falhando sozinho não conta: muitos roteadores despriorizam
    pings dirigidos a eles mesmos, mas continuam encaminhando o tráfego.

    Sequências menores que ``min_cycles`` são tratadas como perda avulsa, não
    como apagão - uma perda isolada de 1 s raramente derruba uma conexão.
    """
    external = session.labels("internet", "app")
    gateways = session.labels("gateway")
    if not external:
        return []
    table = _cycle_table(session)
    times = {s.cycle: s.t for s in session.samples}
    stressed = stressed_cycles(session)

    def cycle_scope(c: int) -> Optional[str]:
        row = table.get(c, {})
        if not all(label in row and row[label] is None for label in external):
            return None
        if not gateways:
            return "unknown"
        return "local" if all(row.get(g, 0) is None for g in gateways) else "upstream"

    events: list[Event] = []
    run: list[tuple[int, str]] = []

    def close_run() -> None:
        if len(run) >= min_cycles:
            cycles = [c for c, _ in run]
            scopes = [sc for _, sc in run]
            local = scopes.count("local")
            scope = "unknown" if "unknown" in scopes else ("local" if local * 2 >= len(scopes) else "upstream")
            events.append(Event(
                start_cycle=cycles[0], end_cycle=cycles[-1],
                start_t=times[cycles[0]], end_t=times[cycles[-1]] + session.interval,
                scope=scope,  # type: ignore[arg-type]
                stressed=sum(c in stressed for c in cycles) * 2 > len(cycles),
            ))
        run.clear()

    for c in sorted(table):
        sc = cycle_scope(c)
        if sc and (not run or run[-1][0] == c - 1):
            run.append((c, sc))
        else:
            close_run()
            if sc:
                run.append((c, sc))
    close_run()
    return events


# --------------------------------------------------------------------------
# Regras
# --------------------------------------------------------------------------

def _clock(seconds: float) -> Text:
    m, s = divmod(int(seconds), 60)
    return same(f"{m:02d}:{s:02d}")


#: Faixas que provedores usam dentro da própria rede. Lista explícita porque
#: ``ip_address.is_private`` também inclui faixas de documentação e reservadas.
_ISP_INTERNAL_NETS = [ipaddress.ip_network(n) for n in
                      ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10")]


def _is_private(ip: Optional[str]) -> bool:
    if not ip:
        return False
    addr = ipaddress.ip_address(ip)
    return any(addr in net for net in _ISP_INTERNAL_NETS)


def _pc_findings(session: Session, stressed: set[int], stats: dict[str, TargetStats]) -> list[Finding]:
    if not session.sys:
        return []
    table = _cycle_table(session)
    watched = session.labels("gateway", "internet", "app")
    lossy = {c for c, row in table.items() if any(row.get(l, 0) is None for l in watched)}
    overlap = lossy & stressed
    peak_cpu = max(x.cpu for x in session.sys)
    peak_ram = max(x.ram for x in session.sys)
    cpu_t, ram_t = f"{CPU_STRESS_PCT:.0f}", f"{RAM_STRESS_PCT:.0f}"
    if len(overlap) >= PC_MIN_OVERLAP and len(overlap) >= PC_OVERLAP_RATIO * len(lossy):
        return [Finding(
            "critical", "pc",
            Text("Your PC is the bottleneck: losses happen when it is overloaded",
                 "O gargalo é o seu PC: as perdas acontecem quando ele está sobrecarregado"),
            Text(f"{len(overlap)} of {len(lossy)} cycles with packet loss happened while CPU was "
                 f"≥ {cpu_t}% or RAM ≥ {ram_t}% (peak CPU {peak_cpu:.0f}%, peak RAM {peak_ram:.0f}%). "
                 "Even the router stopped answering in those moments, which is what happens when "
                 "the machine can't process packets in time.",
                 f"{len(overlap)} de {len(lossy)} ciclos com perda aconteceram com a CPU ≥ {cpu_t}% "
                 f"ou a RAM ≥ {ram_t}% (pico de CPU {peak_cpu:.0f}%, pico de RAM {peak_ram:.0f}%). "
                 "Até o roteador parou de responder nesses momentos - é o que acontece quando a "
                 "máquina não consegue processar os pacotes a tempo."),
            Text("Find what is eating CPU/RAM in Task Manager (updates, antivirus scans, browser tabs, "
                 "game overlays, recording software). Close it and capture again. If RAM is the issue, "
                 "the system is swapping to disk and freezing for short periods.",
                 "Veja no Gerenciador de Tarefas o que está consumindo CPU/RAM (atualizações, "
                 "varredura do antivírus, abas do navegador, overlays, gravação de tela). Feche e "
                 "capture de novo. Se for a RAM, o sistema está usando o disco como memória e "
                 "travando por instantes."),
            score=100,
        )]
    if len(stressed) >= 0.2 * max(len(session.sys), 1):
        return [Finding(
            "info", "pc",
            Text("Your PC was under heavy load for a large part of the capture",
                 "O PC ficou sobrecarregado durante boa parte da captura"),
            Text(f"CPU ≥ {cpu_t}% or RAM ≥ {ram_t}% in {len(stressed)} of {len(session.sys)} cycles, "
                 "but losses did not line up with it.",
                 f"CPU ≥ {cpu_t}% ou RAM ≥ {ram_t}% em {len(stressed)} de {len(session.sys)} ciclos, "
                 "mas as perdas não coincidiram com isso."),
            Text("Not the cause of the drops this time, but worth keeping an eye on.",
                 "Não foi a causa das quedas desta vez, mas vale ficar de olho."),
            score=10,
        )]
    return []


def _event_findings(events: list[Event], pc_blamed: bool) -> list[Finding]:
    out = []
    groups: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        if pc_blamed and e.stressed:
            continue  # já explicados pela máquina saturada
        groups[e.scope].append(e)

    def when(evs: list[Event]) -> Text:
        parts = [_clock(e.start_t) + same(" (") + secs(e.duration) + same(")") for e in evs[:6]]
        text = Text.join(", ", parts)
        if len(evs) > 6:
            text += Text(f" and {len(evs) - 6} more", f" e mais {len(evs) - 6}")
        return text

    def longest(evs: list[Event]) -> Text:
        return secs(max(e.duration for e in evs))

    if evs := groups.get("local"):
        w, lg = when(evs), longest(evs)
        out.append(Finding(
            "critical", "local",
            Text(f"{len(evs)} blackout(s) inside your home network",
                 f"{len(evs)} apagão(ões) dentro da sua rede local"),
            Text(f"Your router stopped answering together with everything else at {w.en}. "
                 f"Longest: {lg.en}. The fault is between this PC and the router.",
                 f"O roteador parou de responder junto com todo o resto em {w.pt}. "
                 f"O mais longo: {lg.pt}. A falha está entre este PC e o roteador."),
            Text("Swap the Ethernet cable and try another router port. Update the network adapter driver "
                 "and disable its power saving (Device Manager → adapter → Power Management / "
                 "Advanced → Energy-Efficient Ethernet). If it persists, reboot or replace the router.",
                 "Troque o cabo de rede e teste outra porta do roteador. Atualize o driver da placa de "
                 "rede e desative a economia de energia (Gerenciador de Dispositivos → placa → "
                 "Gerenciamento de Energia / Avançado → Energy-Efficient Ethernet). Se continuar, "
                 "reinicie ou troque o roteador."),
            score=90,
        ))
    if evs := groups.get("upstream"):
        w, lg = when(evs), longest(evs)
        out.append(Finding(
            "critical", "isp",
            Text(f"{len(evs)} internet blackout(s) while your router stayed reachable",
                 f"{len(evs)} queda(s) de internet com o roteador respondendo normalmente"),
            Text(f"The router kept answering but every external target failed at the same time at "
                 f"{w.en}. Longest: {lg.en}. The connection is dropping after your router: in the "
                 "modem/ONT or at your ISP.",
                 f"O roteador continuou respondendo, mas todos os alvos externos falharam juntos em "
                 f"{w.pt}. A mais longa: {lg.pt}. A conexão cai depois do roteador: no modem/ONT "
                 "ou no provedor."),
            Text("Check the modem/ONT lights (LOS/PON blinking red = fiber signal problem) and reboot it. "
                 "If it keeps happening, open a ticket with your ISP and attach this report: the "
                 "timestamps prove your internal network was fine during the drops.",
                 "Confira as luzes do modem/ONT (LOS/PON piscando em vermelho = problema no sinal da "
                 "fibra) e reinicie. Se continuar, abra um chamado no provedor e anexe este relatório: "
                 "os horários provam que a sua rede interna estava normal durante as quedas."),
            score=80,
        ))
    if evs := groups.get("unknown"):
        w = when(evs)
        out.append(Finding(
            "critical", "isp",
            Text(f"{len(evs)} internet blackout(s)", f"{len(evs)} queda(s) de internet"),
            Text(f"Every external target failed at the same time at {w.en}. The gateway was not "
                 "probed, so it is unknown whether the fault is local or at the ISP.",
                 f"Todos os alvos externos falharam juntos em {w.pt}. O gateway não foi sondado, "
                 "então não dá para saber se a falha é local ou do provedor."),
            Text("Run again with the gateway detected (it is automatic on Windows) to locate the fault.",
                 "Rode de novo com o gateway detectado (é automático no Windows) para localizar a falha."),
            score=70,
        ))
    return out


def _loss_findings(stats: dict[str, TargetStats], session: Session, has_events: set[str]) -> list[Finding]:
    out = []
    gw = [stats[l] for l in session.labels("gateway") if l in stats]
    inet = [stats[l] for l in session.labels("internet") if l in stats]
    inet_loss = min((s.loss_pct for s in inet), default=0.0)
    gw_loss = max((s.loss_pct for s in gw), default=0.0)
    g, i = num(gw_loss), num(inet_loss)

    if gw and gw_loss >= LOSS_WARN_PCT and "local" not in has_events:
        if inet and inet_loss >= gw_loss * 0.5:
            out.append(Finding(
                "warning", "local",
                Text(f"Packet loss starts at your router ({g.en}%)",
                     f"A perda de pacotes começa no seu roteador ({g.pt}%)"),
                Text(f"The router lost {g.en}% of pings and the internet targets lost a similar "
                     f"share ({i.en}%), so the loss happens before the traffic leaves your home.",
                     f"O roteador perdeu {g.pt}% dos pings e os alvos da internet perderam uma parcela "
                     f"parecida ({i.pt}%): a perda acontece antes de o tráfego sair da sua casa."),
                Text("Check the cable and connectors, try another router port and update the NIC driver.",
                     "Confira o cabo e os conectores, teste outra porta do roteador e atualize o "
                     "driver da placa de rede."),
                score=60,
            ))
        else:
            out.append(Finding(
                "info", "local",
                Text("Your router ignores some pings sent to itself (harmless)",
                     "O roteador ignora alguns pings enviados a ele (inofensivo)"),
                Text(f"The router lost {g.en}% of pings, but traffic through it to the internet "
                     f"did not ({i.en}%). Routers answer pings with a low priority.",
                     f"O roteador perdeu {g.pt}% dos pings, mas o tráfego que passa por ele até a "
                     f"internet não ({i.pt}%). Roteadores respondem a ping com baixa prioridade."),
                Text("Nothing to do.", "Nada a fazer."),
                score=5,
            ))

    if inet and inet_loss >= LOSS_WARN_PCT and gw_loss < LOSS_WARN_PCT and "upstream" not in has_events:
        out.append(Finding(
            "warning", "isp",
            Text(f"Packet loss beyond your router ({i.en}% or more)",
                 f"Perda de pacotes depois do roteador ({i.pt}% ou mais)"),
            Text("Every internet target lost packets while your router answered reliably. Loss "
                 "this widespread points to the modem or the ISP network.",
                 "Todos os alvos da internet perderam pacotes enquanto o roteador respondia sem "
                 "falhas. Uma perda tão generalizada aponta para o modem ou a rede do provedor."),
            Text("Reboot the modem/ONT. If loss continues, contact your ISP with this report.",
                 "Reinicie o modem/ONT. Se a perda continuar, acione o provedor com este relatório."),
            score=55,
        ))

    for label in session.labels("app"):
        s = stats.get(label)
        if not s or s.loss_pct < APP_LOSS_PCT:
            continue
        if s.loss_pct >= APP_LOSS_RATIO * max(inet_loss, 0.5):
            a, desc = num(s.loss_pct), session.target(label).describe()
            out.append(Finding(
                "critical" if s.loss_pct >= 10 else "warning", "route",
                Text(f"Only {label} is unreliable ({a.en}% loss)",
                     f"Só o {label} está instável ({a.pt}% de perda)"),
                Text(f"{label} ({desc}) lost {a.en}% of probes while general internet targets lost "
                     f"{i.en}%. Your connection is fine; the problem is on the route to this service "
                     "or on its servers.",
                     f"{label} ({desc}) perdeu {a.pt}% das sondas, enquanto os alvos gerais da "
                     f"internet perderam {i.pt}%. A sua conexão está boa; o problema está na rota "
                     "até esse serviço ou nos servidores dele."),
                Text("This is outside your home network. Check the service status page, try another "
                     "server region, and if it persists report the hop table below to your ISP "
                     "(a VPN that takes a different route is a common workaround).",
                     "Isso está fora da sua rede. Veja a página de status do serviço, tente outra "
                     "região de servidor e, se persistir, mostre a tabela de saltos abaixo ao "
                     "provedor (uma VPN que siga outra rota costuma contornar o problema)."),
                score=65,
            ))
    return out


def _hop_findings(session: Session, bad: dict[str, Optional[HopStat]],
                  limited: dict[str, list[int]]) -> list[Finding]:
    out = []
    for trace in session.traces:
        hop = bad.get(trace.label)
        if hop is not None:
            last = [h for h in trace.hops if h.loss_pct is not None][-1]
            route_role = next((t.role for t in session.targets if t.label == trace.label), "internet")
            if hop.hop == 1:
                where, cat = Text("your router (hop 1)", "no seu roteador (salto 1)"), "local"
            elif _is_private(hop.host):
                where, cat = Text(f"hop {hop.hop} ({hop.host}), inside your ISP's network",
                                  f"no salto {hop.hop} ({hop.host}), dentro da rede do provedor"), "isp"
            else:
                where, cat = Text(f"hop {hop.hop} ({hop.host}), a public router on the way",
                                  f"no salto {hop.hop} ({hop.host}), um roteador público no caminho"), "route"
            h, lst = num(hop.loss_pct or 0), num(last.loss_pct or 0)
            out.append(Finding(
                "warning", cat,
                Text(f"Loss on the route to {trace.label} starts at {where.en}",
                     f"A perda na rota até {trace.label} começa {where.pt}"),
                Text(f"Hop {hop.hop} loses {h.en}% and the loss continues to the last hop "
                     f"({lst.en}% at hop {last.hop}). Loss that persists all the way is real loss.",
                     f"O salto {hop.hop} perde {h.pt}% e a perda continua até o último salto "
                     f"({lst.pt}% no salto {last.hop}). Perda que persiste até o fim é perda real."),
                Text("Hop 1 = your router/cable. Hops in private ranges right after it = your ISP. "
                     "Further away = transit between networks; report it to your ISP with this table.",
                     "Salto 1 = seu roteador/cabo. Saltos com IP privado logo depois = seu provedor. "
                     "Mais adiante = trânsito entre redes; reporte ao provedor com esta tabela."),
                score=50,
                node={"local": "home", "isp": "isp"}.get(cat, "app" if route_role == "app" else "internet"),
            ))
    # Rotas compartilham saltos: junta o rate-limit num único aviso por IP.
    limited_hops: dict[str, int] = {}
    for trace in session.traces:
        for hs in trace.hops:
            if hs.hop in limited.get(trace.label, []) and hs.host:
                limited_hops.setdefault(hs.host, hs.hop)
    if limited_hops:
        names = Text.join(", ", [Text(f"hop {n} ({ip})", f"salto {n} ({ip})")
                                 for ip, n in limited_hops.items()])
        plural = len(limited_hops) > 1
        out.append(Finding(
            "info", "info",
            Text("Some routers on the way rate-limit pings (harmless)",
                 "Alguns roteadores no caminho limitam respostas a ping (inofensivo)"),
            Text(f"{names.en[0].upper() + names.en[1:]} drop{'' if plural else 's'} some pings "
                 "addressed to them, but the hops after them do not lose anything, so traffic "
                 "passing through is fine.",
                 f"{names.pt[0].upper() + names.pt[1:]} descarta{'m' if plural else ''} parte dos "
                 "pings dirigidos a eles, mas os saltos seguintes não perdem nada: o tráfego que "
                 "passa está normal."),
            Text("Ignore this. Routers answer ICMP with spare CPU only, after forwarding real traffic.",
                 "Pode ignorar. Roteadores só respondem ICMP com a CPU que sobra depois de encaminhar "
                 "o tráfego de verdade."),
            score=1,
        ))
    return out


def _dns_findings(stats: dict[str, TargetStats], session: Session) -> list[Finding]:
    out = []
    inet_loss = min((stats[l].loss_pct for l in session.labels("internet") if l in stats), default=0.0)
    for label in session.labels("dns"):
        s = stats[label]
        server = session.target(label).host
        if s.loss_pct >= DNS_LOSS_PCT and inet_loss < LOSS_WARN_PCT:
            d = num(s.loss_pct)
            out.append(Finding(
                "warning", "dns",
                Text(f"Your DNS server fails while the internet works ({d.en}% failed)",
                     f"O seu servidor DNS falha enquanto a internet funciona ({d.pt}% de falhas)"),
                Text(f"Queries to {server} failed {d.en}% of the time while pings to IP addresses "
                     "were fine. Name lookups (e.g. joining a match or a new server) can fail or hang.",
                     f"As consultas a {server} falharam {d.pt}% das vezes, enquanto os pings para "
                     "endereços IP funcionaram. Resolver nomes (ao entrar numa partida ou num "
                     "servidor novo, por exemplo) pode falhar ou travar."),
                Text("Switch the adapter's DNS to 1.1.1.1 and 8.8.8.8 (Settings → Network → Ethernet → "
                     "DNS server assignment) and capture again.",
                     "Troque o DNS da placa para 1.1.1.1 e 8.8.8.8 (Configurações → Rede → Ethernet → "
                     "Atribuição de servidor DNS) e capture de novo."),
                score=45,
            ))
        elif s.median is not None and s.median >= DNS_SLOW_MS:
            m = ms(s.median)
            out.append(Finding(
                "info", "dns",
                Text(f"DNS lookups are slow (median {m.en})", f"O DNS está lento (mediana de {m.pt})"),
                Text(f"{server} takes {m.en} to answer. Not a cause of disconnects, but it delays connecting.",
                     f"{server} leva {m.pt} para responder. Não derruba conexões, mas atrasa o início delas."),
                Text("Consider 1.1.1.1 or 8.8.8.8 as DNS servers.",
                     "Considere usar 1.1.1.1 ou 8.8.8.8 como DNS."),
                score=8,
            ))
    return out


def _nic_findings(before: list[NicSnapshot], after: list[NicSnapshot]) -> list[Finding]:
    out = []
    prev = {n.name: n for n in before}
    wired_up = [n for n in after if n.is_up and not n.wireless]
    for n in after:
        if not n.is_up:
            continue
        if not n.wireless and 0 < n.speed_mbps < 1000:
            out.append(Finding(
                "warning", "cable",
                Text(f"{n.name} negotiated {n.speed_mbps} Mbps instead of 1000",
                     f"{n.name} negociou {n.speed_mbps} Mbps em vez de 1000"),
                Text("A gigabit adapter falling back to 100 Mbps almost always means a damaged cable, "
                     "a bad connector or a cable with only 4 of its 8 wires working.",
                     "Uma placa gigabit caindo para 100 Mbps quase sempre indica cabo danificado, "
                     "conector ruim ou um cabo com só 4 dos 8 fios funcionando."),
                Text("Replace the cable (Cat5e or better) and check both connectors. If the router port "
                     "is only 100 Mbps this is expected - but an unexpected fallback is a classic cause of drops.",
                     "Troque o cabo (Cat5e ou melhor) e confira os dois conectores. Se a porta do "
                     "roteador for de 100 Mbps, é esperado - mas uma queda inesperada de velocidade "
                     "é causa clássica de desconexões."),
                score=40,
            ))
        p = prev.get(n.name)
        if p is None:
            continue
        errors = (n.errin - p.errin) + (n.errout - p.errout)
        drops = (n.dropin - p.dropin) + (n.dropout - p.dropout)
        if errors > 0 or drops >= NIC_DROPS_WARN:
            out.append(Finding(
                "warning", "cable",
                Text(f"{n.name} reported {errors} error(s) and {drops} drop(s) during the capture",
                     f"{n.name} registrou {errors} erro(s) e {drops} descarte(s) durante a captura"),
                Text("The network adapter itself saw corrupted or discarded frames. That happens below "
                     "anything a ping can see: physical layer (cable, port) or driver.",
                     "A própria placa de rede viu quadros corrompidos ou descartados. Isso acontece "
                     "abaixo do que um ping enxerga: camada física (cabo, porta) ou driver."),
                Text("Swap the cable, try another port and update/reinstall the adapter driver from the "
                     "manufacturer's site (not Windows Update).",
                     "Troque o cabo, teste outra porta e atualize/reinstale o driver da placa pelo "
                     "site do fabricante (não pelo Windows Update)."),
                score=42,
            ))
    if after and not wired_up and any(n.wireless and n.is_up for n in after):
        out.append(Finding(
            "info", "wifi",
            Text("This PC is on Wi-Fi", "Este PC está no Wi-Fi"),
            Text("Wireless links drop and retry packets due to interference, distance and other devices.",
                 "Conexões sem fio perdem e retransmitem pacotes por interferência, distância e "
                 "outros aparelhos."),
            Text("For a definitive answer, repeat the capture on a cable.",
                 "Para uma resposta definitiva, repita a captura no cabo."),
            score=20,
        ))
    return out


def _latency_findings(stats: dict[str, TargetStats], session: Session) -> list[Finding]:
    def unstable(s: TargetStats) -> bool:
        if s.median is None or s.p95 is None or (s.sent - s.lost) < MIN_RTTS_FOR_LATENCY:
            return False
        spiky = s.p95 > SPIKE_RATIO * s.median and s.p95 - s.median >= SPIKE_MIN_MS
        return spiky or (s.jitter or 0) > JITTER_MS

    def describe(xs: list[TargetStats]) -> Text:
        return Text.join("; ", [
            Text(f"{s.label}: median {ms(s.median).en}, p95 {ms(s.p95).en}, jitter {ms(s.jitter).en}",
                 f"{s.label}: mediana {ms(s.median).pt}, p95 {ms(s.p95).pt}, jitter {ms(s.jitter).pt}")
            for s in xs])

    out = []
    gw = [stats[l] for l in session.labels("gateway") if unstable(stats[l])]
    inet = [stats[l] for l in session.labels("internet") if unstable(stats[l])]
    apps = [stats[l] for l in session.labels("app") if unstable(stats[l])]
    if gw:
        d = describe(gw)
        out.append(Finding(
            "warning", "local",
            Text("Latency spikes already at your router", "Picos de latência já no seu roteador"),
            Text(f"{d.en}. On a cable the router should answer in ~1 ms consistently.",
                 f"{d.pt}. No cabo, o roteador deveria responder em ~1 ms, sempre."),
            Text("Usually a busy or overheating router, or Wi-Fi. Reboot the router and check whether "
                 "someone is saturating the network during the spikes.",
                 "Costuma ser roteador sobrecarregado ou superaquecido, ou Wi-Fi. Reinicie o roteador "
                 "e veja se alguém está saturando a rede durante os picos."),
            score=35,
        ))
    elif inet:
        d = describe(inet + apps)
        out.append(Finding(
            "warning", "bufferbloat",
            Text("Latency spikes beyond your router (bufferbloat or ISP congestion)",
                 "Picos de latência depois do roteador (bufferbloat ou congestionamento no provedor)"),
            Text(f"{d.en}. The router stayed stable, so the queueing happens in the modem or the ISP.",
                 f"{d.pt}. O roteador ficou estável, então o acúmulo de fila acontece no modem ou no provedor."),
            Text("If spikes match someone downloading/uploading, enable SQM/QoS on the router and limit "
                 "bandwidth to ~90% of your plan (test at waveform.com/tools/bufferbloat). If they happen "
                 "at peak hours regardless, it is ISP congestion.",
                 "Se os picos coincidem com alguém baixando/enviando arquivos, ative SQM/QoS no "
                 "roteador e limite a banda a ~90% do plano (teste em waveform.com/tools/bufferbloat). "
                 "Se acontecem em horário de pico de qualquer jeito, é congestionamento do provedor."),
            score=30,
        ))
    elif apps:
        d = describe(apps)
        names = ", ".join(s.label for s in apps)
        out.append(Finding(
            "warning", "route",
            Text(f"Latency spikes only on the way to {names}", f"Picos de latência só no caminho até {names}"),
            Text(f"{d.en}. General internet targets stayed stable, so the spikes come from the "
                 "route to this service or from its servers.",
                 f"{d.pt}. Os alvos gerais da internet ficaram estáveis, então os picos vêm da rota "
                 "até esse serviço ou dos servidores dele."),
            Text("Try another server region. If it persists, show the hop table to your ISP.",
                 "Tente outra região de servidor. Se persistir, mostre a tabela de saltos ao provedor."),
            score=33,
        ))
    return out


def _udp_findings(stats: dict[str, TargetStats], session: Session, stressed: set[int]) -> list[Finding]:
    """Compara UDP e ICMP ao mesmo destino e olha os descartes de UDP dentro do PC."""
    out = []
    icmp_by_host = {t.host: t.label for t in session.targets if t.role == "internet"}
    pairs = []
    for t in session.targets:
        if t.role == "udp" and t.host in icmp_by_host:
            pairs.append((stats[t.label], stats[icmp_by_host[t.host]], t.host))
    bad = [(u, i, h) for u, i, h in pairs
           if u.loss_pct >= UDP_LOSS_PCT and u.loss_pct >= UDP_LOSS_RATIO * max(i.loss_pct, 0.5)]
    if bad:
        worst = max(u.loss_pct for u, _, _ in bad)
        lines = [Text(f"{h}: UDP {num(u.loss_pct).en}% vs ICMP {num(i.loss_pct).en}%",
                      f"{h}: UDP {num(u.loss_pct).pt}% contra ICMP {num(i.loss_pct).pt}%")
                 for u, i, h in bad]
        d, w = Text.join("; ", lines), num(worst)
        out.append(Finding(
            "critical" if worst >= 10 else "warning", "udp",
            Text(f"UDP is being dropped while pings get through ({w.en}% UDP loss)",
                 f"O UDP está sendo descartado enquanto o ping passa ({w.pt}% de perda em UDP)"),
            Text(f"Same destinations, different protocol - {d.en}. Games use UDP, so this is the "
                 "kind of loss you feel in a match even when every ping looks perfect.",
                 f"Mesmos destinos, protocolo diferente - {d.pt}. Jogos usam UDP, então essa é a "
                 "perda que você sente na partida mesmo com todos os pings perfeitos."),
            Text("Usually the router (SIP ALG, flood/DoS protection, an overloaded NAT table) or ISP "
                 "traffic shaping. Update the router firmware and disable SIP ALG and UDP flood "
                 "protection; if it persists, show this comparison to your ISP.",
                 "Costuma ser o roteador (SIP ALG, proteção contra flood/DoS, tabela de NAT cheia) "
                 "ou modelagem de tráfego do provedor. Atualize o firmware do roteador e desative SIP "
                 "ALG e a proteção contra flood UDP; se continuar, mostre esta comparação ao provedor."),
            score=62,
        ))

    errors = sum(x.errors for x in session.udp)
    if errors >= UDP_RX_ERRORS_WARN:
        received = sum(x.received for x in session.udp)
        during_stress = sum(x.errors for x in session.udp if x.cycle in stressed)
        stress = Text("", "")
        if during_stress:
            stress = Text(f" {during_stress} of them while the PC was overloaded.",
                          f" {during_stress} deles com o PC sobrecarregado.")
        out.append(Finding(
            "warning", "pc",
            Text(f"Windows discarded {errors} incoming UDP datagram(s)",
                 f"O Windows descartou {errors} datagrama(s) UDP recebido(s)"),
            Text(f"{errors} datagrams reached this PC but were dropped before any program read them "
                 f"(out of {received} received).{stress.en} This loss happens inside the machine, "
                 "after the network did its job.",
                 f"{errors} datagramas chegaram a este PC mas foram descartados antes de algum "
                 f"programa lê-los (de {received} recebidos).{stress.pt} Essa perda acontece dentro "
                 "da máquina, depois que a rede fez a parte dela."),
            Text("A program is not reading its UDP socket fast enough - usually CPU starvation, an "
                 "aggressive antivirus/firewall or a VPN client. Close heavy background apps and "
                 "check the CPU chart.",
                 "Algum programa não está lendo o socket UDP a tempo - normalmente CPU no limite, "
                 "antivírus/firewall agressivo ou cliente de VPN. Feche programas pesados em segundo "
                 "plano e confira o gráfico de CPU."),
            score=38,
        ))
    return out


def _process_findings(session: Session) -> list[Finding]:
    if not session.process_name:
        return []
    states = [(x.t, x.proc_running) for x in session.sys if x.proc_running is not None]
    for (_, a), (t1, b) in zip(states, states[1:]):
        if a and not b:
            name, at = session.process_name, _clock(t1).en
            return [Finding(
                "info", "info",
                Text(f"{name} closed at {at}", f"{name} fechou em {at}"),
                Text("The watched process stopped running during the capture. If it crashed instead of "
                     "disconnecting, the network may not be the culprit at all.",
                     "O processo monitorado parou durante a captura. Se ele travou em vez de "
                     "desconectar, a rede pode nem ser a culpada."),
                Text("Compare this time with when you were kicked out.",
                     "Compare esse horário com o momento em que você caiu."),
                score=15,
                node="pc",
            )]
    return []


def analyze(session: Session) -> Analysis:
    """Roda todas as regras e devolve os findings ordenados por gravidade."""
    stats = target_stats(session)
    stressed = stressed_cycles(session)
    events = find_events(session)
    bad = {t.label: find_bad_hop(t.hops) for t in session.traces}
    limited = {t.label: rate_limited_hops(t.hops) for t in session.traces}

    findings: list[Finding] = []
    pc = _pc_findings(session, stressed, stats)
    findings += pc
    pc_blamed = any(f.severity == "critical" for f in pc)
    findings += _event_findings(events, pc_blamed)
    scopes = {e.scope for e in events if not (pc_blamed and e.stressed)}
    if not pc_blamed:
        findings += _loss_findings(stats, session, scopes)
        findings += _latency_findings(stats, session)
    findings += _hop_findings(session, bad, limited)
    findings += _dns_findings(stats, session)
    findings += _udp_findings(stats, session, stressed)
    findings += _nic_findings(session.nics_before, session.nics_after)
    findings += _process_findings(session)

    if not any(f.severity in ("critical", "warning") for f in findings):
        findings.append(Finding(
            "ok", "ok",
            Text("No network problem detected in this capture",
                 "Nenhum problema de rede detectado nesta captura"),
            Text(f"{session.cycles} cycles without blackouts, persistent loss or abnormal latency "
                 "at any point of the path.",
                 f"{session.cycles} ciclos sem apagões, perda persistente ou latência anormal em "
                 "nenhum ponto do caminho."),
            Text("Run it again while the problem actually happens (e.g. during a match), ideally for "
                 "longer. UDP was tested against public resolvers, not against your game server, so "
                 "a clean capture does not rule everything out.",
                 "Rode de novo enquanto o problema estiver acontecendo (durante uma partida, por "
                 "exemplo), de preferência por mais tempo. O UDP foi testado contra resolvedores "
                 "públicos, não contra o servidor do jogo - uma captura limpa não descarta tudo."),
            score=0,
        ))
    findings.sort(key=lambda f: (SEVERITY_RANK[f.severity], -f.score))
    return Analysis(stats, events, findings, bad, limited, stressed)
