"""Relatório HTML único e autocontido (sem CDN, sem dependências).

O relatório é pensado para quem **não** é da área. A peça central é um
"mapa de metrô" do caminho da conexão - Seu PC → Rede de casa → Provedor →
Internet → Servidor - com cada estação colorida pelo que foi encontrado e a
linha cortada no ponto da falha. Depois vêm: o que fazer, réguas com valores
de referência ("bom é abaixo de 1%"), o caminho explicado parada por parada,
os gráficos com um "como ler", as tabelas técnicas (recolhidas) e um glossário.

Decisões técnicas:

* Gráficos em SVG gerado aqui em Python: o arquivo abre offline, pode ser
  anexado num chamado e continua legível daqui a anos. O JavaScript só
  adiciona o crosshair e o botão de idioma; sem ele, os números continuam
  nas tabelas.
* Séries com a paleta Okabe-Ito (segura para daltonismo), com tons próprios
  para o modo escuro validados contra a superfície escura.
* Status (ok / atenção / problema) sempre com ícone e texto, nunca só cor.
* A linha de latência é interrompida onde houve perda: ligar os pontos por
  cima de uma perda inventaria uma medição que não existiu.
* Idiomas: todo texto vai no arquivo em inglês **e** português; o CSS mostra
  só o ativo e o botão EN | PT troca na hora.
"""

from __future__ import annotations

import html
import json
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

from netblame import __version__
from netblame.analysis import SEVERITY_RANK, Analysis, Finding, analyze, finding_node
from netblame.i18n import Lang, Text, ms, num, same, secs
from netblame.models import Session

W = 960  # largura do viewBox; o SVG escala com a página
ML, MR = 72, 16  # margens laterais compartilhadas por todos os gráficos (eixos alinhados)
PLOT_W = W - ML - MR
N_SLOTS = 5

SEVERITY_LABEL = {
    "critical": Text("Critical", "Crítico"),
    "warning": Text("Warning", "Atenção"),
    "info": Text("Note", "Observação"),
    "ok": Text("All clear", "Tudo certo"),
}
STATUS_LABEL = {
    "ok": Text("All good", "Tudo certo"),
    "warn": Text("Attention", "Atenção"),
    "fail": Text("Problem", "Problema"),
    "none": Text("Not tested", "Não testado"),
}
ROLE_LABEL = {
    "gateway": Text("your router", "seu roteador"),
    "internet": Text("internet reference", "referência da internet"),
    "app": Text("your service", "seu serviço"),
    "dns": same("DNS"),
    "udp": Text("UDP test", "teste UDP"),
}


def esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def bi(text: Text | str) -> str:
    """HTML com as duas línguas; o CSS mostra só a ativa (``html[data-lang]``)."""
    if isinstance(text, str):
        return esc(text)
    if text.en == text.pt:
        return esc(text.en)
    return f'<span class="l-en">{esc(text.en)}</span><span class="l-pt" lang="pt-BR">{esc(text.pt)}</span>'


def svg_bi(text: Text) -> str:
    """Mesma ideia de :func:`bi`, para dentro de ``<text>`` do SVG."""
    if text.en == text.pt:
        return esc(text.en)
    return f'<tspan class="l-en">{esc(text.en)}</tspan><tspan class="l-pt">{esc(text.pt)}</tspan>'


def pct(v: float) -> str:
    return bi(num(v) + same("%"))


def fmt_clock(seconds: float) -> str:
    m, s = divmod(int(round(seconds)), 60)
    h, m = divmod(m, 60)
    return f"{h}:{m:02d}:{s:02d}" if h else f"{m:02d}:{s:02d}"


# --------------------------------------------------------------------------
# Ícones (traço de 1,8 px em grade 24x24, herdam a cor do texto)
# --------------------------------------------------------------------------

_ICON_PATHS = {
    "pc": '<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/>',
    "home": ('<rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 13 5.5 7M17 13l1.5-6"/>'
             '<path d="M9.5 6.5a4 4 0 0 1 5 0M7.8 4.6a6.6 6.6 0 0 1 8.4 0"/>'
             '<path d="M7 16.5h.01M10 16.5h.01"/>'),
    "isp": ('<path d="M4 21V6.5L12 3l8 3.5V21"/><path d="M2.5 21h19M10 21v-4h4v4"/>'
            '<path d="M8 9h.01M12 9h.01M16 9h.01M8 13h.01M12 13h.01M16 13h.01"/>'),
    "internet": ('<circle cx="12" cy="12" r="9"/><path d="M3 12h18"/>'
                 '<path d="M12 3c2.8 3.2 2.8 14.8 0 18M12 3c-2.8 3.2-2.8 14.8 0 18"/>'),
    "app": ('<rect x="4" y="3" width="16" height="7.5" rx="1.8"/><rect x="4" y="13.5" width="16" height="7.5" rx="1.8"/>'
            '<path d="M8 6.75h.01M8 17.25h.01M12 6.75h4M12 17.25h4"/>'),
    "ok": '<path d="M5 12.5l4.2 4.2L19 7"/>',
    "warn": '<path d="M12 6v7.5M12 17.5h.01"/>',
    "fail": '<path d="M7 7l10 10M17 7 7 17"/>',
    "none": '<path d="M9.2 9a2.9 2.9 0 1 1 3.9 2.7c-.7.3-1.1.9-1.1 1.6v.4M12 17.5h.01"/>',
    "bulb": ('<path d="M9 18h6M10 21h4"/><path d="M12 3a6 6 0 0 0-3.6 10.8c.6.5 1 1.2 1 2V16h5.2v-.2'
             'c0-.8.4-1.5 1-2A6 6 0 0 0 12 3z"/>'),
    "clock": '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
}


def icon(name: str, size: int = 24, cls: str = "ico") -> str:
    return (f'<svg class="{cls}" width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" '
            f'stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" '
            f'aria-hidden="true">{_ICON_PATHS[name]}</svg>')


# --------------------------------------------------------------------------
# O caminho: estações do mapa
# --------------------------------------------------------------------------

@dataclass
class Stop:
    """Uma estação do mapa do caminho."""

    key: str
    name: Text
    covers: Text  # o que esta parada inclui, em linguagem simples
    status: str = "ok"  # ok | warn | fail | none
    metric: Text = field(default_factory=lambda: same(""))
    summary: Text = field(default_factory=lambda: same(""))
    findings: list[Finding] = field(default_factory=list)


def explained_cycles(analysis: Analysis) -> set[int]:
    """Ciclos cuja perda já tem dono: apagões e, se a culpa é do PC, os de sobrecarga."""
    cycles = {c for e in analysis.events for c in range(e.start_cycle, e.end_cycle + 1)}
    if any(f.category == "pc" and f.severity == "critical" for f in analysis.findings):
        cycles |= analysis.stressed_cycles
    return cycles


def loss_outside_events(session: Session, analysis: Analysis, label: str) -> float:
    """Perda de um alvo desconsiderando os ciclos já explicados (apagões, PC travado).

    Durante um apagão do provedor todos os alvos externos falham juntos; mostrar
    essa perda na estação "Internet" faria parecer que a internet também falhou.
    """
    inside = explained_cycles(analysis)
    values = [x.rtt for x in session.samples if x.target == label and x.cycle not in inside]
    return 100 * sum(v is None for v in values) / len(values) if values else 0.0


def _loss_text(session: Session, analysis: Analysis, labels: list[str]) -> Text:
    loss = max((loss_outside_events(session, analysis, l) for l in labels), default=0.0)
    if any(f.category == "pc" and f.severity == "critical" for f in analysis.findings):
        return num(loss) + Text("% loss outside PC freezes", "% de perda fora dos travamentos do PC")
    if explained_cycles(analysis):
        return num(loss) + Text("% loss outside the drops", "% de perda fora das quedas")
    return num(loss) + Text("% loss", "% de perda")


def _worst(findings: list[Finding]) -> str:
    sev = min((SEVERITY_RANK[f.severity] for f in findings), default=99)
    return {0: "fail", 1: "warn"}.get(sev, "ok")


def build_stops(session: Session, analysis: Analysis) -> list[Stop]:
    """Monta as 5 estações com status, métrica-resumo e frase em linguagem simples."""
    stats = analysis.stats
    stops = [
        Stop("pc", Text("Your PC", "Seu PC"),
             Text("Processor, memory and network adapter", "Processador, memória e placa de rede")),
        Stop("home", Text("Home network", "Rede de casa"),
             Text("Cable or Wi-Fi and your router", "Cabo ou Wi-Fi e o seu roteador")),
        Stop("isp", Text("Provider", "Provedor"),
             Text("Modem/ONT and your internet provider's network", "Modem/ONT e a rede da sua operadora")),
        Stop("internet", same("Internet"),
             Text("The big networks between your provider and the destination",
                  "As grandes redes entre a sua operadora e o destino")),
        Stop("app", Text("Server", "Servidor"),
             Text("The service you use (game, call, VPN...)", "O serviço que você usa (jogo, chamada, VPN...)")),
    ]
    by_key = {s.key: s for s in stops}
    for f in analysis.findings:
        node = finding_node(f)
        if node in by_key and f.severity != "ok":
            by_key[node].findings.append(f)

    # -- métricas e frases "tudo certo" de cada estação --
    pc = by_key["pc"]
    if session.sys:
        cpu = max(x.cpu for x in session.sys)
        ram = max(x.ram for x in session.sys)
        pc.metric = Text(f"CPU peak {cpu:.0f}% · RAM {ram:.0f}%", f"CPU no pico {cpu:.0f}% · RAM {ram:.0f}%")
        pc.summary = Text("Processor and memory kept up during the whole test.",
                          "Processador e memória deram conta durante todo o teste.")
    else:
        pc.status = "none"
        pc.metric = Text("no system data", "sem dados do sistema")
        pc.summary = Text("CPU/RAM were not measured (install psutil to enable).",
                          "CPU e RAM não foram medidas (instale o psutil para ativar).")

    home = by_key["home"]
    gw = [stats[l] for l in session.labels("gateway")]
    if gw:
        g = gw[0]
        home.metric = ms(g.median) + same(" · ") + (
            num(g.loss_pct) + Text("% loss", "% de perda") if home.findings
            else _loss_text(session, analysis, [g.label]))
        home.summary = Text("Your router answered every time, and quickly: cable and home network look healthy.",
                            "O roteador respondeu sempre, e rápido: cabo e rede de casa parecem saudáveis.")
    else:
        home.status = "none"
        home.metric = Text("router not tested", "roteador não testado")
        home.summary = Text("The router was not probed in this capture.", "O roteador não foi sondado nesta captura.")
    wired = [n for n in session.nics_after if n.is_up and not n.wireless and n.speed_mbps]
    if wired and gw:
        home.metric = home.metric + Text(f" · cable {wired[0].speed_mbps} Mbps", f" · cabo {wired[0].speed_mbps} Mbps")

    isp = by_key["isp"]
    upstream = [e for e in analysis.events if e.scope in ("upstream", "unknown")]
    isp.metric = (Text(f"{len(upstream)} drop(s) · ", f"{len(upstream)} queda(s) · ")
                  + secs(sum(e.duration for e in upstream)) + Text(" offline", " fora do ar"))
    udp = [stats[l] for l in session.labels("udp")]
    if udp:
        udp_loss = max(loss_outside_events(session, analysis, u.label) for u in udp)
        isp.metric = isp.metric + same(" · UDP ") + num(udp_loss) + Text("% loss", "% de perda")
    isp.summary = Text("The connection through your provider did not drop during the test.",
                       "A conexão pela sua operadora não caiu durante o teste.")

    net = by_key["internet"]
    inet = [stats[l] for l in session.labels("internet")]
    if inet:
        best = min(inet, key=lambda s: s.median if s.median is not None else 1e9)
        net.metric = ms(best.median) + same(" · ") + _loss_text(session, analysis, [s.label for s in inet])
        net.summary = Text("Big internet services (Cloudflare, Google) answered normally.",
                           "Serviços grandes da internet (Cloudflare, Google) responderam normalmente.")
    else:
        net.status = "none"
        net.metric = Text("not tested", "não testado")

    app = by_key["app"]
    apps = [stats[l] for l in session.labels("app")]
    if apps:
        a = apps[0]
        # O nome da estação fica sempre "Servidor"; o rótulo do alvo (que pode ser
        # técnico, como "app") aparece como o serviço testado, com o endereço real.
        desc = session.target(a.label).describe().replace("tcp://", "")
        app.covers = Text(f"Tested service: {a.label} ({desc})", f"Serviço testado: {a.label} ({desc})")
        app.metric = same(f"{a.label} · ") + ms(a.median) + same(" · ") + _loss_text(session, analysis, [a.label])
        app.summary = Text(f"The service {a.label} answered normally throughout the test.",
                           f"O serviço {a.label} respondeu normalmente durante todo o teste.")
    else:
        app.status = "none"
        app.metric = Text("no service chosen", "nenhum serviço escolhido")
        app.summary = Text("No specific service was tested. Next time add one, e.g. --preset battlenet.",
                           "Nenhum serviço específico foi testado. Na próxima, adicione um, ex.: --preset battlenet.")

    for s in stops:
        worst = _worst(s.findings)
        if worst != "ok":
            s.status = worst
            top = sorted(s.findings, key=lambda f: (SEVERITY_RANK[f.severity], -f.score))[0]
            s.summary = top.title
    return stops


HEADLINES = {
    "pc": Text("The problem is your PC", "O problema está no seu PC"),
    "home": Text("The problem is inside your home network", "O problema está na sua rede de casa"),
    "isp": Text("The problem is at your internet provider", "O problema está no seu provedor"),
    "internet": Text("The problem is on the way through the internet", "O problema está no caminho pela internet"),
    "app": Text("The problem is on the way to the server", "O problema está no caminho até o servidor"),
}


#: Manchete quando o pior achado é só um aviso: aponta o lugar sem afirmar a culpa.
HEADLINES_WARN = {
    "pc": Text("Point of attention: your PC", "Ponto de atenção: seu PC"),
    "home": Text("Point of attention: your home network", "Ponto de atenção: sua rede de casa"),
    "isp": Text("Point of attention: your provider", "Ponto de atenção: seu provedor"),
    "internet": Text("Point of attention: the way through the internet",
                     "Ponto de atenção: o caminho pela internet"),
    "app": Text("Point of attention: the way to the server", "Ponto de atenção: o caminho até o servidor"),
}


def culprit(analysis: Analysis) -> Optional[str]:
    v = analysis.verdict
    if v.severity in ("critical", "warning"):
        return finding_node(v)
    return None


def route_map(stops: list[Stop], culprit_key: Optional[str]) -> str:
    """O "mapa de metrô": estações ligadas por uma linha que corta onde está a falha."""
    items = []
    for i, s in enumerate(stops):
        nxt = stops[i + 1].status if i + 1 < len(stops) else s.status
        here = ""
        if s.key == culprit_key:
            here = f'<p class="here">{icon("warn", 14)}{bi(Text("the problem is here", "o problema está aqui"))}</p>'
        cut = '<span class="cut" aria-hidden="true">' + icon("fail", 14) + "</span>" if i and s.status == "fail" else ""
        items.append(f"""
<li class="stop st-{s.status}{' is-culprit' if s.key == culprit_key else ''}" style="--next: var(--hst-{nxt})">
  {cut}
  <div class="station">{icon(s.key, 30)}<span class="badge">{icon(s.status, 14)}</span></div>
  <p class="stop-name">{bi(s.name)}</p>
  <p class="stop-status">{bi(STATUS_LABEL[s.status])}</p>
  <p class="stop-metric">{bi(s.metric)}</p>
  {here}
</li>""")
    return f'<ol class="route" aria-label="Connection path / Caminho da conexão">{"".join(items)}</ol>'


# --------------------------------------------------------------------------
# Réguas de referência
# --------------------------------------------------------------------------

@dataclass
class Gauge:
    title: Text
    what: Text
    value: Optional[float]
    shown: Text
    good: float  # até aqui é bom
    bad: float  # a partir daqui é ruim
    vmax: float
    unit: str
    note: Text
    source: Text = field(default_factory=lambda: same(""))

    @property
    def status(self) -> str:
        if self.value is None:
            return "none"
        return "ok" if self.value <= self.good else ("fail" if self.value >= self.bad else "warn")


def build_gauges(session: Session, analysis: Analysis) -> list[Gauge]:
    stats = analysis.stats
    ext = [stats[l] for l in session.labels("internet", "app", "udp")]
    worst = max(ext, key=lambda s: s.loss_pct, default=None)
    apps = [stats[l] for l in session.labels("app")]
    inet = [stats[l] for l in session.labels("internet")]
    ref = apps[0] if apps else (min(inet, key=lambda s: s.median or 1e9) if inet else None)
    jit = ref.jitter if ref else None
    offline = sum(e.duration for e in analysis.events)
    return [
        Gauge(Text("Packet loss", "Perda de pacotes"),
              Text("Share of signals that left and never came back. In a game, each lost packet is a "
                   "movement or shot that didn't arrive.",
                   "Parte dos sinais que saíram e nunca voltaram. No jogo, cada pacote perdido é um "
                   "movimento ou tiro que não chegou."),
              worst.loss_pct if worst else None, (num(worst.loss_pct) + same("%")) if worst else same("–"),
              1.0, 3.0, 10.0, "%",
              Text("Good: under 1%. Above 3% you will notice it.", "Bom: abaixo de 1%. Acima de 3% você sente."),
              same(worst.label) if worst else same("")),
        Gauge(Text("Latency (ping)", "Latência (ping)"),
              Text("How long a signal takes to go and come back. It is the delay between your action "
                   "and the server reacting.",
                   "Quanto tempo um sinal leva para ir e voltar. É o atraso entre a sua ação e o "
                   "servidor reagir."),
              ref.median if ref else None, ms(ref.median) if ref else same("–"),
              50.0, 100.0, 200.0, " ms",
              Text("Good: under 50 ms. Above 100 ms games feel sluggish.",
                   "Bom: abaixo de 50 ms. Acima de 100 ms o jogo fica 'pesado'."),
              same(ref.label) if ref else same("")),
        Gauge(Text("Jitter (stability)", "Jitter (estabilidade)"),
              Text("How much the latency jumps from one signal to the next. High jitter means "
                   "teleporting characters and choppy calls.",
                   "Quanto a latência varia de um sinal para o outro. Jitter alto é personagem "
                   "'teleportando' e chamada picotando."),
              jit, ms(jit), 10.0, 30.0, 60.0, " ms",
              Text("Good: under 10 ms. Above 30 ms it gets unstable.",
                   "Bom: abaixo de 10 ms. Acima de 30 ms fica instável."),
              same(ref.label) if ref else same("")),
        Gauge(Text("Time offline", "Tempo fora do ar"),
              Text("Total time the internet was completely unreachable (2 seconds or more in a row). "
                   "This is what kicks you out of a match.",
                   "Tempo total em que a internet ficou totalmente inacessível (2 segundos ou mais "
                   "seguidos). É isso que te derruba da partida."),
              offline, secs(offline), 0.0, 10.0, 60.0, " s",
              Text("Good: zero. Any blackout can disconnect you.",
                   "Bom: zero. Qualquer apagão pode te desconectar."),
              Text(f"{len(analysis.events)} blackout(s)", f"{len(analysis.events)} apagão(ões)")),
    ]


def gauge_card(g: Gauge) -> str:
    def pos(v: float) -> float:
        return max(0.0, min(100.0, 100 * v / g.vmax))

    # A faixa "bom" sempre tem um mínimo visível, mesmo quando o limite é zero.
    good = max(pos(g.good), 3.0)
    bad = max(pos(g.bad), good)
    marker = ""
    if g.value is not None:
        marker = f'<span class="marker" style="left:{pos(g.value):.1f}%"></span>'
    over = '<span class="over">+</span>' if g.value is not None and g.value > g.vmax else ""
    source = f'<span class="g-src">{bi(g.source)}</span>' if g.source.en else ""
    chip = STATUS_LABEL[g.status] if g.status != "none" else Text("No data", "Sem dados")
    return f"""
<article class="gauge st-{g.status}">
  <header><h3>{bi(g.title)}</h3><span class="chip">{icon(g.status, 14)}{bi(chip)}</span></header>
  <p class="g-value">{bi(g.shown)}{over}{source}</p>
  <div class="ruler" aria-hidden="true">
    <span class="band b-ok" style="width:{good:.1f}%"></span><span class="band b-warn" style="width:{bad - good:.1f}%"></span><span class="band b-fail" style="width:{100 - bad:.1f}%"></span>
    {marker}
  </div>
  <div class="ruler-scale" aria-hidden="true"><span>0</span><span style="left:{pos(g.good):.1f}%">{'' if g.good == 0 else f'{g.good:g}'}</span><span style="left:{pos(g.bad):.1f}%">{g.bad:g}</span><span class="end">{g.vmax:g}{esc(g.unit.strip())}</span></div>
  <p class="g-note">{bi(g.note)}</p>
  <p class="g-what"><strong>{bi(Text("What is it?", "O que é?"))}</strong> {bi(g.what)}</p>
</article>"""


# --------------------------------------------------------------------------
# Gráficos SVG
# --------------------------------------------------------------------------

def nice_step(span: float, max_ticks: int) -> float:
    """Passo "redondo" (1, 2, 5 x 10^n) para no máximo ``max_ticks`` divisões."""
    if span <= 0:
        return 1.0
    raw = span / max_ticks
    mag = 10 ** math.floor(math.log10(raw))
    for m in (1, 2, 5, 10):
        if raw <= m * mag:
            return m * mag
    return 10 * mag


def time_step(duration: float) -> float:
    for step in (5, 10, 15, 30, 60, 120, 300, 600, 900, 1800, 3600):
        if duration / step <= 10:
            return step
    return 7200


class Scale:
    def __init__(self, d0: float, d1: float, r0: float, r1: float) -> None:
        self.d0, self.d1, self.r0, self.r1 = d0, d1 if d1 != d0 else d0 + 1, r0, r1

    def __call__(self, v: float) -> float:
        return self.r0 + (v - self.d0) / (self.d1 - self.d0) * (self.r1 - self.r0)


def color_slots(session: Session) -> dict[str, Optional[int]]:
    """Cor (slot da paleta) de cada alvo no gráfico de latência, ou None se não for plotado.

    A cor segue o alvo, nunca a posição: o mesmo alvo tem a mesma cor no
    gráfico, na legenda, na tabela e no tooltip. Só os primeiros 5 alvos
    não-UDP são plotados - a paleta tem 5 cores validadas e repetir cor
    criaria séries indistinguíveis. Os demais (e os UDP, comparados no card
    próprio) continuam na faixa de perdas e nas tabelas.
    """
    slots: dict[str, Optional[int]] = {}
    n = 0
    for t in session.targets:
        if t.role != "udp" and n < N_SLOTS:
            slots[t.label] = n
            n += 1
        else:
            slots[t.label] = None
    return slots


def _svg_open(name: str, h: float, aria: Text) -> str:
    # O aria-label começa em inglês; o JS troca junto com o idioma.
    return (f'<svg class="chart" data-chart="{name}" viewBox="0 0 {W} {h}" role="img" '
            f'aria-label="{esc(aria.en)}" data-aria-en="{esc(aria.en)}" data-aria-pt="{esc(aria.pt)}">')


def _x_axis(x: Scale, duration: float, y: float, tick_top: float) -> list[str]:
    out = [f'<line class="axis" x1="{ML}" x2="{W - MR}" y1="{y}" y2="{y}"/>']
    step = time_step(duration)
    t = 0.0
    while t <= duration + 1e-9:
        px = x(t)
        out.append(f'<line class="grid" x1="{px:.1f}" x2="{px:.1f}" y1="{tick_top}" y2="{y}"/>')
        out.append(f'<text class="tick" x="{px:.1f}" y="{y + 16}" text-anchor="middle">{fmt_clock(t)}</text>')
        t += step
    return out


def _y_axis(y: Scale, ticks: Iterable[float], unit: str) -> list[str]:
    out = []
    for v in ticks:
        py = y(v)
        out.append(f'<line class="grid" x1="{ML}" x2="{W - MR}" y1="{py:.1f}" y2="{py:.1f}"/>')
        out.append(f'<text class="tick" x="{ML - 6}" y="{py + 4:.1f}" text-anchor="end">{v:g}{unit}</text>')
    return out


def _path(points: list[tuple[float, Optional[float]]], x: Scale, y: Scale) -> str:
    """Caminho SVG que se interrompe nos ``None`` (perdas)."""
    parts, pen_down = [], False
    for t, v in points:
        if v is None:
            pen_down = False
            continue
        parts.append(f"{'L' if pen_down else 'M'}{x(t):.1f} {y(v):.1f}")
        pen_down = True
    return "".join(parts)


def _event_bands(analysis: Analysis, x: Scale, top: float, bottom: float) -> list[str]:
    out = []
    for e in analysis.events:
        x0, x1 = x(e.start_t), x(e.end_t)
        out.append(f'<rect class="evt" x="{x0:.1f}" y="{top}" width="{max(x1 - x0, 2):.1f}" '
                   f'height="{bottom - top}"/>')
    return out


def _markers(analysis: Analysis, x: Scale, top: float, bottom: float, label: bool) -> list[str]:
    """Linha vertical nos momentos marcados (ex.: quando o jogo caiu)."""
    out = []
    for t, text in analysis.markers:
        px = x(t)
        out.append(f'<line class="mark" x1="{px:.1f}" x2="{px:.1f}" y1="{top}" y2="{bottom}"/>')
        if label:
            anchor = "end" if px > W - 160 else "start"
            dx = -6 if anchor == "end" else 6
            out.append(f'<text class="mark-lbl" x="{px + dx:.1f}" y="{top + 12}" text-anchor="{anchor}">'
                       f'{svg_bi(text)}</text>')
    return out


def _overlay(h: float, top: float, bottom: float) -> str:
    """Linha do crosshair (escondida) + retângulo que captura o ponteiro."""
    return (f'<line class="xhair" x1="0" x2="0" y1="{top}" y2="{bottom}" visibility="hidden"/>'
            f'<rect class="hit" x="{ML}" y="0" width="{PLOT_W}" height="{h}"/>')


def latency_chart(session: Session, analysis: Analysis, x: Scale) -> str:
    h, top, bottom = 300, 10, 270
    slots = color_slots(session)
    # A escala considera só as séries desenhadas; um pico de uma série oculta achataria as outras.
    rtts = [s.rtt for s in session.samples if s.rtt is not None and slots.get(s.target) is not None]
    vmax = max(rtts, default=10.0)
    step = nice_step(vmax, 5)
    ymax = step * math.ceil(vmax / step)
    y = Scale(0, ymax, bottom, top)
    out = [_svg_open("latency", h, Text("Round-trip time per target over the capture",
                                        "Tempo de resposta por alvo ao longo da captura"))]
    out += _event_bands(analysis, x, top, bottom)
    out += _y_axis(y, [i * step for i in range(int(ymax / step) + 1)], " ms")
    out += _x_axis(x, session.duration, bottom, top)
    by_target: dict[str, list] = {t.label: [] for t in session.targets}
    for s in session.samples:
        by_target[s.target].append((s.t, s.rtt))
    for label, slot in slots.items():
        if slot is not None:
            out.append(f'<path class="line s{slot}" d="{_path(sorted(by_target[label]), x, y)}"/>')
    out += _markers(analysis, x, top, bottom, label=True)
    out.append(_overlay(h, top, bottom))
    out.append("</svg>")
    return "".join(out)


def loss_strip(session: Session, analysis: Analysis, x: Scale) -> str:
    row = 22
    top = 4
    h = top + row * len(session.targets) + 26
    bottom = top + row * len(session.targets)
    out = [_svg_open("loss", h, Text("Packet losses per target over the capture",
                                     "Perdas de pacote por alvo ao longo da captura"))]
    for i, t in enumerate(session.targets):
        cy = top + row * i + row / 2
        out.append(f'<text class="tick lbl" x="{ML - 6}" y="{cy + 4:.1f}" text-anchor="end">{esc(t.label)}</text>')
        out.append(f'<line class="track" x1="{ML}" x2="{W - MR}" y1="{cy:.1f}" y2="{cy:.1f}"/>')
    rows = {t.label: i for i, t in enumerate(session.targets)}
    width = max(PLOT_W / max(session.cycles, 1), 1.5)
    for s in session.samples:
        if s.rtt is None:
            cy = top + row * rows[s.target]
            out.append(f'<rect class="lossmark" x="{x(s.t):.1f}" y="{cy + 4}" width="{width:.1f}" height="{row - 8}"/>')
    out += _x_axis(x, session.duration, bottom, top)
    out += _markers(analysis, x, top, bottom, label=False)
    out.append(_overlay(h, top, bottom))
    out.append("</svg>")
    return "".join(out)


def system_chart(session: Session, analysis: Analysis, x: Scale) -> str:
    h, top, bottom = 190, 10, 160
    y = Scale(0, 100, bottom, top)
    out = [_svg_open("system", h, Text("CPU and RAM usage over the capture",
                                       "Uso de CPU e RAM ao longo da captura"))]
    out += _y_axis(y, [0, 25, 50, 75, 100], "%")
    out += _x_axis(x, session.duration, bottom, top)
    py = y(90)
    out.append(f'<line class="threshold" x1="{ML}" x2="{W - MR}" y1="{py:.1f}" y2="{py:.1f}"/>')
    out.append(f'<text class="tick" x="{W - MR - 4}" y="{py - 4:.1f}" text-anchor="end">'
               f'{svg_bi(Text("overload line 90%", "linha de sobrecarga 90%"))}</text>')
    cpu = [(s.t, s.cpu) for s in session.sys]
    ram = [(s.t, s.ram) for s in session.sys]
    out.append(f'<path class="line s0" d="{_path(cpu, x, y)}"/>')
    out.append(f'<path class="line s1" d="{_path(ram, x, y)}"/>')
    out += _markers(analysis, x, top, bottom, label=True)
    out.append(_overlay(h, top, bottom))
    out.append("</svg>")
    return "".join(out)


def legend(labels: list[tuple[str, Text | str]]) -> str:
    items = "".join(
        f'<li><svg width="18" height="10" aria-hidden="true">'
        f'<line class="line {cls}" x1="1" x2="17" y1="5" y2="5"/></svg>{bi(label)}</li>'
        for cls, label in labels
    )
    return f'<ul class="legend">{items}</ul>'


def not_plotted_note(session: Session) -> str:
    """Avisa quais alvos ficaram fora do gráfico de latência (e onde encontrá-los)."""
    hidden = [label for label, slot in color_slots(session).items()
              if slot is None and session.target(label).role != "udp"]
    if not hidden:
        return ""
    names = ", ".join(hidden)
    return '<p class="fine">' + bi(Text(f"Not plotted (only 5 colors): {names}. See the tables below.",
                                        f"Fora do gráfico (só 5 cores): {names}. Veja as tabelas abaixo.")) + "</p>"


def how_to_read(text: Text) -> str:
    return (f'<aside class="howto">{icon("bulb", 18)}<p><strong>{bi(Text("How to read it", "Como ler"))}</strong> '
            f'{bi(text)}</p></aside>')


# --------------------------------------------------------------------------
# Blocos HTML
# --------------------------------------------------------------------------

def finding_block(f: Finding) -> str:
    return f"""
<div class="finding sev-{f.severity}">
  <p class="f-sev">{bi(SEVERITY_LABEL[f.severity])}</p>
  <h4>{bi(f.title)}</h4>
  <p>{bi(f.detail)}</p>
  <p class="todo"><strong>{bi(Text("What to do", "O que fazer"))}</strong> {bi(f.advice)}</p>
</div>"""


def step_card(n: int, s: Stop) -> str:
    body = "".join(finding_block(f) for f in sorted(s.findings, key=lambda f: (SEVERITY_RANK[f.severity], -f.score)))
    return f"""
<article class="step st-{s.status}" id="step-{s.key}">
  <div class="step-num">{n}</div>
  <div class="step-body">
    <header>
      <span class="step-ico">{icon(s.key, 22)}</span>
      <div><h3>{bi(s.name)}</h3><p class="covers">{bi(s.covers)}</p></div>
      <span class="chip">{icon(s.status, 14)}{bi(STATUS_LABEL[s.status])}</span>
    </header>
    <p class="step-summary">{bi(s.summary)}</p>
    <p class="step-metric">{bi(s.metric)}</p>
    {body}
  </div>
</article>"""


def scoreboard(stops: list[Stop]) -> str:
    """Placar compacto das 5 paradas, para quem só quer bater o olho."""
    rows = "".join(
        f'<li class="st-{s.status}"><span class="sb-ico">{icon(s.key, 18)}</span>'
        f'<span class="sb-name">{bi(s.name)}</span>'
        f'<span class="chip">{icon(s.status, 12)}{bi(STATUS_LABEL[s.status])}</span></li>'
        for s in stops)
    return f'<ul class="scoreboard">{rows}</ul>'


def actions(analysis: Analysis) -> str:
    """Lista numerada do que fazer, na ordem de gravidade, sem repetir conselho."""
    seen, items = set(), []
    for f in analysis.findings:
        if f.severity in ("critical", "warning", "ok") and f.advice.en not in seen:
            seen.add(f.advice.en)
            items.append(f'<li><p class="a-title">{bi(f.title)}</p><p>{bi(f.advice)}</p></li>')
        if len(items) == 4:
            break
    return f'<ol class="actions">{"".join(items)}</ol>'


def _table(headers: list[Text | str], rows: list[list[str]], row_classes: Optional[list[str]] = None,
           numeric: Iterable[int] = ()) -> str:
    """Tabela HTML; colunas em ``numeric`` ficam alinhadas à direita com dígitos tabulares.

    As células já chegam como HTML pronto (passadas por :func:`bi` ou :func:`esc`).
    """
    numeric = set(numeric)
    head = "".join(f'<th{" class=num" if i in numeric else ""}>{bi(h)}</th>' for i, h in enumerate(headers))
    body = []
    for r, row in enumerate(rows):
        cls = f' class="{row_classes[r]}"' if row_classes and row_classes[r] else ""
        cells = "".join(f'<td{" class=num" if i in numeric else ""}>{c}</td>' for i, c in enumerate(row))
        body.append(f"<tr{cls}>{cells}</tr>")
    return f'<div class="table-wrap"><table><thead><tr>{head}</tr></thead><tbody>{"".join(body)}</tbody></table></div>'


def stats_table(session: Session, analysis: Analysis) -> str:
    rows = []
    slots = color_slots(session)
    for t in session.targets:
        s = analysis.stats[t.label]
        slot = slots[t.label]
        key = f'<span class="key {"s" + str(slot) if slot is not None else "none"}" aria-hidden="true"></span>'
        rows.append([
            f"{key}<strong>{esc(t.label)}</strong><br><small>{bi(ROLE_LABEL[t.role])} · {esc(t.describe())}</small>",
            pct(s.loss_pct) + (' <span class="flag">!</span>' if s.loss_pct >= 1 else ""),
            str(s.sent), bi(ms(s.mean)), bi(ms(s.median)), bi(ms(s.p95)), bi(ms(s.max)), bi(ms(s.jitter)),
        ])
    return _table([Text("Target", "Alvo"), Text("Loss", "Perda"), Text("Probes", "Sondas"),
                   Text("Mean", "Média"), Text("Median", "Mediana"), "p95",
                   Text("Max", "Máx."), "Jitter"], rows, numeric=range(1, 8))


SCOPE_LABEL = {
    "local": Text("Local (router unreachable too)", "Local (roteador também inacessível)"),
    "upstream": Text("Upstream (router OK)", "Depois do roteador (roteador OK)"),
    "unknown": Text("Unknown (no gateway probe)", "Indefinido (gateway não sondado)"),
}


def events_table(analysis: Analysis) -> str:
    if not analysis.events:
        return ('<p class="fine">' + bi(Text(
            "No blackouts (2+ consecutive cycles with every external target down).",
            "Nenhum apagão (2+ ciclos seguidos com todos os alvos externos fora).")) + "</p>")
    rows = [[fmt_clock(e.start_t), bi(secs(e.duration)), str(e.cycles),
             bi(SCOPE_LABEL[e.scope] + (Text(" · PC overloaded", " · PC sobrecarregado") if e.stressed else same("")))]
            for e in analysis.events]
    return _table([Text("Start", "Início"), Text("Duration", "Duração"), Text("Cycles", "Ciclos"),
                   Text("Where", "Onde")], rows, numeric=(1, 2))


def hops_tables(session: Session, analysis: Analysis) -> str:
    if not session.traces:
        return '<p class="fine">' + bi(Text("Route tracing was disabled for this capture.",
                                            "O rastreamento de rota foi desativado nesta captura.")) + "</p>"
    blocks = []
    for trace in session.traces:
        bad = analysis.bad_hops.get(trace.label)
        limited = set(analysis.rate_limited.get(trace.label, []))
        rows, classes = [], []
        for h in trace.hops:
            note, cls = "", ""
            if bad and h.hop == bad.hop:
                note = f'<span class="tag tag-bad">{bi(Text("loss starts here", "a perda começa aqui"))}</span>'
                cls = "culprit"
            elif bad and h.hop > bad.hop and h.loss_pct is not None:
                note, cls = f'<span class="tag">{bi(Text("inherits loss", "herda a perda"))}</span>', "after"
            elif h.hop in limited:
                note = f'<span class="tag">{bi(Text("ICMP rate-limit · harmless", "limite de ICMP · inofensivo"))}</span>'
            elif h.host is None:
                note = f'<span class="fine">{bi(Text("no reply to traceroute", "não respondeu ao traceroute"))}</span>'
            loss = "–" if h.loss_pct is None else pct(h.loss_pct)
            rows.append([str(h.hop), esc(h.host or "*"), loss, str(h.sent or "–"),
                         bi(ms(h.rtt_avg)), bi(ms(h.rtt_best)), bi(ms(h.rtt_worst)), note])
            classes.append(cls)
        table = _table([Text("Hop", "Salto"), Text("Address", "Endereço"), Text("Loss", "Perda"),
                        Text("Sent", "Enviados"), Text("Avg", "Média"), Text("Best", "Melhor"),
                        Text("Worst", "Pior"), ""], rows, classes, numeric=range(2, 7))
        title = Text(f"Route to {trace.label}", f"Rota até {trace.label}")
        blocks.append(f'<h4 class="sub-h">{bi(title)} <small>({esc(trace.destination)})</small></h4>{table}')
    return "".join(blocks)


def nics_table(session: Session) -> str:
    if not session.nics_after and not session.nics_before:
        return '<p class="fine">' + bi(Text("No adapter data (psutil not installed).",
                                            "Sem dados das placas (psutil não instalado).")) + "</p>"
    before = {n.name: n for n in session.nics_before}
    rows = []
    for n in session.nics_after or session.nics_before:
        b = before.get(n.name, n)
        speed = f"{n.speed_mbps} Mbps" if n.speed_mbps else bi(Text("unknown", "desconhecida"))
        if not n.wireless and 0 < n.speed_mbps < 1000:
            speed += ' <span class="flag">!</span>'
        d_err = (n.errin - b.errin) + (n.errout - b.errout)
        d_drop = (n.dropin - b.dropin) + (n.dropout - b.dropout)
        rows.append([esc(n.name), "Wi-Fi" if n.wireless else bi(Text("Wired", "Cabo")), speed,
                     f"{n.errin + n.errout}", f"{'+' if d_err else ''}{d_err}",
                     f"{n.dropin + n.dropout}", f"{'+' if d_drop else ''}{d_drop}"])
    return _table([Text("Adapter", "Placa"), Text("Type", "Tipo"), Text("Link speed", "Velocidade"),
                   Text("Errors (total)", "Erros (total)"), Text("Errors (capture)", "Erros (captura)"),
                   Text("Drops (total)", "Descartes (total)"), Text("Drops (capture)", "Descartes (captura)")],
                  rows, numeric=range(2, 7))


def udp_section(session: Session, analysis: Analysis) -> str:
    """Card "UDP vs ICMP": mesmo destino, dois protocolos, lado a lado."""
    icmp_by_host = {t.host: t.label for t in session.targets if t.role == "internet"}
    pairs = [(t, icmp_by_host[t.host]) for t in session.targets if t.role == "udp" and t.host in icmp_by_host]
    if not pairs and not session.udp:
        return ""
    rows = []
    for udp_t, icmp_label in pairs:
        u, i = analysis.stats[udp_t.label], analysis.stats[icmp_label]
        flag = ' <span class="flag">!</span>' if u.loss_pct >= 2 and u.loss_pct >= 3 * max(i.loss_pct, 0.5) else ""
        rows.append([esc(udp_t.host), pct(i.loss_pct), pct(u.loss_pct) + flag,
                     bi(ms(i.median)), bi(ms(u.median))])
    table = _table([Text("Destination", "Destino"), Text("ICMP loss", "Perda ICMP"),
                    Text("UDP loss", "Perda UDP"), Text("ICMP median", "Mediana ICMP"),
                    Text("UDP median", "Mediana UDP")], rows, numeric=range(1, 5)) if rows else ""
    counters = ""
    if session.udp:
        received = sum(x.received for x in session.udp)
        errors = sum(x.errors for x in session.udp)
        counters = '<p class="fine counters">' + bi(Text(
            f"Whole PC during the capture: {received} UDP datagrams received, {errors} discarded by Windows "
            "before a program could read them.",
            f"PC inteiro durante a captura: {received} datagramas UDP recebidos, {errors} descartados pelo "
            "Windows antes de algum programa lê-los.")) + "</p>"
    return f"""
<section class="panel">
  <h3>{bi(Text("UDP vs ICMP", "UDP vs ICMP"))}</h3>
  <p class="lede">{bi(Text("Games talk UDP. The same public servers are tested with ping (ICMP) and with UDP: "
                           "if only UDP loses packets, something on the way treats game traffic worse.",
                           "Jogos conversam por UDP. Os mesmos servidores públicos são testados com ping (ICMP) e "
                           "com UDP: se só o UDP perde pacotes, algo no caminho trata o tráfego de jogo pior."))}</p>
  {table}
  {counters}
</section>"""


GLOSSARY = [
    (Text("Latency (ping)", "Latência (ping)"),
     Text("Time for a signal to reach a point and come back, in milliseconds (ms). Lower is better.",
          "Tempo para um sinal ir até um ponto e voltar, em milissegundos (ms). Quanto menor, melhor.")),
    (Text("Packet loss", "Perda de pacotes"),
     Text("Signals that never came back. Even 1–2% is felt in games and calls.",
          "Sinais que nunca voltaram. Até 1–2% já se sente em jogos e chamadas.")),
    (same("Jitter"),
     Text("How much the latency varies. Stable connections have low jitter.",
          "Quanto a latência varia. Conexões estáveis têm jitter baixo.")),
    (Text("Blackout", "Apagão"),
     Text("2 seconds or more in a row with the internet completely unreachable.",
          "2 segundos ou mais seguidos com a internet totalmente inacessível.")),
    (Text("Gateway / router", "Gateway / roteador"),
     Text("The box that connects your home to the internet. First stop of every signal.",
          "O aparelho que liga a sua casa à internet. Primeira parada de todo sinal.")),
    (Text("Hop", "Salto"),
     Text("Each router the signal passes through on its way. A route has 5 to 20 hops.",
          "Cada roteador por onde o sinal passa no caminho. Uma rota tem de 5 a 20 saltos.")),
    (same("DNS"),
     Text("The internet's phone book: turns names (battle.net) into addresses.",
          "A lista telefônica da internet: transforma nomes (battle.net) em endereços.")),
    (same("ICMP · TCP · UDP"),
     Text("Ways of sending data. Ping uses ICMP, websites use TCP, games and calls use UDP.",
          "Formas de enviar dados. O ping usa ICMP, sites usam TCP, jogos e chamadas usam UDP.")),
    (same("Bufferbloat"),
     Text("Latency spikes when the line is busy (someone downloading), because data waits in a queue.",
          "Picos de latência quando a linha está ocupada (alguém baixando), porque os dados esperam numa fila.")),
]


def glossary() -> str:
    items = "".join(f"<div><dt>{bi(t)}</dt><dd>{bi(d)}</dd></div>" for t, d in GLOSSARY)
    return f'<dl class="glossary">{items}</dl>'


def _chart_data(session: Session) -> dict:
    """Dados mínimos para o tooltip do crosshair (por ciclo)."""
    cycles = session.cycles or (max((s.cycle for s in session.samples), default=-1) + 1)
    t = [0.0] * cycles
    series = {tg.label: [None] * cycles for tg in session.targets}
    for s in session.samples:
        if s.cycle < cycles:
            t[s.cycle] = s.t
            series[s.target][s.cycle] = s.rtt
    cpu = [None] * cycles
    ram = [None] * cycles
    for x in session.sys:
        if x.cycle < cycles:
            cpu[x.cycle], ram[x.cycle] = x.cpu, x.ram
    return {
        "t": t, "labels": [tg.label for tg in session.targets], "series": series,
        "slots": color_slots(session),
        "cpu": cpu, "ram": ram, "x0": ML, "x1": W - MR, "duration": session.duration or 1,
    }


def render(session: Session, analysis: Optional[Analysis] = None, lang: Lang = "en") -> str:
    """Gera o HTML completo do relatório.

    ``lang`` é só o idioma *inicial*: as duas línguas vão no arquivo e o leitor
    troca pelo botão EN | PT (a escolha fica salva no navegador).
    """
    analysis = analysis or analyze(session)
    x = Scale(0, session.duration or 1, ML, W - MR)
    verdict = analysis.verdict
    stops = build_stops(session, analysis)
    where = culprit(analysis)
    headlines = HEADLINES if verdict.severity == "critical" else HEADLINES_WARN
    headline = headlines.get(where or "", Text("Your connection was healthy during the test",
                                                "Sua conexão estava saudável durante o teste"))
    hero_state = {"critical": "fail", "warning": "warn"}.get(verdict.severity, "ok")
    demo = ""
    if session.demo_scenario:
        demo = f'<span class="pill">{bi(Text("Demo", "Demonstração"))} · {esc(session.demo_scenario)}</span>'
    how = Text(
        f"For {fmt_clock(session.duration)} (min:s), every {session.interval:g} s, netblame sent signals to "
        f"{len(session.targets)} points along your connection at the same time and compared which ones failed together.",
        f"Durante {fmt_clock(session.duration)} (min:s), a cada {session.interval:g} s, o netblame mandou sinais para "
        f"{len(session.targets)} pontos da sua conexão ao mesmo tempo e comparou quais falharam juntos.")
    meta = (same(session.started_at.replace("T", " ")) + same(" · ")
            + Text(f"{session.cycles} cycles", f"{session.cycles} ciclos")
            + Text(f" · host {session.hostname or '?'}", f" · máquina {session.hostname or '?'}"))

    system = ""
    if session.sys:
        system = f"""
<section class="panel">
  <h3>{bi(Text("PC load", "Carga do PC"))}</h3>
  <p class="lede">{bi(Text("How busy your processor (CPU) and memory (RAM) were during the test.",
                           "O quanto o processador (CPU) e a memória (RAM) estavam ocupados durante o teste."))}</p>
  {legend([("s0", "CPU"), ("s1", "RAM")])}
  <div class="chart-wrap">{system_chart(session, analysis, x)}</div>
  {how_to_read(Text("If the lines touch the overload line at the same moments the losses happen, the PC "
                    "could not keep up - the network is not to blame.",
                    "Se as linhas encostam na linha de sobrecarga nos mesmos momentos das perdas, o PC não "
                    "deu conta - a culpa não é da rede."))}
</section>"""
    notes = "".join(f"<li>{bi(n)}</li>" for n in session.notes)
    observations = [f for f in analysis.findings
                    if f.severity == "info" and finding_node(f) is None and f.category != "drop"]
    drops = [f for f in analysis.findings if f.category == "drop"]
    drops_html = ""
    if drops:
        drops_html = ('<section class="drops"><h2>' + bi(Text("When the game dropped", "Quando o jogo caiu"))
                      + "</h2>" + "".join(finding_block(f) for f in drops) + "</section>")
    obs_html = ""
    if observations:
        obs_html = ('<div class="observations"><h4>' + bi(Text("Other observations", "Outras observações"))
                    + "</h4>" + "".join(finding_block(f) for f in observations) + "</div>")
    data = json.dumps(_chart_data(session), separators=(",", ":")).replace("</", "<\\/")
    target_legend = legend([(f"s{slot}", label) for label, slot in color_slots(session).items()
                            if slot is not None])

    return f"""<!doctype html>
<html lang="{'pt-BR' if lang == 'pt' else 'en'}" data-lang="{lang}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{'Relatório netblame' if lang == 'pt' else 'netblame report'}</title>
<script>{HEAD_JS}</script>
<style>{CSS}</style>
</head>
<body>
<header class="hero hero-{hero_state}">
  <div class="wrap">
    <nav class="topbar">
      <p class="brand"><span class="logo" aria-hidden="true"></span>netblame <span class="ver">v{__version__}</span> {demo}</p>
      <div class="langswitch" role="group" aria-label="Language / Idioma">
        <button type="button" data-set-lang="en" aria-pressed="{str(lang == 'en').lower()}">EN</button>
        <button type="button" data-set-lang="pt" aria-pressed="{str(lang == 'pt').lower()}">PT</button>
      </div>
    </nav>
    <p class="eyebrow">{bi(Text("Connection diagnosis", "Diagnóstico da conexão"))}</p>
    <h1>{bi(headline)}</h1>
    <p class="hero-sub">{bi(verdict.title)}</p>
    {route_map(stops, where)}
    <p class="hero-how">{icon("clock", 16)}<span>{bi(how)} <span class="meta">{bi(meta)}</span></span></p>
  </div>
</header>

<main class="wrap">

<section class="summary">
  <div class="summary-text">
    <h2>{bi(Text("In 30 seconds", "Em 30 segundos"))}</h2>
    <p class="big">{bi(verdict.detail)}</p>
    {scoreboard(stops)}
  </div>
  <div class="summary-actions">
    <h2>{bi(Text("What to do now", "O que fazer agora"))}</h2>
    {actions(analysis)}
  </div>
</section>

{drops_html}

<section class="block">
  <h2 class="sec">{bi(Text("Key measurements", "Medidas principais"))}</h2>
  <p class="sec-lede">{bi(Text("Your results next to reference values - like a lab test, the marker shows where you are.",
                               "Seus resultados comparados com valores de referência - como num exame, o marcador mostra onde você está."))}</p>
  <div class="gauges">{"".join(gauge_card(g) for g in build_gauges(session, analysis))}</div>
</section>

<section class="block">
  <h2 class="sec">{bi(Text("The path, stop by stop", "O caminho, parada por parada"))}</h2>
  <p class="sec-lede">{bi(Text("Every signal leaves your PC and passes through these stops. This is what we found at each one.",
                               "Todo sinal sai do seu PC e passa por estas paradas. Isto é o que encontramos em cada uma."))}</p>
  <div class="steps">{"".join(step_card(i + 1, s) for i, s in enumerate(stops))}</div>
  {obs_html}
</section>

<section class="block">
  <h2 class="sec">{bi(Text("Timeline", "Linha do tempo"))}</h2>
  <p class="sec-lede">{bi(Text("What happened second by second. Hover the charts (or focus them and use ← →) to see the values.",
                               "O que aconteceu segundo a segundo. Passe o mouse nos gráficos (ou dê foco e use ← →) para ver os valores."))}</p>
  <section class="panel">
    <h3>{bi(Text("Latency", "Latência"))}</h3>
    <p class="lede">{bi(Text("Response time of each point, in milliseconds. Lower and flatter is better.",
                             "Tempo de resposta de cada ponto, em milissegundos. Mais baixo e mais reto é melhor."))}</p>
    {target_legend}{not_plotted_note(session)}
    <div class="chart-wrap">{latency_chart(session, analysis, x)}</div>
    <h4 class="strip-title">{bi(Text("Packet loss", "Perda de pacotes"))} <span class="lossdot" aria-hidden="true"></span><small>{bi(Text("= signal that did not come back", "= sinal que não voltou"))}</small></h4>
    <div class="chart-wrap">{loss_strip(session, analysis, x)}</div>
    {how_to_read(Text("Red marks lined up in every row at the same time = the whole connection dropped (shaded "
                      "bands in the chart above). Marks in a single row = only that point had trouble. If the "
                      "'gateway' row is clean while the others fail together, your home network is fine.",
                      "Marcas vermelhas alinhadas em todas as linhas ao mesmo tempo = a conexão inteira caiu "
                      "(faixas sombreadas no gráfico de cima). Marcas numa linha só = só aquele ponto teve "
                      "problema. Se a linha 'gateway' está limpa enquanto as outras falham juntas, sua rede de "
                      "casa está bem."))}
  </section>
  {system}
  {udp_section(session, analysis)}
</section>

<section class="block">
  <h2 class="sec">{bi(Text("Technical details", "Detalhes técnicos"))}</h2>
  <p class="sec-lede">{bi(Text("For your provider's support team or anyone who wants the raw numbers.",
                               "Para o suporte da sua operadora ou para quem quer os números completos."))}</p>
  <details class="tech" open><summary>{bi(Text("Hop by hop", "Salto a salto"))}</summary>
    <p class="lede">{bi(Text("Each hop was pinged throughout the capture. Real loss starts at one hop and continues to the end; "
                             "loss that appears at one hop and vanishes after it is ICMP rate-limiting and harmless.",
                             "Cada salto foi pingado durante toda a captura. Perda real começa num salto e continua até o fim; "
                             "perda que aparece num salto e some depois dele é limite de ICMP, inofensivo."))}</p>
    {hops_tables(session, analysis)}
  </details>
  <details class="tech"><summary>{bi(Text("Per-target statistics", "Estatísticas por alvo"))}</summary>
    {stats_table(session, analysis)}
  </details>
  <details class="tech"><summary>{bi(Text("Blackouts", "Apagões"))}</summary>
    {events_table(analysis)}
  </details>
  <details class="tech"><summary>{bi(Text("Network adapters", "Placas de rede"))}</summary>
    {nics_table(session)}
  </details>
</section>

<section class="block">
  <h2 class="sec">{bi(Text("Words in this report", "Palavras deste relatório"))}</h2>
  {glossary()}
</section>

<footer class="foot">
  {'<ul class="notes">' + notes + '</ul>' if notes else ''}
  <p>{bi(Text("UDP was tested against public resolvers, not against your game server, and probes can't see "
              "everything a game does - a clean report is strong evidence, not proof.",
              "O UDP foi testado contra resolvedores públicos, não contra o servidor do jogo, e as sondas não "
              "enxergam tudo o que um jogo faz - um relatório limpo é uma evidência forte, não uma prova."))}</p>
  <p>{bi(Text("Generated by", "Gerado pelo"))} netblame {__version__}.</p>
</footer>
</main>
<div class="tip" role="status" aria-live="polite" hidden></div>
<script id="nb-data" type="application/json">{data}</script>
<script>{JS}</script>
</body>
</html>
"""


def write_report(session: Session, path: str | Path, lang: Lang = "en") -> Path:
    path = Path(path)
    path.write_text(render(session, lang=lang), encoding="utf-8")
    return path


# --------------------------------------------------------------------------
# CSS e JS embutidos
# --------------------------------------------------------------------------

CSS = """
:root {
  color-scheme: light;
  --font: "Segoe UI Variable Text", "Segoe UI", system-ui, -apple-system, Roboto, "Helvetica Neue", Arial, sans-serif;
  --font-display: "Segoe UI Variable Display", "Segoe UI", system-ui, -apple-system, Roboto, sans-serif;
  --page: #eef2f7; --card: #ffffff; --ink: #0f1b2d; --ink-2: #44546a; --muted: #6b7a90;
  --line: #dce3ec; --grid: #e8edf3; --axis: #c3cdd9; --soft: #f5f8fb;
  --accent: #3d6bff;
  --s0: #0072B2; --s1: #E69F00; --s2: #009E73; --s3: #56B4E9; --s4: #CC79A7;
  --st-ok: #1f9d61; --st-warn: #c77700; --st-fail: #d9381e; --st-none: #8a97ab;
  --bg-ok: #e3f5ec; --bg-warn: #fff1dc; --bg-fail: #fde7e3; --bg-none: #edf1f6;
  --loss: var(--st-fail); --loss-wash: rgba(217, 56, 30, .10);
  /* A capa é escura nos dois temas: é o "mapa" da conexão. */
  --hero: #0d1a2b; --hero-2: #17305a; --hero-ink: #eaf1fb; --hero-muted: #9fb0c8;
  --hst-ok: #3ddc97; --hst-warn: #ffb547; --hst-fail: #ff6b57; --hst-none: #6f7e96;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    color-scheme: dark;
    --page: #0b1422; --card: #121e30; --ink: #e6edf7; --ink-2: #b3c0d3; --muted: #8494ab;
    --line: #22324a; --grid: #1b2a40; --axis: #2e405b; --soft: #0f1a2a;
    --accent: #7b9bff;
    --s0: #2B7FC2; --s1: #C08200; --s2: #008C66; --s3: #479CD8; --s4: #C46F9F;
    --st-ok: #3ddc97; --st-warn: #ffb547; --st-fail: #ff6b57; --st-none: #7e8ca3;
    --bg-ok: #12352a; --bg-warn: #3a2a10; --bg-fail: #3f1a16; --bg-none: #1a2638;
    --loss-wash: rgba(255, 107, 87, .14);
    --hero: #07101d; --hero-2: #10244a;
  }
}
:root[data-theme="dark"] {
  color-scheme: dark;
  --page: #0b1422; --card: #121e30; --ink: #e6edf7; --ink-2: #b3c0d3; --muted: #8494ab;
  --line: #22324a; --grid: #1b2a40; --axis: #2e405b; --soft: #0f1a2a;
  --accent: #7b9bff;
  --s0: #2B7FC2; --s1: #C08200; --s2: #008C66; --s3: #479CD8; --s4: #C46F9F;
  --st-ok: #3ddc97; --st-warn: #ffb547; --st-fail: #ff6b57; --st-none: #7e8ca3;
  --bg-ok: #12352a; --bg-warn: #3a2a10; --bg-fail: #3f1a16; --bg-none: #1a2638;
  --loss-wash: rgba(255, 107, 87, .14);
  --hero: #07101d; --hero-2: #10244a;
}
/* Só o idioma ativo aparece. */
html[data-lang="pt"] .l-en, html:not([data-lang="pt"]) .l-pt { display: none !important; }
* { box-sizing: border-box; }
html { -webkit-text-size-adjust: 100%; }
body { margin: 0; background: var(--page); color: var(--ink); font: 16px/1.55 var(--font); }
h1, h2, h3, h4 { font-family: var(--font-display); line-height: 1.2; margin: 0; letter-spacing: -.01em; }
p { margin: 0; }
small { color: var(--muted); }
.wrap { max-width: 1120px; margin: 0 auto; padding: 0 20px; }

/* ---------- capa / mapa ---------- */
.hero { color: var(--hero-ink); padding: 18px 0 64px;
  background:
    radial-gradient(circle at 1px 1px, rgba(255,255,255,.07) 1px, transparent 0) 0 0 / 22px 22px,
    radial-gradient(760px 380px at 82% -8%, var(--hero-2), transparent 70%),
    radial-gradient(520px 300px at 8% 110%, var(--glow, transparent), transparent 70%),
    var(--hero); }
.hero-fail { --glow: rgba(255,107,87,.16); } .hero-warn { --glow: rgba(255,181,71,.14); } .hero-ok { --glow: rgba(61,220,151,.12); }
.topbar { display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap; }
.brand { display: flex; align-items: center; gap: 10px; font: 700 1.05rem var(--font-display); letter-spacing: .01em; }
.logo { width: 22px; height: 22px; border-radius: 6px; flex: none;
  background: conic-gradient(from 200deg, var(--hst-ok), #5aa9ff, var(--hst-warn), var(--hst-fail), var(--hst-ok)); }
.ver { color: var(--hero-muted); font-weight: 500; font-size: .85rem; }
.pill { font: 600 .75rem var(--font); padding: 3px 10px; border-radius: 99px; color: var(--hero-ink);
  background: rgba(255,255,255,.08); border: 1px solid rgba(255,255,255,.12); }
.langswitch { display: inline-flex; padding: 3px; border-radius: 99px; background: rgba(255,255,255,.08);
  border: 1px solid rgba(255,255,255,.12); }
.langswitch button { font: 700 .78rem var(--font); letter-spacing: .06em; border: 0; border-radius: 99px;
  padding: 6px 14px; min-height: 32px; background: transparent; color: var(--hero-muted); cursor: pointer; }
.langswitch button[aria-pressed="true"] { background: var(--hero-ink); color: #0d1a2b; }
.langswitch button:focus-visible { outline: 2px solid var(--hst-ok); outline-offset: 2px; }
.eyebrow { margin-top: 38px; color: var(--hero-muted); font-weight: 600; font-size: .8rem;
  letter-spacing: .14em; text-transform: uppercase; }
.hero h1 { font-size: clamp(1.9rem, 4.4vw, 3.1rem); font-weight: 800; margin-top: 8px; max-width: 22ch; }
.hero-sub { margin-top: 10px; font-size: 1.08rem; color: #c9d6e8; max-width: 60ch; }
.hero-how { margin-top: 30px; display: flex; gap: 8px; align-items: flex-start;
  color: var(--hero-muted); font-size: .9rem; max-width: 92ch; }
.hero-how .ico { flex: none; margin-top: 3px; }
.hero-how .meta { opacity: .75; white-space: nowrap; }

.route { list-style: none; margin: 44px 0 0; padding: 0; display: grid; grid-template-columns: repeat(5, 1fr); }
.stop { position: relative; text-align: center; padding: 0 6px; --c: var(--hst-ok); }
.stop.st-ok { --c: var(--hst-ok); } .stop.st-warn { --c: var(--hst-warn); }
.stop.st-fail { --c: var(--hst-fail); } .stop.st-none { --c: var(--hst-none); }
/* trilho que chega a esta estação, na cor do status dela */
.stop + .stop::before { content: ""; position: absolute; top: 37px; right: 50%; width: 100%; height: 6px;
  border-radius: 6px; background: var(--c); }
.stop.st-fail + .stop::before, .stop + .stop.st-fail::before {
  background: repeating-linear-gradient(90deg, var(--hst-fail) 0 10px, transparent 10px 18px); }
.stop + .stop.st-none::before { background: repeating-linear-gradient(90deg, var(--hst-none) 0 4px, transparent 4px 10px); }
.cut { position: absolute; z-index: 2; top: 28px; left: 0; transform: translateX(-50%); width: 24px; height: 24px;
  border-radius: 50%; display: grid; place-items: center; background: var(--hst-fail); color: #0d1a2b; }
.cut .ico { stroke-width: 3; }
.station { position: relative; z-index: 1; width: 80px; height: 80px; margin: 0 auto; border-radius: 50%;
  display: grid; place-items: center; background: var(--hero); color: var(--hero-ink);
  border: 3px solid var(--c); box-shadow: 0 0 0 6px var(--hero), 0 0 30px -6px var(--c); }
.station > .ico { width: 34px; height: 34px; }
.badge { position: absolute; right: -2px; bottom: -2px; width: 26px; height: 26px; border-radius: 50%;
  display: grid; place-items: center; background: var(--c); color: #0d1a2b; box-shadow: 0 0 0 3px var(--hero); }
.badge .ico { width: 14px; height: 14px; stroke-width: 3; display: block; }
.stop-name { margin-top: 14px; font: 700 1rem var(--font-display); overflow-wrap: anywhere; }
.stop-status { color: var(--c); font-weight: 700; font-size: .78rem; letter-spacing: .06em; text-transform: uppercase; margin-top: 2px; }
.stop-metric { color: var(--hero-muted); font-size: .82rem; margin-top: 4px; font-variant-numeric: tabular-nums; }
.here { display: inline-flex; align-items: center; gap: 6px; margin-top: 10px; padding: 5px 11px; border-radius: 99px;
  background: var(--c); color: #0d1a2b; font-weight: 800; font-size: .78rem; letter-spacing: .02em; }
.here .ico { stroke-width: 3; }
.is-culprit .station { animation: pulse 2.2s ease-out infinite; }
@keyframes pulse {
  0% { box-shadow: 0 0 0 6px var(--hero), 0 0 0 6px var(--c); }
  70% { box-shadow: 0 0 0 6px var(--hero), 0 0 0 24px transparent; }
  100% { box-shadow: 0 0 0 6px var(--hero), 0 0 0 6px transparent; } }
@media (prefers-reduced-motion: reduce) { .is-culprit .station { animation: none; } }

/* ---------- blocos ---------- */
main.wrap { padding-bottom: 56px; }
.block { margin-top: 52px; }
.sec { font-size: 1.6rem; font-weight: 800; }
.sec-lede { color: var(--ink-2); margin-top: 6px; max-width: 72ch; }
.summary { margin-top: -38px; position: relative; display: grid; grid-template-columns: 1.15fr 1fr;
  background: var(--card); border: 1px solid var(--line); border-radius: 22px; overflow: hidden;
  box-shadow: 0 24px 50px -30px rgba(13, 26, 43, .45); }
.summary > div { padding: 28px 30px; }
.summary h2 { font-size: .78rem; letter-spacing: .14em; text-transform: uppercase; color: var(--muted); font-weight: 700; }
.summary .big { margin-top: 12px; font-size: 1.14rem; line-height: 1.65; }
.summary-actions { background: var(--soft); border-left: 1px solid var(--line); }
.scoreboard { list-style: none; margin: 22px 0 0; padding: 0; display: grid; gap: 2px; }
.scoreboard li { display: grid; grid-template-columns: auto 1fr auto; align-items: center; gap: 12px;
  padding: 9px 0; border-top: 1px solid var(--line); }
.sb-ico { width: 32px; height: 32px; border-radius: 10px; display: grid; place-items: center;
  background: var(--bg); color: var(--fg); }
.sb-name { font-weight: 600; overflow-wrap: anywhere; }
.actions { list-style: none; counter-reset: a; margin: 14px 0 0; padding: 0; display: grid; gap: 16px; }
.actions li { counter-increment: a; position: relative; padding-left: 44px; color: var(--ink-2); font-size: .94rem; }
.actions li::before { content: counter(a); position: absolute; left: 0; top: 0; width: 30px; height: 30px; border-radius: 50%;
  display: grid; place-items: center; background: var(--accent); color: #fff; font: 800 .88rem var(--font-display); }
.a-title { color: var(--ink); font-weight: 700; margin-bottom: 2px; }

.chip { display: inline-flex; align-items: center; gap: 6px; padding: 4px 11px; border-radius: 99px; white-space: nowrap;
  font-weight: 700; font-size: .78rem; background: var(--bg); color: var(--fg); }
.st-ok { --fg: var(--st-ok); --bg: var(--bg-ok); } .st-warn { --fg: var(--st-warn); --bg: var(--bg-warn); }
.st-fail { --fg: var(--st-fail); --bg: var(--bg-fail); } .st-none { --fg: var(--st-none); --bg: var(--bg-none); }
.chip .ico { stroke-width: 3; }

.gauges { margin-top: 20px; display: grid; gap: 16px; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); }
.gauge { background: var(--card); border: 1px solid var(--line); border-radius: 20px; padding: 20px 20px 18px;
  display: flex; flex-direction: column; gap: 10px; border-top: 5px solid var(--fg); }
.gauge header { display: flex; justify-content: space-between; align-items: center; gap: 8px; }
.gauge h3 { font-size: 1rem; }
.g-value { font: 800 2.4rem/1.05 var(--font-display); letter-spacing: -.02em; display: flex; align-items: baseline; gap: 8px; flex-wrap: wrap; }
.g-src { font: 600 .8rem var(--font); color: var(--muted); letter-spacing: 0; }
.over { color: var(--st-fail); }
.ruler { position: relative; display: flex; height: 12px; margin-top: 8px; gap: 2px; }
.band { height: 100%; }
.band:first-child { border-radius: 99px 0 0 99px; } .band:nth-child(3) { border-radius: 0 99px 99px 0; }
.b-ok { background: var(--st-ok); opacity: .35; } .b-warn { background: var(--st-warn); opacity: .45; } .b-fail { background: var(--st-fail); opacity: .45; }
.marker { position: absolute; top: 50%; width: 24px; height: 24px; border-radius: 50%; transform: translate(-50%, -50%);
  background: var(--card); border: 6px solid var(--fg); box-shadow: 0 2px 10px rgba(0,0,0,.28); }
.ruler-scale { position: relative; height: 16px; font-size: .72rem; color: var(--muted); font-variant-numeric: tabular-nums; }
.ruler-scale span { position: absolute; transform: translateX(-50%); }
.ruler-scale span:first-child { transform: none; left: 0; } .ruler-scale .end { right: 0; transform: none; }
.g-note { font-weight: 600; font-size: .9rem; }
.g-what { color: var(--ink-2); font-size: .87rem; border-top: 1px dashed var(--line); padding-top: 10px; margin-top: auto; }

.steps { margin-top: 20px; display: grid; gap: 14px; position: relative; }
.step { display: grid; grid-template-columns: 60px 1fr; background: var(--card); border: 1px solid var(--line);
  border-radius: 20px; overflow: hidden; }
.step-num { display: grid; place-items: start center; padding-top: 22px; font: 800 1.35rem var(--font-display);
  background: var(--bg); color: var(--fg); }
.step-body { padding: 20px 22px; display: grid; gap: 8px; }
.step-body header { display: grid; grid-template-columns: auto 1fr auto; gap: 12px; align-items: center; }
.step-ico { width: 42px; height: 42px; border-radius: 12px; display: grid; place-items: center; background: var(--soft);
  color: var(--ink-2); border: 1px solid var(--line); }
.step h3 { font-size: 1.14rem; }
.covers { color: var(--muted); font-size: .85rem; }
.step-summary { font-size: 1.03rem; font-weight: 600; }
.step-metric { color: var(--muted); font-size: .85rem; font-variant-numeric: tabular-nums; }
.finding { margin-top: 6px; border-radius: 14px; padding: 14px 16px; background: var(--soft); border: 1px solid var(--line); }
.finding h4 { font-size: 1rem; margin: 2px 0 6px; }
.finding p { color: var(--ink-2); font-size: .93rem; }
.f-sev { font-size: .72rem; font-weight: 800; letter-spacing: .08em; text-transform: uppercase; color: var(--fg) !important; }
.sev-critical { --fg: var(--st-fail); } .sev-warning { --fg: var(--st-warn); } .sev-info { --fg: var(--st-none); } .sev-ok { --fg: var(--st-ok); }
.todo { margin-top: 10px; padding: 10px 12px; border-radius: 10px; background: var(--card); border-left: 4px solid var(--accent); }
.todo strong { color: var(--ink); margin-right: 4px; }
.observations { margin-top: 22px; }
.observations > h4 { font-size: .8rem; letter-spacing: .12em; text-transform: uppercase; color: var(--muted); }

.panel { margin-top: 18px; background: var(--card); border: 1px solid var(--line); border-radius: 20px; padding: 24px; }
.panel h3 { font-size: 1.15rem; }
.lede { color: var(--ink-2); margin: 4px 0 14px; font-size: .95rem; }
.fine { color: var(--muted); font-size: .85rem; }
.counters { margin-top: 12px; }
.howto { margin-top: 16px; display: flex; gap: 10px; align-items: flex-start; padding: 12px 14px; border-radius: 12px;
  background: var(--soft); border: 1px dashed var(--line); color: var(--ink-2); font-size: .9rem; }
.howto .ico { flex: none; color: var(--st-warn); margin-top: 2px; }
.howto strong { color: var(--ink); margin-right: 4px; }

.legend { list-style: none; display: flex; flex-wrap: wrap; gap: 4px 18px; padding: 0; margin: 0 0 8px;
  font-size: .88rem; color: var(--ink-2); }
.legend li { display: flex; align-items: center; gap: 6px; }
.chart-wrap { position: relative; }
.chart { display: block; width: 100%; height: auto; overflow: visible; touch-action: pan-y; }
.chart:focus { outline: 2px solid var(--accent); outline-offset: 4px; border-radius: 6px; }
.grid { stroke: var(--grid); stroke-width: 1; shape-rendering: crispEdges; }
.axis { stroke: var(--axis); stroke-width: 1; shape-rendering: crispEdges; }
.track { stroke: var(--grid); stroke-width: 1; }
.threshold { stroke: var(--st-fail); stroke-width: 1; opacity: .55; }
.tick { fill: var(--muted); font-size: 11px; font-family: var(--font); font-variant-numeric: tabular-nums; }
.line { fill: none; stroke-width: 1.6; stroke-linejoin: round; stroke-linecap: round; }
.s0 { stroke: var(--s0); } .s1 { stroke: var(--s1); } .s2 { stroke: var(--s2); } .s3 { stroke: var(--s3); } .s4 { stroke: var(--s4); }
.evt { fill: var(--loss-wash); }
.mark { stroke: var(--ink); stroke-width: 1.5; opacity: .7; }
.mark-lbl { fill: var(--ink); font-size: 11px; font-weight: 700; font-family: var(--font); }
.drops { margin-top: 28px; background: var(--card); border: 1px solid var(--line); border-left: 6px solid var(--ink);
  border-radius: 20px; padding: 22px 24px; }
.drops > h2 { font-size: 1.2rem; }
.drops .finding { background: var(--soft); }
.lossmark { fill: var(--loss); }
.xhair { stroke: var(--ink-2); stroke-width: 1; pointer-events: none; }
.hit { fill: transparent; cursor: crosshair; }
.strip-title { font-size: .95rem; display: flex; align-items: center; gap: 8px; margin-top: 20px; }
.lossdot { display: inline-block; width: 4px; height: 13px; background: var(--loss); border-radius: 1px; }

details.tech { margin-top: 12px; background: var(--card); border: 1px solid var(--line); border-radius: 16px; padding: 0 20px; }
details.tech summary { cursor: pointer; list-style: none; padding: 16px 0; font: 700 1.02rem var(--font-display);
  display: flex; align-items: center; justify-content: space-between; }
details.tech summary::-webkit-details-marker { display: none; }
details.tech summary::after { content: "+"; font: 400 1.5rem/1 var(--font); color: var(--muted); }
details.tech[open] summary::after { content: "–"; }
details.tech[open] { padding-bottom: 18px; }
details.tech summary:focus-visible { outline: 2px solid var(--accent); outline-offset: 4px; border-radius: 6px; }
.sub-h { font-size: .95rem; margin: 18px 0 8px; }
.table-wrap { overflow-x: auto; }
table { border-collapse: collapse; width: 100%; font-size: .9rem; }
th, td { text-align: left; padding: 9px 10px; border-bottom: 1px solid var(--line); vertical-align: top; }
th { color: var(--muted); font-weight: 600; font-size: .76rem; letter-spacing: .05em; text-transform: uppercase; white-space: nowrap; }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; white-space: nowrap; }
tr.culprit td { background: var(--bg-fail); }
tr.culprit td:first-child { box-shadow: inset 4px 0 var(--st-fail); }
tr.after td { color: var(--ink-2); }
.key { display: inline-block; width: 14px; height: 3px; border-radius: 2px; margin: 0 8px 3px 0; background: currentColor; }
.key.s0 { color: var(--s0); } .key.s1 { color: var(--s1); } .key.s2 { color: var(--s2); }
.key.s3 { color: var(--s3); } .key.s4 { color: var(--s4); } .key.none { color: var(--axis); }
.flag { display: inline-grid; place-items: center; width: 17px; height: 17px; border-radius: 50%;
  background: var(--st-warn); color: #fff; font-size: .7rem; font-weight: 800; }
.tag { font-size: .76rem; padding: 2px 9px; border-radius: 99px; background: var(--bg-none); color: var(--ink-2); white-space: nowrap; }
.tag-bad { background: var(--st-fail); color: #fff; font-weight: 700; }

.glossary { margin: 20px 0 0; display: grid; gap: 12px; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); }
.glossary div { background: var(--card); border: 1px solid var(--line); border-radius: 16px; padding: 14px 16px; }
.glossary dt { font: 700 .98rem var(--font-display); }
.glossary dd { margin: 4px 0 0; color: var(--ink-2); font-size: .9rem; }

.foot { margin-top: 52px; padding-top: 20px; border-top: 1px solid var(--line); color: var(--muted); font-size: .85rem; display: grid; gap: 6px; }
.notes { margin: 0; padding-left: 18px; }

.tip { position: fixed; z-index: 10; pointer-events: none; background: var(--card); color: var(--ink);
  border: 1px solid var(--line); border-radius: 10px; padding: 9px 11px; font-size: .82rem;
  box-shadow: 0 10px 30px rgba(0,0,0,.2); min-width: 160px; }
.tip .tt { color: var(--muted); margin-bottom: 4px; font-variant-numeric: tabular-nums; }
.tip .row { display: flex; align-items: center; gap: 8px; }
.tip .row b { font-variant-numeric: tabular-nums; min-width: 58px; }
.tip .row b.lost { color: var(--loss); }
.tip .sw { width: 12px; height: 2px; border-radius: 1px; }

/* ---------- telas estreitas: o mapa vira uma linha vertical ---------- */
@media (max-width: 760px) {
  .route { grid-template-columns: 1fr; margin-top: 30px; }
  .stop { display: grid; grid-template-columns: 64px 1fr; text-align: left; column-gap: 16px; padding: 0 0 26px;
    grid-template-areas: "st name" "st status" "st metric" "st here"; align-content: start; }
  .stop + .stop::before { display: none; }
  .stop:not(:last-child)::after { content: ""; position: absolute; left: 29px; top: 64px; bottom: 0; width: 6px;
    border-radius: 6px; background: var(--next); }
  .stop .station { grid-area: st; width: 64px; height: 64px; margin: 0; }
  .station > .ico { width: 28px; height: 28px; }
  .stop-name { grid-area: name; margin-top: 2px; } .stop-status { grid-area: status; } .stop-metric { grid-area: metric; }
  .here { grid-area: here; justify-self: start; }
  .cut { display: none; }
  .hero-how .meta { white-space: normal; }
  .summary { grid-template-columns: 1fr; margin-top: -30px; }
  .summary-actions { border-left: 0; border-top: 1px solid var(--line); }
  .summary > div { padding: 20px; }
  .step { grid-template-columns: 40px 1fr; }
  .step-body { padding: 16px; }
  .step-body header { grid-template-columns: auto 1fr; }
  .step-body header .chip { grid-column: 1 / -1; justify-self: start; }
  .chart-wrap { overflow-x: auto; }
  .chart { min-width: 600px; }
  .tick { font-size: 16px; }
  .tick.lbl { font-size: 13px; }
  .panel { padding: 16px; }
}
@media print {
  .hero, .chip, .step-num, .marker, .band { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  .langswitch, .tip { display: none; }
  .is-culprit .station { animation: none; }
}
"""

#: Roda antes da pintura: aplica o idioma salvo para a página não "piscar" no outro.
HEAD_JS = """
(() => { try { const l = localStorage.getItem('netblame-lang');
  if (l === 'en' || l === 'pt') { document.documentElement.dataset.lang = l;
    document.documentElement.lang = l === 'pt' ? 'pt-BR' : 'en'; } } catch (e) {} })();
"""

JS = r"""
(() => {
  const root = document.documentElement;
  const TITLES = { en: 'netblame report', pt: 'Relatório netblame' };
  const WORDS = { en: { lost: 'lost', cycle: 'cycle' }, pt: { lost: 'perdida', cycle: 'ciclo' } };
  const lang = () => root.dataset.lang === 'pt' ? 'pt' : 'en';
  function applyLang(l) {
    root.dataset.lang = l; root.lang = l === 'pt' ? 'pt-BR' : 'en'; document.title = TITLES[l];
    document.querySelectorAll('[data-set-lang]').forEach(b =>
      b.setAttribute('aria-pressed', String(b.dataset.setLang === l)));
    document.querySelectorAll('svg[data-aria-en]').forEach(s =>
      s.setAttribute('aria-label', s.dataset['aria' + (l === 'pt' ? 'Pt' : 'En')]));
  }
  document.querySelectorAll('[data-set-lang]').forEach(b => b.addEventListener('click', () => {
    applyLang(b.dataset.setLang);
    try { localStorage.setItem('netblame-lang', b.dataset.setLang); } catch (e) {}
  }));
  applyLang(lang());
  // Na impressão, abre os detalhes técnicos para nada ficar escondido no papel.
  addEventListener('beforeprint', () => document.querySelectorAll('details').forEach(d => {
    d.dataset.wasOpen = d.open; d.open = true; }));
  addEventListener('afterprint', () => document.querySelectorAll('details').forEach(d => {
    d.open = d.dataset.wasOpen === 'true'; }));

  const D = JSON.parse(document.getElementById('nb-data').textContent);
  const tip = document.querySelector('.tip');
  const charts = [...document.querySelectorAll('svg.chart')];
  const n = D.t.length;
  if (!n) return;
  const css = getComputedStyle(document.documentElement);
  const xOf = i => D.x0 + (D.t[i] / D.duration) * (D.x1 - D.x0);
  const dec = s => lang() === 'pt' ? String(s).replace('.', ',') : String(s);
  const fmt = v => v == null ? WORDS[lang()].lost : dec(v < 10 ? v.toFixed(1) : Math.round(v)) + ' ms';
  const clock = s => { s = Math.round(s); const m = Math.floor(s / 60);
    return String(m).padStart(2, '0') + ':' + String(s % 60).padStart(2, '0'); };
  let current = -1;

  function nearest(vx) {
    let lo = 0, hi = n - 1;
    while (hi - lo > 1) { const mid = (lo + hi) >> 1; if (xOf(mid) < vx) lo = mid; else hi = mid; }
    return Math.abs(xOf(lo) - vx) <= Math.abs(xOf(hi) - vx) ? lo : hi;
  }
  function row(color, value, label, lost) {
    const r = document.createElement('div'); r.className = 'row';
    const sw = document.createElement('span'); sw.className = 'sw'; sw.style.background = color;
    const b = document.createElement('b'); b.textContent = value; if (lost) b.className = 'lost';
    const l = document.createElement('span'); l.textContent = label;
    r.append(sw, b, l); return r;
  }
  function show(i, chart, clientX, clientY) {
    current = i;
    const x = xOf(i);
    charts.forEach(c => { const l = c.querySelector('.xhair');
      l.setAttribute('x1', x); l.setAttribute('x2', x); l.setAttribute('visibility', 'visible'); });
    tip.replaceChildren();
    const head = document.createElement('div'); head.className = 'tt';
    head.textContent = clock(D.t[i]) + ' · ' + WORDS[lang()].cycle + ' ' + i; tip.append(head);
    if (chart.dataset.chart === 'system') {
      tip.append(row(css.getPropertyValue('--s0'), D.cpu[i] == null ? '–' : D.cpu[i].toFixed(0) + '%', 'CPU'));
      tip.append(row(css.getPropertyValue('--s1'), D.ram[i] == null ? '–' : D.ram[i].toFixed(0) + '%', 'RAM'));
    } else {
      D.labels.forEach(lab => {
        const v = D.series[lab][i], slot = D.slots[lab];
        tip.append(row(css.getPropertyValue(slot == null ? '--axis' : '--s' + slot), fmt(v), lab, v == null));
      });
    }
    tip.hidden = false;
    const w = tip.offsetWidth, h = tip.offsetHeight;
    let left = clientX + 14, top = clientY + 14;
    if (left + w > innerWidth - 8) left = clientX - w - 14;
    if (top + h > innerHeight - 8) top = clientY - h - 14;
    tip.style.left = Math.max(8, left) + 'px'; tip.style.top = Math.max(8, top) + 'px';
  }
  function hide() {
    tip.hidden = true; current = -1;
    charts.forEach(c => c.querySelector('.xhair').setAttribute('visibility', 'hidden'));
  }
  charts.forEach(chart => {
    chart.tabIndex = 0;
    const hit = chart.querySelector('.hit');
    hit.addEventListener('pointermove', e => {
      const p = new DOMPoint(e.clientX, e.clientY).matrixTransform(chart.getScreenCTM().inverse());
      show(nearest(p.x), chart, e.clientX, e.clientY);
    });
    hit.addEventListener('pointerleave', hide);
    chart.addEventListener('blur', hide);
    chart.addEventListener('keydown', e => {
      if (e.key !== 'ArrowLeft' && e.key !== 'ArrowRight') return;
      e.preventDefault();
      const step = e.shiftKey ? 10 : 1;
      const i = Math.min(n - 1, Math.max(0, (current < 0 ? 0 : current) + (e.key === 'ArrowRight' ? step : -step)));
      const r = chart.getBoundingClientRect();
      const px = r.left + (xOf(i) / chart.viewBox.baseVal.width) * r.width;
      show(i, chart, px, r.top + r.height / 3);
    });
  });
})();
"""
