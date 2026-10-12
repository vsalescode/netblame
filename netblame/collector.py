"""Loop de captura: sonda todos os pontos do caminho ao mesmo tempo, ciclo a ciclo.

A ideia central do netblame está aqui: em cada ciclo, *todos* os alvos são
sondados em paralelo. Assim, quando algo falha, sabemos exatamente quem mais
falhou no mesmo segundo - e é esse padrão (só o app? todos menos o roteador?
até o roteador?) que aponta onde está o problema.
"""

from __future__ import annotations

import socket
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime
from functools import partial
from typing import Callable, Optional
from urllib.parse import urlsplit

from netblame import netinfo
from netblame.i18n import Text
from netblame.models import Sample, Session, SysSample, Target, UdpSample
from netblame.probes import DnsProbe, TcpProbe, ping, udp_counters
from netblame.sysmon import SystemMonitor
from netblame.tracing import HopMonitor, traceroute

#: Atalhos para serviços comuns. São só pontos de entrada TCP conhecidos;
#: servem para "consigo chegar na infraestrutura deste serviço?".
PRESETS: dict[str, str] = {
    "battlenet": "tcp://battle.net:443",
    "steam": "tcp://api.steampowered.com:443",
    "riot": "tcp://auth.riotgames.com:443",
    "epic": "tcp://store.epicgames.com:443",
}

#: Alvos de referência na internet: anycast, altíssima disponibilidade e de
#: operadores diferentes. Se os dois caem juntos, o problema não é deles.
INTERNET_TARGETS = (("cloudflare", "1.1.1.1"), ("google", "8.8.8.8"))


def parse_target_spec(spec: str, role: str = "app") -> Target:
    """Interpreta ``label=host`` (ICMP) ou ``label=tcp://host:porta`` (TCP).

    Sem ``label=``, o próprio host vira o rótulo.
    """
    label, sep, value = spec.partition("=")
    if not sep:
        label, value = "", spec
    value = value.strip()
    if value.startswith("tcp://"):
        parts = urlsplit(value)
        if not parts.hostname or not parts.port:
            raise ValueError(f"TCP target needs host and port: {spec!r}")
        return Target(label.strip() or parts.hostname, "tcp", parts.hostname, role, parts.port)  # type: ignore[arg-type]
    if not value or "://" in value:
        raise ValueError(f"invalid target {spec!r}; use label=host or label=tcp://host:port")
    return Target(label.strip() or value, "icmp", value, role)  # type: ignore[arg-type]


def build_targets(gateway: Optional[str], dns_server: Optional[str],
                  extra: list[str] = (), presets: list[str] = (), udp: bool = True) -> list[Target]:
    """Monta a lista padrão: gateway, referências da internet, DNS, alvos do usuário e UDP.

    Com ``udp``, cada referência da internet ganha uma "gêmea" UDP: uma
    consulta DNS ao mesmo IP (1.1.1.1 e 8.8.8.8 são resolvedores). Mesmo
    destino, protocolo diferente - se só o UDP perde, a rede está tratando
    UDP de outro jeito, e é UDP que os jogos usam.
    """
    targets: list[Target] = []
    if gateway:
        targets.append(Target("gateway", "icmp", gateway, "gateway"))
    for label, host in INTERNET_TARGETS:
        targets.append(Target(label, "icmp", host, "internet"))
    if dns_server:
        targets.append(Target("dns", "dns", dns_server, "dns"))
    for name in presets:
        if name not in PRESETS:
            raise ValueError(f"unknown preset {name!r}; choose from {', '.join(PRESETS)}")
        targets.append(parse_target_spec(f"{name}={PRESETS[name]}"))
    for spec in extra:
        targets.append(parse_target_spec(spec))
    if udp:
        for label, host in INTERNET_TARGETS:
            targets.append(Target(f"{label}-udp", "dns", host, "udp"))
    seen: set[str] = set()
    for t in targets:
        if t.label in seen:
            raise ValueError(f"duplicate target label {t.label!r}")
        seen.add(t.label)
    return targets


def make_probe(target: Target) -> Callable[[int], Optional[float]]:
    if target.kind == "tcp":
        return TcpProbe(target.host, target.port or 443)
    if target.kind == "dns":
        return DnsProbe(target.host)
    return partial(ping, target.host)


def _trace_destination(target: Target, probe) -> Optional[str]:
    if isinstance(probe, TcpProbe):
        return probe.resolve()
    try:
        return socket.gethostbyname(target.host)
    except OSError:
        return None


@dataclass
class CaptureConfig:
    targets: list[Target]
    minutes: float = 10.0
    interval: float = 1.0
    process_name: Optional[str] = None
    trace: bool = True
    hop_every: int = 2  # pinga os saltos a cada N ciclos (ver medição no README)
    timeout_ms: Optional[int] = None
    notes: list[Text] = field(default_factory=list)

    def probe_timeout(self) -> int:
        """Timeout de cada sonda: cabe dentro do intervalo, entre 300 ms e 2 s."""
        if self.timeout_ms:
            return self.timeout_ms
        return int(min(2000, max(300, self.interval * 800)))


CycleCallback = Callable[[int, int, dict[str, Optional[float]], Optional[SysSample]], None]
#: Mensagens de progresso chegam nas duas línguas; quem exibe escolhe.
StatusCallback = Callable[[Text], None]


def _print_en(msg: Text) -> None:
    print(msg.en)


def capture(cfg: CaptureConfig, on_cycle: Optional[CycleCallback] = None,
            status: StatusCallback = _print_en) -> Session:
    """Executa a captura e devolve a sessão. Ctrl+C encerra e devolve o que já foi coletado."""
    monitor = SystemMonitor(cfg.process_name)
    session = Session(
        started_at=datetime.now().isoformat(timespec="seconds"),
        interval=cfg.interval,
        targets=cfg.targets,
        process_name=cfg.process_name,
        hostname=socket.gethostname(),
        notes=list(cfg.notes),
    )
    if not monitor.available:
        session.notes.append(Text("psutil not installed: CPU/RAM and NIC checks were skipped.",
                                  "psutil não instalado: as checagens de CPU/RAM e da placa de rede foram puladas."))
    session.nics_before = netinfo.snapshot_nics()
    probes = {t.label: make_probe(t) for t in cfg.targets}
    timeout = cfg.probe_timeout()
    total_cycles = max(1, round(cfg.minutes * 60 / cfg.interval))
    hops = HopMonitor()
    udp_last = udp_counters()

    # Alvos + saltos de até duas rotas; as threads só esperam subprocessos/sockets.
    with ThreadPoolExecutor(max_workers=len(cfg.targets) + 48, thread_name_prefix="probe") as pool:
        try:
            if cfg.trace:
                _trace_routes(cfg.targets, probes, hops, pool, status)
            status(Text(f"Capturing {total_cycles} cycles every {cfg.interval:g}s "
                        f"(~{cfg.minutes:g} min). Press Ctrl+C to stop early.",
                        f"Capturando {total_cycles} ciclos a cada {cfg.interval:g}s "
                        f"(~{cfg.minutes:g} min). Ctrl+C encerra antes."))
            t0 = time.monotonic()
            next_at = t0
            for cycle in range(total_cycles):
                delay = next_at - time.monotonic()
                if delay > 0:
                    time.sleep(delay)
                started = time.monotonic()
                t = round(started - t0, 3)
                futures = {label: pool.submit(p, timeout) for label, p in probes.items()}
                hop_futures = {}
                if cycle % max(1, cfg.hop_every) == 0:
                    hop_futures = {ip: pool.submit(ping, ip, timeout) for ip in hops.addresses()}
                results = {label: f.result() for label, f in futures.items()}
                for ip, f in hop_futures.items():
                    hops.record(ip, f.result())
                for label, rtt in results.items():
                    session.samples.append(Sample(cycle, t, label, None if rtt is None else round(rtt, 2)))
                udp_now = udp_counters()
                if udp_last and udp_now:
                    session.udp.append(UdpSample(cycle, t, received=max(udp_now[0] - udp_last[0], 0),
                                                 errors=max(udp_now[2] - udp_last[2], 0)))
                udp_last = udp_now or udp_last
                sys_sample = monitor.sample(cycle, t)
                if sys_sample:
                    session.sys.append(sys_sample)
                session.cycles = cycle + 1
                session.duration = round(time.monotonic() - t0, 1)
                if on_cycle:
                    on_cycle(cycle, total_cycles, results, sys_sample)
                # Se um ciclo atrasar, o próximo começa já - sem "recuperar" ciclos perdidos.
                next_at = max(next_at + cfg.interval, time.monotonic())
        except KeyboardInterrupt:
            session.notes.append(Text(f"Stopped early by the user after {session.cycles} cycles.",
                                      f"Interrompida pelo usuário após {session.cycles} ciclos."))
            status(Text("\nStopping... (finishing in-flight probes)",
                        "\nEncerrando... (terminando as sondas em andamento)"))

    session.traces = hops.traces()
    session.nics_after = netinfo.snapshot_nics()
    return session


def _trace_routes(targets: list[Target], probes: dict, hops: HopMonitor,
                  pool: ThreadPoolExecutor, status: StatusCallback) -> None:
    """Traça (em paralelo) a rota até a primeira referência da internet e até cada app."""
    chosen = [t for t in targets if t.role == "internet"][:1] + [t for t in targets if t.role == "app"]
    dests = {t.label: _trace_destination(t, probes[t.label]) for t in chosen}
    dests = {k: v for k, v in dests.items() if v}
    if not dests:
        return
    names = ", ".join(dests)
    status(Text(f"Tracing routes to {names} (up to ~15 s)...", f"Traçando rotas até {names} (até ~15 s)..."))
    futures = {label: pool.submit(traceroute, ip) for label, ip in dests.items()}
    for label, f in futures.items():
        route = f.result()
        if route:
            hops.add_route(label, dests[label], route)
            status(Text(f"  {label}: {len(route)} hops", f"  {label}: {len(route)} saltos"))
        else:
            status(Text(f"  {label}: traceroute failed", f"  {label}: traceroute falhou"))
