"""Sessões sintéticas e reprodutíveis para demonstração e testes.

Cada cenário simula uma causa de queda conhecida. Eles servem a dois
propósitos: gerar o relatório de exemplo do README sem expor a rede de
ninguém, e provar nos testes que a análise chega ao diagnóstico certo para
cada causa. A seed fixa garante que o mesmo cenário produza sempre a mesma
sessão (e portanto a mesma screenshot).

Os IPs públicos usam faixas reservadas para documentação (RFC 5737).
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Optional

from netblame.i18n import Text
from netblame.models import HopStat, NicSnapshot, Sample, Session, SysSample, Target, Trace, UdpSample

SCENARIOS = ("healthy", "isp", "local", "route", "udp", "pc")

#: Categoria que o veredito precisa ter em cada cenário (usada nos testes).
EXPECTED_CATEGORY = {"healthy": "ok", "isp": "isp", "local": "local", "route": "route",
                     "udp": "udp", "pc": "pc"}

DESCRIPTIONS = {
    "healthy": Text("Clean connection with a harmless ICMP rate-limiting hop.",
                    "Conexão limpa, com um salto que limita ICMP (inofensivo)."),
    "isp": Text("Router stays up while everything beyond it drops: modem/ISP outages.",
                "O roteador segue de pé enquanto tudo depois dele cai: quedas no modem/provedor."),
    "local": Text("Router itself becomes unreachable; NIC fell back to 100 Mbps with errors.",
                  "O próprio roteador fica inacessível; a placa caiu para 100 Mbps e tem erros."),
    "route": Text("Internet is fine but the route to the game server loses packets.",
                  "A internet está boa, mas a rota até o servidor do jogo perde pacotes."),
    "udp": Text("Pings are perfect but UDP to the same servers is dropped.",
                "Os pings estão perfeitos, mas o UDP para os mesmos servidores é descartado."),
    "pc": Text("Losses happen exactly when the CPU is pegged at 100%.",
               "As perdas acontecem exatamente quando a CPU está em 100%."),
}

TARGETS = [
    Target("gateway", "icmp", "192.168.0.1", "gateway"),
    Target("cloudflare", "icmp", "1.1.1.1", "internet"),
    Target("google", "icmp", "8.8.8.8", "internet"),
    Target("dns", "dns", "192.168.0.1", "dns"),
    Target("game", "tcp", "play.example.net", "app", 443),
    Target("cloudflare-udp", "dns", "1.1.1.1", "udp"),
    Target("google-udp", "dns", "8.8.8.8", "udp"),
]
BASE_RTT = {"gateway": 0.8, "cloudflare": 11.0, "google": 17.0, "dns": 6.0, "game": 38.0,
            "cloudflare-udp": 11.5, "google-udp": 17.5}

# Rotas: os três primeiros saltos são compartilhados (roteador + rede do ISP).
ROUTE_CLOUDFLARE = ["192.168.0.1", "100.64.12.1", "100.64.0.9", "203.0.113.1", "1.1.1.1"]
ROUTE_APP = ["192.168.0.1", "100.64.12.1", "100.64.0.9", "203.0.113.1", None,
             "198.51.100.17", "198.51.100.42", "198.51.100.77", "203.0.113.50"]
HOP_RTT = {"192.168.0.1": 0.8, "100.64.12.1": 4.0, "100.64.0.9": 6.5, "203.0.113.1": 9.0,
           "1.1.1.1": 11.0, "198.51.100.17": 21.0, "198.51.100.42": 27.0,
           "198.51.100.77": 33.0, "203.0.113.50": 38.0}


@dataclass
class _Plan:
    """O que acontece em cada cenário, em termos de ciclos."""

    outages: list[tuple[int, int, str]] = field(default_factory=list)  # (início, duração, "local"|"upstream")
    loss: dict[str, float] = field(default_factory=dict)  # perda aleatória por alvo (0-1)
    spikes: dict[str, float] = field(default_factory=dict)  # chance de pico de latência por alvo
    cpu_bursts: list[tuple[int, int]] = field(default_factory=list)
    stress_loss: float = 0.0  # chance de todos perderem juntos durante um burst
    hop_loss: dict[str, float] = field(default_factory=dict)  # perda por IP de salto (0-1)
    nic_speed: int = 1000
    nic_errors: int = 0
    udp_rx_errors: float = 0.0  # chance de o Windows descartar UDP num ciclo de CPU saturada


def _plan(scenario: str) -> _Plan:
    if scenario == "healthy":
        return _Plan(loss={"cloudflare": 0.001, "game": 0.002},
                     hop_loss={"100.64.0.9": 0.35})
    if scenario == "isp":
        return _Plan(
            outages=[(128, 9, "upstream"), (341, 16, "upstream"), (486, 6, "upstream")],
            loss={"cloudflare": 0.012, "google": 0.012, "game": 0.015},
            spikes={"cloudflare": 0.02, "google": 0.02, "game": 0.02},
            hop_loss={"100.64.12.1": 0.045, "100.64.0.9": 0.05, "203.0.113.1": 0.048,
                      "1.1.1.1": 0.05, "198.51.100.17": 0.05, "198.51.100.42": 0.047,
                      "198.51.100.77": 0.05, "203.0.113.50": 0.052},
        )
    if scenario == "local":
        return _Plan(
            outages=[(95, 7, "local"), (260, 12, "local"), (410, 4, "local"), (532, 8, "local")],
            loss={"gateway": 0.01, "cloudflare": 0.01, "google": 0.01, "game": 0.01},
            hop_loss={ip: 0.06 for ip in HOP_RTT},
            nic_speed=100, nic_errors=37,
        )
    if scenario == "route":
        return _Plan(
            loss={"game": 0.075},
            spikes={"game": 0.08},
            hop_loss={"100.64.0.9": 0.3, "198.51.100.17": 0.07, "198.51.100.42": 0.08,
                      "198.51.100.77": 0.075, "203.0.113.50": 0.078},
        )
    if scenario == "udp":
        return _Plan(
            loss={"cloudflare-udp": 0.07, "google-udp": 0.065, "game": 0.003},
            spikes={"cloudflare-udp": 0.03, "google-udp": 0.03},
            hop_loss={"100.64.0.9": 0.3},
        )
    if scenario == "pc":
        return _Plan(cpu_bursts=[(70, 35), (230, 25), (400, 40), (520, 20)], stress_loss=0.3,
                     udp_rx_errors=0.4)
    raise ValueError(f"unknown scenario {scenario!r}; choose from {', '.join(SCENARIOS)}")


def generate(scenario: str = "isp", seed: int = 42, minutes: float = 10, interval: float = 1.0) -> Session:
    """Gera uma sessão sintética do cenário pedido."""
    plan = _plan(scenario)
    rng = random.Random(f"{scenario}:{seed}")  # seed por cenário: cenários independentes
    n = round(minutes * 60 / interval)

    outage_at: dict[int, str] = {}
    for start, length, scope in plan.outages:
        for c in range(start, start + length):
            outage_at[c] = scope
    burst = {c for start, length in plan.cpu_bursts for c in range(start, start + length)}

    session = Session(
        started_at="2026-10-11T21:30:00", interval=interval, targets=list(TARGETS),
        process_name="Game.exe", hostname="DEMO-PC", demo_scenario=scenario,
        notes=[Text(f"Synthetic demo session ({scenario}): ", f"Sessão sintética de demonstração ({scenario}): ")
               + DESCRIPTIONS[scenario]],
    )

    def rtt_for(label: str, slow: float = 1.0) -> float:
        base = BASE_RTT[label]
        value = base * (1 + abs(rng.gauss(0, 0.06))) + rng.expovariate(1 / max(base * 0.05, 0.1))
        if rng.random() < plan.spikes.get(label, 0.0):
            value += rng.uniform(80, 220)
        return round(value * slow, 2)

    cpu = 18.0
    for c in range(n):
        t = round(c * interval + rng.uniform(0, 0.03), 3)
        scope = outage_at.get(c)
        stressed = c in burst
        all_lost = stressed and rng.random() < plan.stress_loss
        for target in TARGETS:
            label = target.label
            lost = rng.random() < plan.loss.get(label, 0.0) or all_lost
            if scope == "local" or (scope == "upstream" and label not in ("gateway", "dns")):
                lost = True
            if scope == "upstream" and label == "dns":
                lost = rng.random() < 0.5  # o DNS do roteador às vezes responde do cache
            rtt = None if lost else rtt_for(label, slow=3.0 if stressed else 1.0)
            session.samples.append(Sample(c, t, label, rtt))

        received = rng.randint(55, 70)  # ~60 pacotes/s, típico de um jogo online
        dropped = rng.randint(1, 6) if stressed and rng.random() < plan.udp_rx_errors else 0
        session.udp.append(UdpSample(c, t, received=received, errors=dropped))

        target_cpu = rng.uniform(96, 100) if stressed else rng.uniform(8, 30)
        cpu += (target_cpu - cpu) * (0.7 if stressed else 0.3)
        ram = 62 + 3 * rng.random() + (6 if stressed else 0)
        recv = max(0.0, rng.gauss(60_000, 15_000))
        session.sys.append(SysSample(
            c, t, cpu=round(min(cpu, 100.0), 1), ram=round(ram, 1),
            sent_bps=round(recv * 0.25, 1), recv_bps=round(recv, 1),
            proc_cpu=round(rng.uniform(150, 300) if not stressed else rng.uniform(20, 60), 1),
            proc_running=True,
        ))

    session.cycles = n
    session.duration = round(n * interval, 1)
    session.traces = [
        _trace("cloudflare", "1.1.1.1", ROUTE_CLOUDFLARE, plan, n, rng),
        _trace("game", "203.0.113.50", ROUTE_APP, plan, n, rng),
    ]
    nic = NicSnapshot("Ethernet", True, plan.nic_speed, False, errin=3)
    session.nics_before = [nic]
    session.nics_after = [NicSnapshot("Ethernet", True, plan.nic_speed, False,
                                      errin=3 + plan.nic_errors, dropin=plan.nic_errors // 3)]
    return session


def _trace(label: str, destination: str, route: list[Optional[str]], plan: _Plan,
           cycles: int, rng: random.Random, hop_every: int = 2) -> Trace:
    hops = []
    sent = cycles // hop_every
    for i, ip in enumerate(route, start=1):
        if ip is None:
            hops.append(HopStat(i, None))
            continue
        loss = plan.hop_loss.get(ip, 0.0)
        lost = sum(rng.random() < loss for _ in range(sent))
        base = HOP_RTT[ip]
        hops.append(HopStat(i, ip, sent, lost, rtt_avg=round(base * 1.08, 2),
                            rtt_best=round(base * 0.9, 2), rtt_worst=round(base * 4 + 15, 2)))
    return Trace(label, destination, hops)
