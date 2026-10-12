"""Estruturas de dados compartilhadas por todos os módulos.

Tudo o que uma captura produz fica numa única :class:`Session`, salva em JSON.
Guardar as amostras brutas (e não só os números agregados) permite gerar o
relatório de novo - ou melhorar a análise - depois, sem repetir uma captura
de dez minutos.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal, Optional

from netblame.i18n import Text

SCHEMA_VERSION = 1

ProbeKind = Literal["icmp", "tcp", "dns"]
#: O que o alvo representa no caminho. A análise compara papéis, não nomes:
#: "o gateway falhou" significa algo bem diferente de "o app falhou".
#: "udp" são consultas DNS via UDP aos mesmos destinos das sondas ICMP de
#: internet: mesmo destino, protocolo diferente.
Role = Literal["gateway", "internet", "app", "dns", "udp"]


@dataclass
class Target:
    """Algo que sondamos a cada ciclo."""

    label: str
    kind: ProbeKind
    host: str
    role: Role
    port: Optional[int] = None

    def describe(self) -> str:
        if self.kind == "tcp":
            return f"tcp://{self.host}:{self.port}"
        if self.kind == "dns":
            return f"dns query via {self.host}"
        return self.host


@dataclass
class Sample:
    """Resultado de uma sonda. ``rtt`` em milissegundos, ou ``None`` para perda."""

    cycle: int
    t: float  # segundos desde o início da sessão
    target: str  # Target.label
    rtt: Optional[float]


@dataclass
class SysSample:
    """Saúde da máquina em um ciclo (só registrada quando o psutil existe)."""

    cycle: int
    t: float
    cpu: float  # percentual, máquina inteira
    ram: float  # percentual em uso
    sent_bps: float  # bytes/s somando as placas físicas
    recv_bps: float
    proc_cpu: Optional[float] = None  # processo monitorado, % de um núcleo
    proc_running: Optional[bool] = None


@dataclass
class UdpSample:
    """Variação dos contadores UDP do sistema em um ciclo (ver ``probes.udp_counters``)."""

    cycle: int
    t: float
    received: int  # datagramas UDP entregues a algum programa
    errors: int  # datagramas descartados pelo sistema (buffer de recepção cheio)


@dataclass
class HopStat:
    """Sondas agregadas para um salto do traceroute."""

    hop: int
    host: Optional[str]  # None quando o salto nunca respondeu ao tracert ("* * *")
    sent: int = 0
    lost: int = 0
    rtt_avg: Optional[float] = None
    rtt_best: Optional[float] = None
    rtt_worst: Optional[float] = None

    @property
    def loss_pct(self) -> Optional[float]:
        if self.sent == 0:
            return None
        return 100.0 * self.lost / self.sent


@dataclass
class Trace:
    """Uma rota traçada mais as estatísticas por salto coletadas na captura."""

    label: str  # alvo ao qual a rota leva
    destination: str  # IP que foi traçado
    hops: list[HopStat] = field(default_factory=list)


@dataclass
class NicSnapshot:
    """Contadores de uma placa de rede física num instante."""

    name: str
    is_up: bool
    speed_mbps: int  # 0 quando o driver não informa
    wireless: bool
    errin: int = 0
    errout: int = 0
    dropin: int = 0
    dropout: int = 0


@dataclass
class Session:
    """Uma captura completa: configuração, amostras brutas e medições paralelas."""

    started_at: str  # ISO-8601, horário local
    interval: float
    targets: list[Target]
    samples: list[Sample] = field(default_factory=list)
    sys: list[SysSample] = field(default_factory=list)
    udp: list[UdpSample] = field(default_factory=list)
    traces: list[Trace] = field(default_factory=list)
    nics_before: list[NicSnapshot] = field(default_factory=list)
    nics_after: list[NicSnapshot] = field(default_factory=list)
    cycles: int = 0
    duration: float = 0.0
    process_name: Optional[str] = None
    hostname: str = ""
    notes: list[Text] = field(default_factory=list)  # avisos sobre a captura, nas duas línguas
    demo_scenario: Optional[str] = None
    version: int = SCHEMA_VERSION

    # -- conveniências ---------------------------------------------------
    def target(self, label: str) -> Target:
        for t in self.targets:
            if t.label == label:
                return t
        raise KeyError(label)

    def labels(self, *roles: Role) -> list[str]:
        """Rótulos dos alvos com algum dos papéis informados (todos, se vazio)."""
        return [t.label for t in self.targets if not roles or t.role in roles]

    # -- persistência ----------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Session":
        d = dict(d)
        if d.get("version", 1) > SCHEMA_VERSION:
            raise ValueError(f"session schema v{d['version']} is newer than this netblame")
        d["targets"] = [Target(**x) for x in d.get("targets", [])]
        d["samples"] = [Sample(**x) for x in d.get("samples", [])]
        d["sys"] = [SysSample(**x) for x in d.get("sys", [])]
        d["udp"] = [UdpSample(**x) for x in d.get("udp", [])]
        d["traces"] = [
            Trace(label=x["label"], destination=x["destination"],
                  hops=[HopStat(**h) for h in x.get("hops", [])])
            for x in d.get("traces", [])
        ]
        d["nics_before"] = [NicSnapshot(**x) for x in d.get("nics_before", [])]
        d["nics_after"] = [NicSnapshot(**x) for x in d.get("nics_after", [])]
        d["notes"] = [Text(x, x) if isinstance(x, str) else Text(**x) for x in d.get("notes", [])]
        return cls(**d)

    def save(self, path: str | Path) -> Path:
        path = Path(path)
        # Separadores compactos: uma captura de 10 minutos tem milhares de amostras.
        path.write_text(json.dumps(self.to_dict(), separators=(",", ":")), encoding="utf-8")
        return path

    @classmethod
    def load(cls, path: str | Path) -> "Session":
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))
