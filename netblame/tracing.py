"""Mini-MTR: descobre a rota com ``tracert`` e mede perda/latência por salto.

Por que medir os saltos *durante* a captura, e não só no fim?
Quedas de conexão costumam ser intermitentes. Um MTR rodado depois que o
problema passou mostra uma rota limpa. Por isso a rota é traçada uma vez no
início e cada salto é pingado ao longo de toda a sessão, junto com os demais
alvos - assim as perdas por salto cobrem os mesmos minutos dos apagões.

Como ler perda por salto (e por que a maior parte dela é inofensiva):
roteadores encaminham pacotes em hardware, mas respondem ICMP pela CPU, e
quase todos limitam a taxa dessas respostas (*ICMP rate-limit*). Um salto
intermediário com 30% de "perda" cujos saltos seguintes têm 0% está só
economizando CPU - o tráfego passa por ele normalmente. Perda real é aquela
que **começa** num salto e **continua** até o destino.
"""

from __future__ import annotations

import re
import subprocess
import threading
from dataclasses import dataclass, field
from typing import Optional

from netblame.models import HopStat, Trace
from netblame.probes import IS_WINDOWS, NO_WINDOW, decode_console

_HOP_LINE_RE = re.compile(r"^\s*(\d{1,2})\s+(.*)$")
_IPV4_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
# Uma coluna de tempo do tracert: "<1 ms", "12 ms" ou "*".
_TIMING_RE = re.compile(r"(<?\d+\s*ms|\*)")


def parse_tracert_line(line: str) -> Optional[tuple[int, Optional[str]]]:
    """Interpreta uma linha de salto: ``(número, ip)`` ou ``(número, None)`` para ``* * *``.

    Só aceita linhas que começam com o número do salto **e** têm colunas de
    tempo, o que exclui o cabeçalho e o rodapé em qualquer idioma. O IP é o
    primeiro endereço IPv4 da linha; isso cobre também as linhas
    "10.0.0.1 relatórios: Rede de destino inacessível".
    """
    m = _HOP_LINE_RE.match(line)
    if not m:
        return None
    rest = m.group(2)
    if not _TIMING_RE.match(rest.strip()):
        return None
    ip = _IPV4_RE.search(rest)
    return int(m.group(1)), (ip.group(1) if ip else None)


def parse_tracert(output: str) -> list[tuple[int, Optional[str]]]:
    """Interpreta a saída completa do ``tracert -d``, removendo saltos mudos do final."""
    hops = [h for h in (parse_tracert_line(l) for l in output.splitlines()) if h]
    while hops and hops[-1][1] is None:
        hops.pop()
    return hops


def traceroute(host: str, max_hops: int = 24, timeout_ms: int = 500,
               give_up_after: int = 8) -> list[tuple[int, Optional[str]]]:
    """Roda ``tracert -d`` (sem DNS reverso, que é lento e irrelevante aqui).

    Muitos servidores de jogos descartam ICMP, então o tracert nunca "chega"
    e gastaria 30 saltos x 3 timeouts. Lemos a saída linha a linha e
    encerramos após ``give_up_after`` saltos mudos seguidos. O limite é
    generoso de propósito: backbones de nuvem (AWS, por exemplo) costumam
    ter 6 ou mais saltos que não respondem antes de o destino aparecer.
    """
    if IS_WINDOWS:
        cmd = ["tracert", "-d", "-4", "-h", str(max_hops), "-w", str(timeout_ms), host]
    else:
        cmd = ["traceroute", "-n", "-m", str(max_hops), "-w", str(max(1, timeout_ms // 1000)), host]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                creationflags=NO_WINDOW)
    except OSError:
        return []
    lines: list[str] = []
    silent = 0
    assert proc.stdout is not None
    for raw in proc.stdout:
        line = decode_console(raw)
        lines.append(line)
        parsed = parse_tracert_line(line)
        if parsed is None:
            continue
        silent = silent + 1 if parsed[1] is None else 0
        if silent >= give_up_after:
            proc.kill()
            break
    proc.wait()
    return parse_tracert("\n".join(lines))


# --------------------------------------------------------------------------
# Estatísticas por salto
# --------------------------------------------------------------------------

@dataclass
class _Acc:
    sent: int = 0
    lost: int = 0
    total: float = 0.0
    best: Optional[float] = None
    worst: Optional[float] = None


@dataclass
class HopMonitor:
    """Acumula pings aos saltos de uma ou mais rotas.

    Rotas diferentes compartilham os primeiros saltos (o roteador, a rede do
    provedor). Cada IP é pingado uma única vez por ciclo e o resultado é
    reaproveitado por todas as rotas que passam por ele.
    """

    routes: dict[str, tuple[str, list[tuple[int, Optional[str]]]]] = field(default_factory=dict)
    _acc: dict[str, _Acc] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def add_route(self, label: str, destination: str, hops: list[tuple[int, Optional[str]]]) -> None:
        self.routes[label] = (destination, hops)
        for _, ip in hops:
            if ip:
                self._acc.setdefault(ip, _Acc())

    def addresses(self) -> list[str]:
        return list(self._acc)

    def record(self, ip: str, rtt: Optional[float]) -> None:
        with self._lock:
            a = self._acc[ip]
            a.sent += 1
            if rtt is None:
                a.lost += 1
                return
            a.total += rtt
            a.best = rtt if a.best is None else min(a.best, rtt)
            a.worst = rtt if a.worst is None else max(a.worst, rtt)

    def traces(self) -> list[Trace]:
        out = []
        for label, (destination, hops) in self.routes.items():
            stats = []
            for n, ip in hops:
                a = self._acc.get(ip) if ip else None
                if a is None:
                    stats.append(HopStat(n, ip))
                    continue
                answered = a.sent - a.lost
                stats.append(HopStat(
                    n, ip, a.sent, a.lost,
                    round(a.total / answered, 2) if answered else None,
                    a.best, a.worst,
                ))
            out.append(Trace(label, destination, stats))
        return out


def find_bad_hop(hops: list[HopStat], min_loss: float = 2.0) -> Optional[HopStat]:
    """Devolve o salto onde começa uma perda que persiste até o fim da rota.

    Regra: olhamos o último salto medido (o mais perto do destino). Se ele
    perde menos que ``min_loss`` %, a rota está saudável e qualquer perda
    intermediária é rate-limit de ICMP. Caso contrário, voltamos salto a
    salto enquanto cada um perder pelo menos metade do que o último perde;
    o primeiro salto dessa sequência é o culpado.

    Saltos que não responderam ao tracert (``* * *``) são transparentes:
    não quebram nem iniciam a sequência.
    """
    measured = [h for h in hops if h.loss_pct is not None]
    if not measured:
        return None
    final = measured[-1]
    final_loss = final.loss_pct or 0.0
    if final_loss < min_loss:
        return None
    floor = max(min_loss / 2, final_loss / 2)
    culprit = final
    for h in reversed(measured[:-1]):
        if (h.loss_pct or 0.0) >= floor:
            culprit = h
        else:
            break
    return culprit


def rate_limited_hops(hops: list[HopStat], min_loss: float = 2.0) -> list[int]:
    """Saltos com perda aparente que **não** se propaga: rate-limit inofensivo."""
    bad = find_bad_hop(hops, min_loss)
    limit = bad.hop if bad else None
    return [
        h.hop for h in hops
        if h.loss_pct is not None and h.loss_pct >= min_loss and (limit is None or h.hop < limit)
    ]
