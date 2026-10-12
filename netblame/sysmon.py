"""Amostragem da saúde da máquina (CPU, RAM, tráfego e um processo opcional).

Serve para responder a uma pergunta que nenhuma sonda de rede responde:
"a perda aconteceu porque o PC travou?". Se o processador está a 100%, os
pacotes chegam mas ninguém os processa a tempo, e o resultado parece
exatamente uma queda de rede. Cruzar perdas com CPU/RAM separa os dois casos.

Tudo aqui depende do psutil; sem ele, ``SystemMonitor.available`` é False e
a captura segue só com as sondas de rede.
"""

from __future__ import annotations

import time
from typing import Optional

from netblame.models import SysSample
from netblame.netinfo import is_virtual_nic

try:
    import psutil
except ImportError:  # pragma: no cover - depende do ambiente
    psutil = None


class SystemMonitor:
    """Lê CPU/RAM/throughput a cada ciclo e, se pedido, acompanha um processo pelo nome."""

    #: Procurar um processo percorre a lista inteira do sistema; não vale
    #: fazer isso a cada segundo enquanto o processo não existe.
    PROCESS_RESCAN_S = 10.0

    def __init__(self, process_name: Optional[str] = None) -> None:
        self.available = psutil is not None
        self.process_name = process_name.lower() if process_name else None
        self._proc = None
        self._last_scan = float("-inf")
        self._last_io: Optional[tuple[float, int, int]] = None
        if self.available:
            psutil.cpu_percent(None)  # a primeira chamada só zera a referência
            self._last_io = self._io_totals()

    @staticmethod
    def _io_totals() -> tuple[float, int, int]:
        sent = recv = 0
        for name, io in psutil.net_io_counters(pernic=True).items():
            if not is_virtual_nic(name):
                sent += io.bytes_sent
                recv += io.bytes_recv
        return time.monotonic(), sent, recv

    def _find_process(self):
        now = time.monotonic()
        if self._proc is not None:
            try:
                if self._proc.is_running():
                    return self._proc
            except psutil.Error:
                pass
            self._proc = None
        if now - self._last_scan < self.PROCESS_RESCAN_S:
            return None
        self._last_scan = now
        for p in psutil.process_iter(["name"]):
            if (p.info.get("name") or "").lower() == self.process_name:
                self._proc = p
                p.cpu_percent(None)
                return p
        return None

    def sample(self, cycle: int, t: float) -> Optional[SysSample]:
        """Lê os contadores. CPU e tráfego são médias desde a chamada anterior."""
        if not self.available:
            return None
        cpu = psutil.cpu_percent(None)
        ram = psutil.virtual_memory().percent
        now, sent, recv = self._io_totals()
        last_t, last_sent, last_recv = self._last_io  # type: ignore[misc]
        dt = max(now - last_t, 1e-6)
        self._last_io = (now, sent, recv)

        proc_cpu = proc_running = None
        if self.process_name:
            proc = self._find_process()
            proc_running = proc is not None
            if proc is not None:
                try:
                    proc_cpu = proc.cpu_percent(None)
                except psutil.Error:
                    self._proc, proc_running = None, False
        return SysSample(
            cycle=cycle, t=round(t, 3), cpu=cpu, ram=ram,
            sent_bps=round(max(sent - last_sent, 0) / dt, 1),
            recv_bps=round(max(recv - last_recv, 0) / dt, 1),
            proc_cpu=proc_cpu, proc_running=proc_running,
        )
