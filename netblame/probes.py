"""Sondas de disparo único: ICMP (via ``ping`` do sistema), conexão TCP e DNS cru.

Por que chamar o ``ping`` do sistema em vez de montar pacotes ICMP?
Sockets ICMP crus exigem administrador no Windows (e root no Linux), e uma
ferramenta de diagnóstico que dá medo de rodar como admin é uma ferramenta
que ninguém roda. O ``ping.exe`` está sempre lá e não pede privilégio. O
preço é interpretar a saída dele, que é traduzida conforme o idioma do
Windows - por isso o parser nunca procura palavras como "time" ou "tempo",
só tokens estruturais que todo idioma mantém: ``TTL=`` e um número seguido
de ``ms``.

O parsing fica em funções puras para que os testes possam usar saídas reais
do Windows em qualquer sistema operacional.
"""

from __future__ import annotations

import random
import re
import socket
import struct
import subprocess
import sys
import threading
import time
from typing import Optional

IS_WINDOWS = sys.platform == "win32"

#: Evita que uma janela de console pisque a cada ping quando o netblame é
#: iniciado fora de um terminal (pythonw, agendador de tarefas etc.).
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

# "tempo=12ms", "time<1ms", "Zeit=3ms", Linux "time=2.31 ms"
_RTT_RE = re.compile(r"[=<]\s*(\d+(?:[.,]\d+)?)\s*ms\b", re.IGNORECASE)
_TTL_RE = re.compile(r"\bTTL=\d+", re.IGNORECASE)


def decode_console(data: bytes) -> str:
    """Decodifica a saída de ferramentas de console.

    Programas de console do Windows escrevem na code page OEM (cp850 no
    pt-BR), não em UTF-8. Como só dependemos de tokens ASCII, acentos mal
    decodificados não quebram nada - mas decodificar certo mantém as
    mensagens de depuração legíveis.
    """
    for enc in ("oem", "utf-8") if IS_WINDOWS else ("utf-8",):
        try:
            return data.decode(enc)
        except (LookupError, UnicodeDecodeError):
            continue
    return data.decode("latin-1", errors="replace")


def parse_ping_rtt(output: str) -> Optional[float]:
    """Devolve o RTT (ms) da primeira resposta de eco na saída do ``ping``, ou None.

    Uma linha só conta como resposta se tiver o campo ``TTL=``. Esse detalhe
    importa: quando a própria máquina não tem rota, o Windows imprime
    "Resposta de <seu IP>: Host de destino inacessível" (en-US: "Destination
    host unreachable") e sai com código 0. Confiar no código de saída - ou em
    qualquer linha que comece com "Resposta" - contaria isso como sucesso.
    A exigência do ``TTL=`` também impede que o resumo ("Mínimo = 2ms") seja
    confundido com uma resposta.

    ``<1ms`` é registrado como 0,5 ms: o valor real está em algum ponto de [0, 1).
    """
    for line in output.splitlines():
        if not _TTL_RE.search(line):
            continue
        m = _RTT_RE.search(line)
        if not m:
            continue
        value = float(m.group(1).replace(",", "."))
        if line[m.start()] == "<":
            value = value / 2
        return value
    return None


def ping_command(host: str, timeout_ms: int) -> list[str]:
    if IS_WINDOWS:
        return ["ping", "-n", "1", "-w", str(timeout_ms), host]
    # Linux/macOS: útil durante o desenvolvimento; a análise não depende do SO.
    return ["ping", "-c", "1", "-W", str(max(1, round(timeout_ms / 1000))), host]


def ping(host: str, timeout_ms: int = 1000) -> Optional[float]:
    """Envia um eco ICMP com o ping do sistema. Devolve o RTT em ms ou None."""
    try:
        proc = subprocess.run(
            ping_command(host, timeout_ms),
            capture_output=True,
            timeout=timeout_ms / 1000 + 2,
            creationflags=NO_WINDOW,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None
    return parse_ping_rtt(decode_console(proc.stdout))


class TcpProbe:
    """Mede o tempo do handshake TCP até ``host:port``.

    Muitos servidores de jogos e serviços descartam ICMP, mas precisam aceitar
    TCP na porta do serviço. Um handshake é então a checagem mais honesta de
    "consigo alcançar o serviço?" que não exige privilégios.

    A resolução de nome fica em cache e é renovada no máximo a cada
    ``refresh_s`` segundos. Assim um DNS lento ou fora do ar aparece na linha
    de DNS do relatório, e não disfarçado de perda TCP. Se a renovação falhar,
    o último endereço bom é mantido.
    """

    def __init__(self, host: str, port: int, refresh_s: float = 60.0) -> None:
        self.host = host
        self.port = port
        self.refresh_s = refresh_s
        self._addr: Optional[tuple] = None
        self._family = socket.AF_INET
        self._resolved_at = 0.0
        self._lock = threading.Lock()

    def resolve(self) -> Optional[str]:
        """Devolve o IP em cache (renovando se expirou), ou None se nunca resolveu."""
        with self._lock:
            now = time.monotonic()
            if self._addr is None or now - self._resolved_at > self.refresh_s:
                try:
                    info = socket.getaddrinfo(self.host, self.port, socket.AF_INET, socket.SOCK_STREAM)
                    self._family, _, _, _, self._addr = info[0]
                except OSError:
                    pass
                self._resolved_at = now
            return self._addr[0] if self._addr else None

    def __call__(self, timeout_ms: int = 1000) -> Optional[float]:
        if self.resolve() is None:
            return None
        start = time.perf_counter()
        try:
            with socket.socket(self._family, socket.SOCK_STREAM) as s:
                s.settimeout(timeout_ms / 1000)
                s.connect(self._addr)
        except OSError:
            return None
        return (time.perf_counter() - start) * 1000


# --------------------------------------------------------------------------
# DNS
# --------------------------------------------------------------------------

def build_dns_query(name: str, query_id: int) -> bytes:
    """Monta uma consulta DNS recursiva mínima pelo registro A de ``name``."""
    header = struct.pack(">HHHHHH", query_id, 0x0100, 1, 0, 0, 0)  # RD=1, 1 pergunta
    qname = b"".join(
        bytes([len(label)]) + label.encode("ascii") for label in name.strip(".").split(".")
    ) + b"\x00"
    return header + qname + struct.pack(">HH", 1, 1)  # QTYPE=A, QCLASS=IN


def dns_response_ok(data: bytes, query_id: int) -> bool:
    """True quando ``data`` é a resposta à nossa consulta vinda de um resolvedor funcionando.

    NOERROR e NXDOMAIN provam que o resolvedor está vivo. SERVFAIL/REFUSED
    significam que ele respondeu mas não resolveu - que é exatamente o que o
    usuário percebe como "o DNS está quebrado".
    """
    if len(data) < 12:
        return False
    rid, flags = struct.unpack(">HH", data[:4])
    is_response = bool(flags & 0x8000)
    rcode = flags & 0x000F
    return rid == query_id and is_response and rcode in (0, 3)


class DnsProbe:
    """Cronometra uma consulta DNS enviada direto ao resolvedor via UDP.

    ``socket.getaddrinfo`` seria respondido pelo cache do cliente DNS do
    Windows em ~0 ms e esconderia um resolvedor morto. Falar direto com o
    resolvedor mede o que uma consulta "fria" (por exemplo, o matchmaking
    contatando um servidor novo) realmente enfrentaria.
    """

    def __init__(self, server: str, name: str = "www.google.com") -> None:
        self.server = server
        self.name = name

    def __call__(self, timeout_ms: int = 1000) -> Optional[float]:
        qid = random.randrange(1, 0xFFFF)
        packet = build_dns_query(self.name, qid)
        start = time.perf_counter()
        deadline = start + timeout_ms / 1000
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.sendto(packet, (self.server, 53))
                while True:  # descarta datagramas atrasados de consultas anteriores
                    remaining = deadline - time.perf_counter()
                    if remaining <= 0:
                        return None
                    s.settimeout(remaining)
                    data, _ = s.recvfrom(2048)
                    if dns_response_ok(data, qid):
                        return (time.perf_counter() - start) * 1000
        except OSError:
            return None


# --------------------------------------------------------------------------
# Contadores UDP do sistema
# --------------------------------------------------------------------------

def parse_proc_net_snmp(text: str) -> Optional[tuple[int, int, int]]:
    """Extrai ``(InDatagrams, NoPorts, InErrors)`` de ``/proc/net/snmp`` (Linux).

    O arquivo traz pares de linhas "Udp:": a primeira com os nomes das
    colunas, a segunda com os valores.
    """
    rows = [line.split()[1:] for line in text.splitlines() if line.startswith("Udp:")]
    if len(rows) < 2:
        return None
    values = dict(zip(rows[0], rows[1]))
    try:
        return int(values["InDatagrams"]), int(values["NoPorts"]), int(values["InErrors"])
    except (KeyError, ValueError):
        return None


def udp_counters() -> Optional[tuple[int, int, int]]:
    """Contadores UDP/IPv4 da máquina inteira: ``(recebidos, sem porta, erros de recepção)``.

    O que interessa é o ``InErrors``: datagramas que chegaram à máquina mas
    foram descartados pelo próprio sistema, quase sempre porque o buffer de
    recepção do programa encheu (ele não leu a tempo). Para um jogo, isso é
    pacote perdido *dentro do PC* - algo que nenhuma sonda externa enxerga.

    No Windows vem de ``GetUdpStatisticsEx`` (iphlpapi), que não exige
    administrador. Devolve None se não for possível ler.
    """
    if IS_WINDOWS:
        import ctypes
        from ctypes import wintypes

        class MIB_UDPSTATS(ctypes.Structure):
            _fields_ = [(name, wintypes.DWORD) for name in
                        ("dwInDatagrams", "dwNoPorts", "dwInErrors", "dwOutDatagrams", "dwNumAddrs")]

        stats = MIB_UDPSTATS()
        try:
            if ctypes.windll.iphlpapi.GetUdpStatisticsEx(ctypes.byref(stats), socket.AF_INET) != 0:
                return None
        except (AttributeError, OSError):
            return None
        return stats.dwInDatagrams, stats.dwNoPorts, stats.dwInErrors
    try:
        with open("/proc/net/snmp", encoding="ascii") as f:
            return parse_proc_net_snmp(f.read())
    except OSError:
        return None
