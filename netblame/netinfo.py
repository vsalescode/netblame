"""Descoberta da rede local: gateway padrão, servidores DNS e placas físicas.

Nada aqui exige administrador: ``route print`` e o registro do TCP/IP podem
ser lidos por qualquer usuário, e o psutil lê os contadores das placas via
APIs públicas do Windows.
"""

from __future__ import annotations

import ipaddress
import re
import subprocess
import sys
from typing import Optional

from netblame.models import NicSnapshot
from netblame.probes import IS_WINDOWS, NO_WINDOW, decode_console

try:  # psutil é opcional: sem ele, só perdemos o snapshot das placas.
    import psutil
except ImportError:  # pragma: no cover - depende do ambiente
    psutil = None

# Linha de rota ativa: destino, máscara, gateway, interface, métrica (5 colunas).
# As rotas persistentes têm só 4 colunas, então ficam de fora naturalmente.
_ROUTE_RE = re.compile(
    r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d{1,3}(?:\.\d{1,3}){3})\s+(\d{1,3}(?:\.\d{1,3}){3})\s+(\d+)\s*$"
)


def parse_default_gateway(route_output: str) -> Optional[str]:
    """Extrai o gateway padrão da saída de ``route print -4``.

    Procura as rotas ``0.0.0.0/0`` e escolhe a de menor métrica, que é a que
    o Windows realmente usa quando há mais de uma (Ethernet + Wi-Fi, VPN...).
    A regex só olha a estrutura numérica das colunas, então funciona em
    qualquer idioma ("Rotas ativas", "Active Routes", "Aktive Routen"...).
    """
    best: Optional[tuple[int, str]] = None
    for line in route_output.splitlines():
        m = _ROUTE_RE.match(line)
        if not m:
            continue
        gateway, metric = m.group(1), int(m.group(3))
        if best is None or metric < best[0]:
            best = (metric, gateway)
    return best[1] if best else None


def parse_ip_route(output: str) -> Optional[str]:
    """Equivalente do Linux (``ip -4 route``): ``default via X ... metric N``."""
    best: Optional[tuple[int, str]] = None
    for line in output.splitlines():
        m = re.match(r"^default via (\S+)", line.strip())
        if not m:
            continue
        mm = re.search(r"\bmetric (\d+)", line)
        metric = int(mm.group(1)) if mm else 0
        if best is None or metric < best[0]:
            best = (metric, m.group(1))
    return best[1] if best else None


def _run(cmd: list[str]) -> str:
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=10, creationflags=NO_WINDOW)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return decode_console(proc.stdout)


def detect_gateway() -> Optional[str]:
    """Descobre o gateway padrão (o roteador) desta máquina."""
    if IS_WINDOWS:
        return parse_default_gateway(_run(["route", "print", "-4"]))
    return parse_ip_route(_run(["ip", "-4", "route"]))


def parse_nameserver_value(value: str) -> list[str]:
    """Os valores ``NameServer`` do registro vêm separados por espaço ou vírgula."""
    out = []
    for token in re.split(r"[\s,]+", value.strip()):
        try:
            if ipaddress.ip_address(token).version == 4:
                out.append(token)
        except ValueError:
            continue
    return out


def system_dns_servers() -> list[str]:
    """Lista os servidores DNS IPv4 configurados no sistema.

    No Windows vem do registro (``Tcpip\\Parameters\\Interfaces``): é legível
    sem admin e, ao contrário de ``ipconfig /all``, não depende do idioma.
    Servidores fixos (``NameServer``) têm prioridade sobre os do DHCP.
    """
    servers: list[str] = []
    if IS_WINDOWS:
        import winreg

        base = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
        try:
            root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base)
        except OSError:
            return []
        with root:
            for i in range(winreg.QueryInfoKey(root)[0]):
                try:
                    with winreg.OpenKey(root, winreg.EnumKey(root, i)) as key:
                        found = []
                        for name in ("NameServer", "DhcpNameServer"):
                            try:
                                found = parse_nameserver_value(winreg.QueryValueEx(key, name)[0])
                            except OSError:
                                continue
                            if found:
                                break
                        servers += [s for s in found if s not in servers]
                except OSError:
                    continue
    else:
        try:
            with open("/etc/resolv.conf", encoding="utf-8") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 2 and parts[0] == "nameserver":
                        servers += parse_nameserver_value(parts[1])
        except OSError:
            pass
    return servers


# --------------------------------------------------------------------------
# Placas de rede
# --------------------------------------------------------------------------

#: Palavras que denunciam placas virtuais, de VPN ou de túnel. Os contadores
#: delas não dizem nada sobre o cabo e poluiriam o diagnóstico.
VIRTUAL_KEYWORDS = (
    "loopback", "vethernet", "hyper-v", "vmware", "virtualbox", "vbox", "docker",
    "wsl", "tap", "tun", "vpn", "wireguard", "wg", "tailscale", "zerotier",
    "openvpn", "nordlynx", "hamachi", "radmin", "isatap", "teredo", "6to4",
    "bluetooth", "npcap", "pseudo-interface", "virtual",
)
WIRELESS_KEYWORDS = ("wi-fi", "wifi", "wireless", "wlan", "802.11")


def _words(name: str) -> set[str]:
    return set(re.split(r"[^a-z0-9]+", name.lower()))


def is_virtual_nic(name: str) -> bool:
    """True para placas virtuais/VPN, que devem ser ignoradas.

    Palavras curtas e ambíguas ("tap", "tun", "wg", "wsl") só contam como
    palavra inteira, para não descartar algo como "Ethernet Startech".
    """
    lowered = name.lower()
    words = _words(name)
    for kw in VIRTUAL_KEYWORDS:
        if len(kw) <= 4:
            if kw in words:
                return True
        elif kw in lowered:
            return True
    return False


def is_wireless_nic(name: str) -> bool:
    lowered = name.lower()
    return any(kw in lowered for kw in WIRELESS_KEYWORDS)


def snapshot_nics() -> list[NicSnapshot]:
    """Fotografa velocidade negociada e contadores de erro das placas físicas ativas."""
    if psutil is None:
        return []
    stats = psutil.net_if_stats()
    counters = psutil.net_io_counters(pernic=True)
    out = []
    for name, st in stats.items():
        if not st.isup or is_virtual_nic(name):
            continue
        io = counters.get(name)
        out.append(
            NicSnapshot(
                name=name,
                is_up=st.isup,
                speed_mbps=int(st.speed or 0),
                wireless=is_wireless_nic(name),
                errin=getattr(io, "errin", 0),
                errout=getattr(io, "errout", 0),
                dropin=getattr(io, "dropin", 0),
                dropout=getattr(io, "dropout", 0),
            )
        )
    return out


def has_psutil() -> bool:
    return psutil is not None


if __name__ == "__main__":  # pragma: no cover - diagnóstico rápido manual
    print("gateway:", detect_gateway())
    print("dns:", system_dns_servers())
    for nic in snapshot_nics():
        print(nic)
    sys.exit(0)
