"""Parser do ``route print`` e filtro de placas virtuais."""

import pytest

from netblame.netinfo import (
    is_virtual_nic,
    is_wireless_nic,
    parse_default_gateway,
    parse_ip_route,
    parse_nameserver_value,
)

PT_ROUTE = """
===========================================================================
Lista de interfaces
 10...74 56 3c f2 3c a6 ......Realtek Gaming GbE Family Controller
  1...........................Software Loopback Interface 1
===========================================================================

Tabela de rotas IPv4
===========================================================================
Rotas ativas:
Endereço de rede          Máscara   Ender. gateway       Interface   Custo
          0.0.0.0          0.0.0.0    192.168.100.1   192.168.100.27     25
        127.0.0.0        255.0.0.0      No vínculo         127.0.0.1    331
    192.168.100.0    255.255.255.0      No vínculo    192.168.100.27    281
===========================================================================
Rotas persistentes:
  Nenhuma
"""

# Ethernet (métrica 25) e Wi-Fi (métrica 50): vence a de menor métrica,
# mesmo aparecendo depois. A rota persistente (4 colunas) é ignorada.
EN_ROUTE_TWO_DEFAULTS = """
IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      192.168.0.1     192.168.0.42     50
          0.0.0.0          0.0.0.0       10.0.0.254       10.0.0.17     25
        127.0.0.0        255.0.0.0         On-link         127.0.0.1    331
===========================================================================
Persistent Routes:
  Network Address          Netmask  Gateway Address  Metric
          0.0.0.0          0.0.0.0      172.16.0.1       1
"""

NO_DEFAULT = """
Active Routes:
        127.0.0.0        255.0.0.0         On-link         127.0.0.1    331
"""


def test_route_pt_br():
    assert parse_default_gateway(PT_ROUTE) == "192.168.100.1"


def test_route_lowest_metric_wins_and_persistent_ignored():
    assert parse_default_gateway(EN_ROUTE_TWO_DEFAULTS) == "10.0.0.254"


def test_route_no_default():
    assert parse_default_gateway(NO_DEFAULT) is None


def test_ip_route_linux():
    out = "default via 10.0.0.1 dev wlan0 metric 600\ndefault via 192.168.1.1 dev eth0 metric 100\n"
    assert parse_ip_route(out) == "192.168.1.1"


def test_nameserver_value():
    assert parse_nameserver_value("192.168.1.1 8.8.8.8,fe80::1 lixo") == ["192.168.1.1", "8.8.8.8"]


@pytest.mark.parametrize(
    "name, virtual",
    [
        ("Ethernet", False),
        ("Ethernet 2", False),
        ("Wi-Fi", False),
        ("Ethernet Startech", False),  # contém "tap" no meio, mas não é TAP
        ("vEthernet (WSL)", True),
        ("vEthernet (Default Switch)", True),
        ("Loopback Pseudo-Interface 1", True),
        ("VMware Network Adapter VMnet8", True),
        ("VirtualBox Host-Only Network", True),
        ("TAP-Windows Adapter V9", True),
        ("NordLynx", True),
        ("Tailscale", True),
        ("Conexão de Rede Bluetooth", True),
    ],
)
def test_is_virtual_nic(name, virtual):
    assert is_virtual_nic(name) is virtual


def test_is_wireless():
    assert is_wireless_nic("Wi-Fi 2")
    assert not is_wireless_nic("Ethernet")
