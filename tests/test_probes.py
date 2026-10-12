"""Parser do ping com saídas reais do Windows em pt-BR e en-US."""

import struct

import pytest

from netblame.probes import build_dns_query, dns_response_ok, parse_ping_rtt

PT_REPLY = """
Disparando 1.1.1.1 com 32 bytes de dados:
Resposta de 1.1.1.1: bytes=32 tempo=12ms TTL=60

Estatísticas do Ping para 1.1.1.1:
    Pacotes: Enviados = 1, Recebidos = 1, Perdidos = 0 (0% de
             perda),
Aproximar um número redondo de vezes em milissegundos:
    Mínimo = 12ms, Máximo = 12ms, Média = 12ms
"""

PT_SUBMS = "Resposta de 192.168.100.1: bytes=32 tempo<1ms TTL=64\n"

PT_TIMEOUT = """
Disparando 10.255.255.1 com 32 bytes de dados:
Esgotado o tempo limite do pedido.

Estatísticas do Ping para 10.255.255.1:
    Pacotes: Enviados = 1, Recebidos = 0, Perdidos = 1 (100% de
             perda),
"""

# O Windows sai com código 0 e conta como "Recebidos = 1"; não é uma resposta.
PT_UNREACHABLE = """
Disparando 10.0.0.5 com 32 bytes de dados:
Resposta de 192.168.100.27: Host de destino inacessível.

Estatísticas do Ping para 10.0.0.5:
    Pacotes: Enviados = 1, Recebidos = 1, Perdidos = 0 (0% de
             perda),
"""

EN_REPLY = """
Pinging 8.8.8.8 with 32 bytes of data:
Reply from 8.8.8.8: bytes=32 time=23ms TTL=117

Ping statistics for 8.8.8.8:
    Packets: Sent = 1, Received = 1, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 23ms, Maximum = 23ms, Average = 23ms
"""

EN_TIMEOUT = """
Pinging 10.255.255.1 with 32 bytes of data:
Request timed out.

Ping statistics for 10.255.255.1:
    Packets: Sent = 1, Received = 0, Lost = 1 (100% loss),
"""

EN_UNREACHABLE = """
Pinging 10.0.0.5 with 32 bytes of data:
Reply from 192.168.1.20: Destination host unreachable.

Ping statistics for 10.0.0.5:
    Packets: Sent = 1, Received = 1, Lost = 0 (0% loss),
"""

LINUX_REPLY = "64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=2.31 ms\n"


@pytest.mark.parametrize(
    "output, expected",
    [
        (PT_REPLY, 12.0),
        (PT_SUBMS, 0.5),
        (PT_TIMEOUT, None),
        (PT_UNREACHABLE, None),
        (EN_REPLY, 23.0),
        (EN_TIMEOUT, None),
        (EN_UNREACHABLE, None),
        (LINUX_REPLY, 2.31),
        ("", None),
    ],
    ids=["pt-reply", "pt-sub-ms", "pt-timeout", "pt-unreachable", "en-reply",
         "en-timeout", "en-unreachable", "linux", "empty"],
)
def test_parse_ping_rtt(output, expected):
    assert parse_ping_rtt(output) == expected


def test_summary_line_is_not_a_reply():
    # As linhas de resumo têm "= 12ms" mas nenhum TTL.
    assert parse_ping_rtt("    Mínimo = 12ms, Máximo = 12ms, Média = 12ms") is None


def test_dns_query_layout():
    q = build_dns_query("www.google.com", 0x1234)
    assert q[:2] == b"\x12\x34"
    assert b"\x03www\x06google\x03com\x00" in q
    assert q.endswith(b"\x00\x01\x00\x01")


@pytest.mark.parametrize("rcode, ok", [(0, True), (3, True), (2, False), (5, False)])
def test_dns_response_rcodes(rcode, ok):
    reply = struct.pack(">HHHHHH", 0x1234, 0x8180 | rcode, 1, 1, 0, 0)
    assert dns_response_ok(reply, 0x1234) is ok


def test_dns_response_wrong_id_or_query():
    assert not dns_response_ok(struct.pack(">HHHHHH", 0x9999, 0x8180, 1, 1, 0, 0), 0x1234)
    assert not dns_response_ok(struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0), 0x1234)
    assert not dns_response_ok(b"\x12", 0x1234)
