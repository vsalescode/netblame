"""Parser do tracert e a lógica de salto culpado vs rate-limit."""

from netblame.models import HopStat
from netblame.tracing import HopMonitor, find_bad_hop, parse_tracert, rate_limited_hops

PT_TRACERT = """
Rastreando a rota para 1.1.1.1 com no máximo 30 saltos

  1    <1 ms    <1 ms    <1 ms  192.168.100.1
  2     2 ms     2 ms     1 ms  10.10.0.1
  3     *        *        *     Esgotado o tempo limite do pedido.
  4     2 ms     3 ms     2 ms  45.68.72.137
  5     3 ms     *        3 ms  1.1.1.1

Rastreamento concluído.
"""

EN_TRACERT_NOT_REACHED = """
Tracing route to 24.105.30.129 over a maximum of 20 hops

  1    <1 ms    <1 ms    <1 ms  192.168.0.1
  2    11 ms     9 ms    10 ms  100.64.0.1
  3    12 ms    12 ms    11 ms  200.160.0.10
  4     *        *        *     Request timed out.
  5     *        *        *     Request timed out.
"""

EN_UNREACHABLE = """
  1    <1 ms    <1 ms    <1 ms  192.168.0.1
  2     1 ms     1 ms     1 ms  10.0.0.1  reports: Destination net unreachable.
"""


def test_parse_pt_br():
    assert parse_tracert(PT_TRACERT) == [
        (1, "192.168.100.1"), (2, "10.10.0.1"), (3, None), (4, "45.68.72.137"), (5, "1.1.1.1"),
    ]


def test_parse_trims_trailing_silent_hops():
    assert parse_tracert(EN_TRACERT_NOT_REACHED) == [
        (1, "192.168.0.1"), (2, "100.64.0.1"), (3, "200.160.0.10"),
    ]


def test_parse_unreachable_report():
    assert parse_tracert(EN_UNREACHABLE)[-1] == (2, "10.0.0.1")


def test_header_with_hop_count_is_not_a_hop():
    assert parse_tracert("30 saltos no máximo\n") == []


def hops(*losses):
    """Cria saltos com 100 pings cada; None = salto mudo no tracert."""
    out = []
    for i, loss in enumerate(losses, start=1):
        if loss is None:
            out.append(HopStat(i, None))
        else:
            out.append(HopStat(i, f"10.0.0.{i}", sent=100, lost=loss, rtt_avg=10))
    return out


def test_persistent_loss_points_to_first_hop():
    route = hops(0, 0, 8, 9, 7, 8)
    assert find_bad_hop(route).hop == 3
    assert rate_limited_hops(route) == []


def test_intermediate_rate_limit_is_ignored():
    route = hops(0, 40, 0, 60, 0, 0)
    assert find_bad_hop(route) is None
    assert rate_limited_hops(route) == [2, 4]


def test_rate_limit_before_real_loss():
    # Salto 2 limita ICMP; a perda real começa no 4 e persiste.
    route = hops(0, 50, 0, 10, 12, 11)
    assert find_bad_hop(route).hop == 4
    assert rate_limited_hops(route) == [2]


def test_silent_hops_are_transparent():
    route = hops(0, 0, 10, None, 9, 10)
    assert find_bad_hop(route).hop == 3


def test_gateway_is_culprit():
    assert find_bad_hop(hops(15, 14, 15, 16)).hop == 1


def test_clean_route_and_empty():
    assert find_bad_hop(hops(0, 0, 1, 0)) is None
    assert find_bad_hop([]) is None


def test_hop_monitor_shares_ips_between_routes():
    mon = HopMonitor()
    mon.add_route("a", "1.1.1.1", [(1, "192.168.0.1"), (2, None), (3, "1.1.1.1")])
    mon.add_route("b", "8.8.8.8", [(1, "192.168.0.1"), (2, "8.8.8.8")])
    assert sorted(mon.addresses()) == ["1.1.1.1", "192.168.0.1", "8.8.8.8"]
    for rtt in (1.0, None, 3.0):
        mon.record("192.168.0.1", rtt)
    a, b = mon.traces()
    gw = a.hops[0]
    assert (gw.sent, gw.lost, gw.rtt_avg, gw.rtt_best, gw.rtt_worst) == (3, 1, 2.0, 1.0, 3.0)
    assert b.hops[0] == gw
    assert a.hops[1].loss_pct is None
