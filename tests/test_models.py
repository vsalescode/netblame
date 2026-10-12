"""Persistência da sessão em JSON e propriedades dos modelos."""

from netblame.models import HopStat, NicSnapshot, Sample, Session, SysSample, Target, Trace


def make_session() -> Session:
    s = Session(
        started_at="2026-10-11T20:00:00",
        interval=1.0,
        targets=[
            Target("gateway", "icmp", "192.168.0.1", "gateway"),
            Target("app", "tcp", "example.com", "app", port=443),
        ],
    )
    s.samples += [Sample(0, 0.0, "gateway", 1.0), Sample(0, 0.0, "app", None)]
    s.sys.append(SysSample(0, 0.0, cpu=12.5, ram=40.0, sent_bps=100, recv_bps=200))
    s.traces.append(Trace("app", "93.184.216.34", [HopStat(1, "192.168.0.1", 10, 1, 1.0, 0.5, 2.0)]))
    s.nics_before.append(NicSnapshot("Ethernet", True, 1000, False))
    return s


def test_round_trip(tmp_path):
    s = make_session()
    loaded = Session.load(s.save(tmp_path / "s.json"))
    assert loaded == s
    assert loaded.target("app").describe() == "tcp://example.com:443"
    assert loaded.labels("gateway") == ["gateway"]


def test_hop_loss_pct():
    assert HopStat(1, None).loss_pct is None
    assert HopStat(1, "1.1.1.1", sent=20, lost=5).loss_pct == 25.0
