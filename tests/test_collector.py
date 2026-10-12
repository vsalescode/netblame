"""Montagem de alvos e o loop de captura (com sondas falsas, sem rede)."""

import itertools

import pytest

from netblame import collector
from netblame.collector import CaptureConfig, build_targets, parse_target_spec
from netblame.models import Target


def test_parse_target_spec():
    assert parse_target_spec("game=tcp://battle.net:443") == Target("game", "tcp", "battle.net", "app", 443)
    assert parse_target_spec("nas=192.168.0.10") == Target("nas", "icmp", "192.168.0.10", "app")
    assert parse_target_spec("example.com").label == "example.com"
    for bad in ("x=tcp://host", "x=", "x=http://host"):
        with pytest.raises(ValueError):
            parse_target_spec(bad)


def test_build_targets_roles_and_presets():
    ts = build_targets("192.168.0.1", "192.168.0.1", extra=["vpn=10.8.0.1"], presets=["battlenet"])
    assert [(t.label, t.role) for t in ts] == [
        ("gateway", "gateway"), ("cloudflare", "internet"), ("google", "internet"),
        ("dns", "dns"), ("battlenet", "app"), ("vpn", "app"),
        ("cloudflare-udp", "udp"), ("google-udp", "udp"),
    ]
    udp = [t for t in ts if t.role == "udp"]
    assert [(t.kind, t.host) for t in udp] == [("dns", "1.1.1.1"), ("dns", "8.8.8.8")]
    assert not any(t.role == "udp" for t in build_targets(None, None, udp=False))
    with pytest.raises(ValueError):
        build_targets(None, None, presets=["nope"])
    with pytest.raises(ValueError):
        build_targets("192.168.0.1", None, extra=["gateway=1.2.3.4"])


def test_capture_loop_with_fake_probes(monkeypatch):
    rtts = itertools.cycle([1.0, None, 3.0])
    monkeypatch.setattr(collector, "make_probe", lambda t: (lambda timeout: next(rtts)))
    monkeypatch.setattr(collector.netinfo, "snapshot_nics", lambda: [])
    cfg = CaptureConfig(
        targets=[Target("a", "icmp", "x", "internet"), Target("b", "icmp", "y", "internet"),
                 Target("c", "icmp", "z", "app")],
        minutes=0.05, interval=0.01, trace=False,
    )
    seen = []
    s = collector.capture(cfg, on_cycle=lambda c, n, r, sy: seen.append(c), status=lambda m: None)
    assert s.cycles == len(seen) == 0.05 * 60 / 0.01
    assert len(s.samples) == 3 * s.cycles
    assert any(x.rtt is None for x in s.samples)


def test_probe_timeout_fits_interval():
    assert CaptureConfig([], interval=1).probe_timeout() == 800
    assert CaptureConfig([], interval=0.1).probe_timeout() == 300
    assert CaptureConfig([], interval=5).probe_timeout() == 2000
