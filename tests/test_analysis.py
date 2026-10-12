"""Estatísticas, apagões e regras de diagnóstico com sessões montadas à mão."""

import pytest

from netblame.analysis import analyze, find_events, jitter, percentile, target_stats
from netblame.models import NicSnapshot, Sample, Session, SysSample, Target

TARGETS = [
    Target("gateway", "icmp", "192.168.0.1", "gateway"),
    Target("cloudflare", "icmp", "1.1.1.1", "internet"),
    Target("google", "icmp", "8.8.8.8", "internet"),
    Target("app", "tcp", "example.com", "app", 443),
]


def session_from(pattern: dict[str, str], rtt: dict[str, float] | None = None) -> Session:
    """Monta uma sessão a partir de strings por alvo: '.' = resposta, 'x' = perda."""
    rtt = rtt or {}
    s = Session("2026-10-11T20:00:00", 1.0, list(TARGETS))
    n = len(next(iter(pattern.values())))
    for c in range(n):
        for label, row in pattern.items():
            s.samples.append(Sample(c, float(c), label, None if row[c] == "x" else rtt.get(label, 10.0)))
    s.cycles = n
    return s


def test_percentile_and_jitter():
    assert percentile([1, 2, 3, 4, 5], 50) == 3
    assert percentile([1, 2, 3, 4, 5], 95) == pytest.approx(4.8)
    assert percentile([7], 95) == 7
    assert jitter([10, 12, 10, 14]) == pytest.approx((2 + 2 + 4) / 3)
    assert jitter([10]) is None


def test_target_stats():
    s = session_from({"gateway": "..x.", "cloudflare": "....", "google": "....", "app": "...."})
    st = target_stats(s)["gateway"]
    assert (st.sent, st.lost, st.loss_pct, st.median) == (4, 1, 25.0, 10.0)


def test_find_events_upstream_and_local():
    s = session_from({
        "gateway":    "....xxx.......",
        "cloudflare": ".xxxxxx...x...",
        "google":     ".xxxxxx...x...",
        "app":        ".xxxxxx...x...",
    })
    events = find_events(s)
    # ciclos 1-3: só externos (upstream); 4-6: tudo (local). Um único apagão contínuo
    # com maioria local. O ciclo 10 sozinho não é apagão.
    assert len(events) == 1
    e = events[0]
    assert (e.start_cycle, e.end_cycle, e.cycles, e.scope) == (1, 6, 6, "local")
    assert e.duration == 6.0


def test_find_events_separate_runs():
    s = session_from({
        "gateway":    "..........",
        "cloudflare": ".xx....xxx",
        "google":     ".xx....xxx",
        "app":        ".xx....xxx",
    })
    events = find_events(s)
    assert [(e.start_cycle, e.end_cycle, e.scope) for e in events] == [(1, 2, "upstream"), (7, 9, "upstream")]


def test_gateway_alone_or_partial_external_is_not_blackout():
    s = session_from({
        "gateway":    ".xxxx.",
        "cloudflare": "..xx..",
        "google":     "......",
        "app":        "..xx..",
    })
    assert find_events(s) == []


def test_unknown_scope_without_gateway():
    s = session_from({"cloudflare": ".xx.", "google": ".xx.", "app": ".xx."})
    s.targets = s.targets[1:]
    assert find_events(s)[0].scope == "unknown"


def test_clean_session_verdict():
    s = session_from({k: "." * 60 for k in ("gateway", "cloudflare", "google", "app")})
    a = analyze(s)
    assert a.verdict.severity == "ok"


def test_app_only_route_verdict():
    app = "".join("x" if i % 8 == 0 else "." for i in range(80))
    s = session_from({"gateway": "." * 80, "cloudflare": "." * 80, "google": "." * 80, "app": app})
    a = analyze(s)
    assert a.verdict.category == "route"


def test_pc_correlation_beats_local():
    pattern = "".join("xx" if i % 10 == 0 else "." for i in range(60))[:60]
    s = session_from({k: pattern for k in ("gateway", "cloudflare", "google", "app")})
    s.sys = [SysSample(c, float(c), cpu=99.0 if pattern[c] == "x" else 20.0, ram=50.0,
                       sent_bps=0, recv_bps=0) for c in range(60)]
    a = analyze(s)
    assert a.verdict.category == "pc"
    assert not any(f.category == "local" and f.severity == "critical" for f in a.findings)


def test_dns_failure_with_working_internet():
    s = session_from({"gateway": "." * 50, "cloudflare": "." * 50, "google": "." * 50, "app": "." * 50,
                      "dns": "xx......." * 5 + "....."})
    s.targets = TARGETS + [Target("dns", "dns", "192.168.0.1", "dns")]
    assert analyze(s).verdict.category == "dns"


def test_nic_speed_and_errors():
    s = session_from({k: "." * 30 for k in ("gateway", "cloudflare", "google", "app")})
    s.nics_before = [NicSnapshot("Ethernet", True, 100, False, errin=5)]
    s.nics_after = [NicSnapshot("Ethernet", True, 100, False, errin=12)]
    titles = [f.title.en for f in analyze(s).findings]
    assert any("100 Mbps" in t for t in titles)
    assert any("7 error(s)" in t for t in titles)


def test_bufferbloat_spikes():
    n = 100
    rtts = {i: (200.0 if i % 10 == 0 else 20.0) for i in range(n)}
    s = session_from({k: "." * n for k in ("gateway", "cloudflare", "google", "app")})
    for smp in s.samples:
        if smp.target in ("cloudflare", "google"):
            smp.rtt = rtts[smp.cycle]
        elif smp.target == "gateway":
            smp.rtt = 1.0
    assert analyze(s).verdict.category == "bufferbloat"
