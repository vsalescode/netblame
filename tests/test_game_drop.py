"""Queda do jogo pela CPU do processo, RAM no limite por muito tempo e DNS interceptado."""

from netblame.analysis import analyze, find_game_drops, wall_clock
from netblame.models import Sample, Session, SysSample, Target
from netblame.report import render

TARGETS = [Target("gateway", "icmp", "192.168.0.1", "gateway"),
           Target("cloudflare", "icmp", "1.1.1.1", "internet"),
           Target("game", "tcp", "example.com", "app", 443)]


def session(n: int = 120, game_cpu=None, ram=None, lost: dict | None = None) -> Session:
    """Sessão de ``n`` ciclos; ``game_cpu``/``ram`` são funções do ciclo, ``lost`` = {ciclo: [alvos]}."""
    s = Session("2026-10-11T21:59:16", 1.0, list(TARGETS), process_name="Overwatch.exe")
    lost = lost or {}
    for c in range(n):
        for t in TARGETS:
            s.samples.append(Sample(c, float(c), t.label, None if t.label in lost.get(c, []) else 10.0))
        s.sys.append(SysSample(c, float(c), cpu=20.0, ram=ram(c) if ram else 60.0, sent_bps=0, recv_bps=0,
                               proc_cpu=game_cpu(c) if game_cpu else None, proc_running=True))
    s.cycles, s.duration = n, float(n)
    return s


def test_game_drop_detected_with_clean_network():
    s = session(game_cpu=lambda c: 250.0 if c < 100 else 40.0)
    assert find_game_drops(s) == [100]
    a = analyze(s)
    drop = next(f for f in a.findings if f.category == "drop")
    assert "22:00:56" in drop.title.pt  # 21:59:16 + 100 s
    assert "responderam normalmente" in drop.detail.pt
    assert a.markers and a.markers[0][0] == 100.0


def test_game_drop_names_failing_points():
    s = session(game_cpu=lambda c: 250.0 if c < 100 else 40.0, lost={98: ["cloudflare", "game"]})
    drop = next(f for f in analyze(s).findings if f.category == "drop")
    assert "cloudflare, game" in drop.detail.en


def test_steady_or_idle_game_is_not_a_drop():
    assert find_game_drops(session(game_cpu=lambda c: 250.0)) == []
    assert find_game_drops(session(game_cpu=lambda c: 30.0 if c % 2 else 10.0)) == []
    assert find_game_drops(session()) == []


def test_sustained_ram_is_a_warning_and_headline_is_soft():
    s = session(ram=lambda c: 99.0 if 20 <= c < 80 else 70.0)
    a = analyze(s)
    assert a.verdict.category == "pc" and a.verdict.severity == "warning"
    assert "60s" in a.verdict.title.en
    page = render(s, a)
    assert "Ponto de atenção: seu PC" in page


def test_short_ram_spike_is_ignored():
    s = session(ram=lambda c: 99.0 if 20 <= c < 40 else 70.0)
    assert not any(f.category == "pc" and f.severity == "warning" for f in analyze(s).findings)


def test_dns_interception_detected():
    s = session(n=40)
    s.targets.append(Target("cloudflare-udp", "dns", "1.1.1.1", "udp"))
    for c in range(40):
        s.samples.append(Sample(c, float(c), "cloudflare-udp", 47.0))
    for x in s.samples:
        if x.target == "cloudflare":
            x.rtt = 2.0
    titles = [f.title.en for f in analyze(s).findings]
    assert "Your provider seems to intercept DNS traffic" in titles


def test_wall_clock():
    s = session(n=1)
    assert wall_clock(s, 65) == "22:00:21"
