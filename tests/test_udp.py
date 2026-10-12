"""Sondas UDP: contadores do sistema, regra UDP vs ICMP e o card do relatório."""

from netblame import cli, collector
from netblame.analysis import analyze
from netblame.demo import generate
from netblame.models import Sample, Session, Target, UdpSample
from netblame.probes import parse_proc_net_snmp
from netblame.report import color_slots, render

PROC_NET_SNMP = """\
Ip: Forwarding DefaultTTL InReceives
Ip: 1 64 12345
Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors InCsumErrors IgnoredMulti
Udp: 98765 12 7 4321 7 0 0 3
"""


def test_parse_proc_net_snmp():
    assert parse_proc_net_snmp(PROC_NET_SNMP) == (98765, 12, 7)
    assert parse_proc_net_snmp("Ip: a b\nIp: 1 2\n") is None


def _session(udp_pattern: str, icmp_pattern: str) -> Session:
    targets = [Target("gateway", "icmp", "192.168.0.1", "gateway"),
               Target("cloudflare", "icmp", "1.1.1.1", "internet"),
               Target("cloudflare-udp", "dns", "1.1.1.1", "udp")]
    s = Session("2026-10-11T20:00:00", 1.0, targets)
    for c in range(len(udp_pattern)):
        s.samples += [Sample(c, float(c), "gateway", 1.0),
                      Sample(c, float(c), "cloudflare", None if icmp_pattern[c] == "x" else 10.0),
                      Sample(c, float(c), "cloudflare-udp", None if udp_pattern[c] == "x" else 11.0)]
    s.cycles = s.duration = len(udp_pattern)
    return s


def test_udp_only_loss_is_flagged():
    s = _session(("x" + "." * 9) * 10, "." * 100)
    assert analyze(s).verdict.category == "udp"


def test_udp_and_icmp_losing_together_is_not_udp_problem():
    pattern = ("x" + "." * 9) * 10
    assert not any(f.category == "udp" for f in analyze(_session(pattern, pattern)).findings)


def test_windows_udp_discards_finding():
    s = _session("." * 50, "." * 50)
    s.udp = [UdpSample(c, float(c), received=60, errors=1 if c % 5 == 0 else 0) for c in range(50)]
    titles = [f.title.en for f in analyze(s).findings]
    assert any("discarded 10 incoming UDP" in t for t in titles)


def test_udp_targets_are_not_plotted_but_reported():
    s = generate("udp")
    slots = color_slots(s)
    assert slots["cloudflare-udp"] is None and slots["gateway"] == 0
    page = render(s)
    assert "UDP vs ICMP" in page
    assert page.count('class="line s') >= 5


def test_cli_run_smoke(monkeypatch, tmp_path, capsys):
    """O caminho completo do ``netblame run``, com a captura trocada por uma sessão pronta."""
    def fake_capture(cfg, on_cycle=None, status=print):
        status(collector.Text("hello", "olá"))
        s = generate("udp", minutes=0.5)
        return s

    monkeypatch.setattr(cli.netinfo, "detect_gateway", lambda: "192.168.0.1")
    monkeypatch.setattr(cli.netinfo, "system_dns_servers", lambda: ["192.168.0.1"])
    monkeypatch.setattr(cli, "capture", fake_capture)
    rc = cli.main(["--lang", "pt", "run", "--minutes", "0.1", "--out", str(tmp_path / "s")])
    out = capsys.readouterr().out
    assert rc == 0
    assert "olá" in out and "VEREDITO" in out
    assert (tmp_path / "s.html").exists() and (tmp_path / "s.json").exists()
