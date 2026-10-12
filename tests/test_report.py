"""Relatório: autocontido, escapado e com as seções esperadas."""

import re

import pytest

from netblame.demo import SCENARIOS, generate
from netblame.models import Sample, Session, Target
from netblame.report import _path, nice_step, render, Scale


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_report_is_self_contained(scenario):
    page = render(generate(scenario))
    # Nenhum recurso externo: nada de src/href http, nem @import.
    assert not re.search(r'(src|href)\s*=\s*"https?://', page)
    assert "@import" not in page
    for section in ("Latency", "Packet loss", "Per-target statistics", "Hop by hop", "Network adapters"):
        assert section in page


def test_culprit_hop_highlighted():
    page = render(generate("route"))
    assert 'class="culprit"' in page
    assert "loss starts here" in page


def test_labels_are_escaped():
    s = Session("2026-10-11T20:00:00", 1.0, [Target("<script>x</script>", "icmp", "1.1.1.1", "internet")])
    s.samples = [Sample(0, 0.0, "<script>x</script>", 1.0), Sample(1, 1.0, "<script>x</script>", None)]
    s.cycles, s.duration = 2, 2.0
    page = render(s)
    assert "<script>x</script>" not in page
    assert "&lt;script&gt;" in page


def test_path_breaks_on_loss():
    x = Scale(0, 10, 0, 10)
    y = Scale(0, 10, 0, 10)
    d = _path([(0, 1.0), (1, 2.0), (2, None), (3, 3.0)], x, y)
    assert d.count("M") == 2


def test_nice_step():
    assert nice_step(230, 5) == 50
    assert nice_step(9, 5) == 2
