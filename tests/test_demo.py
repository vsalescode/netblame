"""Cada cenário do demo precisa chegar ao diagnóstico esperado."""

import pytest

from netblame.analysis import analyze
from netblame.demo import EXPECTED_CATEGORY, SCENARIOS, generate


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_scenario_verdict(scenario):
    a = analyze(generate(scenario))
    assert a.verdict.category == EXPECTED_CATEGORY[scenario], [f.title.en for f in a.findings]


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_scenario_is_reproducible(scenario):
    assert generate(scenario) == generate(scenario)


def test_isp_hop_inside_isp_network():
    a = analyze(generate("isp"))
    assert a.bad_hops["game"].hop == 2
    assert any(e.scope == "upstream" for e in a.events)


def test_route_scenario_blames_transit_hop_and_ignores_rate_limit():
    a = analyze(generate("route"))
    assert a.bad_hops["game"].host == "198.51.100.17"
    assert a.bad_hops["cloudflare"] is None
    assert a.rate_limited["cloudflare"] == [3]


def test_local_scenario_findings():
    a = analyze(generate("local"))
    cats = {f.category for f in a.findings}
    assert {"local", "cable"} <= cats
    assert all(e.scope == "local" for e in a.events)


def test_healthy_has_no_events():
    a = analyze(generate("healthy"))
    assert a.events == []
    assert a.verdict.severity == "ok"


def test_unknown_scenario():
    with pytest.raises(ValueError):
        generate("nope")
