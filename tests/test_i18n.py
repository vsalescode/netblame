"""Textos bilíngues, formatação numérica e o switch de idioma do relatório."""

import pytest

from netblame.analysis import analyze
from netblame.cli import build_parser
from netblame.demo import SCENARIOS, generate
from netblame.i18n import Text, detect_lang, ms, num, secs
from netblame.report import render


def test_number_formatting():
    assert num(6.75) == Text("6.8", "6,8")
    assert ms(4.25) == Text("4.2 ms", "4,2 ms")
    assert ms(41.6) == Text("42 ms", "42 ms")
    assert ms(None).en == "–"
    assert secs(2.5) == Text("2.5s", "2,5s")


def test_text_join_and_add():
    t = Text.join(", ", [Text("a", "x"), Text("b", "y")]) + Text("!", "?")
    assert (t.en, t.pt) == ("a, b!", "x, y?")


def test_detect_lang_env(monkeypatch):
    monkeypatch.setenv("NETBLAME_LANG", "pt")
    assert detect_lang() == "pt"
    monkeypatch.setenv("NETBLAME_LANG", "en")
    assert detect_lang() == "en"


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_every_finding_is_translated(scenario):
    for f in analyze(generate(scenario)).findings:
        for field in (f.title, f.detail, f.advice):
            assert field.en and field.pt
            assert field.en != field.pt, field.en


def test_report_carries_both_languages():
    page = render(generate("isp"), lang="pt")
    assert 'data-lang="pt"' in page and 'lang="pt-BR"' in page
    assert 'data-set-lang="en"' in page and 'data-set-lang="pt"' in page
    assert '<span class="l-en">Latency</span>' in page
    assert '<span class="l-pt" lang="pt-BR">Latência</span>' in page
    # Vírgula decimal no português, ponto no inglês.
    assert "6,9%" in page or "7,0%" in page
    assert 'html[data-lang="pt"] .l-en' in page


def test_lang_flag_before_or_after_subcommand():
    p = build_parser()
    assert p.parse_args(["--lang", "en", "demo"]).lang == "en"
    assert p.parse_args(["demo", "--lang", "pt"]).lang == "pt"
    assert p.parse_args(["--lang", "en", "demo", "--lang", "pt"]).lang == "pt"
