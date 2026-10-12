"""Textos bilíngues (inglês e português do Brasil).

Por que cada mensagem carrega as duas línguas, em vez de um catálogo de
chaves (gettext)? O relatório HTML embute **as duas** versões e troca na
hora com um botão, sem recarregar - então a análise precisa produzir as duas
de uma vez. E manter o texto em português ao lado do texto em inglês, no
ponto onde a regra é decidida, deixa óbvio quando uma tradução ficou para
trás.
"""

from __future__ import annotations

import locale
import os
from dataclasses import dataclass
from typing import Literal, Optional, Union

Lang = Literal["en", "pt"]
LANGS: tuple[Lang, ...] = ("en", "pt")


@dataclass(frozen=True)
class Text:
    """Um texto nas duas línguas suportadas."""

    en: str
    pt: str

    def get(self, lang: str) -> str:
        return self.pt if lang == "pt" else self.en

    def __add__(self, other: "Text") -> "Text":
        return Text(self.en + other.en, self.pt + other.pt)

    @staticmethod
    def join(sep: Union[str, "Text"], items: list["Text"]) -> "Text":
        s = sep if isinstance(sep, Text) else Text(sep, sep)
        return Text(s.en.join(i.en for i in items), s.pt.join(i.pt for i in items))


def same(s: str) -> Text:
    """Texto idêntico nas duas línguas (nomes, IPs, números inteiros)."""
    return Text(s, s)


def num(value: float, digits: int = 1) -> Text:
    """Número com casas decimais: ponto em inglês, vírgula em português."""
    s = f"{value:.{digits}f}"
    return Text(s, s.replace(".", ","))


def ms(value: Optional[float]) -> Text:
    """Latência legível: uma casa decimal abaixo de 10 ms, inteiro acima."""
    if value is None:
        return same("–")
    return num(value, 1 if value < 10 else 0) + same(" ms")


def secs(value: float) -> Text:
    """Duração curta em segundos ("9s", "2.5s" / "2,5s")."""
    s = f"{value:g}s"
    return Text(s, s.replace(".", ","))


def detect_lang() -> Lang:
    """Escolhe o idioma padrão pelo ambiente: ``NETBLAME_LANG`` > idioma do sistema > inglês."""
    env = os.environ.get("NETBLAME_LANG", "").lower()
    if env in LANGS:
        return env  # type: ignore[return-value]
    try:
        name = (locale.getlocale()[0] or "").lower()
    except ValueError:
        name = ""
    # Windows devolve "Portuguese_Brazil"; Linux/macOS, "pt_BR".
    return "pt" if name.startswith(("pt", "portuguese")) else "en"
