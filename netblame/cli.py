"""Interface de linha de comando: ``netblame run | report | demo``."""

from __future__ import annotations

import argparse
import sys
import webbrowser
from datetime import datetime
from pathlib import Path
from typing import Optional, Sequence

from netblame import __version__, netinfo
from netblame.analysis import Analysis, analyze
from netblame.collector import PRESETS, CaptureConfig, build_targets, capture
from netblame.demo import DESCRIPTIONS, SCENARIOS, generate
from netblame.i18n import LANGS, Lang, Text, detect_lang
from netblame.models import Session, SysSample
from netblame.report import SEVERITY_LABEL, write_report


def _print_summary(analysis: Analysis, lang: Lang) -> None:
    v = analysis.verdict
    print()
    sev = lambda f: SEVERITY_LABEL[f.severity].get(lang).upper()  # noqa: E731
    print(f"{Text('VERDICT', 'VEREDITO').get(lang)} [{sev(v)}] {v.title.get(lang)}")
    print(f"  {v.detail.get(lang)}")
    print(f"  -> {v.advice.get(lang)}")
    for f in analysis.findings[1:]:
        if f.severity in ("critical", "warning"):
            print(f"  * [{sev(f)}] {f.title.get(lang)}")


def _save_outputs(session: Session, prefix: Path, open_browser: bool, lang: Lang) -> Path:
    json_path = session.save(prefix.with_suffix(".json"))
    html_path = write_report(session, prefix.with_suffix(".html"), lang=lang)
    print()
    print(f"{Text('Session', 'Sessão').get(lang)}: {json_path}")
    print(f"{Text('Report', 'Relatório').get(lang)}: {html_path}")
    if open_browser:
        webbrowser.open(html_path.resolve().as_uri())
    return html_path


def _default_prefix(kind: str) -> Path:
    return Path(f"netblame-{kind}-{datetime.now():%Y%m%d-%H%M%S}")


def cmd_run(args: argparse.Namespace) -> int:
    lang: Lang = args.lang
    say = lambda en, pt: print(Text(en, pt).get(lang))  # noqa: E731

    gateway = None if args.no_gateway else netinfo.detect_gateway()
    if gateway is None and not args.no_gateway:
        say("warning: could not detect the default gateway; local vs ISP faults cannot be separated.",
            "aviso: gateway padrão não detectado; não será possível separar falha local de falha do provedor.")
    dns_server = None
    if not args.no_dns:
        dns_server = args.dns_server or next(iter(netinfo.system_dns_servers()), None) or gateway
    try:
        targets = build_targets(gateway, dns_server, args.target, args.preset, udp=not args.no_udp)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    say(f"netblame {__version__} - probing:", f"netblame {__version__} - sondando:")
    for t in targets:
        print(f"  {t.label:<15} {t.role:<9} {t.describe()}")
    if not any(t.role == "app" for t in targets):
        say("  (tip: add the service you care about, e.g. --preset battlenet or --target game=tcp://host:port)",
            "  (dica: adicione o serviço que importa, ex.: --preset battlenet ou --target jogo=tcp://host:porta)")

    cfg = CaptureConfig(targets=targets, minutes=args.minutes, interval=args.interval,
                        process_name=args.process, trace=not args.no_trace, hop_every=args.hop_every)
    losses = {t.label: 0 for t in targets}
    lost_word = Text("LOST", "PERDA").get(lang)
    losses_word = Text("losses", "perdas").get(lang)

    def on_cycle(cycle: int, total: int, results: dict, sys_sample: Optional[SysSample]) -> None:
        for label, rtt in results.items():
            if rtt is None:
                losses[label] += 1
        parts = " ".join(f"{label}:{lost_word if rtt is None else f'{rtt:.0f}'}" for label, rtt in results.items())
        cpu = f" cpu:{sys_sample.cpu:.0f}%" if sys_sample else ""
        line = f"[{cycle + 1:>4}/{total}] {parts}{cpu} | {losses_word}:{sum(losses.values())}"
        print("\r" + line[:118].ljust(118), end="", flush=True)

    session = capture(cfg, on_cycle=on_cycle, status=lambda msg: print(msg.get(lang)))
    print()
    if not session.cycles:
        say("No cycles captured.", "Nenhum ciclo capturado.")
        return 1
    analysis = analyze(session)
    _print_summary(analysis, lang)
    _save_outputs(session, Path(args.out) if args.out else _default_prefix("session"), args.open, lang)
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    session = Session.load(args.session)
    out = Path(args.output) if args.output else Path(args.session).with_suffix(".html")
    write_report(session, out, lang=args.lang)
    _print_summary(analyze(session), args.lang)
    print()
    print(f"{Text('Report', 'Relatório').get(args.lang)}: {out}")
    if args.open:
        webbrowser.open(out.resolve().as_uri())
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    session = generate(args.scenario, seed=args.seed)
    intro = Text(f"Demo scenario '{args.scenario}': ", f"Cenário de demonstração '{args.scenario}': ")
    print((intro + DESCRIPTIONS[args.scenario]).get(args.lang))
    _print_summary(analyze(session), args.lang)
    _save_outputs(session, Path(args.out) if args.out else Path(f"netblame-demo-{args.scenario}"),
                  args.open, args.lang)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="netblame",
        description="Find out WHERE your connection drops: your PC, your router, your ISP or the route.",
    )
    p.add_argument("--version", action="version", version=f"netblame {__version__}")
    lang_help = ("terminal language and the report's initial language (default: system language). "
                 "The report always has an EN/PT switch.")
    p.add_argument("--lang", choices=LANGS, default=detect_lang(), help=lang_help)
    # Também aceito depois do subcomando; SUPPRESS evita que o padrão do
    # subparser sobrescreva um --lang dado antes dele.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--lang", choices=LANGS, default=argparse.SUPPRESS, help=lang_help)
    sub = p.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", parents=[common], help="capture and diagnose")
    run.add_argument("--minutes", type=float, default=10, help="capture length (default 10)")
    run.add_argument("--interval", type=float, default=1, help="seconds between cycles (default 1)")
    run.add_argument("--target", action="append", default=[], metavar="LABEL=HOST",
                     help="extra target: label=host (ICMP) or label=tcp://host:port. Repeatable.")
    run.add_argument("--preset", action="append", default=[], choices=sorted(PRESETS),
                     help="add a known service as the app target. Repeatable.")
    run.add_argument("--process", metavar="NAME.exe", help="also watch this process (CPU, running)")
    run.add_argument("--dns-server", metavar="IP", help="resolver to test (default: the system's)")
    run.add_argument("--no-dns", action="store_true", help="skip the DNS probe")
    run.add_argument("--no-gateway", action="store_true", help="do not probe the router")
    run.add_argument("--no-udp", action="store_true",
                     help="skip the UDP probes (DNS over UDP to the public resolvers)")
    run.add_argument("--no-trace", action="store_true", help="skip traceroute / per-hop stats")
    run.add_argument("--hop-every", type=int, default=2, metavar="N", help="ping route hops every N cycles")
    run.add_argument("--out", metavar="PREFIX", help="output file prefix (default netblame-session-<time>)")
    run.add_argument("--open", action="store_true", help="open the report in the browser when done")
    run.set_defaults(func=cmd_run)

    rep = sub.add_parser("report", parents=[common], help="(re)build the HTML report from a saved session")
    rep.add_argument("session", help="session .json file")
    rep.add_argument("-o", "--output", help="output .html (default: next to the session)")
    rep.add_argument("--open", action="store_true")
    rep.set_defaults(func=cmd_report)

    demo = sub.add_parser("demo", parents=[common], help="generate a synthetic session and report")
    demo.add_argument("--scenario", choices=SCENARIOS, default="isp")
    demo.add_argument("--seed", type=int, default=42)
    demo.add_argument("--out", metavar="PREFIX")
    demo.add_argument("--open", action="store_true")
    demo.set_defaults(func=cmd_demo)
    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    # O console do Windows (cp850/cp1252) não tem "≥" ou "→": troca por "?" em vez de quebrar.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")
    args = build_parser().parse_args(argv)
    return args.func(args)
