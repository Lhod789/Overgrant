import argparse
import sys
from pathlib import Path
import json

from .assessment import assess
from .inputs import (
    detect_provider,
    parse_consent_url,
    parse_scope_list,
    parse_slack_manifest,
)
from .report import (
    render_correlate_json,
    render_egress_json,
    render_json,
    render_text,
)
from .findings import Tier

from .catalogue import available_providers, load_provider
from .drift import Drift, classify
from .scoring import score
from .correlate import correlate
from .egress import build_map, capture_window, format_duration, load_har, scrub_har


def _read(source) -> dict:
    if source.startswith("http"):
        return parse_consent_url(source)
    if source == "-":
        return parse_scope_list(sys.stdin.read())
    text = Path(source).read_text(encoding="utf-8")
    if source.endswith(".json"):
        return parse_slack_manifest(text)
    return parse_scope_list(text)


def _lint(args) -> int:
    parsed = _read(args.input)
    if not parsed:
        raise ValueError(f"no scopes found in {args.input!r}")

    every_scope = {scope for granted in parsed.values() for scope in granted}
    provider = args.provider or detect_provider(every_scope)
    scopes, combinations = load_provider(provider)

    assessments = [
        assess(set(granted), scopes, combinations, provider, label=label)
        for label, granted in parsed.items()
    ]
    if args.format == "json":
        print(render_json(assessments, source=args.input))
    else:
        print(render_text(assessments))

    if args.fail_on is None:
        return 0

    threshold = Tier[args.fail_on.upper()]
    breached = any(
        finding.tier >= threshold
        for assessment in assessments
        for finding in assessment.findings
    )
    return 1 if breached else 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="overgrant")
    commands = parser.add_subparsers(dest="command", required=True)

    scopes = commands.add_parser("scopes", help="assess declared OAuth scopes")
    scopes_commands = scopes.add_subparsers(dest="subcommand", required=True)

    lint = scopes_commands.add_parser("lint", help="assess a grant set")
    lint.add_argument(
        "input",
        help="consent URL, .json manifest, scope list file, or - for stdin",
    )
    lint.add_argument(
        "--provider",
        help="override shape detection (e.g. slack, google)",
    )
    lint.add_argument(
        "--fail-on",
        choices=["medium", "high", "critical"],
        help="exit 1 if any finding reaches this tier (default: report only)",
    )
    lint.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="text for humans, json for machines (default: text)",
    )
    lint.set_defaults(handler=_lint)

    explain = scopes_commands.add_parser("explain", help="describe a single scope")
    explain.add_argument("scope", help="scope id, e.g. channels:join")
    explain.add_argument("--provider", help="override shape detection")
    explain.set_defaults(handler=_explain)

    browse = scopes_commands.add_parser("list", help="browse a provider catalogue")
    browse.add_argument("provider", nargs="?", help="omit to list every catalogue")
    browse.set_defaults(handler=_list)

    snapshot = scopes_commands.add_parser(
        "snapshot", help="record the current grant sets to a lockfile"
    )
    snapshot.add_argument("input", help="same inputs as lint")
    snapshot.add_argument("-o", "--output", required=True, help="lockfile path")
    snapshot.add_argument("--provider", help="override shape detection")
    snapshot.set_defaults(handler=_snapshot)

    diff = scopes_commands.add_parser(
        "diff", help="compare the current grant sets against a lockfile"
    )
    diff.add_argument("input", help="same inputs as lint")
    diff.add_argument("--against", required=True, help="lockfile to compare against")
    diff.set_defaults(handler=_diff)

    egress = commands.add_parser("egress", help="work with captured traffic")
    egress_commands = egress.add_subparsers(dest="subcommand", required=True)

    scrub = egress_commands.add_parser(
        "scrub", help="strip credentials and bodies from a HAR"
    )
    scrub.add_argument("input", help="HAR file to scrub")
    scrub.add_argument("-o", "--output", required=True, help="scrubbed HAR path")
    scrub.set_defaults(handler=_scrub)

    egress_map = egress_commands.add_parser(
        "map", help="group captured traffic by vendor"
    )
    egress_map.add_argument("input", help="HAR file to map")
    egress_map.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="text for humans, json for machines (default: text)",
    )
    egress_map.set_defaults(handler=_map)

    correlate_command = commands.add_parser(
        "correlate", help="join a lockfile against an egress map"
    )
    correlate_command.add_argument(
        "--scopes", required=True, help="lockfile from scopes snapshot"
    )
    correlate_command.add_argument(
        "--egress", required=True, help="JSON from egress map --format json"
    )
    correlate_command.add_argument(
        "--format", choices=["text", "json"], default="text", help="default: text"
    )
    correlate_command.set_defaults(handler=_correlate)

    args = parser.parse_args(argv)

    try:
        return args.handler(args)
    except (ValueError, OSError) as error:
        print(f"overgrant: {error}", file=sys.stderr)
        return 2


def _explain(args) -> int:
    provider = args.provider or detect_provider({args.scope})
    scopes, _ = load_provider(provider)

    scope = scopes.get(args.scope)
    if scope is None:
        raise ValueError(
            f"{args.scope!r} is not in the {provider} catalogue "
            f"({len(scopes)} scopes known)"
        )

    finding = score(scope)

    print(f"{scope.id}")
    print(f"  {scope.short}")
    print()
    print(f"  Grants        {scope.grants}")
    print(f"  Breadth       {scope.breadth.name.lower()}")
    print(f"  Mutability    {scope.mutability.name.lower()}")
    print(f"  Sensitivity   {scope.sensitivity.name.lower()}")
    print(f"  Data classes  {', '.join(scope.data_classes) or '-'}")
    print(f"  Endpoints     {', '.join(scope.endpoints) or '-'}")
    print(f"  Supersedes    {', '.join(scope.supersedes) or '-'}")
    print(f"  Admin consent {'yes' if scope.admin_consent else 'no'}")
    print(f"  Source        {scope.source or '-'}")
    if scope.notes:
        print(f"  Notes         {scope.notes}")
    print()
    print(f"  Assessed as   {finding.tier.name}  {finding.rule}")
    print(f"                {finding.title}")
    return 0


def _list(args) -> int:
    providers = [args.provider] if args.provider else available_providers()
    for provider in providers:
        scopes, _ = load_provider(provider)
        print(provider)
        for scope in scopes.values():
            print(f"  {score(scope).tier.name:<8}  {scope.id:<40}  {scope.short}")
    return 0


def _snapshot(args) -> int:
    parsed = _read(args.input)
    if not parsed:
        raise ValueError(f"no scopes found in {args.input!r}")

    every_scope = {scope for granted in parsed.values() for scope in granted}
    provider = args.provider or detect_provider(every_scope)

    document = {
        "provider": provider,
        "grant_sets": {
            label: sorted(granted) for label, granted in sorted(parsed.items())
        },
    }

    Path(args.output).write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return 0


BLOCKING = {Drift.BROADENED, Drift.ADDED_ESCALATION}

MARKERS = {
    Drift.BROADENED: "FAIL",
    Drift.ADDED_ESCALATION: "FAIL",
    Drift.ADDED_LATERAL: "WARN",
    Drift.NARROWED: "ok",
    Drift.REMOVED: "ok",
}


def _load_lockfile(path) -> dict:
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    if "provider" not in document or "grant_sets" not in document:
        raise ValueError(f"{path} is not an overgrant lockfile")
    return document


def _diff(args) -> int:
    lockfile = _load_lockfile(args.against)
    current = _read(args.input)
    if not current:
        raise ValueError(f"no scopes found in {args.input!r}")

    provider = lockfile["provider"]
    scopes, _ = load_provider(provider)
    recorded = lockfile["grant_sets"]

    blocking = False
    changed = False

    for label in sorted(set(recorded) | set(current)):
        before = set(recorded.get(label, []))
        after = set(current.get(label, []))

        if label not in recorded:
            print(f"{label}: new grant set")
        elif label not in current:
            print(f"{label}: grant set no longer present")

        changes = classify(before, after, scopes)
        if not changes:
            continue

        changed = True
        print(f"{label}:")
        for change in changes:
            was = f"  (was {change.previous})" if change.previous else ""
            print(
                f"  {MARKERS[change.kind]:<4}  {change.kind.value:<18}  "
                f"{change.scope}{was}"
            )
            if change.kind in BLOCKING:
                blocking = True

    if not changed:
        print(f"No changes against {args.against}")

    return 1 if blocking else 0


def _scrub(args) -> int:
    data = json.loads(Path(args.input).read_text(encoding="utf-8"))
    scrubbed = scrub_har(data)
    Path(args.output).write_text(
        json.dumps(scrubbed, indent=2) + "\n", encoding="utf-8"
    )
    return


def _map(args) -> int:
    requests = load_har(args.input)
    rows = build_map(requests)
    window = capture_window(requests)
    if not rows:
        raise ValueError(f"no requests found in {args.input!r}")
    if args.format == "json":
        print(render_egress_json(rows, source=args.input, window=window))
        return 0
    if window["start"]:
        print(
            f"Capture window: {window['start']} to {window['end']} "
            f"({window['duration_seconds']:.0f}s)"
        )
        print()
    for row in rows:
        detections = (
            ", ".join(f"{kind} x{count}" for kind, count in row["detections"].items())
            or "-"
        )
        plural = "" if row["requests"] == 1 else "s"
        print(f"{row['vendor']}  ({row['requests']} request{plural})")
        print(f"  hosts       {', '.join(row['hosts'])}")
        for path in row["paths"]:
            print(f"  path        {path}")
        print(f"  detected    {detections}")
        print()
    return 0


def _correlate(args) -> int:
    lockfile = _load_lockfile(args.scopes)
    egress = json.loads(Path(args.egress).read_text(encoding="utf-8"))
    if "vendors" not in egress:
        raise ValueError(f"{args.egress} is not an overgrant egress map")

    provider = lockfile["provider"]
    scopes, _ = load_provider(provider)
    window = egress.get("window")

    findings = correlate(
        lockfile["grant_sets"], egress["vendors"], scopes, provider, window
    )

    sources = {"scopes": args.scopes, "egress": args.egress}
    if args.format == "json":
        print(render_correlate_json(findings, provider, sources, window))
        return 0

    duration = format_duration((window or {}).get("duration_seconds"))
    print(f"Correlating {provider} scopes against {duration} of capture")
    print()

    if not findings:
        print("Every granted scope was exercised, and every observed path is covered.")
        return 0

    for index, finding in enumerate(findings, start=1):
        print(f"[{index}] {finding.tier.name}  {finding.rule}")
        print(f"    {finding.title}")
        print(f"    Evidence: {finding.claim.evidence.name}")
        print(f"    Caveat: {finding.claim.caveat}")
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
