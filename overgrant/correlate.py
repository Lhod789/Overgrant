from .evidence import Claim, Evidence
from .findings import Finding, Tier
from .scoring import score
from .egress import format_duration

OVER_GRANT = "over-grant"
UNDECLARED = "undeclared-capability"


def _window_caveat(window) -> str:
    if not window or not window.get("start"):
        return (
            "Absence of evidence over an unknown capture window. Nothing here "
            "shows the scope is unused, only that this capture did not see it."
        )

    return (
        f"Absence of evidence over {format_duration(window['duration_seconds'])} "
        f"of capture "
        f"identical to one never used, at this window length."
    )


def _matches(path, endpoint) -> bool:
    return path == endpoint or path.endswith("/" + endpoint)


def correlate(grant_sets, vendors, scopes, provider, window=None) -> list:
    observed = sorted(
        {
            path
            for row in vendors
            if row["vendor"].lower() == provider.lower()
            for path in row["paths"]
        }
    )

    findings = []
    claimed = set()

    for label, granted in sorted(grant_sets.items()):
        for scope_id in sorted(granted):
            scope = scopes.get(scope_id)
            if scope is None or not scope.endpoints:
                continue

            hits = [
                path
                for path in observed
                for endpoint in scope.endpoints
                if _matches(path, endpoint)
            ]
            claimed.update(hits)
            if hits:
                continue

            findings.append(
                Finding(
                    tier=score(scope).tier,
                    title=f"{scope.short} - granted to {label}, never observed",
                    detail=(
                        f"{scope_id} covers {', '.join(scope.endpoints)}. None of "
                        f"those appear in the capture. If this holds over a "
                        f"representative window, the scope can be dropped."
                    ),
                    rule=OVER_GRANT,
                    scopes=[scope_id],
                    claim=Claim(
                        text=f"{scope_id} was not exercised during the capture",
                        evidence=Evidence.INFERRED,
                        source="correlation of lockfile against egress map",
                        caveat=_window_caveat(window),
                    ),
                )
            )

    for path in observed:
        if path in claimed:
            continue
        findings.append(
            Finding(
                tier=Tier.MEDIUM,
                title=f"{path} observed, matching no granted scope",
                detail=(
                    f"{path} was called on a {provider} host, but no scope in the "
                    f"grant set lists it. Either the catalogue is missing an "
                    f"endpoint or the call is not covered by the grant."
                ),
                rule=UNDECLARED,
                scopes=[],
                claim=Claim(
                    text=f"{path} matches no granted scope's endpoints",
                    evidence=Evidence.INFERRED,
                    source="correlation of lockfile against egress map",
                    caveat=(
                        "The catalogue covers a subset of each provider's scopes. "
                        "An unmatched path may be an uncurated endpoint rather "
                        "than an undeclared capability."
                    ),
                ),
            )
        )

    findings.sort(key=lambda f: f.tier, reverse=True)
    return findings
