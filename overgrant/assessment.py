from dataclasses import dataclass

from .findings import Finding
from .scoring import find_redundant, match_combinations, score


@dataclass(frozen=True)
class Assessment:
    provider: str
    granted: list[str]
    findings: list[Finding]
    unrecognised: list[str]


def assess(granted, scopes, combinations, provider="") -> Assessment:
    known = sorted(s for s in granted if s in scopes)

    unrecognised = sorted(s for s in granted if s not in scopes)

    findings = [score(scopes[scope_id]) for scope_id in known]
    findings += match_combinations(set(known), scopes, combinations)
    findings += find_redundant(set(known), scopes)

    findings.sort(key=lambda f: f.tier, reverse=True)

    return Assessment(
        provider=provider,
        granted=sorted(granted),
        findings=findings,
        unrecognised=unrecognised,
    )