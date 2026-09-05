from collections.abc import Callable
from dataclasses import dataclass

from .catalogue import Scope
from .evidence import Claim, Evidence
from .findings import Finding, Tier

from .risk import (
    IDENTIFIES_PEOPLE,
    PRIVATE_CORRESPONDENCE,
    Breadth,
    Mutability,
    Sensitivity,
)


@dataclass(frozen=True)
class Rule:
    id: str
    tier: Tier
    title: str
    applies: Callable[[Scope], bool]


RULES = [
    Rule(
        id="R1-credentials",
        tier=Tier.CRITICAL,
        title="Grants access to credentials or secrets",
        applies=lambda s: s.sensitivity is Sensitivity.CREDENTIALS,
    ),
    Rule(
        id="R2-org-admin",
        tier=Tier.CRITICAL,
        title="Administrative reach across the whole organisation",
        applies=lambda s: s.breadth is Breadth.ORG_ADMIN,
    ),
    Rule(
        id="R3-admin-at-scale",
        tier=Tier.HIGH,
        title="Administrative control across the entire workspace",
        applies=lambda s: s.mutability is Mutability.ADMIN
        and s.breadth >= Breadth.WORKSPACE,
    ),
    Rule(
        id="R4-tenant-wide-content",
        tier=Tier.HIGH,
        title="Reads content across the entire workspace",
        applies=lambda s: s.sensitivity is Sensitivity.CONTENT
        and s.breadth >= Breadth.WORKSPACE,
    ),
    Rule(
        id="R5-destructive",
        tier=Tier.HIGH,
        title="Can delete or destroy data",
        applies=lambda s: s.mutability >= Mutability.DELETE,
    ),
    Rule(
        id="R6-private-correspondence",
        tier=Tier.HIGH,
        title="Reads private correspondence",
        applies=lambda s: bool(set(s.data_classes) & PRIVATE_CORRESPONDENCE),
    ),
    Rule(
        id="R7-content",
        tier=Tier.MEDIUM,
        title="Reads message or file content",
        applies=lambda s: s.sensitivity is Sensitivity.CONTENT,
    ),
    Rule(
        id="R8-tenant-wide-write",
        tier=Tier.MEDIUM,
        title="Writes across the entire workspace",
        applies=lambda s: s.mutability >= Mutability.WRITE
        and s.breadth >= Breadth.WORKSPACE,
    ),
    Rule(
        id="R9-directory-enumeration",
        tier=Tier.MEDIUM,
        title="Can enumerate people across the organisation",
        applies=lambda s: bool(set(s.data_classes) & IDENTIFIES_PEOPLE)
        and s.breadth >= Breadth.WORKSPACE,
    ),
    Rule(
        id="R10-default",
        tier=Tier.LOW,
        title="Scope granted with no elevated risk pattern",
        applies=lambda s: True,
    ),
]


def score(scope: Scope) -> Finding:
    for rule in RULES:
        if rule.applies(scope):
            return Finding(
                tier=rule.tier,
                title=rule.title,
                detail=scope.grants,
                rule=rule.id,
                scopes=[scope.id],
                claim=Claim(
                    text=f"{scope.id} grants: {scope.grants}",
                    evidence=Evidence.DECLARED,
                    source=scope.source,
                ),
            )
    raise ValueError(f"{scope.id}: no rule matched - RULES must end in a catch-all")
