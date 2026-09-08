from dataclasses import dataclass
from enum import Enum

from .findings import Tier
from .scoring import score


class Drift(Enum):
    BROADENED = "broadened"
    NARROWED = "narrowed"
    ADDED_ESCALATION = "added_escalation"
    ADDED_LATERAL = "added_lateral"
    REMOVED = "removed"


@dataclass(frozen=True)
class Change:
    kind: Drift
    scope: str
    previous: str | None = None


def _supersedes(scopes, wider, narrower) -> bool:
    scope = scopes.get(wider)
    return scope is not None and narrower in scope.supersedes


def classify(before, after, scopes) -> list:
    removed = sorted(set(before) - set(after))
    added = sorted(set(after) - set(before))

    changes = []
    for new in list(added):
        for old in list(removed):
            if _supersedes(scopes, new, old):
                changes.append(Change(Drift.BROADENED, new, old))
            elif _supersedes(scopes, old, new):
                changes.append(Change(Drift.NARROWED, new, old))
            else:
                continue
            added.remove(new)
            removed.remove(old)
            break

    for new in added:
        scope = scopes.get(new)
        escalation = scope is None or score(scope).tier >= Tier.HIGH
        changes.append(
            Change(Drift.ADDED_ESCALATION if escalation else Drift.ADDED_LATERAL, new)
        )

    for old in removed:
        changes.append(Change(Drift.REMOVED, old))

    return changes
