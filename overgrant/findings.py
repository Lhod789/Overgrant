from dataclasses import dataclass
from enum import IntEnum

from .evidence import Claim


class Tier(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass(frozen=True)
class Finding:
    tier: Tier
    title: str
    detail: str
    rule: str
    scopes: list[str]
    claim: Claim
