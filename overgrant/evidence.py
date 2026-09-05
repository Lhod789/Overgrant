from enum import Enum
from dataclasses import dataclass


class Evidence(Enum):
    DECLARED = "Declared"
    OBSERVED = "Observed"
    INFERRED = "Inferred"
    UNKNOWN = "Unknown"


@dataclass
class Claim:
    text: str
    evidence: Evidence
    source: str
    caveat: str | None = None

    def __post_init__(self):
        if self.evidence == Evidence.INFERRED and not self.caveat:
            raise ValueError("Inferred claims must have a caveat")
