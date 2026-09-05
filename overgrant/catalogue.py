import tomllib

from dataclasses import dataclass, field
from .risk import DATA_CLASSES, Breadth, Mutability, Sensitivity


@dataclass(frozen=True)
class Scope:
    id: str
    short: str
    grants: str
    breadth: Breadth
    mutability: Mutability
    sensitivity: Sensitivity
    data_classes: list[str] = field(default_factory=list)
    endpoints: list[str] = field(default_factory=list)
    supersedes: list[str] = field(default_factory=list)
    admin_consent: bool = False
    source: str = ""
    notes: str = ""


def load_scopes(path) -> dict[str, Scope]:
    with open(path, "rb") as f:
        data = tomllib.load(f)

    scopes = {}
    for entry in data["scopes"]:
        scope = Scope(
            id=entry["id"],
            short=entry["short"],
            grants=entry["grants"],
            breadth=Breadth[entry["breadth"].upper()],
            mutability=Mutability[entry["mutability"].upper()],
            sensitivity=Sensitivity[entry["sensitivity"].upper()],
            data_classes=entry.get("data_classes", []),
            endpoints=entry.get("endpoints", []),
            supersedes=entry.get("supersedes", []),
            admin_consent=entry.get("admin_consent", False),
            source=entry.get("source", ""),
            notes=entry.get("notes", ""),
        )

        if scope.id in scopes:
            raise ValueError(f"{scope.id}: duplicate scope id")

        if not scope.source.startswith("https://"):
            raise ValueError(
                f"{scope.id}: source must be an https:// URL (got {scope.source!r})"
            )

        for data_class in scope.data_classes:
            if data_class not in DATA_CLASSES:
                raise ValueError(
                    f"{scope.id}: unknown data class {data_class!r} "
                    f"(allowed: {', '.join(sorted(DATA_CLASSES))})"
                )

        if scope.sensitivity is Sensitivity.CONTENT and not scope.data_classes:
            raise ValueError(
                f"{scope.id}: sensitivity is content but data_classes is empty"
            )

        scopes[scope.id] = scope

    for scope in scopes.values():
        for superseded in scope.supersedes:
            if superseded == scope.id:
                raise ValueError(f"{scope.id}: scope supersedes itself")
            if superseded not in scopes:
                raise ValueError(f"{scope.id}: supersedes unknown scope {superseded!r}")

    return scopes
