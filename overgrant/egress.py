import re
import json
from dataclasses import dataclass, field
from urllib.parse import urlsplit
import tomllib
from pathlib import Path
from enum import Enum
from datetime import datetime


@dataclass(frozen=True)
class Request:
    method: str
    url: str
    host: str
    path: str
    status: int
    request_headers: dict = field(default_factory=dict)
    response_headers: dict = field(default_factory=dict)
    request_body_size: int = 0
    response_body_size: int = 0
    tls_version: str = ""
    detections: tuple = ()
    started: str = ""


def _headers(entries) -> dict:
    return {h.get("name", "").lower(): h.get("value", "") for h in entries or []}


def load_har(path) -> list:
    with open(path, "r", encoding="utf-8") as f:
        document = json.load(f)

    entries = document.get("log", {}).get("entries")
    if entries is None:
        raise ValueError(f"{path} is not a HAR file (no log.entries)")

    requests = []
    for entry in entries:
        request = entry.get("request", {})
        response = entry.get("response", {})
        url = request.get("url", "")
        split = urlsplit(url)

        requests.append(
            Request(
                method=request.get("method", ""),
                url=url,
                host=split.hostname or "",
                path=split.path or "",
                status=response.get("status", 0),
                request_headers=_headers(request.get("headers")),
                response_headers=_headers(response.get("headers")),
                request_body_size=request.get("bodySize", 0),
                response_body_size=response.get("bodySize", 0),
                tls_version=entry.get("_securityDetails", {}).get("protocol", ""),
                started=entry.get("startedDateTime", ""),
                detections=tuple(
                    detect(
                        {
                            **_headers(request.get("headers")),
                            **_headers(response.get("headers")),
                        },
                        (request.get("postData") or {}).get("text", "")
                        + (response.get("content") or {}).get("text", ""),
                    )
                ),
            )
        )

    return requests


REDACTED = "[redacted]"
SENSITIVE_HEADERS = {"authorization", "proxy-authorization", "cookie", "set-cookie"}
SENSITIVE_HINTS = ("token", "key", "secret")


def _is_sensitive(name) -> bool:
    name = name.lower()
    return name in SENSITIVE_HEADERS or any(hint in name for hint in SENSITIVE_HINTS)


def _scrub_pairs(pairs) -> list:
    return [
        {
            **pair,
            "value": (
                REDACTED
                if _is_sensitive(pair.get("name", ""))
                else pair.get("value", "")
            ),
        }
        for pair in pairs or []
    ]


def scrub_har(data) -> dict:
    document = json.loads(json.dumps(data))

    for entry in document.get("log", {}).get("entries", []):
        request = entry.get("request", {})
        response = entry.get("response", {})

        request["headers"] = _scrub_pairs(request.get("headers"))
        response["headers"] = _scrub_pairs(response.get("headers"))

        for holder in (request, response):
            if "cookies" in holder:
                holder["cookies"] = [
                    {**cookie, "value": REDACTED} for cookie in holder["cookies"] or []
                ]

        if request.get("postData"):
            request["postData"]["text"] = REDACTED
            request["postData"].pop("params", None)
        if response.get("content"):
            response["content"]["text"] = REDACTED

    return document


PLACEHOLDER = ":id"

ID_SHAPES = (
    re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I),
    re.compile(r"^[0-9a-f]{16,}$", re.I),
    re.compile(r"^\d+$"),
)


def normalise_path(path) -> str:
    segments = [
        PLACEHOLDER if any(shape.match(segment) for shape in ID_SHAPES) else segment
        for segment in path.split("/")
    ]
    return "/".join(segments)


REFERENCE_DIR = Path(__file__).parent / "reference"

UNKNOWN_VENDOR = "UNKNOWN"

_VENDORS = None


def _vendors() -> dict:
    global _VENDORS
    if _VENDORS is None:
        with open(REFERENCE_DIR / "vendors.toml", "rb") as f:
            document = tomllib.load(f)
        _VENDORS = {
            domain.lower(): vendor["name"]
            for vendor in document.get("vendors", [])
            for domain in vendor.get("domains", [])
        }
    return _VENDORS


def resolve_vendor(host) -> str:
    host = (host or "").lower().rstrip(".")
    for domain, name in _vendors().items():
        if host == domain or host.endswith("." + domain):
            return name
    return UNKNOWN_VENDOR


class Confidence(Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


DETECTORS = (
    ("email_address", Confidence.HIGH, re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")),
    ("credential", Confidence.HIGH, re.compile(r"\b[Bb]earer\s+[\w\-._~+/]{8,}")),
    ("jwt", Confidence.HIGH, re.compile(r"\beyJ[\w-]{6,}\.[\w-]{6,}\.[\w-]{6,}")),
    ("phone_number", Confidence.LOW, re.compile(r"(?<![\w.])\+\d[\d\s().-]{7,}\d")),
)


@dataclass(frozen=True, slots=True)
class Detection:
    kind: str
    confidence: Confidence
    count: int

    def __post_init__(self):
        if self.count < 1:
            raise ValueError("a Detection records at least one match")


def detect(headers, body="") -> list:
    haystack = "\n".join(list((headers or {}).values()) + [body or ""])

    detections = []
    for kind, confidence, pattern in DETECTORS:
        count = len(pattern.findall(haystack))
        if count:
            detections.append(Detection(kind, confidence, count))
    return detections


def build_map(requests) -> list:
    hosts = {}
    for request in requests:
        vendor = resolve_vendor(request.host)
        row = hosts.setdefault(
            vendor,
            {
                "vendor": vendor,
                "hosts": set(),
                "paths": set(),
                "requests": 0,
                "detections": {},
            },
        )
        row["hosts"].add(request.host)
        row["paths"].add(normalise_path(request.path))
        row["requests"] += 1
        for detection in request.detections:
            # kind -> count only. There is no field here that could hold a
            # sample, so the map cannot carry the value it detected.
            row["detections"][detection.kind] = (
                row["detections"].get(detection.kind, 0) + detection.count
            )

    rows = [
        {
            "vendor": row["vendor"],
            "hosts": sorted(row["hosts"]),
            "paths": sorted(row["paths"]),
            "requests": row["requests"],
            "detections": dict(sorted(row["detections"].items())),
        }
        for row in hosts.values()
    ]
    return sorted(rows, key=lambda r: (r["vendor"] == UNKNOWN_VENDOR, r["vendor"]))


def capture_window(requests) -> dict:
    stamps = []
    for request in requests:
        try:
            stamps.append(datetime.fromisoformat(request.started))
        except ValueError:
            continue

    if not stamps:
        return {"start": None, "end": None, "duration_seconds": None}

    start, end = min(stamps), max(stamps)
    return {
        "start": start.isoformat(),
        "end": end.isoformat(),
        "duration_seconds": (end - start).total_seconds(),
    }
