import json
from urllib.parse import parse_qs, urlsplit

SLACK_GRANT_SETS = ("bot", "user")


def parse_slack_manifest(text) -> dict:
    manifest = json.loads(text)

    scopes = manifest.get("oauth_config", {}).get("scopes", {})
    if not isinstance(scopes, dict):
        raise ValueError("oauth_config.scopes is not an object")

    parsed = {}
    for grant_set in SLACK_GRANT_SETS:
        granted = scopes.get(grant_set) or []
        if not isinstance(granted, list):
            raise ValueError(f"oauth_config.scopes.{grant_set} is not a list")
        if granted:
            parsed[grant_set] = list(granted)

    return parsed


SCOPE_DELIMITERS = ",\t\n "
DEFAULT_LABEL = "granted"


def _split_scopes(raw) -> list:
    scopes = [raw]
    for delimiter in SCOPE_DELIMITERS:
        scopes = [part for chunk in scopes for part in chunk.split(delimiter)]
    return [scope for scope in scopes if scope]


def parse_consent_url(url) -> dict:
    params = parse_qs(urlsplit(url).query)

    bot = _split_scopes(" ".join(params.get("scope", [])))
    user = _split_scopes(" ".join(params.get("user_scope", [])))

    parsed = {}
    if bot:
        parsed["bot" if user else DEFAULT_LABEL] = bot
    if user:
        parsed["user"] = user

    return parsed


def parse_scope_list(text) -> dict:
    scopes = _split_scopes(text)
    return {DEFAULT_LABEL: scopes} if scopes else {}
