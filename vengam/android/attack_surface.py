"""
VENGAM Auditor — Attack Surface Mapping
"""
from __future__ import annotations

NOISE_DOMAINS: frozenset[str] = frozenset({
    "w3.org", "schemas.android.com", "example.com", "localhost",
    "127.0.0.1", "google.com", "android.com", "goo.gl",
    "play.google.com", "schema.org", "xmlpull.org",
    "ns.adobe.com", "purl.org",
})

NOISE_EXTENSIONS: frozenset[str] = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp",
    ".ico", ".js", ".css", ".woff", ".ttf", ".otf",
    ".mp3", ".ogg", ".wav", ".mp4", ".avi", ".zip", ".so",
})


def categorise_url(path: str, netloc: str) -> str:
    """
    Map a URL path / netloc to one of five attack-surface categories:
    auth | payment | user_data | internal_api | other
    """
    route = (path if len(path) > 1 else netloc).lower()

    if any(k in route for k in [
        "login", "auth", "oauth", "token", "register",
        "sso", "identity", "signin",
    ]):
        return "auth"

    if any(k in route for k in [
        "pay", "checkout", "billing", "wallet",
        "stripe", "klarna", "invoice",
    ]):
        return "payment"

    if any(k in route for k in [
        "user", "profile", "account", "member",
        "customer", "player",
    ]):
        return "user_data"

    if any(k in route for k in [
        "api", "graphql", "v1", "v2", "v3",
        "service", "backend", "rpc",
    ]):
        return "internal_api"

    return "other"
