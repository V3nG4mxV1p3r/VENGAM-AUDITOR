"""
VENGAM — Endpoint Intelligence
APK içinden API endpoint'lerini, GraphQL sorgularını,
WebSocket bağlantılarını ve Protobuf şemalarını çıkartır.
"""
from __future__ import annotations
import re
from dataclasses import dataclass, field
from pathlib import Path
from vengam.utils.logger import log


# ── Veri modelleri ────────────────────────────────────────────────

@dataclass
class Endpoint:
    url:          str
    method:       str        = "GET"    # GET POST PUT DELETE WS GRAPHQL
    protocol:     str        = "https"  # https http ws wss
    category:     str        = "other"  # auth payment api game other
    risk:         str        = "LOW"
    file_found:   str        = ""
    line_number:  int        = 0
    evidence:     str        = ""
    params:       list[str]  = field(default_factory=list)

    @property
    def is_sensitive(self) -> bool:
        return self.risk in ("HIGH", "CRITICAL")


@dataclass
class GraphQLQuery:
    query_type:  str   # query mutation subscription
    name:        str
    fields:      list[str] = field(default_factory=list)
    file_found:  str       = ""
    line_number: int       = 0


@dataclass
class WebSocketEndpoint:
    url:         str
    protocol:    str  = "wss"
    file_found:  str  = ""
    line_number: int  = 0


@dataclass
class ProtobufHint:
    descriptor:  str
    fields:      list[str] = field(default_factory=list)
    file_found:  str       = ""


@dataclass
class EndpointIntelligence:
    endpoints:    list[Endpoint]
    graphql:      list[GraphQLQuery]
    websockets:   list[WebSocketEndpoint]
    protobuf:     list[ProtobufHint]
    total_unique: int = 0

    def sensitive_endpoints(self) -> list[Endpoint]:
        return [e for e in self.endpoints if e.is_sensitive]

    def by_category(self, cat: str) -> list[Endpoint]:
        return [e for e in self.endpoints if e.category == cat]


# ── Regex pattern'leri ────────────────────────────────────────────

# HTTP/HTTPS URL'ler
_URL_RE = re.compile(
    r'https?://[a-zA-Z0-9\-\.]+'
    r'(?::\d+)?'
    r'(?:/[a-zA-Z0-9_/\-\.%~@!$&\'()*+,;=:?#\[\]]*)?',
    re.IGNORECASE
)

# WebSocket URL'ler
_WS_RE = re.compile(
    r'wss?://[a-zA-Z0-9\-\.]+(?::\d+)?(?:/[a-zA-Z0-9_/\-\.]*)?',
    re.IGNORECASE
)

# GraphQL sorgu tespiti
_GRAPHQL_RE = re.compile(
    r'(query|mutation|subscription)\s+(\w+)?\s*\{([^}]{0,300})\}',
    re.IGNORECASE | re.DOTALL
)

# GraphQL endpoint tespiti
_GRAPHQL_ENDPOINT_RE = re.compile(
    r'(?i)(graphql|gql)["\'\s]*[=:]\s*["\']?(https?://[^\s"\']+)',
)

# Protobuf tespiti
_PROTO_RE = re.compile(
    r'(?i)(\.proto|protobuf|proto[_\s]?buf|'
    r'MessageLite|GeneratedMessageV3|parseFrom|toByteArray)',
)

# HTTP method tespiti (satır bağlamı)
_METHOD_RE = re.compile(
    r'(?i)(\.get\(|\.post\(|\.put\(|\.delete\(|\.patch\(|'
    r'"GET"|"POST"|"PUT"|"DELETE"|"PATCH")',
)

# Hassas path pattern'leri
_SENSITIVE_PATHS = {
    "CRITICAL": [
        r"/admin", r"/superuser", r"/internal", r"/debug",
        r"/backdoor", r"/secret", r"/private",
    ],
    "HIGH": [
        r"/auth", r"/login", r"/token", r"/oauth",
        r"/payment", r"/pay", r"/billing", r"/checkout",
        r"/api/key", r"/credentials",
    ],
    "MEDIUM": [
        r"/api/v\d", r"/graphql", r"/user", r"/player",
        r"/account", r"/profile", r"/leaderboard",
    ],
}

# Gürültü domain'leri
_NOISE_DOMAINS = frozenset({
    "schemas.android.com", "www.w3.org", "example.com",
    "localhost", "127.0.0.1", "google.com", "android.com",
    "goo.gl", "play.google.com", "schema.org", "xmlpull.org",
    "ns.adobe.com", "purl.org", "fonts.googleapis.com",
    "cdnjs.cloudflare.com", "cdn.jsdelivr.net",
})

# Gürültü uzantıları
_NOISE_EXTS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp",
    ".ico", ".mp3", ".ogg", ".wav", ".mp4", ".ttf",
    ".woff", ".woff2", ".otf", ".css",
})


def _is_noise_url(url: str) -> bool:
    url_lower = url.lower()
    if any(nd in url_lower for nd in _NOISE_DOMAINS):
        return True
    if any(url_lower.endswith(ext) for ext in _NOISE_EXTS):
        return True
    if len(url) < 12:
        return True
    return False


def _assess_risk(url: str) -> str:
    url_lower = url.lower()
    for risk, patterns in _SENSITIVE_PATHS.items():
        if any(re.search(p, url_lower) for p in patterns):
            return risk
    return "LOW"


def _categorize(url: str) -> str:
    u = url.lower()
    if any(k in u for k in ["auth", "login", "oauth", "token", "sso", "signin"]):
        return "auth"
    if any(k in u for k in ["pay", "billing", "checkout", "wallet", "stripe"]):
        return "payment"
    if any(k in u for k in ["user", "player", "account", "profile", "member"]):
        return "user_data"
    if any(k in u for k in ["graphql", "gql"]):
        return "graphql"
    if any(k in u for k in ["/api/", "/v1/", "/v2/", "/v3/", "rpc", "service"]):
        return "api"
    if any(k in u for k in ["game", "match", "leaderboard", "score", "rank"]):
        return "game"
    return "other"


def _extract_method(context_line: str) -> str:
    m = _METHOD_RE.search(context_line)
    if not m:
        return "GET"
    v = m.group(0).upper().strip('."()')
    for method in ["POST", "PUT", "DELETE", "PATCH"]:
        if method in v:
            return method
    return "GET"


# ── Ana analizör ──────────────────────────────────────────────────

class EndpointAnalyzer:
    """APK dosyalarından endpoint intelligence çıkartır."""

    SCANNABLE_EXTENSIONS = frozenset({
        ".smali", ".java", ".kt", ".xml", ".json",
        ".properties", ".gradle", ".yml", ".yaml",
        ".txt", ".js", ".ts", ".html",
    })

    def analyze_directory(self, decompiled_dir: str) -> EndpointIntelligence:
        base = Path(decompiled_dir)
        all_endpoints:   dict[str, Endpoint]          = {}
        all_graphql:     list[GraphQLQuery]            = []
        all_websockets:  list[WebSocketEndpoint]       = []
        all_protobuf:    list[ProtobufHint]            = []
        files_scanned    = 0

        for filepath in base.rglob("*"):
            if not filepath.is_file():
                continue
            if filepath.suffix.lower() not in self.SCANNABLE_EXTENSIONS:
                continue
            files_scanned += 1

            try:
                lines = filepath.read_text(
                    encoding="utf-8", errors="ignore"
                ).splitlines()
            except OSError:
                continue

            relative = str(filepath.relative_to(base))

            for line_no, line in enumerate(lines, 1):
                # HTTP/HTTPS endpoints
                for m in _URL_RE.finditer(line):
                    url = m.group(0).rstrip('"\',;)')
                    if _is_noise_url(url):
                        continue
                    if url not in all_endpoints:
                        all_endpoints[url] = Endpoint(
                            url=url,
                            method=_extract_method(line),
                            protocol="https" if url.startswith("https") else "http",
                            category=_categorize(url),
                            risk=_assess_risk(url),
                            file_found=relative,
                            line_number=line_no,
                            evidence=line.strip()[:80],
                        )

                # WebSocket endpoints
                for m in _WS_RE.finditer(line):
                    url = m.group(0).rstrip('"\',;)')
                    all_websockets.append(WebSocketEndpoint(
                        url=url,
                        protocol="wss" if url.startswith("wss") else "ws",
                        file_found=relative,
                        line_number=line_no,
                    ))

                # GraphQL queries
                for m in _GRAPHQL_RE.finditer(line):
                    qtype = m.group(1).lower()
                    qname = m.group(2) or "anonymous"
                    body  = m.group(3)
                    fields= re.findall(r'\b([a-zA-Z_]\w+)\b', body)[:10]
                    all_graphql.append(GraphQLQuery(
                        query_type=qtype, name=qname, fields=fields,
                        file_found=relative, line_number=line_no,
                    ))

                # GraphQL endpoint URL
                for m in _GRAPHQL_ENDPOINT_RE.finditer(line):
                    url = m.group(2)
                    if url not in all_endpoints:
                        all_endpoints[url] = Endpoint(
                            url=url, method="POST",
                            category="graphql", risk="HIGH",
                            file_found=relative, line_number=line_no,
                            evidence=line.strip()[:80],
                        )

                # Protobuf hints
                if _PROTO_RE.search(line):
                    all_protobuf.append(ProtobufHint(
                        descriptor=line.strip()[:80],
                        file_found=relative,
                    ))

        endpoints_list = list(all_endpoints.values())
        log.info(
            f"Endpoint analizi: {files_scanned} dosya → "
            f"{len(endpoints_list)} endpoint | "
            f"{len(all_graphql)} GraphQL | "
            f"{len(all_websockets)} WebSocket | "
            f"{len(all_protobuf)} Protobuf hint"
        )

        return EndpointIntelligence(
            endpoints=sorted(
                endpoints_list,
                key=lambda e: {"CRITICAL":3,"HIGH":2,"MEDIUM":1,"LOW":0}.get(e.risk,0),
                reverse=True,
            ),
            graphql=all_graphql[:50],
            websockets=all_websockets[:50],
            protobuf=all_protobuf[:20],
            total_unique=len(endpoints_list),
        )

    def generate_report(self, intel: EndpointIntelligence) -> dict:
        """Endpoint intelligence'ı rapor formatına çevir."""
        return {
            "summary": {
                "total_endpoints":  intel.total_unique,
                "sensitive":        len(intel.sensitive_endpoints()),
                "graphql_queries":  len(intel.graphql),
                "websockets":       len(intel.websockets),
                "protobuf_hints":   len(intel.protobuf),
            },
            "by_category": {
                cat: len(intel.by_category(cat))
                for cat in ["auth","payment","api","game","graphql","user_data","other"]
            },
            "critical": [
                {"url": e.url, "method": e.method,
                 "file": e.file_found, "evidence": e.evidence}
                for e in intel.endpoints if e.risk == "CRITICAL"
            ],
            "high": [
                {"url": e.url, "method": e.method, "category": e.category}
                for e in intel.endpoints if e.risk == "HIGH"
            ][:20],
            "graphql": [
                {"type": q.query_type, "name": q.name, "fields": q.fields}
                for q in intel.graphql[:10]
            ],
            "websockets": [
                {"url": w.url, "protocol": w.protocol}
                for w in intel.websockets
            ],
        }
