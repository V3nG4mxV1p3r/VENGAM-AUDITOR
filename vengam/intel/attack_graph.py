"""
VENGAM — Attack Graph
Backend servis ilişkilerini, saldırı zincirlerini ve
exploit yollarını görselleştirilebilir bir grafik olarak üretir.
"""
from __future__ import annotations
import json
from dataclasses import dataclass, field
from vengam.core.models import Finding, AttackSurface
from vengam.intel.endpoint import EndpointIntelligence


@dataclass
class GraphNode:
    id:       str
    label:    str
    type:     str   # apk | endpoint | service | finding | attacker
    risk:     str   = "LOW"
    metadata: dict  = field(default_factory=dict)


@dataclass
class GraphEdge:
    source:   str
    target:   str
    label:    str
    type:     str   # calls | exposes | exploits | leads_to
    risk:     str   = "LOW"


@dataclass
class AttackGraph:
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    attack_chains: list[dict]

    def to_json(self) -> str:
        return json.dumps({
            "nodes": [
                {"id": n.id, "label": n.label, "type": n.type,
                 "risk": n.risk, "metadata": n.metadata}
                for n in self.nodes
            ],
            "edges": [
                {"source": e.source, "target": e.target,
                 "label": e.label, "type": e.type, "risk": e.risk}
                for e in self.edges
            ],
            "attack_chains": self.attack_chains,
        }, ensure_ascii=False, indent=2)

    def to_d3(self) -> dict:
        """D3.js force-directed graph formatı."""
        return {
            "nodes": [
                {
                    "id":    n.id,
                    "label": n.label,
                    "type":  n.type,
                    "risk":  n.risk,
                    "color": {
                        "CRITICAL": "#e53935",
                        "HIGH":     "#ff8c00",
                        "MEDIUM":   "#ffc107",
                        "LOW":      "#4caf50",
                    }.get(n.risk, "#607d8b"),
                    "size": {
                        "apk":      40,
                        "attacker": 35,
                        "finding":  20,
                        "endpoint": 15,
                        "service":  25,
                    }.get(n.type, 15),
                }
                for n in self.nodes
            ],
            "links": [
                {
                    "source": e.source,
                    "target": e.target,
                    "label":  e.label,
                    "type":   e.type,
                    "color":  "#e53935" if e.risk == "CRITICAL" else
                              "#ff8c00" if e.risk == "HIGH" else "#607d8b",
                }
                for e in self.edges
            ],
            "chains": self.attack_chains,
        }


class AttackGraphBuilder:
    """
    Bulgular + endpoint intelligence'dan saldırı grafiği oluşturur.
    """

    def build(
        self,
        apk_name:    str,
        findings:    list[Finding],
        surface:     AttackSurface,
        intel:       EndpointIntelligence | None = None,
    ) -> AttackGraph:
        nodes: list[GraphNode] = []
        edges: list[GraphEdge] = []
        chains: list[dict]     = []
        _id = lambda x: x.replace(" ", "_").replace("/", "_").replace(".", "_")[:40]

        # ── APK node ──────────────────────────────────────────────
        apk_id = "APK"
        nodes.append(GraphNode(
            id=apk_id, label=apk_name,
            type="apk", risk="HIGH",
            metadata={"findings": len(findings)},
        ))

        # ── Attacker node ─────────────────────────────────────────
        atk_id = "ATTACKER"
        nodes.append(GraphNode(
            id=atk_id, label="Attacker",
            type="attacker", risk="CRITICAL",
        ))

        # ── Finding node'ları ─────────────────────────────────────
        seen_findings: set[str] = set()
        for f in findings:
            fid = f"FINDING_{_id(f.title)}"
            if fid in seen_findings:
                continue
            seen_findings.add(fid)

            nodes.append(GraphNode(
                id=fid, label=f.title,
                type="finding", risk=f.severity,
                metadata={
                    "category":      f.category,
                    "exploitability":f.exploitability,
                    "score":         f.score_value,
                    "triage":        f.triage_note[:80] if f.triage_note else "",
                },
            ))
            edges.append(GraphEdge(
                source=apk_id, target=fid,
                label="exposes", type="exposes",
                risk=f.severity,
            ))
            if f.severity in ("CRITICAL", "HIGH"):
                edges.append(GraphEdge(
                    source=atk_id, target=fid,
                    label="exploits", type="exploits",
                    risk=f.severity,
                ))

        # ── Attack surface node'ları ──────────────────────────────
        surface_map = {
            "auth":         ("AUTH ROUTES",    "HIGH"),
            "payment":      ("PAYMENT ROUTES", "CRITICAL"),
            "user_data":    ("USER DATA",       "HIGH"),
            "internal_api": ("INTERNAL API",   "MEDIUM"),
            "other":        ("OTHER ROUTES",   "LOW"),
        }
        for attr, (label, risk) in surface_map.items():
            routes = getattr(surface, attr, set())
            if not routes:
                continue
            sid = f"SURFACE_{attr.upper()}"
            nodes.append(GraphNode(
                id=sid, label=f"{label} ({len(routes)})",
                type="endpoint", risk=risk,
                metadata={"routes": list(routes)[:5]},
            ))
            edges.append(GraphEdge(
                source=apk_id, target=sid,
                label="calls", type="calls", risk=risk,
            ))
            if risk in ("CRITICAL", "HIGH"):
                edges.append(GraphEdge(
                    source=atk_id, target=sid,
                    label="targets", type="exploits", risk=risk,
                ))

        # ── Endpoint intelligence node'ları ───────────────────────
        if intel:
            for ep in intel.endpoints[:15]:
                if ep.risk not in ("CRITICAL", "HIGH"):
                    continue
                eid = f"EP_{_id(ep.url)}"
                nodes.append(GraphNode(
                    id=eid,
                    label=f"{ep.method} {ep.url[:40]}",
                    type="endpoint", risk=ep.risk,
                    metadata={
                        "url":      ep.url,
                        "category": ep.category,
                        "file":     ep.file_found,
                    },
                ))
                edges.append(GraphEdge(
                    source=apk_id, target=eid,
                    label="requests", type="calls",
                    risk=ep.risk,
                ))

            if intel.graphql:
                gql_id = "GRAPHQL_API"
                nodes.append(GraphNode(
                    id=gql_id,
                    label=f"GraphQL API ({len(intel.graphql)} queries)",
                    type="service", risk="HIGH",
                    metadata={"query_count": len(intel.graphql)},
                ))
                edges.append(GraphEdge(
                    source=apk_id, target=gql_id,
                    label="queries", type="calls", risk="HIGH",
                ))
                edges.append(GraphEdge(
                    source=atk_id, target=gql_id,
                    label="introspects", type="exploits", risk="HIGH",
                ))

            if intel.websockets:
                ws_id = "WEBSOCKET"
                nodes.append(GraphNode(
                    id=ws_id,
                    label=f"WebSocket ({len(intel.websockets)} endpoints)",
                    type="service", risk="MEDIUM",
                    metadata={"count": len(intel.websockets)},
                ))
                edges.append(GraphEdge(
                    source=apk_id, target=ws_id,
                    label="connects", type="calls", risk="MEDIUM",
                ))

        # ── Saldırı zincirleri ────────────────────────────────────
        titles = {f.title.lower() for f in findings}

        def has(*kws: str) -> bool:
            return any(any(k in t for t in titles) for k in kws)

        # Zincir 1: Backend takeover
        if has("playfab","gamesparks","nakama","braincloud"):
            chains.append({
                "id":      "CHAIN_BACKEND_TAKEOVER",
                "title":   "Game Backend Takeover",
                "severity":"CRITICAL",
                "steps": [
                    "APK'dan backend secret key çıkart",
                    "Admin API'yi enumerate et",
                    "Tüm oyuncu hesaplarını listele",
                    "Sınırsız para birimi ver",
                    "Oyuncu PII veritabanını export et",
                ],
                "impact": "Ekonomi çöküşü + GDPR ihlali",
            })

        # Zincir 2: Anti-cheat + IAP
        if has("anti-cheat","bypass") and has("iap","receipt"):
            chains.append({
                "id":      "CHAIN_FULL_CHEAT",
                "title":   "Complete Game Exploit Chain",
                "severity":"CRITICAL",
                "steps": [
                    "Root detection bypass",
                    "Frida ile oyuna attach ol",
                    "Anti-cheat flag'ini devre dışı bırak",
                    "IAP receipt validation'ı bypass et",
                    "God mode + sonsuz kaynak aktifleştir",
                ],
                "impact": "Gelir kaybı + leaderboard bozulması",
            })

        # Zincir 3: SSL + JWT
        if has("ssl","pinning") and has("jwt","token"):
            chains.append({
                "id":      "CHAIN_MITM_SESSION",
                "title":   "MITM + Session Hijack",
                "severity":"HIGH",
                "steps": [
                    "SSL pinning bypass ile HTTPS trafiği yakala",
                    "JWT token'ı intercept et",
                    "Token'ı başka hesapta replay et",
                    "Privilege escalation dene",
                ],
                "impact": "Hesap ele geçirme",
            })

        # Zincir 4: PAK + Root
        if has("pak","encryption") and has("root","bypass"):
            chains.append({
                "id":      "CHAIN_ASSET_THEFT",
                "title":   "Game Asset Theft",
                "severity":"HIGH",
                "steps": [
                    "PAK şifreleme anahtarını APK'dan çıkart",
                    "Root bypass ile cihaza eriş",
                    "PAK dosyalarını decrypt et",
                    "Oyun asset'lerini çal ve yeniden dağıt",
                ],
                "impact": "IP hırsızlığı + mod client dağıtımı",
            })

        # Zincir 5: GraphQL introspection
        if intel and intel.graphql:
            chains.append({
                "id":      "CHAIN_GRAPHQL_INTROSPECT",
                "title":   "GraphQL Schema Extraction",
                "severity":"MEDIUM",
                "steps": [
                    "GraphQL endpoint URL'sini APK'dan al",
                    "Introspection query gönder",
                    "Tüm schema'yı dump et",
                    "Yetkisiz mutation'ları keşfet",
                    "Economy mutation'larını çalıştır",
                ],
                "impact": "Yetkisiz veri erişimi + economy manipülasyonu",
            })

        return AttackGraph(nodes=nodes, edges=edges, attack_chains=chains)
