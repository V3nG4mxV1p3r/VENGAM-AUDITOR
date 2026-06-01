"""
VENGAM Auditor — False Positive Filter Engine
v8: Ultimate SOC-grade Context-aware Suppression
"""
from __future__ import annotations
import base64
import re
from vengam.utils.entropy import is_alphabet_string

class FalsePositiveFilter:

    SAFE_PACKAGES: frozenset[str] = frozenset({
        "androidx", "kotlinx", "kotlin",
        "com.google.android", "com.google.firebase",
        "com.android", "org.apache",
        "com.facebook.react", "io.flutter",
        "com.unity3d", "com.epicgames", "com.cocos2d", "com.defold",
        "com.adjust", "com.appsflyer", "io.branch",
        "com.onesignal", "com.mixpanel", "com.amplitude",
        "okhttp3", "retrofit2", "io.grpc", "com.squareup",
        "javax.crypto", "java.security", "android.support",
        "com.huawei.agconnect", "com.huawei.hms",
        "com.apm.insight", # ByteDance APM eklendi
    })

    KNOWN_BENIGN_CORPUS: frozenset[str] = frozenset({
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "abcdefghijklmnopqrstuvwxyz0123456789",
        "application/x-www-form-urlencoded",
        "X-Requested-With", "Content-Type", "multipart/form-data",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
        "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
    })

    _SMALI_RE = re.compile(
        r"^(L[a-z][a-zA-Z0-9/$]+;|"
        r"\[B|\[C|\[I|\[J|\[F|\[D|"
        r"V|Z|B|C|S|I|J|F|D|"
        r"[0-9a-f]{8}-[0-9a-f]{4}-|"
        r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    )

    _GAME_ASSET_RE = re.compile(
        r"unity_default_resources|sharedassets\d+|level\d+|"
        r"globalgamemanagers|resources\.assets|UE4Game|"
        r"pak_\d+|Pak_P\.|BaseMeshAttributes",
        re.IGNORECASE,
    )

    _TEST_VECTOR_RE = re.compile(
        r"deadbeef|cafebabe|feedface|0{16,}|f{16,}|(01234567){2,}|(abcdef){3,}",
        re.IGNORECASE,
    )

    _AGC_RE = re.compile(r"agc_|agconnect|huawei|hms_|HMS_", re.IGNORECASE)

    _GAME_CTX_RE = re.compile(
        r"\b(game|economy|currency|coin|gem|gold|balance|score|player|"
        r"inventory|chest|reward|loot|shop|store|purchase|wallet|"
        r"leaderboard|rank|level|xp|exp|achievement)\b",
        re.IGNORECASE,
    )

    _GENERIC_LIB_RE = re.compile(
        r"com\.adyen|com\.braintree|com\.paypal|com\.stripe|"
        r"retrofit2\.|okhttp3\.|com\.squareup\.|io\.realm\.|"
        r"com\.firebase\.|io\.fabric\.|com\.crashlytics\.|"
        r"timber[/.]|com\.jakewharton",
        re.IGNORECASE,
    )

    _PAYMENT_FILE_FRAGS = frozenset({
        "adyen", "braintree", "stripe", "paypal", "checkout",
        "address", "billing", "shipping", "validation",
    })

    _GAME_FILE_FRAGS = frozenset({
        "game", "economy", "currency", "coin", "gem", "wallet",
        "shop", "store", "loot", "reward", "inventory",
    })

    @classmethod
    def check(
        cls,
        candidate: str,
        context_line: str,
        filename: str,
        pattern_title: str = "",
    ) -> tuple[bool, str]:
        
        lower      = candidate.lower()
        ctx_lower  = context_line.lower()
        pt_lower   = pattern_title.lower()
        fname_lower = filename.replace("\\", "/").lower()

        # 12. ULTIMATE AD SDK SUPPRESSION (Balyoz katmanını en üste aldık)
        # Reklam SDK'ları ve analitik toollarındaki hiçbir şeyi raporlama
        ad_keywords = [
            "mbridge", "applovin", "bytedance", "gms/ads", "gms.ads", 
            "unity3d/ads", "ironsource", "chartboost", "vungle", "facebook/ads"
        ]
        combined_text = f"{fname_lower} {ctx_lower} {lower}"
        if any(kw in combined_text for kw in ad_keywords):
            return True, "Aggressive Ad SDK / Analytics suppression"

        # 1. Safe package prefix (Düzeltildi: Artık dosya ismine de bakıyor)
        for pkg in cls.SAFE_PACKAGES:
            pkg_path = pkg.replace(".", "/")
            if pkg_path in fname_lower or pkg_path in lower or pkg in ctx_lower:
                return True, f"Safe library namespace: {pkg}"

        # 2. Known benign corpus
        if candidate in cls.KNOWN_BENIGN_CORPUS:
            return True, "Known benign string"

        # 3. Base62/64 alphabet string
        if is_alphabet_string(candidate):
            return True, "Base62/Base64 alphabet definition"

        # 4. Smali structural descriptor
        if cls._SMALI_RE.match(candidate):
            return True, "Smali structural / type descriptor"

        # 5. Game engine asset
        if cls._GAME_ASSET_RE.search(candidate) or cls._GAME_ASSET_RE.search(filename):
            return True, "Game engine asset marker"

        # 6. Test vector / placeholder
        if cls._TEST_VECTOR_RE.match(candidate):
            return True, "Cryptographic test vector / placeholder"

        # 7. Numeric / version string
        if re.match(r"^[\d.\-_]+$", candidate):
            return True, "Numeric / version string"

        # 8. Short base64 (< 8 decoded bytes)
        if re.match(r"^[A-Za-z0-9+/=]+$", candidate):
            try:
                decoded = base64.b64decode(candidate + "==")
                if len(decoded) < 8:
                    return True, "Short base64 (< 8 decoded bytes)"
            except Exception:
                pass

        # 9. Android resource reference
        if re.match(r"^@(string|color|drawable|layout|id|dimen|style|attr)/", lower):
            return True, "Android resource reference"

        # 10. Twilio SID pattern
        if "twilio" in pt_lower or "account sid" in pt_lower:
            if cls._AGC_RE.search(context_line) or cls._AGC_RE.search(filename) or "agc_" in lower:
                return True, "Twilio SID pattern matched Huawei AGC resource ID"

        # 11a. debugMode
        if any(kw in pt_lower for kw in ("debug", "god mode", "debug flag")):
            if cls._GENERIC_LIB_RE.search(filename):
                return True, "debugMode in third-party library (non-game)"
            if any(p in fname_lower for p in cls._PAYMENT_FILE_FRAGS):
                return True, "Debug flag in payment/UI library"

        # 11b. clientValidat
        if "client-side currency" in pt_lower or "clientvalidat" in lower:
            has_game_ctx  = bool(cls._GAME_CTX_RE.search(context_line))
            game_in_file  = any(k in fname_lower for k in cls._GAME_FILE_FRAGS)
            if not has_game_ctx and not game_in_file:
                return True, "clientValidat outside game economy context"

        return False, ""