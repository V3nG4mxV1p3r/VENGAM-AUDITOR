"""
VENGAM — Otomatik Frida Hook Üreteci
Bulgulardan ve IL2CPP analizinden otomatik Frida script üretir.
Araştırmacı tek tıkla hook script'i alır, Frida'ya yapıştırır.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from vengam.core.models import Finding


@dataclass
class FridaHook:
    title:       str
    category:    str
    severity:    str
    description: str
    script:      str
    tags:        list[str] = field(default_factory=list)


# ── Hook şablonları ───────────────────────────────────────────────

_HEADER = """/**
 * VENGAM Auditor — Auto-generated Frida Hook Script
 * Target: {apk_name}
 * Generated: {timestamp}
 * Hooks: {hook_count}
 *
 * Kullanım:
 *   frida -U -f {package} -l vengam_hooks.js --no-pause
 *   frida -U --attach-pid PID -l vengam_hooks.js
 */
'use strict';

function vlog(tag, msg) {{
  var ts = new Date().toISOString().substr(11,12);
  send({{ tag: tag, msg: msg, ts: ts }});
  console.log('[VENGAM][' + ts + '][' + tag + '] ' + msg);
}}

Java.perform(function() {{
  vlog('VENGAM', 'Hook script loaded — {hook_count} hooks active');
"""

_FOOTER = """
  vlog('VENGAM', 'All hooks installed successfully');
});
"""


def _ssl_pinning_hook() -> str:
    return """
  // ── SSL Certificate Pinning Bypass ───────────────────────────
  try {
    var OkHttpClient = Java.use('okhttp3.CertificatePinner');
    OkHttpClient.check.overloads.forEach(function(o) {
      o.implementation = function() {
        vlog('SSL_BYPASS', 'CertificatePinner.check() bypassed');
      };
    });
    OkHttpClient['check$okhttp'].overloads.forEach(function(o) {
      o.implementation = function() {
        vlog('SSL_BYPASS', 'CertificatePinner.check$okhttp() bypassed');
      };
    });
    vlog('SSL_BYPASS', 'OkHttp pinning disabled');
  } catch(_) {}

  try {
    var TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var SSLContext   = Java.use('javax.net.ssl.SSLContext');
    var TrustAll     = Java.registerClass({
      name: 'com.vengam.TrustAll',
      implements: [TrustManager],
      methods: {
        checkClientTrusted: function(chain, type) {},
        checkServerTrusted: function(chain, type) {},
        getAcceptedIssuers: function() { return []; }
      }
    });
    var ctx = SSLContext.getInstance('TLS');
    ctx.init(null, [TrustAll.$new()], null);
    SSLContext.getDefault.implementation = function() { return ctx; };
    vlog('SSL_BYPASS', 'TrustManager override active');
  } catch(_) {}"""


def _root_detection_hook() -> str:
    return """
  // ── Root / Jailbreak Detection Bypass ───────────────────────
  ['isRooted','isDeviceRooted','checkRoot','detectRoot',
   'isJailbroken','checkJailbreak'].forEach(function(method) {
    try {
      Java.enumerateLoadedClasses({
        onMatch: function(name) {
          try {
            var C = Java.use(name);
            if (C[method]) {
              C[method].overloads.forEach(function(o) {
                o.implementation = function() {
                  vlog('ROOT_BYPASS', name + '.' + method + '() → false');
                  return false;
                };
              });
            }
          } catch(_) {}
        }, onComplete: function() {}
      });
    } catch(_) {}
  });

  try {
    var File = Java.use('java.io.File');
    File.exists.implementation = function() {
      var path = this.getAbsolutePath();
      var rootPaths = ['/su','/system/xbin/su','/system/bin/su',
                       '/sbin/su','/data/local/su'];
      if (rootPaths.some(function(p){ return path.indexOf(p) !== -1; })) {
        vlog('ROOT_BYPASS', 'File.exists() blocked: ' + path);
        return false;
      }
      return this.exists();
    };
  } catch(_) {}"""


def _iap_hook() -> str:
    return """
  // ── IAP / Receipt Validation Bypass ─────────────────────────
  ['verifyPurchase','validateReceipt','verifyReceipt',
   'checkPurchase','validatePurchase'].forEach(function(method) {
    try {
      Java.enumerateLoadedClasses({
        onMatch: function(name) {
          try {
            var C = Java.use(name);
            if (C[method]) {
              C[method].overloads.forEach(function(o) {
                o.implementation = function() {
                  vlog('IAP_BYPASS', name + '.' + method + '() → true');
                  return true;
                };
              });
            }
          } catch(_) {}
        }, onComplete: function() {}
      });
    } catch(_) {}
  });

  try {
    var BillingClient = Java.use(
      'com.android.billingclient.api.BillingClient'
    );
    if (BillingClient.queryPurchasesAsync) {
      BillingClient.queryPurchasesAsync.overloads.forEach(function(o) {
        o.implementation = function() {
          vlog('IAP', 'BillingClient.queryPurchasesAsync() monitored');
          return o.apply(this, arguments);
        };
      });
    }
  } catch(_) {}"""


def _economy_hook() -> str:
    return """
  // ── Economy / Currency Monitor ───────────────────────────────
  ['getGold','getGems','getCoins','getCurrency','getBalance',
   'addGold','addGems','spendCurrency','deductCurrency'].forEach(function(m) {
    try {
      Java.enumerateLoadedClasses({
        onMatch: function(name) {
          var nl = name.toLowerCase();
          if (!nl.includes('economy') && !nl.includes('currency') &&
              !nl.includes('wallet') && !nl.includes('player') &&
              !nl.includes('game')) return;
          try {
            var C = Java.use(name);
            if (C[m]) {
              C[m].overloads.forEach(function(o) {
                o.implementation = function() {
                  var r = o.apply(this, arguments);
                  vlog('ECONOMY', name + '.' + m + '() = ' + r);
                  return r;
                };
              });
            }
          } catch(_) {}
        }, onComplete: function() {}
      });
    } catch(_) {}
  });"""


def _crypto_hook() -> str:
    return """
  // ── Cryptographic Key Extraction ────────────────────────────
  try {
    var Cipher = Java.use('javax.crypto.Cipher');
    Cipher.init.overload('int','java.security.Key').implementation =
      function(mode, key) {
        var algo = this.getAlgorithm();
        var enc  = key.getEncoded ? key.getEncoded() : null;
        var hex  = enc ? Array.from(enc).map(function(b){
          return ('0'+(b&0xFF).toString(16)).slice(-2);
        }).join('').substring(0,32) : 'N/A';
        vlog('CRYPTO', 'Cipher.init | Algo:' + algo +
             ' | Mode:' + mode + ' | Key:' + hex + '...');
        return this.init(mode, key);
      };
  } catch(_) {}

  try {
    var SKS = Java.use('javax.crypto.spec.SecretKeySpec');
    SKS.$init.overload('[B','java.lang.String').implementation =
      function(keyBytes, algo) {
        var hex = Array.from(keyBytes).map(function(b){
          return ('0'+(b&0xFF).toString(16)).slice(-2);
        }).join('');
        vlog('CRYPTO_KEY', 'SecretKeySpec | Algo:' + algo +
             ' | Key:' + hex);
        return this.$init(keyBytes, algo);
      };
  } catch(_) {}"""


def _frida_detection_hook() -> str:
    return """
  // ── Frida Self-Detection Bypass ─────────────────────────────
  try {
    var System = Java.use('java.lang.System');
    System.exit.implementation = function(code) {
      vlog('FRIDA_DETECT', 'System.exit(' + code + ') blocked!');
    };
  } catch(_) {}

  try {
    var Runtime = Java.use('java.lang.Runtime');
    Runtime.exec.overload('java.lang.String').implementation =
      function(cmd) {
        if (cmd && (cmd.indexOf('frida') !== -1 ||
                    cmd.indexOf('gdb') !== -1)) {
          vlog('FRIDA_DETECT', 'Runtime.exec blocked: ' + cmd);
          return null;
        }
        return this.exec(cmd);
      };
  } catch(_) {}"""


def _network_monitor_hook() -> str:
    return """
  // ── Network Request Monitor ──────────────────────────────────
  try {
    var URL = Java.use('java.net.URL');
    URL.$init.overload('java.lang.String').implementation =
      function(url) {
        if (url && (url.indexOf('api') !== -1 ||
                    url.indexOf('auth') !== -1 ||
                    url.indexOf('pay') !== -1)) {
          vlog('NETWORK', 'URL opened: ' + url);
        }
        return this.$init(url);
      };
  } catch(_) {}

  try {
    var OkHttp = Java.use('okhttp3.Request$Builder');
    OkHttp.url.overload('java.lang.String').implementation =
      function(url) {
        vlog('NETWORK', 'OkHttp request: ' + url);
        return this.url(url);
      };
  } catch(_) {}"""


# ── Hook seçici ───────────────────────────────────────────────────

_HOOK_MAP: dict[str, tuple[str, str]] = {
    # finding title keyword → (hook_func_name, açıklama)
    "ssl":        ("ssl_pinning",    "SSL Pinning Bypass"),
    "pinning":    ("ssl_pinning",    "SSL Pinning Bypass"),
    "root":       ("root_detect",    "Root Detection Bypass"),
    "emulator":   ("root_detect",    "Root/Emulator Bypass"),
    "iap":        ("iap",            "IAP Receipt Bypass"),
    "receipt":    ("iap",            "IAP Receipt Bypass"),
    "purchase":   ("iap",            "IAP Purchase Monitor"),
    "economy":    ("economy",        "Economy Monitor"),
    "currency":   ("economy",        "Currency Monitor"),
    "gold":       ("economy",        "Gold/Gems Monitor"),
    "crypto":     ("crypto",         "Crypto Key Extractor"),
    "aes":        ("crypto",         "AES Key Extractor"),
    "encryption": ("crypto",         "Encryption Monitor"),
    "frida":      ("frida_detect",   "Frida Detection Bypass"),
    "network":    ("network",        "Network Monitor"),
    "endpoint":   ("network",        "Endpoint Monitor"),
}

_HOOK_BUILDERS = {
    "ssl_pinning":  _ssl_pinning_hook,
    "root_detect":  _root_detection_hook,
    "iap":          _iap_hook,
    "economy":      _economy_hook,
    "crypto":       _crypto_hook,
    "frida_detect": _frida_detection_hook,
    "network":      _network_monitor_hook,
}


# ── Ana üretici sınıf ─────────────────────────────────────────────

class FridaHookGenerator:
    """
    VENGAM bulgularından otomatik Frida hook script üretir.
    """

    def generate_from_findings(
        self,
        findings:  list[Finding],
        apk_name:  str = "target.apk",
        package:   str = "com.target.app",
    ) -> str:
        """Bulgulara uygun hook'ları seç ve tam script üret."""
        import datetime
        selected: dict[str, bool] = {}

        for f in findings:
            title_lower = f.title.lower()
            for kw, (hook_key, _) in _HOOK_MAP.items():
                if kw in title_lower:
                    selected[hook_key] = True

        # Hiç seçilmediyse en kritik hook'ları varsayılan ekle
        if not selected:
            selected = {"ssl_pinning": True, "root_detect": True}

        return self._build_script(
            selected, apk_name, package,
            datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
        )

    def generate_full(
        self,
        apk_name: str = "target.apk",
        package:  str = "com.target.app",
    ) -> str:
        """Tüm hook'ları içeren tam script üret."""
        import datetime
        all_hooks = {k: True for k in _HOOK_BUILDERS}
        return self._build_script(
            all_hooks, apk_name, package,
            datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
        )

    def generate_from_il2cpp(
        self,
        security_hits: list,
        apk_name:  str = "target.apk",
        package:   str = "com.target.app",
    ) -> str:
        """IL2CPP analiz bulgularından hook üret."""
        import datetime
        selected: dict[str, bool] = {"ssl_pinning": True}

        for hit in security_hits:
            cat = hit.category.lower()
            if "anti" in cat:    selected["root_detect"] = True
            if "economy" in cat: selected["economy"]     = True
            if "iap" in cat:     selected["iap"]         = True
            if "crypto" in cat:  selected["crypto"]      = True
            if "auth" in cat:    selected["network"]     = True

        # IL2CPP-spesifik hook'lar
        il2cpp_hooks = []
        for hit in security_hits:
            if hit.frida_hook:
                il2cpp_hooks.append(
                    f"\n  // IL2CPP: {hit.name}\n  {hit.frida_hook}"
                )

        script = self._build_script(
            selected, apk_name, package,
            datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
        )
        if il2cpp_hooks:
            insert = "\n".join(il2cpp_hooks)
            script = script.replace(
                _FOOTER,
                f"\n  // ── IL2CPP Auto-Hooks ───────────────────────────────\n"
                + insert + _FOOTER
            )
        return script

    def _build_script(
        self,
        selected: dict[str, bool],
        apk_name: str,
        package:  str,
        timestamp: str,
    ) -> str:
        parts = [_HEADER.format(
            apk_name=apk_name,
            package=package,
            timestamp=timestamp,
            hook_count=len(selected),
        )]
        for hook_key in selected:
            builder = _HOOK_BUILDERS.get(hook_key)
            if builder:
                parts.append(builder())
        parts.append(_FOOTER)
        return "".join(parts)

    def list_available_hooks(self) -> list[dict]:
        return [
            {"key": k, "description": v}
            for k, v in {
                "ssl_pinning":  "SSL/TLS Certificate Pinning Bypass",
                "root_detect":  "Root & Emulator Detection Bypass",
                "iap":          "In-App Purchase Receipt Bypass",
                "economy":      "Economy/Currency Monitor & Hook",
                "crypto":       "Cryptographic Key Extraction",
                "frida_detect": "Frida Self-Detection Bypass",
                "network":      "Network Request Monitor",
            }.items()
        ]


# ── Singleton ─────────────────────────────────────────────────────
_generator: FridaHookGenerator | None = None

def get_generator() -> FridaHookGenerator:
    global _generator
    if _generator is None:
        _generator = FridaHookGenerator()
    return _generator
