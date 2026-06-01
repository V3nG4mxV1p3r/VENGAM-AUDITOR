/**
 * VENGAM Auditor v7 — Android Runtime Hook Script
 * Frida JavaScript — loads into target process via frida_runner.py
 *
 * Hooks:
 *   1. SSL Certificate Pinning
 *   2. Root / Emulator Detection
 *   3. IAP / Receipt Validation
 *   4. Cryptographic Key Usage
 *   5. Native Library Detection
 *   6. SharedPreferences Secret Reads  (v7)
 *   7. WebView JS Interface Exposure   (v7)
 */

'use strict';

function tag(t, msg) { send({ tag: t, msg: msg }); }

Java.perform(function () {

    // ── 1. SSL Certificate Pinning ────────────────────────────────
    var sslTargets = [
        { cls: 'okhttp3.CertificatePinner',                    method: 'check'              },
        { cls: 'okhttp3.CertificatePinner',                    method: 'check$okhttp'        },
        { cls: 'com.android.org.conscrypt.TrustManagerImpl',   method: 'verifyChain'         },
        { cls: 'javax.net.ssl.HttpsURLConnection',             method: 'setSSLSocketFactory' },
    ];
    sslTargets.forEach(function (t) {
        try {
            var C = Java.use(t.cls);
            C[t.method].overloads.forEach(function (o) {
                o.implementation = function () {
                    tag('SSL_PINNING', t.cls + '.' + t.method + '() intercepted');
                    return o.apply(this, arguments);
                };
            });
        } catch (_) {}
    });

    // ── 2. Root / Emulator Detection ─────────────────────────────
    var rootPaths = ['/su', '/system/xbin/su', '/system/bin/su', '/sbin/su'];
    try {
        var File = Java.use('java.io.File');
        File.exists.implementation = function () {
            var p = this.getAbsolutePath();
            if (rootPaths.some(function (r) { return p.indexOf(r) !== -1; })) {
                tag('ROOT_CHECK', 'File.exists() probing: ' + p);
            }
            return this.exists();
        };
    } catch (_) {}

    ['com.scottyab.rootbeer.RootBeer', 'com.topjohnwu.superuser.Shell'].forEach(function (cls) {
        try {
            var C = Java.use(cls);
            if (C.isRooted) {
                C.isRooted.implementation = function () {
                    tag('ROOT_CHECK', cls + '.isRooted() intercepted — returning false');
                    return false;
                };
            }
        } catch (_) {}
    });

    // ── 3. IAP / Receipt Validation ──────────────────────────────
    try {
        var BC = Java.use('com.android.billingclient.api.BillingClient');
        if (BC.queryPurchasesAsync) {
            BC.queryPurchasesAsync.overloads.forEach(function (o) {
                o.implementation = function () {
                    tag('IAP', 'BillingClient.queryPurchasesAsync() called');
                    return o.apply(this, arguments);
                };
            });
        }
    } catch (_) {}

    ['verifyPurchase', 'validateReceipt', 'verifyReceipt', 'checkPurchase'].forEach(function (method) {
        try {
            Java.enumerateLoadedClasses({
                onMatch: function (name) {
                    try {
                        var C = Java.use(name);
                        if (C[method]) {
                            C[method].overloads.forEach(function (o) {
                                o.implementation = function () {
                                    tag('IAP_VALIDATION', name + '.' + method + '() called');
                                    return o.apply(this, arguments);
                                };
                            });
                        }
                    } catch (_) {}
                },
                onComplete: function () {}
            });
        } catch (_) {}
    });

    // ── 4. Cryptographic Key Usage ───────────────────────────────
    try {
        var Cipher = Java.use('javax.crypto.Cipher');
        Cipher.init.overload('int', 'java.security.Key').implementation = function (mode, key) {
            var algo    = this.getAlgorithm();
            var encoded = key.getEncoded ? key.getEncoded() : null;
            var hex     = encoded
                ? Array.from(encoded).map(function (b) {
                    return ('0' + (b & 0xFF).toString(16)).slice(-2);
                }).join('').substring(0, 32)
                : 'N/A';
            tag('CRYPTO', 'Cipher.init() — Algo: ' + algo + ' | Mode: ' + mode + ' | Key: ' + hex + '...');
            return this.init(mode, key);
        };
    } catch (_) {}

    try {
        var SKS = Java.use('javax.crypto.spec.SecretKeySpec');
        SKS.$init.overload('[B', 'java.lang.String').implementation = function (keyBytes, algo) {
            var hex = Array.from(keyBytes).map(function (b) {
                return ('0' + (b & 0xFF).toString(16)).slice(-2);
            }).join('');
            tag('CRYPTO_HARDCODED_KEY', 'SecretKeySpec — Algo: ' + algo + ' | Key: ' + hex);
            return this.$init(keyBytes, algo);
        };
    } catch (_) {}

    // ── 5. Native Library Detection ──────────────────────────────
    ['libil2cpp.so', 'libunity.so', 'libUE4.so', 'libgodot.so'].forEach(function (lib) {
        try {
            var base = Module.findBaseAddress(lib);
            if (base) {
                tag('NATIVE', lib + ' loaded at ' + base);
            }
        } catch (_) {}
    });

    // ── 6. SharedPreferences Secret Reads (v7) ───────────────────
    try {
        var SPI = Java.use('android.app.SharedPreferencesImpl');
        SPI.getString.overload('java.lang.String', 'java.lang.String')
            .implementation = function (key, def) {
            var result = this.getString(key, def);
            var k = key ? key.toLowerCase() : '';
            if (k.indexOf('token') !== -1 || k.indexOf('key') !== -1 ||
                k.indexOf('secret') !== -1 || k.indexOf('auth') !== -1) {
                tag('SHARED_PREFS_SECRET',
                    'SharedPrefs.getString(' + key + ') = ' +
                    (result ? result.substring(0, 20) + '…' : 'null'));
            }
            return result;
        };
    } catch (_) {}

    // ── 7. WebView JS Interface (v7) ─────────────────────────────
    try {
        var WV = Java.use('android.webkit.WebView');
        WV.addJavascriptInterface.implementation = function (obj, name) {
            tag('WEBVIEW_JS_INTERFACE',
                'addJavascriptInterface(name=' + name +
                ', class=' + obj.getClass().getName() + ')');
            return this.addJavascriptInterface(obj, name);
        };
    } catch (_) {}

    tag('VENGAM', 'v7 hook script loaded — monitoring ' + Java.androidVersion);
});
