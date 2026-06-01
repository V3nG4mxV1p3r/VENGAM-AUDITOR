/**
 * VENGAM Auditor v7 — iOS Runtime Hook Script
 * Frida JavaScript — attaches to iOS game process
 *
 * Hooks:
 *   1. SSL Certificate Pinning (NSURLSession, TrustKit, Alamofire)
 *   2. Jailbreak Detection
 *   3. StoreKit / IAP Validation
 *   4. Keychain Access Monitoring
 *   5. CommonCrypto Key Usage
 *   6. LocalAuthentication Bypass Detection
 *   7. UserDefaults Secret Reads  (v7)
 *   8. WKWebView JS Interface     (v7)
 */

'use strict';

function tag(t, msg) { send({ tag: t, msg: msg }); }

// ── 1. SSL Certificate Pinning ────────────────────────────────────────────────
// Hook SecTrustEvaluate (CoreFoundation level — catches all HTTP clients)
try {
    var SecTrustEvaluate = Module.findExportByName('Security', 'SecTrustEvaluate');
    if (SecTrustEvaluate) {
        Interceptor.attach(SecTrustEvaluate, {
            onLeave: function (retval) {
                tag('SSL_PINNING', 'SecTrustEvaluate called — result: ' + retval);
            }
        });
    }
} catch (_) {}

// NSURLSession delegate pinning
try {
    var cls = ObjC.classes.NSURLSession;
    if (cls) {
        var method = cls['- URLSession:didReceiveChallenge:completionHandler:'];
        if (method) {
            Interceptor.attach(method.implementation, {
                onEnter: function (args) {
                    tag('SSL_PINNING', 'NSURLSession didReceiveChallenge intercepted');
                }
            });
        }
    }
} catch (_) {}

// TrustKit pinning
try {
    var TrustKit = ObjC.classes.TKPinningValidator;
    if (TrustKit) {
        tag('SSL_PINNING', 'TrustKit detected — certificate pinning framework in use');
    }
} catch (_) {}

// ── 2. Jailbreak Detection ────────────────────────────────────────────────────
var jailbreakPaths = [
    '/Applications/Cydia.app',
    '/Library/MobileSubstrate/MobileSubstrate.dylib',
    '/bin/bash',
    '/usr/sbin/sshd',
    '/etc/apt',
    '/private/var/lib/apt/',
    '/usr/bin/ssh',
    '/private/var/stash',
];

try {
    var NSFileManager = ObjC.classes.NSFileManager;
    var defaultManager = NSFileManager['+ defaultManager']();
    var fileExistsMethod = NSFileManager['- fileExistsAtPath:'];

    Interceptor.attach(fileExistsMethod.implementation, {
        onEnter: function (args) {
            var path = ObjC.Object(args[2]).toString();
            if (jailbreakPaths.some(function (p) { return path.indexOf(p) !== -1; })) {
                tag('JAILBREAK_CHECK', 'fileExistsAtPath: probing ' + path);
                this._jailbreakPath = path;
            }
        },
        onLeave: function (retval) {
            if (this._jailbreakPath) {
                tag('JAILBREAK_CHECK', 'Result for ' + this._jailbreakPath + ': ' + retval);
            }
        }
    });
} catch (_) {}

// ── 3. StoreKit / IAP Validation ─────────────────────────────────────────────
try {
    var SKPaymentQueue = ObjC.classes.SKPaymentQueue;
    if (SKPaymentQueue) {
        var addPayment = SKPaymentQueue['- addPayment:'];
        if (addPayment) {
            Interceptor.attach(addPayment.implementation, {
                onEnter: function (args) {
                    var payment = ObjC.Object(args[2]);
                    tag('IAP', 'SKPaymentQueue addPayment: ' + payment.productIdentifier());
                }
            });
        }
    }
} catch (_) {}

try {
    var SKReceiptRefreshRequest = ObjC.classes.SKReceiptRefreshRequest;
    if (SKReceiptRefreshRequest) {
        tag('IAP', 'SKReceiptRefreshRequest class detected — receipt refresh in use');
    }
} catch (_) {}

// ── 4. Keychain Access Monitoring ────────────────────────────────────────────
try {
    var SecItemCopyMatching = Module.findExportByName('Security', 'SecItemCopyMatching');
    if (SecItemCopyMatching) {
        Interceptor.attach(SecItemCopyMatching, {
            onEnter: function (args) {
                tag('KEYCHAIN', 'SecItemCopyMatching called — reading keychain item');
            },
            onLeave: function (retval) {
                // errSecSuccess = 0
                if (retval.toInt32() === 0) {
                    tag('KEYCHAIN', 'SecItemCopyMatching SUCCESS — item retrieved');
                }
            }
        });
    }
} catch (_) {}

try {
    var SecItemAdd = Module.findExportByName('Security', 'SecItemAdd');
    if (SecItemAdd) {
        Interceptor.attach(SecItemAdd, {
            onEnter: function (args) {
                tag('KEYCHAIN_WRITE', 'SecItemAdd called — writing to keychain');
            }
        });
    }
} catch (_) {}

// ── 5. CommonCrypto Key Usage ─────────────────────────────────────────────────
try {
    var CCCrypt = Module.findExportByName('libcommonCrypto.dylib', 'CCCrypt');
    if (!CCCrypt) {
        CCCrypt = Module.findExportByName(null, 'CCCrypt');
    }
    if (CCCrypt) {
        Interceptor.attach(CCCrypt, {
            onEnter: function (args) {
                // args[0]=operation, args[1]=algorithm, args[2]=options
                // args[3]=key, args[4]=keyLength
                var op   = args[0].toInt32();   // 0=encrypt, 1=decrypt
                var algo = args[1].toInt32();   // 0=AES, 1=DES, 2=3DES...
                var keyLen = args[4].toInt32();
                var algoName = ['AES','DES','3DES','CAST','RC4','RC2','Blowfish'][algo] || 'Unknown';
                var opName   = op === 0 ? 'Encrypt' : 'Decrypt';
                tag('CRYPTO', 'CCCrypt — ' + opName + ' | Algo: ' + algoName + ' | KeyLen: ' + keyLen);

                // Read key bytes (first 16 bytes max)
                if (args[3] && !args[3].isNull()) {
                    var maxBytes = Math.min(keyLen, 16);
                    try {
                        var keyBytes = Memory.readByteArray(args[3], maxBytes);
                        var hex = Array.from(new Uint8Array(keyBytes))
                            .map(function(b){ return ('0'+(b&0xFF).toString(16)).slice(-2); })
                            .join('');
                        tag('CRYPTO_KEY', 'CCCrypt key bytes (first 16): ' + hex);
                    } catch(_) {}
                }
            }
        });
    }
} catch (_) {}

// ── 6. LocalAuthentication Bypass Detection ───────────────────────────────────
try {
    var LAContext = ObjC.classes.LAContext;
    if (LAContext) {
        var evaluatePolicy = LAContext['- evaluatePolicy:localizedReason:reply:'];
        if (evaluatePolicy) {
            Interceptor.attach(evaluatePolicy.implementation, {
                onEnter: function (args) {
                    var policy = args[2].toInt32();
                    // 1 = deviceOwnerAuthenticationWithBiometrics
                    // 2 = deviceOwnerAuthentication (biometrics OR passcode)
                    tag('BIOMETRIC', 'LAContext evaluatePolicy: ' + policy +
                        (policy === 2 ? ' (allows passcode fallback)' : ' (biometrics only)'));
                }
            });
        }

        // canEvaluatePolicy — detect if app checks for biometric availability
        var canEvaluate = LAContext['- canEvaluatePolicy:error:'];
        if (canEvaluate) {
            Interceptor.attach(canEvaluate.implementation, {
                onEnter: function (args) {
                    tag('BIOMETRIC', 'LAContext canEvaluatePolicy: called');
                }
            });
        }
    }
} catch (_) {}

// ── 7. UserDefaults Secret Reads (v7) ────────────────────────────────────────
try {
    var NSUserDefaults = ObjC.classes.NSUserDefaults;
    var stringForKey   = NSUserDefaults['- stringForKey:'];
    if (stringForKey) {
        Interceptor.attach(stringForKey.implementation, {
            onEnter: function (args) {
                this._key = ObjC.Object(args[2]).toString();
            },
            onLeave: function (retval) {
                var k = this._key ? this._key.toLowerCase() : '';
                if (k.indexOf('token') !== -1 || k.indexOf('key') !== -1 ||
                    k.indexOf('secret') !== -1 || k.indexOf('auth') !== -1 ||
                    k.indexOf('password') !== -1) {
                    var val = retval.isNull() ? 'null' :
                        ObjC.Object(retval).toString().substring(0, 20) + '…';
                    tag('USERDEFAULTS_SECRET',
                        'NSUserDefaults stringForKey:' + this._key + ' = ' + val);
                }
            }
        });
    }
} catch (_) {}

// ── 8. WKWebView JS Interface (v7) ────────────────────────────────────────────
try {
    var WKWebView = ObjC.classes.WKWebView;
    if (WKWebView) {
        // addScriptMessageHandler:name: — the iOS equivalent of addJavascriptInterface
        var WKUserContentController = ObjC.classes.WKUserContentController;
        if (WKUserContentController) {
            var addHandler = WKUserContentController['- addScriptMessageHandler:name:'];
            if (addHandler) {
                Interceptor.attach(addHandler.implementation, {
                    onEnter: function (args) {
                        var name    = ObjC.Object(args[3]).toString();
                        var handler = ObjC.Object(args[2]);
                        tag('WEBVIEW_JS_INTERFACE',
                            'WKUserContentController addScriptMessageHandler: ' +
                            name + ' (' + handler.$className + ')');
                    }
                });
            }
        }
    }
} catch (_) {}

// ── 9. Sensitive URL Requests ────────────────────────────────────────────────
try {
    var NSURLRequest = ObjC.classes.NSMutableURLRequest;
    var setValue     = NSURLRequest['- setValue:forHTTPHeaderField:'];
    if (setValue) {
        Interceptor.attach(setValue.implementation, {
            onEnter: function (args) {
                var field = ObjC.Object(args[3]).toString().toLowerCase();
                if (field === 'authorization' || field === 'x-api-key' || field === 'x-auth-token') {
                    var value = ObjC.Object(args[2]).toString();
                    tag('HTTP_AUTH_HEADER',
                        'Authorization header set: ' + field + ' = ' + value.substring(0, 30) + '…');
                }
            }
        });
    }
} catch (_) {}

tag('VENGAM', 'v7 iOS hook script loaded successfully');
