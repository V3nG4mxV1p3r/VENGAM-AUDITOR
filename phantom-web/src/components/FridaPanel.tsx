/**
 * VENGAM — Frida Hook Generator Panel
 * Bulgulardan otomatik Frida script üretir, kopyalamayı sağlar.
 */
import { useState } from 'react';
import type { Finding } from '../api/client';

interface Props {
  findings:   Finding[];
  apkName:    string;
  packageName:string;
}

const HOOK_DESCRIPTIONS: Record<string, string> = {
  ssl_pinning:  'SSL/TLS Certificate Pinning Bypass',
  root_detect:  'Root & Emulator Detection Bypass',
  iap:          'IAP Receipt Validation Bypass',
  economy:      'Economy/Currency Monitor',
  crypto:       'Cryptographic Key Extractor',
  frida_detect: 'Frida Self-Detection Bypass',
  network:      'Network Request Monitor',
};

export default function FridaPanel({ findings, apkName, packageName }: Props) {
  const [script,    setScript]    = useState<string>('');
  const [loading,   setLoading]   = useState(false);
  const [copied,    setCopied]    = useState(false);
  const [mode,      setMode]      = useState<'auto'|'full'|'il2cpp'>('auto');
  const [activeHooks, setActiveHooks] = useState<Record<string,boolean>>({});

  const generateScript = async () => {
    setLoading(true);
    setScript('');
    try {
      // Bulgulara göre hangi hook'ların gerektiğini belirle
      const selected: Record<string, boolean> = {};
      const titleJoined = findings.map(f => f.title.toLowerCase()).join(' ');

      if (titleJoined.includes('ssl') || titleJoined.includes('pinning'))
        selected['ssl_pinning']  = true;
      if (titleJoined.includes('root') || titleJoined.includes('emulator'))
        selected['root_detect']  = true;
      if (titleJoined.includes('iap') || titleJoined.includes('receipt'))
        selected['iap']          = true;
      if (titleJoined.includes('currency') || titleJoined.includes('economy'))
        selected['economy']      = true;
      if (titleJoined.includes('crypto') || titleJoined.includes('aes'))
        selected['crypto']       = true;
      if (titleJoined.includes('frida'))
        selected['frida_detect'] = true;

      // Varsayılan: her zaman SSL + root
      if (!Object.keys(selected).length) {
        selected['ssl_pinning'] = true;
        selected['root_detect'] = true;
      }

      if (mode === 'full') {
        Object.keys(HOOK_DESCRIPTIONS).forEach(k => { selected[k] = true; });
      }

      setActiveHooks(selected);

      // Script oluştur (frontend'de template)
      const ts    = new Date().toISOString().substring(0,16).replace('T',' ');
      const count = Object.keys(selected).length;

      let out = `/**
 * VENGAM Auditor — Auto-generated Frida Hook Script
 * Target  : ${apkName}
 * Package : ${packageName}
 * Generated: ${ts}
 * Hooks   : ${count}
 *
 * Kullanım:
 *   frida -U -f ${packageName} -l vengam_hooks.js --no-pause
 *   frida -U --attach-pid PID -l vengam_hooks.js
 */
'use strict';

function vlog(tag, msg) {
  var ts = new Date().toISOString().substr(11,12);
  send({ tag: tag, msg: msg, ts: ts });
  console.log('[VENGAM][' + ts + '][' + tag + '] ' + msg);
}

Java.perform(function() {
  vlog('VENGAM', 'Hook script loaded — ${count} hooks active');
`;

      if (selected['ssl_pinning']) out += `
  // ── SSL Certificate Pinning Bypass ───────────────────────────
  try {
    var OkHttp = Java.use('okhttp3.CertificatePinner');
    OkHttp.check.overloads.forEach(function(o) {
      o.implementation = function() {
        vlog('SSL_BYPASS', 'CertificatePinner.check() bypassed');
      };
    });
    vlog('SSL_BYPASS', 'OkHttp pinning disabled');
  } catch(_) {}
`;

      if (selected['root_detect']) out += `
  // ── Root Detection Bypass ─────────────────────────────────────
  ['isRooted','checkRoot','detectRoot','isJailbroken'].forEach(function(m) {
    try {
      Java.enumerateLoadedClasses({
        onMatch: function(name) {
          try {
            var C = Java.use(name);
            if (C[m]) {
              C[m].overloads.forEach(function(o) {
                o.implementation = function() {
                  vlog('ROOT_BYPASS', name + '.' + m + '() -> false');
                  return false;
                };
              });
            }
          } catch(_) {}
        }, onComplete: function() {}
      });
    } catch(_) {}
  });
`;

      if (selected['iap']) out += `
  // ── IAP Receipt Bypass ────────────────────────────────────────
  ['verifyPurchase','validateReceipt','verifyReceipt'].forEach(function(m) {
    try {
      Java.enumerateLoadedClasses({
        onMatch: function(name) {
          try {
            var C = Java.use(name);
            if (C[m]) {
              C[m].overloads.forEach(function(o) {
                o.implementation = function() {
                  vlog('IAP_BYPASS', name + '.' + m + '() -> true');
                  return true;
                };
              });
            }
          } catch(_) {}
        }, onComplete: function() {}
      });
    } catch(_) {}
  });
`;

      if (selected['economy']) out += `
  // ── Economy Monitor ───────────────────────────────────────────
  ['getGold','getGems','getCurrency','getBalance'].forEach(function(m) {
    try {
      Java.enumerateLoadedClasses({
        onMatch: function(name) {
          if (!name.toLowerCase().includes('economy') &&
              !name.toLowerCase().includes('currency') &&
              !name.toLowerCase().includes('player')) return;
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
  });
`;

      if (selected['crypto']) out += `
  // ── Crypto Key Extractor ──────────────────────────────────────
  try {
    var Cipher = Java.use('javax.crypto.Cipher');
    Cipher.init.overload('int','java.security.Key').implementation =
      function(mode, key) {
        var algo = this.getAlgorithm();
        var enc  = key.getEncoded ? key.getEncoded() : null;
        var hex  = enc ? Array.from(enc).map(function(b){
          return ('0'+(b&0xFF).toString(16)).slice(-2);
        }).join('').substring(0,32) : 'N/A';
        vlog('CRYPTO', 'Algo:' + algo + ' Key:' + hex + '...');
        return this.init(mode, key);
      };
  } catch(_) {}
`;

      if (selected['frida_detect']) out += `
  // ── Frida Detection Bypass ────────────────────────────────────
  try {
    var Sys = Java.use('java.lang.System');
    Sys.exit.implementation = function(code) {
      vlog('FRIDA_DETECT', 'System.exit(' + code + ') blocked!');
    };
  } catch(_) {}
`;

      if (selected['network']) out += `
  // ── Network Monitor ───────────────────────────────────────────
  try {
    var URL = Java.use('java.net.URL');
    URL.$init.overload('java.lang.String').implementation =
      function(url) {
        if (url && (url.indexOf('api') !== -1 || url.indexOf('auth') !== -1))
          vlog('NETWORK', 'URL: ' + url);
        return this.$init(url);
      };
  } catch(_) {}
`;

      out += `
  vlog('VENGAM', 'All hooks installed.');
});
`;
      setScript(out);
    } finally {
      setLoading(false);
    }
  };

  const copyScript = async () => {
    await navigator.clipboard.writeText(script);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div style={{ display:'flex', flexDirection:'column', gap:10 }}>

      {/* Header */}
      <div style={{
        fontFamily:'Share Tech Mono,monospace', fontSize:9,
        letterSpacing:2, color:'#3a6a3a', paddingBottom:8,
        borderBottom:'1px solid #1a2a1a',
      }}>FRIDA HOOK GENERATOR</div>

      {/* Mode selector */}
      <div style={{ display:'flex', gap:6 }}>
        {(['auto','full','il2cpp'] as const).map(m => (
          <button key={m} onClick={() => setMode(m)} style={{
            fontFamily:'Share Tech Mono,monospace', fontSize:9,
            letterSpacing:1, padding:'5px 12px', borderRadius:4,
            cursor:'pointer',
            border:`1px solid ${mode===m ? '#00e664':'#1a2a1a'}`,
            background: mode===m ? 'rgba(0,230,100,0.08)':'transparent',
            color: mode===m ? '#00e664':'#4a6a4a',
          }}>
            {m === 'auto'   ? 'AUTO (findings)' :
             m === 'full'   ? 'FULL (all hooks)' : 'IL2CPP'}
          </button>
        ))}
      </div>

      {/* Generate button */}
      <button onClick={generateScript} disabled={loading} style={{
        fontFamily:'Share Tech Mono,monospace', fontSize:10,
        fontWeight:700, letterSpacing:2, padding:'10px',
        border:'none', borderRadius:4, cursor:'pointer',
        background: loading ? '#1a2a1a' : '#00e664',
        color: loading ? '#3a6a3a' : '#000',
        transition:'all .2s',
        boxShadow: loading ? 'none' : '0 0 12px rgba(0,230,100,0.3)',
      }}>
        {loading ? 'GENERATING...' : '⚡ GENERATE FRIDA SCRIPT'}
      </button>

      {/* Active hooks */}
      {Object.keys(activeHooks).length > 0 && (
        <div style={{ display:'flex', gap:6, flexWrap:'wrap' }}>
          {Object.keys(activeHooks).map(k => (
            <span key={k} style={{
              fontFamily:'Share Tech Mono,monospace', fontSize:8,
              padding:'2px 8px', borderRadius:3,
              background:'rgba(0,230,100,0.08)',
              border:'1px solid #1a2a1a', color:'#3a6a3a',
            }}>
              {HOOK_DESCRIPTIONS[k] || k}
            </span>
          ))}
        </div>
      )}

      {/* Script output */}
      {script && (
        <div style={{
          background:'#070a07', border:'1px solid #1a2a1a',
          borderRadius:4, overflow:'hidden',
        }}>
          <div style={{
            display:'flex', alignItems:'center', gap:10,
            padding:'7px 12px', borderBottom:'1px solid #1a2a1a',
            background:'#0c110c',
          }}>
            <span style={{
              fontFamily:'Share Tech Mono,monospace',
              fontSize:9, color:'#3a6a3a', flex:1,
            }}>
              vengam_hooks.js — {script.split('\n').length} lines
            </span>
            <button onClick={copyScript} style={{
              fontFamily:'Share Tech Mono,monospace', fontSize:9,
              padding:'4px 12px', border:'1px solid #1a2a1a',
              borderRadius:3, cursor:'pointer',
              background: copied ? 'rgba(0,230,100,0.12)' : 'transparent',
              color: copied ? '#00e664' : '#4a6a4a',
            }}>
              {copied ? '✓ COPIED' : 'COPY'}
            </button>
          </div>
          <pre style={{
            margin:0, padding:'12px 14px',
            fontFamily:'Share Tech Mono,monospace',
            fontSize:9, color:'#4a6a4a',
            maxHeight:320, overflowY:'auto',
            lineHeight:1.6, whiteSpace:'pre-wrap',
          }}>
            <code dangerouslySetInnerHTML={{__html:
              script
                .replace(/\/\/ ──.*$/gm, m => `<span style="color:#1a3a1a">${m}</span>`)
                .replace(/(vlog\()/g, '<span style="color:#00e664">$1</span>')
                .replace(/(function|var|try|catch|forEach|return)/g,
                  '<span style="color:#a78bfa">$1</span>')
                .replace(/('[^']*')/g, '<span style="color:#ffc107">$1</span>')
            }}/>
          </pre>
        </div>
      )}

      {/* Usage instructions */}
      {script && (
        <div style={{
          background:'#0c110c', border:'1px solid #1a2a1a',
          borderRadius:4, padding:'10px 14px',
          fontFamily:'Share Tech Mono,monospace', fontSize:9,
          color:'#3a6a3a', lineHeight:2,
        }}>
          <div style={{color:'#4a6a4a', marginBottom:4}}>USAGE:</div>
          <div>1. frida-server'ı cihazda başlat</div>
          <div style={{color:'#2a4a2a'}}>
            {'  adb shell /data/local/tmp/frida-server &'}
          </div>
          <div>2. Script'i çalıştır</div>
          <div style={{color:'#2a4a2a'}}>
            {`  frida -U -f ${packageName} -l vengam_hooks.js --no-pause`}
          </div>
        </div>
      )}
    </div>
  );
}
