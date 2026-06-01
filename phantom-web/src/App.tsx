/**
 * VENGAM Auditor — App v2
 * Auth + Scan + History + Intel sayfaları tam entegre
 */
import { useState, useEffect } from 'react';
import LoginPage    from './pages/LoginPage';
import IntelPage    from './pages/IntelPage';
import {
  isLoggedIn, logout, getCurrentUser,
  scanAndroid, scanIos, getScanHistory, deleteScan,
  reportUrl,
} from './api/client';
import type { ScanResponse, ScanSummary, Finding } from './api/client';

// ── Renkler ───────────────────────────────────────────────────────
const SEV_COLOR: Record<string, string> = {
  CRITICAL:'#e53935', HIGH:'#ff8c00', MEDIUM:'#ffc107', LOW:'#4caf50', INFO:'#607d8b',
};
const CAT_CLS: Record<string, string> = {
  General:'#4facfe', AntiCheat:'#e53935', Economy:'#ffc107',
  Config:'#7a9a7a', GameEngine:'#00e664',
};

const STEPS = [
  'Uploading...','Decompiling...','Pattern engine...','Entropy analysis...',
  'FP filter...','Attack surface...','Generating reports...',
];

type Page = 'scan' | 'history' | 'intel';

// ── VIPER LOGO SVG ────────────────────────────────────────────────
function ViperLogo({ size = 38 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 200 200" fill="none"
      style={{ filter:'drop-shadow(0 0 6px rgba(0,230,100,.25))' }}>
      <path d="M73 151 C79 139 89 129 101 127 C116 124 130 131 133 144 C137 158 129 170 116 172 C103 174 91 167 86 157 C81 149 83 139 91 134" stroke="#0a1e0a" strokeWidth="32" fill="none" strokeLinecap="round"/>
      <path d="M73 151 C79 139 89 129 101 127 C116 124 130 131 133 144 C137 158 129 170 116 172 C103 174 91 167 86 157 C81 149 83 139 91 134" stroke="#0d6628" strokeWidth="22" fill="none" strokeLinecap="round"/>
      <path d="M91 134 C97 124 109 111 121 104 C136 96 151 97 159 109 C166 120 163 135 153 142 C143 149 129 148 119 140 C109 132 107 117 116 109" stroke="#0a1e0a" strokeWidth="32" fill="none" strokeLinecap="round"/>
      <path d="M91 134 C97 124 109 111 121 104 C136 96 151 97 159 109 C166 120 163 135 153 142 C143 149 129 148 119 140 C109 132 107 117 116 109" stroke="#0d6628" strokeWidth="22" fill="none" strokeLinecap="round"/>
      <path d="M116 109 C119 99 123 87 131 77 C139 67 149 59 156 51" stroke="#0a1e0a" strokeWidth="28" fill="none" strokeLinecap="round"/>
      <path d="M116 109 C119 99 123 87 131 77 C139 67 149 59 156 51" stroke="#0d6628" strokeWidth="18" fill="none" strokeLinecap="round"/>
      <path d="M147 38 C157 30 172 26 181 32 C189 39 186 53 178 59 C170 66 157 66 149 59 C141 52 140 42 147 38Z" fill="#0d6628"/>
      <path d="M149 59 C146 67 144 74 149 78 C155 82 163 78 169 71" fill="#070f07"/>
      <path d="M151 69 L148 80 L154 73Z" fill="#d4ffd4"/>
      <path d="M159 66 L156 76 L162 70Z" fill="#d4ffd4"/>
      <path d="M143 71 C136 69 129 65 125 60" stroke="#ee2233" strokeWidth="2.2" fill="none" strokeLinecap="round"/>
      <path d="M125 60 L121 55 M125 60 L121 65" stroke="#ee2233" strokeWidth="1.8" fill="none" strokeLinecap="round"/>
      <ellipse cx="172" cy="40" rx="8" ry="7" fill="#000"/>
      <ellipse cx="172" cy="40" rx="5.5" ry="4.5" fill="#00e664"/>
      <ellipse cx="172" cy="40" rx="2.8" ry="4.5" fill="#000" transform="rotate(15 172 40)"/>
      <ellipse cx="170" cy="38" rx="1.4" ry="1" fill="#fff" opacity="0.85"/>
      <path d="M97 141 L97 146 L103 146 L103 151" stroke="#00e664" strokeWidth="1.1" fill="none" opacity="0.75"/>
      <circle cx="97" cy="141" r="2.2" fill="none" stroke="#00e664" strokeWidth="1.1" opacity="0.75"/>
      <circle cx="103" cy="151" r="2.2" fill="#00e664" opacity="0.65"/>
    </svg>
  );
}

// ── Finding Card ──────────────────────────────────────────────────
function FindingCard({ f }: { f: Finding }) {
  const [open, setOpen] = useState(false);
  const dot   = SEV_COLOR[f.severity] || '#607d8b';
  const catClr= CAT_CLS[f.category]  || '#7a9a7a';
  return (
    <div style={{
      background:'#0c110c', border:'1px solid #1a2a1a',
      borderRadius:6, marginBottom:7, overflow:'hidden',
    }}>
      <div onClick={() => setOpen(o=>!o)} style={{
        display:'flex', alignItems:'center', gap:10,
        padding:'10px 14px', cursor:'pointer',
      }}>
        <div style={{
          width:7, height:7, borderRadius:'50%', flexShrink:0,
          background:dot,
          boxShadow: f.severity==='CRITICAL' ? `0 0 6px ${dot}` : 'none',
        }}/>
        <span style={{ fontFamily:'Rajdhani,sans-serif', fontSize:13, fontWeight:600, flex:1, color:'#d0ecd0' }}>
          {f.title}
        </span>
        <span style={{
          fontFamily:'Share Tech Mono,monospace', fontSize:8,
          padding:'2px 7px', borderRadius:3,
          background:`${catClr}18`, color:catClr,
        }}>{f.category}</span>
        <span style={{
          fontFamily:'Share Tech Mono,monospace', fontSize:9,
          color:'#4a6a4a', background:'#141e14', padding:'2px 8px', borderRadius:3,
        }}>+{f.score_value}pts</span>
        <span style={{ fontSize:8, color:'#2a4a2a' }}>{open?'▲':'▼'}</span>
      </div>
      {open && (
        <div style={{ padding:'0 14px 12px', borderTop:'1px solid #1a2a1a' }}>
          <div style={{ display:'flex', gap:6, flexWrap:'wrap', marginTop:10 }}>
            {[['Confidence',f.confidence],['Exploitability',f.exploitability],
              f.cwe_id?['CWE',f.cwe_id]:null, f.owasp_ref?['OWASP',f.owasp_ref]:null,
            ].filter(Boolean).map(([k,v])=>(
              <span key={k} style={{
                fontFamily:'Share Tech Mono,monospace', fontSize:8,
                padding:'2px 8px', background:'#141e14', borderRadius:3, color:'#4a6a4a',
              }}>{k}: <span style={{color:'#d0ecd0'}}>{v}</span></span>
            ))}
          </div>
          <p style={{ fontFamily:'Rajdhani,sans-serif', fontSize:12, color:'#7a9a7a', lineHeight:1.7, marginTop:9 }}>
            {f.description}
          </p>
          <div style={{
            background:'#0a0d0a', borderLeft:'2px solid #e53935',
            padding:'8px 12px', borderRadius:'0 4px 4px 0', marginTop:8,
            fontFamily:'Share Tech Mono,monospace', fontSize:9, color:'#4a6a4a',
          }}>⚔ {f.simulation}</div>
          {f.triage_note && (
            <div style={{
              background:'#0a0d0a', borderLeft:'2px solid #00e664',
              padding:'8px 12px', borderRadius:'0 4px 4px 0', marginTop:6,
              fontFamily:'Share Tech Mono,monospace', fontSize:9, color:'#3a6a3a',
            }}>▶ {f.triage_note}</div>
          )}
          {f.locations?.slice(0,5).map((loc,i)=>(
            <div key={i} style={{
              display:'flex', gap:8, marginTop:3,
              fontFamily:'Share Tech Mono,monospace', fontSize:9,
              color:'#4a6a4a', background:'#0a0d0a',
              padding:'4px 8px', borderRadius:3,
            }}>
              <span style={{color:'#00e664',flexShrink:0}}>:{loc.line}</span>
              <span style={{flex:1,overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>{loc.file}</span>
              {loc.redacted_match && <span style={{color:'#ff8c00',flexShrink:0}}>{loc.redacted_match}</span>}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Main App ──────────────────────────────────────────────────────
export default function App() {
  const [authed,    setAuthed]    = useState(isLoggedIn());
  const [user,      setUser]      = useState<{username:string;role:string}|null>(null);
  const [page,      setPage]      = useState<Page>('scan');
  const [file,      setFile]      = useState<File|null>(null);
  const [platform,  setPlatform]  = useState<'android'|'ios'>('android');
  const [scanning,  setScanning]  = useState(false);
  const [stepIdx,   setStepIdx]   = useState(0);
  const [result,    setResult]    = useState<ScanResponse|null>(null);
  const [history,   setHistory]   = useState<ScanSummary[]>([]);
  const [sevFilter, setSevFilter] = useState('ALL');
  const [error,     setError]     = useState('');

  useEffect(() => {
    if (authed) getCurrentUser().then(setUser);
  }, [authed]);

  const handleLogout = async () => {
    await logout();
    setAuthed(false);
    setResult(null);
  };

  const handleFile = (f: File) => {
    setFile(f);
    if (f.name.endsWith('.ipa')) setPlatform('ios');
    else setPlatform('android');
  };

  const runScan = async () => {
    if (!file) return;
    setScanning(true); setError(''); setResult(null); setStepIdx(0);
    const timer = setInterval(() =>
      setStepIdx(i => Math.min(i+1, STEPS.length-1)), 2400);
    try {
      const res = platform === 'ios'
        ? await scanIos(file)
        : await scanAndroid(file);
      setResult(res);
      setPage('scan');
    } catch(e: any) {
      setError(e.message || 'Scan failed');
    } finally {
      clearInterval(timer);
      setScanning(false);
    }
  };

  const loadHistory = async () => {
    const data = await getScanHistory();
    setHistory(data.scans);
  };

  const filtered = result
    ? (sevFilter==='ALL' ? result.findings : result.findings.filter(f=>f.severity===sevFilter))
    : [];

  if (!authed) return <LoginPage onLogin={() => setAuthed(true)} />;

  const sc = result?.risk_score || 0;
  const scColor = sc>=75?'#e53935':sc>=40?'#ff8c00':'#00e664';

  return (
    <div style={{ minHeight:'100vh', background:'#070a07', color:'#d0ecd0',
      fontFamily:'Rajdhani,sans-serif', display:'flex', flexDirection:'column' }}>

      {/* Header */}
      <header style={{
        height:54, background:'#0c110c', borderBottom:'1px solid #1a2a1a',
        display:'flex', alignItems:'center', padding:'0 18px', gap:12,
        position:'sticky', top:0, zIndex:100,
      }}>
        <ViperLogo size={36}/>
        <div>
          <div style={{ fontSize:18, fontWeight:700, color:'#00e664', letterSpacing:3 }}>VENGAM</div>
          <div style={{ fontFamily:'Share Tech Mono,monospace', fontSize:8, color:'#2a4a2a', letterSpacing:4 }}>AUDITOR</div>
        </div>
        <span style={{
          fontFamily:'Share Tech Mono,monospace', fontSize:8,
          background:'#141e14', color:'#3a6a3a', padding:'2px 7px', borderRadius:3, border:'1px solid #1a2a1a',
        }}>v7.0.0</span>

        <div style={{ display:'flex', gap:3, marginLeft:'auto' }}>
          {(['scan','history','intel'] as Page[]).map(p => (
            <button key={p} onClick={() => { setPage(p); if(p==='history') loadHistory(); }} style={{
              fontFamily:'Share Tech Mono,monospace', fontSize:9, letterSpacing:1,
              padding:'5px 13px', borderRadius:4, cursor:'pointer',
              border:`1px solid ${page===p?'#00e664':'#1a2a1a'}`,
              background: page===p?'rgba(0,230,100,0.08)':'transparent',
              color: page===p?'#00e664':'#4a6a4a',
            }}>
              {p==='scan'?'SCAN':p==='history'?'HISTORY':'INTEL'}
            </button>
          ))}
        </div>

        <button onClick={() => runScan()} disabled={!file||scanning} style={{
          fontFamily:'Share Tech Mono,monospace', fontSize:9, fontWeight:700, letterSpacing:2,
          padding:'6px 16px', borderRadius:4, cursor:'pointer', border:'none',
          background: file&&!scanning?'#00e664':'#1a2a1a',
          color: file&&!scanning?'#000':'#3a6a3a',
          boxShadow: file&&!scanning?'0 0 10px rgba(0,230,100,.3)':'none',
        }}>+ NEW SCAN</button>

        {user && (
          <div style={{ display:'flex', alignItems:'center', gap:8 }}>
            <span style={{ fontFamily:'Share Tech Mono,monospace', fontSize:9, color:'#3a6a3a' }}>
              {user.username}
            </span>
            <button onClick={handleLogout} style={{
              fontFamily:'Share Tech Mono,monospace', fontSize:8,
              padding:'4px 10px', border:'1px solid #1a2a1a',
              background:'transparent', color:'#3a6a3a', borderRadius:3, cursor:'pointer',
            }}>LOGOUT</button>
          </div>
        )}
      </header>

      {/* Body */}
      <div style={{ display:'flex', flex:1, overflow:'hidden' }}>

        {/* Sidebar */}
        <div style={{
          width:200, background:'#0c110c', borderRight:'1px solid #1a2a1a',
          display:'flex', flexDirection:'column', overflow:'hidden',
        }}>
          {[
            ['ALL','All Findings', result?.findings.length||0, '#d0ecd0'],
            ['CRITICAL','Critical', result?.findings.filter(f=>f.severity==='CRITICAL').length||0, '#e53935'],
            ['HIGH','High',         result?.findings.filter(f=>f.severity==='HIGH').length||0,     '#ff8c00'],
            ['MEDIUM','Medium',     result?.findings.filter(f=>f.severity==='MEDIUM').length||0,   '#ffc107'],
            ['LOW','Low',           result?.findings.filter(f=>f.severity==='LOW').length||0,      '#4caf50'],
          ].map(([sev,label,cnt,clr])=>(
            <div key={sev as string} onClick={()=>setSevFilter(sev as string)} style={{
              display:'flex', alignItems:'center', gap:10, padding:'8px 14px',
              cursor:'pointer', borderLeft:`2px solid ${sevFilter===sev?clr:'transparent'}`,
              background: sevFilter===sev?`${clr}10`:'transparent',
              fontFamily:'Share Tech Mono,monospace', fontSize:10,
              color: sevFilter===sev?clr as string:'#4a6a4a',
            }}>
              <span style={{ flex:1 }}>{label as string}</span>
              <span style={{
                fontSize:8, background:'#141e14', padding:'1px 6px', borderRadius:10,
                color: sevFilter===sev?clr as string:'#3a6a3a',
              }}>{cnt as number}</span>
            </div>
          ))}

          <div style={{ height:1, background:'#1a2a1a', margin:'8px 14px' }}/>

          {result && ['txt','json','sarif','pdf'].map(fmt => (
            <div key={fmt} onClick={() => window.open(reportUrl(result.scan_id,fmt))} style={{
              display:'flex', alignItems:'center', gap:10, padding:'7px 14px',
              cursor:'pointer', fontFamily:'Share Tech Mono,monospace', fontSize:10, color:'#4a6a4a',
            }}>
              <span>{fmt==='txt'?'📄':fmt==='json'?'⚙':fmt==='sarif'?'🔬':'📑'}</span>
              <span>{fmt.toUpperCase()} Report</span>
            </div>
          ))}
        </div>

        {/* Main content */}
        <div style={{ flex:1, overflow:'hidden', display:'flex', flexDirection:'column' }}>

          {/* SCAN PAGE */}
          {page === 'scan' && !result && (
            <div style={{ flex:1, display:'flex', alignItems:'center', justifyContent:'center', padding:30 }}>
              <div style={{ width:'100%', maxWidth:440, display:'flex', flexDirection:'column', gap:12 }}>
                {/* Drop zone */}
                <div
                  onClick={() => document.getElementById('apk-file-input')?.click()}
                  style={{
                    background:'#0c110c', border:'1px dashed #1a2a1a',
                    borderRadius:8, padding:'44px 32px', textAlign:'center', cursor:'pointer',
                    transition:'all .2s',
                  }}
                  onDragOver={e => e.preventDefault()}
                  onDrop={e => { e.preventDefault(); const f=e.dataTransfer.files[0]; if(f) handleFile(f); }}
                >
                  <input id="apk-file-input" type="file" accept=".apk,.ipa"
                    style={{ display:'none' }}
                    onChange={e => { const f=e.target.files?.[0]; if(f) handleFile(f); }}
                  />
                  <div style={{ fontSize:38, marginBottom:12, color:'#1a4a1a' }}>⬆</div>
                  <div style={{ fontSize:16, fontWeight:600, color:'#d0ecd0' }}>Drop APK / IPA here</div>
                  <div style={{ fontFamily:'Share Tech Mono,monospace', fontSize:10, color:'#3a6a3a', marginTop:6 }}>
                    or click to browse
                  </div>
                  {file && (
                    <div style={{ marginTop:12, fontFamily:'Share Tech Mono,monospace', fontSize:10, color:'#00e664' }}>
                      ✓ {file.name}
                    </div>
                  )}
                </div>

                {/* Platform + scan */}
                <div style={{ display:'flex', gap:8 }}>
                  {(['android','ios'] as const).map(p=>(
                    <button key={p} onClick={()=>setPlatform(p)} style={{
                      flex:1, padding:'8px', borderRadius:4, cursor:'pointer',
                      border:`1px solid ${platform===p?'#00e664':'#1a2a1a'}`,
                      background: platform===p?'rgba(0,230,100,.08)':'transparent',
                      color: platform===p?'#00e664':'#4a6a4a',
                      fontFamily:'Share Tech Mono,monospace', fontSize:10, letterSpacing:1,
                    }}>{p.toUpperCase()}</button>
                  ))}
                </div>

                <button onClick={runScan} disabled={!file||scanning} style={{
                  padding:14, border:'none', borderRadius:6, cursor:file?'pointer':'not-allowed',
                  background: file&&!scanning?'#00e664':'#1a2a1a',
                  color: file&&!scanning?'#000':'#3a6a3a',
                  fontFamily:'Share Tech Mono,monospace', fontSize:11, fontWeight:700, letterSpacing:2,
                  boxShadow: file&&!scanning?'0 0 14px rgba(0,230,100,.3)':'none',
                }}>
                  {scanning ? STEPS[stepIdx] : 'RUN SECURITY AUDIT'}
                </button>

                {scanning && (
                  <div>
                    <div style={{ height:3, background:'#1a2a1a', borderRadius:2, overflow:'hidden' }}>
                      <div style={{
                        height:'100%', background:'#00e664', borderRadius:2,
                        width:`${((stepIdx+1)/STEPS.length)*100}%`, transition:'width .4s',
                        boxShadow:'0 0 8px rgba(0,230,100,.4)',
                      }}/>
                    </div>
                    <div style={{ fontFamily:'Share Tech Mono,monospace', fontSize:9, color:'#3a6a3a', marginTop:5 }}>
                      {STEPS[stepIdx]}
                    </div>
                  </div>
                )}

                {error && (
                  <div style={{
                    padding:'10px 14px', background:'rgba(229,57,53,.1)',
                    border:'1px solid rgba(229,57,53,.3)', borderRadius:6,
                    fontFamily:'Share Tech Mono,monospace', fontSize:9, color:'#e53935',
                  }}>⚠ {error}</div>
                )}
              </div>
            </div>
          )}

          {/* RESULTS */}
          {page === 'scan' && result && (
            <div style={{ flex:1, display:'flex', flexDirection:'column', overflow:'hidden' }}>
              {/* Top bar */}
              <div style={{
                background:'#0c110c', borderBottom:'1px solid #1a2a1a',
                padding:'10px 18px', display:'flex', alignItems:'center', gap:12,
              }}>
                <button onClick={()=>setResult(null)} style={{
                  fontFamily:'Share Tech Mono,monospace', fontSize:9, padding:'4px 12px',
                  border:'1px solid #1a2a1a', background:'transparent', color:'#4a6a4a',
                  borderRadius:3, cursor:'pointer',
                }}>← New</button>
                <div style={{ flex:1, overflow:'hidden' }}>
                  <div style={{ fontWeight:600, whiteSpace:'nowrap', overflow:'hidden', textOverflow:'ellipsis' }}>
                    {result.apk_name}
                  </div>
                  <div style={{ fontFamily:'Share Tech Mono,monospace', fontSize:9, color:'#3a6a3a' }}>
                    {result.engine_stats.files_scanned.toLocaleString()} files ·{' '}
                    {(result.engine_stats.lines_scanned/1e6).toFixed(1)}M lines ·{' '}
                    {result.engine_stats.fp_suppressed.toLocaleString()} FP ·{' '}
                    {result.engine_stats.scan_duration_sec}s
                  </div>
                </div>
                <div style={{
                  fontFamily:'Share Tech Mono,monospace', fontSize:9, fontWeight:700,
                  padding:'5px 13px', borderRadius:4,
                  background: result.verdict==='BLOCK RELEASE'?'rgba(229,57,53,.12)':
                               result.verdict.includes('AT RISK')?'rgba(255,140,0,.10)':'rgba(0,230,100,.08)',
                  color: result.verdict==='BLOCK RELEASE'?'#e53935':
                         result.verdict.includes('AT RISK')?'#ff8c00':'#00e664',
                  border:`1px solid ${result.verdict==='BLOCK RELEASE'?'rgba(229,57,53,.3)':
                         result.verdict.includes('AT RISK')?'rgba(255,140,0,.3)':'#1a4a1a'}`,
                }}>{result.verdict}</div>
              </div>

              {/* Score row */}
              <div style={{
                display:'grid', gridTemplateColumns:'repeat(5,1fr)', gap:8,
                padding:'10px 18px', borderBottom:'1px solid #1a2a1a',
                background:'#0c110c',
              }}>
                {[
                  [sc+'/100', 'RISK SCORE', scColor],
                  [result.findings.filter(f=>f.severity==='CRITICAL').length, 'CRITICAL', '#e53935'],
                  [result.findings.filter(f=>f.severity==='HIGH').length, 'HIGH', '#ff8c00'],
                  [result.engine_stats.fp_suppressed.toLocaleString(), 'FP SUPPRESSED', '#00e664'],
                  [result.engine_stats.scan_duration_sec+'s', 'DURATION', '#7a9a7a'],
                ].map(([v,l,c])=>(
                  <div key={l as string} style={{
                    background:'#141e14', border:'1px solid #1a2a1a', borderRadius:5, padding:'8px 12px',
                  }}>
                    <div style={{ fontFamily:'Share Tech Mono,monospace', fontSize:20, fontWeight:700, color:c as string }}>
                      {v as string|number}
                    </div>
                    <div style={{ fontFamily:'Share Tech Mono,monospace', fontSize:8, color:'#3a6a3a', marginTop:4, letterSpacing:1 }}>
                      {l as string}
                    </div>
                  </div>
                ))}
              </div>

              {/* Findings */}
              <div style={{ flex:1, overflowY:'auto', padding:'12px 18px' }}>
                <div style={{ display:'flex', gap:6, marginBottom:12, flexWrap:'wrap' }}>
                  {['ALL','CRITICAL','HIGH','MEDIUM','LOW'].map(s=>(
                    <button key={s} onClick={()=>setSevFilter(s)} style={{
                      fontFamily:'Share Tech Mono,monospace', fontSize:9, letterSpacing:1,
                      padding:'4px 12px', borderRadius:20, cursor:'pointer',
                      border:`1px solid ${sevFilter===s?SEV_COLOR[s]||'#00e664':'#1a2a1a'}`,
                      background: sevFilter===s?`${SEV_COLOR[s]||'#00e664'}10`:'transparent',
                      color: sevFilter===s?SEV_COLOR[s]||'#00e664':'#4a6a4a',
                    }}>{s==='ALL'?`All (${result.findings.length})`:s}</button>
                  ))}
                </div>
                {filtered.length===0
                  ? <p style={{ fontFamily:'Share Tech Mono,monospace', fontSize:10, color:'#2a4a2a' }}>
                      No findings for this filter.
                    </p>
                  : filtered.map((f,i) => <FindingCard key={i} f={f}/>)
                }
              </div>
            </div>
          )}

          {/* HISTORY PAGE */}
          {page === 'history' && (
            <div style={{ flex:1, overflowY:'auto', padding:'16px 18px' }}>
              <div style={{
                fontFamily:'Share Tech Mono,monospace', fontSize:9, letterSpacing:2,
                color:'#3a6a3a', marginBottom:14, paddingBottom:8, borderBottom:'1px solid #1a2a1a',
                display:'flex', alignItems:'center', gap:10,
              }}>
                SCAN HISTORY
                <span style={{marginLeft:'auto',color:'#2a4a2a'}}>{history.length} scans</span>
              </div>
              {history.length===0
                ? <div style={{ textAlign:'center', padding:'60px 20px', fontFamily:'Share Tech Mono,monospace', fontSize:10, color:'#2a4a2a' }}>
                    No scans yet.
                  </div>
                : history.map(s => {
                    const sc2 = s.total_score;
                    const c2  = sc2>=75?'#e53935':sc2>=40?'#ff8c00':'#00e664';
                    return (
                      <div key={s.id} style={{
                        background:'#0c110c', border:'1px solid #1a2a1a',
                        borderRadius:6, padding:'12px 16px', marginBottom:8,
                        display:'flex', alignItems:'center', gap:14,
                      }}>
                        <div style={{ fontFamily:'Share Tech Mono,monospace', fontSize:24, fontWeight:700, color:c2, minWidth:44, textAlign:'center' }}>
                          {sc2}
                        </div>
                        <div style={{ flex:1, overflow:'hidden' }}>
                          <div style={{ fontWeight:600, whiteSpace:'nowrap', overflow:'hidden', textOverflow:'ellipsis' }}>{s.apk_name}</div>
                          <div style={{ fontFamily:'Share Tech Mono,monospace', fontSize:9, color:'#3a6a3a', marginTop:2 }}>
                            {s.platform.toUpperCase()} · {new Date(s.scan_timestamp).toLocaleString()} · {s.duration_sec}s
                          </div>
                        </div>
                        <div style={{
                          fontFamily:'Share Tech Mono,monospace', fontSize:8, fontWeight:700,
                          padding:'3px 10px', borderRadius:3,
                          background: s.verdict==='BLOCK RELEASE'?'rgba(229,57,53,.12)':'rgba(0,230,100,.08)',
                          color: s.verdict==='BLOCK RELEASE'?'#e53935':'#00e664',
                          whiteSpace:'nowrap',
                        }}>{s.verdict}</div>
                        {(['txt','json','sarif'] as const).map(fmt=>(
                          <a key={fmt} href={reportUrl(s.id,fmt)} download style={{
                            fontFamily:'Share Tech Mono,monospace', fontSize:9,
                            padding:'3px 9px', border:'1px solid #1a2a1a',
                            borderRadius:3, color:'#4a6a4a', textDecoration:'none',
                          }}>{fmt}</a>
                        ))}
                        <button onClick={()=>deleteScan(s.id).then(loadHistory)} style={{
                          padding:'4px 8px', border:'1px solid #1a2a1a',
                          background:'transparent', color:'#3a6a3a',
                          borderRadius:3, cursor:'pointer', fontSize:12,
                        }}>🗑</button>
                      </div>
                    );
                  })
              }
            </div>
          )}

          {/* INTEL PAGE */}
          {page === 'intel' && (
            <IntelPage
              scanId={result?.scan_id || null}
              findings={result?.findings || []}
              apkName={result?.apk_name || ''}
              pkg=""
            />
          )}

        </div>
      </div>
    </div>
  );
}
