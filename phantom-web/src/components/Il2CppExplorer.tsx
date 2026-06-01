/**
 * VENGAM — IL2CPP Explorer
 * Unity IL2CPP analiz sonuçlarını gösterir.
 * Class/method listesi, security hit'ler, Frida hook önerileri.
 */
import { useState } from 'react';

interface SecurityHit {
  category:   string;
  severity:   string;
  name:       string;
  context:    string;
  frida_hook: string;
  score:      number;
}

interface Il2CppClass {
  name:      string;
  namespace: string;
  methods:   { name: string; class_name: string }[];
}

interface Il2CppData {
  version:       number;
  class_count:   number;
  method_count:  number;
  string_count:  number;
  classes:       Il2CppClass[];
  security_hits: SecurityHit[];
  raw_strings:   string[];
}

interface Props {
  data: Il2CppData | null;
}

const SEV_COLOR: Record<string, string> = {
  CRITICAL: '#e53935',
  HIGH:     '#ff8c00',
  MEDIUM:   '#ffc107',
  LOW:      '#4caf50',
};

const CAT_COLOR: Record<string, string> = {
  'Anti-Cheat':    '#e53935',
  'IAP Validation':'#ff8c00',
  'Economy':       '#ffc107',
  'Crypto':        '#a78bfa',
  'Auth':          '#4facfe',
  'Hidden Admin':  '#e53935',
  'Debug Flag':    '#ff8c00',
  'Root Detection':'#ff8c00',
};

export default function Il2CppExplorer({ data }: Props) {
  const [tab,      setTab]      = useState<'hits'|'classes'|'strings'>('hits');
  const [hookView, setHookView] = useState<string | null>(null);
  const [search,   setSearch]   = useState('');
  const [copied,   setCopied]   = useState<string | null>(null);

  const copy = async (text: string, id: string) => {
    await navigator.clipboard.writeText(text);
    setCopied(id);
    setTimeout(() => setCopied(null), 2000);
  };

  if (!data) return (
    <div style={{
      background:'#0c110c', border:'1px solid #1a2a1a',
      borderRadius:6, padding:'40px 20px', textAlign:'center',
      fontFamily:'Share Tech Mono,monospace', fontSize:11, color:'#2a4a2a',
    }}>
      No IL2CPP metadata found — not a Unity IL2CPP project, or metadata not extracted.
    </div>
  );

  const filteredHits = data.security_hits.filter(h =>
    !search || h.name.toLowerCase().includes(search.toLowerCase()) ||
    h.category.toLowerCase().includes(search.toLowerCase())
  );

  const filteredClasses = data.classes.filter(c =>
    !search || c.name.toLowerCase().includes(search.toLowerCase()) ||
    c.namespace.toLowerCase().includes(search.toLowerCase())
  );

  const filteredStrings = data.raw_strings.filter(s =>
    !search || s.toLowerCase().includes(search.toLowerCase())
  ).slice(0, 100);

  return (
    <div style={{ display:'flex', flexDirection:'column', gap:10 }}>

      {/* Header stats */}
      <div style={{
        display:'grid', gridTemplateColumns:'repeat(4,1fr)', gap:8,
      }}>
        {[
          ['VERSION',  `v${data.version}`],
          ['CLASSES',  data.class_count],
          ['METHODS',  data.method_count],
          ['SEC HITS', data.security_hits.length],
        ].map(([label, value]) => (
          <div key={label} style={{
            background:'#0c110c', border:'1px solid #1a2a1a',
            borderRadius:6, padding:'10px 12px',
          }}>
            <div style={{
              fontFamily:'Share Tech Mono,monospace',
              fontSize: 20, fontWeight:700,
              color: label==='SEC HITS' && Number(value)>0 ? '#ff8c00' : '#00e664',
            }}>{value}</div>
            <div style={{
              fontFamily:'Share Tech Mono,monospace',
              fontSize:8, color:'#3a6a3a', marginTop:3, letterSpacing:1,
            }}>{label}</div>
          </div>
        ))}
      </div>

      {/* Search */}
      <input
        value={search}
        onChange={e => setSearch(e.target.value)}
        placeholder="Search classes, methods, hits..."
        style={{
          background:'#0c110c', border:'1px solid #1a2a1a',
          borderRadius:4, padding:'8px 12px',
          fontFamily:'Share Tech Mono,monospace', fontSize:10,
          color:'#d0ecd0', outline:'none', width:'100%',
        }}
      />

      {/* Tabs */}
      <div style={{ display:'flex', gap:4 }}>
        {([
          ['hits',    `Security Hits (${data.security_hits.length})`],
          ['classes', `Classes (${data.classes.length})`],
          ['strings', `Strings (${data.raw_strings.length})`],
        ] as [string,string][]).map(([t, label]) => (
          <button key={t} onClick={() => setTab(t as typeof tab)} style={{
            fontFamily:'Share Tech Mono,monospace', fontSize:9,
            letterSpacing:1, padding:'5px 12px', borderRadius:4,
            cursor:'pointer',
            border:`1px solid ${tab===t ? '#00e664':'#1a2a1a'}`,
            background: tab===t ? 'rgba(0,230,100,0.08)':'transparent',
            color: tab===t ? '#00e664':'#4a6a4a',
          }}>{label}</button>
        ))}
      </div>

      {/* Security Hits tab */}
      {tab === 'hits' && (
        <div style={{ display:'flex', flexDirection:'column', gap:6 }}>
          {filteredHits.length === 0 ? (
            <div style={{
              fontFamily:'Share Tech Mono,monospace', fontSize:10,
              color:'#2a4a2a', padding:'20px 0', textAlign:'center',
            }}>No security hits found.</div>
          ) : filteredHits.map((hit, i) => (
            <div key={i} style={{
              background:'#0c110c', border:`1px solid #1a2a1a`,
              borderRadius:6, overflow:'hidden',
            }}>
              <div style={{
                display:'flex', alignItems:'center', gap:10,
                padding:'10px 14px', cursor:'pointer',
              }} onClick={() => setHookView(hookView===hit.name ? null : hit.name)}>
                <div style={{
                  width:7, height:7, borderRadius:'50%', flexShrink:0,
                  background: SEV_COLOR[hit.severity] || '#607d8b',
                  boxShadow: hit.severity==='CRITICAL'
                    ? `0 0 6px ${SEV_COLOR.CRITICAL}` : 'none',
                }}/>
                <span style={{
                  fontFamily:'Share Tech Mono,monospace',
                  fontSize:11, color:'#d0ecd0', flex:1,
                }}>{hit.name}</span>
                <span style={{
                  fontFamily:'Share Tech Mono,monospace', fontSize:8,
                  padding:'2px 8px', borderRadius:3,
                  background:`${CAT_COLOR[hit.category]||'#607d8b'}18`,
                  color: CAT_COLOR[hit.category] || '#607d8b',
                }}>{hit.category}</span>
                <span style={{
                  fontFamily:'Share Tech Mono,monospace', fontSize:8,
                  color: SEV_COLOR[hit.severity]||'#607d8b',
                  background:'#141e14', padding:'2px 7px', borderRadius:3,
                }}>{hit.severity}</span>
                <span style={{color:'#2a4a2a',fontSize:9}}>
                  {hookView===hit.name?'▲':'▼'}
                </span>
              </div>

              {hookView === hit.name && (
                <div style={{
                  padding:'0 14px 12px',
                  borderTop:'1px solid #1a2a1a',
                }}>
                  <div style={{
                    marginTop:10,
                    fontFamily:'Share Tech Mono,monospace',
                    fontSize:9, color:'#4a6a4a', marginBottom:8,
                  }}>{hit.context}</div>

                  {hit.frida_hook && (
                    <div style={{
                      background:'#070a07', borderRadius:4, overflow:'hidden',
                      border:'1px solid #1a2a1a',
                    }}>
                      <div style={{
                        display:'flex', alignItems:'center',
                        padding:'5px 10px', background:'#0c110c',
                        borderBottom:'1px solid #1a2a1a',
                        gap:8,
                      }}>
                        <span style={{
                          fontFamily:'Share Tech Mono,monospace',
                          fontSize:8, color:'#3a6a3a', flex:1,
                        }}>FRIDA HOOK</span>
                        <button onClick={() => copy(hit.frida_hook, hit.name)} style={{
                          fontFamily:'Share Tech Mono,monospace', fontSize:8,
                          padding:'3px 10px', border:'1px solid #1a2a1a',
                          borderRadius:3, cursor:'pointer',
                          background: copied===hit.name
                            ? 'rgba(0,230,100,0.1)' : 'transparent',
                          color: copied===hit.name ? '#00e664' : '#3a6a3a',
                        }}>
                          {copied===hit.name ? '✓ COPIED' : 'COPY'}
                        </button>
                      </div>
                      <pre style={{
                        margin:0, padding:'10px 12px',
                        fontFamily:'Share Tech Mono,monospace',
                        fontSize:9, color:'#4a6a4a',
                        maxHeight:160, overflowY:'auto',
                        lineHeight:1.6, whiteSpace:'pre-wrap',
                      }}>{hit.frida_hook}</pre>
                    </div>
                  )}

                  <div style={{
                    marginTop:6, fontFamily:'Share Tech Mono,monospace',
                    fontSize:8, color:'#2a4a2a',
                  }}>Score impact: +{hit.score}pts</div>
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {/* Classes tab */}
      {tab === 'classes' && (
        <div style={{
          background:'#0c110c', border:'1px solid #1a2a1a',
          borderRadius:6, overflow:'hidden',
          maxHeight:400, overflowY:'auto',
        }}>
          {filteredClasses.length === 0 ? (
            <div style={{
              fontFamily:'Share Tech Mono,monospace', fontSize:10,
              color:'#2a4a2a', padding:'20px', textAlign:'center',
            }}>No classes found.</div>
          ) : filteredClasses.map((cls, i) => (
            <div key={i} style={{
              padding:'8px 14px',
              borderBottom:'1px solid #1a2a1a',
              fontFamily:'Share Tech Mono,monospace',
            }}>
              <div style={{ display:'flex', gap:8, alignItems:'center' }}>
                <span style={{ fontSize:10, color:'#00e664' }}>
                  {cls.namespace ? `${cls.namespace}.` : ''}{cls.name}
                </span>
                <span style={{
                  fontSize:8, color:'#3a6a3a', background:'#141e14',
                  padding:'1px 6px', borderRadius:3, marginLeft:'auto',
                }}>
                  {cls.methods.length} methods
                </span>
              </div>
              {cls.methods.slice(0,5).map((m, j) => (
                <div key={j} style={{
                  fontSize:9, color:'#3a6a3a',
                  paddingLeft:12, marginTop:2,
                }}>
                  ↳ {m.name}
                </div>
              ))}
              {cls.methods.length > 5 && (
                <div style={{
                  fontSize:8, color:'#2a4a2a', paddingLeft:12, marginTop:2,
                }}>... +{cls.methods.length-5} more</div>
              )}
            </div>
          ))}
        </div>
      )}

      {/* Strings tab */}
      {tab === 'strings' && (
        <div style={{
          background:'#0c110c', border:'1px solid #1a2a1a',
          borderRadius:6, overflow:'hidden',
          maxHeight:400, overflowY:'auto',
        }}>
          {filteredStrings.map((s, i) => (
            <div key={i} style={{
              padding:'4px 14px',
              borderBottom:'1px solid #0f150f',
              fontFamily:'Share Tech Mono,monospace',
              fontSize:9, color:'#3a6a3a',
              display:'flex', gap:8,
            }}>
              <span style={{ color:'#1a2a1a', minWidth:36 }}>{i+1}</span>
              <span style={{ color:'#4a7a4a', flex:1,
                overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap',
              }}>{s}</span>
            </div>
          ))}
          {data.raw_strings.length > 100 && (
            <div style={{
              padding:'8px 14px',
              fontFamily:'Share Tech Mono,monospace',
              fontSize:9, color:'#2a4a2a', textAlign:'center',
            }}>
              Showing 100 of {data.raw_strings.length} strings
            </div>
          )}
        </div>
      )}
    </div>
  );
}
