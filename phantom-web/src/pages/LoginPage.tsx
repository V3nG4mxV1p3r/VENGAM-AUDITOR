/**
 * VENGAM — Login Page
 */
import { useState } from 'react';
import { login } from '../api/client';

interface Props { onLogin: () => void; }

export default function LoginPage({ onLogin }: Props) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [loading,  setLoading]  = useState(false);
  const [error,    setError]    = useState('');

  const handleLogin = async () => {
    if (!username || !password) return;
    setLoading(true); setError('');
    try {
      const ok = await login(username, password);
      if (ok) onLogin();
      else setError('Geçersiz kullanıcı adı veya şifre.');
    } catch { setError('Sunucuya bağlanılamadı.'); }
    finally { setLoading(false); }
  };

  return (
    <div style={{
      minHeight:'100vh', background:'#070a07',
      display:'flex', alignItems:'center', justifyContent:'center',
    }}>
      <div style={{
        background:'#0c110c', border:'1px solid #1a2a1a',
        borderRadius:10, padding:'40px 44px', width:360,
      }}>
        {/* Logo */}
        <div style={{ textAlign:'center', marginBottom:32 }}>
          <svg width="52" height="52" viewBox="0 0 200 200" fill="none" style={{margin:'0 auto 12px'}}>
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
          </svg>
          <div style={{ fontFamily:'Rajdhani,sans-serif', fontSize:22, fontWeight:700, color:'#00e664', letterSpacing:3 }}>VENGAM</div>
          <div style={{ fontFamily:'Share Tech Mono,monospace', fontSize:9, color:'#3a6a3a', letterSpacing:5, marginTop:3 }}>AUDITOR</div>
        </div>

        {/* Form */}
        <div style={{ display:'flex', flexDirection:'column', gap:12 }}>
          <input
            value={username}
            onChange={e => setUsername(e.target.value)}
            placeholder="Kullanıcı adı"
            autoFocus
            onKeyDown={e => e.key === 'Enter' && handleLogin()}
            style={{
              background:'#141e14', border:'1px solid #1a2a1a',
              borderRadius:5, padding:'10px 14px',
              fontFamily:'Share Tech Mono,monospace', fontSize:11,
              color:'#d0ecd0', outline:'none', width:'100%',
            }}
          />
          <input
            type="password"
            value={password}
            onChange={e => setPassword(e.target.value)}
            placeholder="Şifre"
            onKeyDown={e => e.key === 'Enter' && handleLogin()}
            style={{
              background:'#141e14', border:'1px solid #1a2a1a',
              borderRadius:5, padding:'10px 14px',
              fontFamily:'Share Tech Mono,monospace', fontSize:11,
              color:'#d0ecd0', outline:'none', width:'100%',
            }}
          />

          {error && (
            <div style={{
              padding:'8px 12px', background:'rgba(229,57,53,.1)',
              border:'1px solid rgba(229,57,53,.3)', borderRadius:4,
              fontFamily:'Share Tech Mono,monospace', fontSize:9, color:'#e53935',
            }}>⚠ {error}</div>
          )}

          <button onClick={handleLogin} disabled={loading || !username || !password} style={{
            padding:'11px', background: (!username||!password||loading) ? '#1a2a1a' : '#00e664',
            border:'none', borderRadius:5, cursor:'pointer',
            fontFamily:'Share Tech Mono,monospace', fontSize:11,
            fontWeight:700, letterSpacing:2,
            color: (!username||!password||loading) ? '#3a6a3a' : '#000',
            transition:'all .2s',
            boxShadow: (!username||!password||loading) ? 'none' : '0 0 14px rgba(0,230,100,.3)',
          }}>
            {loading ? 'GİRİŞ YAPILIYOR...' : 'GİRİŞ YAP'}
          </button>
        </div>

        <div style={{
          marginTop:20, textAlign:'center',
          fontFamily:'Share Tech Mono,monospace', fontSize:9, color:'#2a4a2a',
        }}>
          İlk çalıştırmada admin şifresi terminal'de gösterilir.
        </div>
      </div>
    </div>
  );
}
