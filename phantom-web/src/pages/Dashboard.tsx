/**
 * VENGAM — Main Dashboard Page
 */
import { useState } from 'react';
import UploadZone from '../components/UploadZone';
import FindingCard from '../components/FindingCard';
import RadarChart from '../components/RadarChart';
import { scanAndroid, scanIos, reportUrl } from '../api/client';
import type { ScanResponse } from '../api/client';

const SEV_COLOR: Record<string, string> = {
  CRITICAL: '#ff3b5c', HIGH: '#ff8c00', MEDIUM: '#ffd700',
  LOW: '#4facfe', INFO: '#6b7280',
};

const STEPS = [
  'Uploading file…', 'Decompiling…', 'Running pattern engine…',
  'Entropy analysis…', 'FP filter…', 'Mapping attack surface…', 'Generating reports…',
];

export default function Dashboard() {
  const [file,       setFile]       = useState<File | null>(null);
  const [platform,   setPlatform]   = useState<'android' | 'ios'>('android');
  const [scanning,   setScanning]   = useState(false);
  const [stepIdx,    setStepIdx]    = useState(0);
  const [result,     setResult]     = useState<ScanResponse | null>(null);
  const [error,      setError]      = useState<string | null>(null);
  const [sevFilter,  setSevFilter]  = useState('ALL');

  const scoreColor = (s: number) =>
    s >= 75 ? '#ff3b5c' : s >= 40 ? '#ff8c00' : '#00f593';

  const runScan = async () => {
    if (!file) return;
    setScanning(true); setError(null); setResult(null); setStepIdx(0);

    const timer = setInterval(() =>
      setStepIdx(i => Math.min(i + 1, STEPS.length - 1)), 2500);

    try {
      const res = platform === 'android'
        ? await scanAndroid(file)
        : await scanIos(file);
      setResult(res);
    } catch (e: any) {
      setError(e.message ?? 'Scan failed');
    } finally {
      clearInterval(timer);
      setScanning(false);
    }
  };

  const filtered = result
    ? (sevFilter === 'ALL'
        ? result.findings
        : result.findings.filter(f => f.severity === sevFilter))
    : [];

  const crit = result?.findings.filter(f => f.severity === 'CRITICAL').length ?? 0;
  const high = result?.findings.filter(f => f.severity === 'HIGH').length ?? 0;

  return (
    <div style={{ maxWidth: 1200, margin: '0 auto', padding: '40px 24px' }}>

      {!result ? (
        /* ── Upload Section ── */
        <div>
          {/* Platform toggle */}
          <div style={{ display: 'flex', gap: 10, marginBottom: 20 }}>
            {(['android', 'ios'] as const).map(p => (
              <button key={p} onClick={() => setPlatform(p)} style={{
                padding: '8px 24px', borderRadius: 6,
                border: `1px solid ${platform === p ? '#4facfe' : '#1e2130'}`,
                background: platform === p ? 'rgba(79,172,254,.1)' : 'transparent',
                color: '#e8eaf0', cursor: 'pointer', fontWeight: 700,
                textTransform: 'uppercase', fontSize: 12, letterSpacing: 1,
              }}>{p}</button>
            ))}
          </div>

          <UploadZone
            onFile={setFile}
            accept={platform === 'android' ? '.apk' : '.ipa'}
            label={`Drop your ${platform.toUpperCase()} file here`}
          />

          <button
            onClick={runScan}
            disabled={!file || scanning}
            style={{
              display: 'block', width: '100%', marginTop: 16,
              padding: 16, background: file && !scanning ? '#ff3b5c' : '#1e2130',
              color: 'white', border: 'none', borderRadius: 8,
              fontSize: 16, fontWeight: 700, cursor: file ? 'pointer' : 'not-allowed',
              transition: 'background 0.2s',
            }}
          >
            {scanning ? `${STEPS[stepIdx]}` : 'Run Security Audit'}
          </button>

          {scanning && (
            <div style={{ marginTop: 12 }}>
              <div style={{ height: 4, background: '#1e2130', borderRadius: 2, overflow: 'hidden' }}>
                <div style={{
                  height: '100%', background: '#ff3b5c',
                  width: `${((stepIdx + 1) / STEPS.length) * 100}%`,
                  transition: 'width 0.4s',
                }} />
              </div>
              <p style={{ fontFamily: 'monospace', fontSize: 12, color: '#6b7280', marginTop: 6 }}>
                {STEPS[stepIdx]}
              </p>
            </div>
          )}

          {error && (
            <div style={{
              marginTop: 16, padding: 14, background: 'rgba(255,59,92,.1)',
              border: '1px solid rgba(255,59,92,.3)', borderRadius: 8,
              color: '#ff3b5c', fontSize: 13,
            }}>⚠️ {error}</div>
          )}
        </div>

      ) : (
        /* ── Results Section ── */
        <div>
          <button
            onClick={() => { setResult(null); setFile(null); }}
            style={{
              marginBottom: 24, padding: '8px 18px', border: '1px solid #1e2130',
              background: 'transparent', color: '#e8eaf0', borderRadius: 6,
              cursor: 'pointer', fontSize: 13,
            }}
          >← New Scan</button>

          {/* Summary row */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16, marginBottom: 24 }}>
            {[
              { label: 'Risk Score', value: `${result.risk_score}/100`, color: scoreColor(result.risk_score) },
              { label: 'Critical',   value: crit, color: '#ff3b5c' },
              { label: 'High',       value: high, color: '#ff8c00' },
              { label: 'FP Suppressed', value: result.engine_stats.fp_suppressed, color: '#6b7280' },
            ].map(({ label, value, color }) => (
              <div key={label} style={{
                background: '#13151c', border: '1px solid #1e2130',
                borderRadius: 10, padding: '20px 24px',
              }}>
                <div style={{ fontSize: 38, fontWeight: 800, color }}>{value}</div>
                <div style={{ fontSize: 11, color: '#6b7280', marginTop: 6, textTransform: 'uppercase', letterSpacing: 1 }}>
                  {label}
                </div>
              </div>
            ))}
          </div>

          {/* Verdict */}
          <div style={{
            background: '#13151c', border: '1px solid #1e2130',
            borderRadius: 10, padding: '16px 24px', marginBottom: 24,
            display: 'flex', alignItems: 'center', gap: 16,
          }}>
            <span style={{
              padding: '8px 20px', borderRadius: 6, fontWeight: 700, fontSize: 14,
              background: result.verdict === 'BLOCK RELEASE'
                ? 'rgba(255,59,92,.15)' : result.verdict.includes('AT RISK')
                ? 'rgba(255,140,0,.15)' : 'rgba(0,245,147,.12)',
              color: result.verdict === 'BLOCK RELEASE' ? '#ff3b5c'
                : result.verdict.includes('AT RISK') ? '#ff8c00' : '#00f593',
              border: `1px solid ${result.verdict === 'BLOCK RELEASE'
                ? 'rgba(255,59,92,.3)' : result.verdict.includes('AT RISK')
                ? 'rgba(255,140,0,.3)' : 'rgba(0,245,147,.25)'}`,
            }}>
              {result.verdict}
            </span>
            <span style={{ fontSize: 13, color: '#6b7280' }}>
              {result.findings.length} findings · {result.engine_stats.files_scanned} files ·{' '}
              {result.engine_stats.lines_scanned.toLocaleString()} lines ·{' '}
              {result.engine_stats.scan_duration_sec}s
            </span>
          </div>

          {/* Two column: findings + radar */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 320px', gap: 24, marginBottom: 24 }}>
            <div>
              {/* Severity filter tabs */}
              <div style={{ display: 'flex', gap: 8, marginBottom: 14, flexWrap: 'wrap' }}>
                {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(s => (
                  <button key={s} onClick={() => setSevFilter(s)} style={{
                    padding: '5px 14px', borderRadius: 20, cursor: 'pointer',
                    border: `1px solid ${sevFilter === s ? '#4facfe' : '#1e2130'}`,
                    background: sevFilter === s ? 'rgba(79,172,254,.1)' : 'transparent',
                    color: sevFilter === s ? '#e8eaf0' : '#6b7280',
                    fontSize: 12,
                  }}>
                    {s === 'ALL' ? `All (${result.findings.length})` : (
                      <span style={{ color: SEV_COLOR[s] }}>{s}</span>
                    )}
                  </button>
                ))}
              </div>

              {filtered.length === 0
                ? <p style={{ color: '#6b7280', fontSize: 13 }}>No findings for this filter.</p>
                : filtered.map((f, i) => <FindingCard key={i} finding={f} index={i} />)
              }
            </div>

            <div>
              <RadarChart findings={result.findings} />

              {/* Attack surface */}
              <div style={{ marginTop: 16, background: '#13151c', border: '1px solid #1e2130', borderRadius: 10, padding: 16 }}>
                <div style={{ fontSize: 11, fontWeight: 700, letterSpacing: 2, textTransform: 'uppercase', color: '#6b7280', marginBottom: 12 }}>
                  Attack Surface
                </div>
                {(Object.entries(result.attack_surface) as [string, string[]][])
                  .filter(([, routes]) => routes.length > 0)
                  .map(([cat, routes]) => (
                    <div key={cat} style={{ marginBottom: 10 }}>
                      <div style={{ fontSize: 10, color: '#6b7280', textTransform: 'uppercase', letterSpacing: 1 }}>{cat}</div>
                      <div style={{ fontSize: 28, fontWeight: 800 }}>{routes.length}</div>
                      <div style={{ fontFamily: 'monospace', fontSize: 10, color: '#6b7280', lineHeight: 1.6 }}>
                        {routes.slice(0, 2).map(r => r.substring(0, 32)).join('\n')}
                      </div>
                    </div>
                  ))}
              </div>
            </div>
          </div>

          {/* Download row */}
          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
            {(['txt', 'json', 'sarif'] as const).map(fmt => (
              <a key={fmt} href={reportUrl(result.scan_id, fmt)} download style={{
                display: 'inline-flex', alignItems: 'center', gap: 8,
                padding: '10px 20px', borderRadius: 8,
                border: '1px solid #1e2130', background: '#13151c',
                color: '#e8eaf0', textDecoration: 'none', fontSize: 13, fontWeight: 600,
              }}>
                {fmt === 'txt' ? '📄' : fmt === 'json' ? '⚙️' : '🔬'} {fmt.toUpperCase()} Report
              </a>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
