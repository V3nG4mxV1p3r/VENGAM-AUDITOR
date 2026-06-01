/**
 * VENGAM — Scan History Page
 */
import { useState, useEffect } from 'react';
import { getScanHistory, deleteScan, reportUrl } from '../api/client';
import type { ScanSummary } from '../api/client';

const VERDICT_STYLE: Record<string, { color: string; bg: string }> = {
  'BLOCK RELEASE':                { color: '#ff3b5c', bg: 'rgba(255,59,92,.12)' },
  'AT RISK — REMEDIATION REQUIRED': { color: '#ff8c00', bg: 'rgba(255,140,0,.12)' },
  'CONDITIONALLY SAFE':           { color: '#00f593', bg: 'rgba(0,245,147,.1)'  },
};

function scoreColor(s: number) {
  return s >= 75 ? '#ff3b5c' : s >= 40 ? '#ff8c00' : '#00f593';
}

export default function ScanHistory() {
  const [scans,    setScans]    = useState<ScanSummary[]>([]);
  const [loading,  setLoading]  = useState(true);
  const [platform, setPlatform] = useState<'all' | 'android' | 'ios'>('all');
  const [deleting, setDeleting] = useState<string | null>(null);

  const load = async () => {
    setLoading(true);
    try {
      const res = await getScanHistory(50, 0, platform === 'all' ? undefined : platform);
      setScans(res.scans);
    } catch { setScans([]); }
    finally { setLoading(false); }
  };

  useEffect(() => { load(); }, [platform]);

  const handleDelete = async (id: string) => {
    if (!confirm('Delete this scan record?')) return;
    setDeleting(id);
    try { await deleteScan(id); await load(); }
    catch { alert('Delete failed'); }
    finally { setDeleting(null); }
  };

  return (
    <div style={{ maxWidth: 1200, margin: '0 auto', padding: '40px 24px' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 16, marginBottom: 28 }}>
        <h2 style={{ fontSize: 22, fontWeight: 800 }}>Scan History</h2>
        <div style={{ display: 'flex', gap: 8 }}>
          {(['all', 'android', 'ios'] as const).map(p => (
            <button key={p} onClick={() => setPlatform(p)} style={{
              padding: '5px 14px', borderRadius: 20, cursor: 'pointer',
              border: `1px solid ${platform === p ? '#4facfe' : '#1e2130'}`,
              background: platform === p ? 'rgba(79,172,254,.1)' : 'transparent',
              color: platform === p ? '#e8eaf0' : '#6b7280', fontSize: 12,
            }}>{p.toUpperCase()}</button>
          ))}
        </div>
        <button onClick={load} style={{
          marginLeft: 'auto', padding: '6px 16px', border: '1px solid #1e2130',
          background: 'transparent', color: '#6b7280', borderRadius: 6,
          cursor: 'pointer', fontSize: 12,
        }}>⟳ Refresh</button>
      </div>

      {loading ? (
        <p style={{ color: '#6b7280' }}>Loading…</p>
      ) : scans.length === 0 ? (
        <div style={{
          textAlign: 'center', padding: '60px 40px',
          background: '#13151c', border: '1px solid #1e2130', borderRadius: 12,
        }}>
          <div style={{ fontSize: 48, marginBottom: 12 }}>📭</div>
          <p style={{ color: '#6b7280' }}>No scans yet. Run your first scan from the Dashboard.</p>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          {scans.map(scan => {
            const vs = VERDICT_STYLE[scan.verdict] ?? { color: '#6b7280', bg: '#1e2130' };
            return (
              <div key={scan.id} style={{
                background: '#13151c', border: '1px solid #1e2130',
                borderRadius: 10, padding: '16px 20px',
                display: 'flex', alignItems: 'center', gap: 16,
              }}>
                {/* Score */}
                <div style={{
                  fontSize: 28, fontWeight: 800,
                  color: scoreColor(scan.total_score), minWidth: 52, textAlign: 'center',
                }}>
                  {scan.total_score}
                </div>

                {/* Info */}
                <div style={{ flex: 1 }}>
                  <div style={{ fontWeight: 700, fontSize: 14 }}>{scan.apk_name}</div>
                  <div style={{ fontSize: 11, color: '#6b7280', marginTop: 3, fontFamily: 'monospace' }}>
                    {scan.platform.toUpperCase()} ·{' '}
                    {new Date(scan.scan_timestamp).toLocaleString()} ·{' '}
                    {scan.duration_sec}s
                  </div>
                </div>

                {/* Verdict pill */}
                <span style={{
                  padding: '5px 14px', borderRadius: 6, fontSize: 12, fontWeight: 700,
                  background: vs.bg, color: vs.color,
                  whiteSpace: 'nowrap',
                }}>
                  {scan.verdict}
                </span>

                {/* Download links */}
                <div style={{ display: 'flex', gap: 6 }}>
                  {(['txt', 'json', 'sarif'] as const).map(fmt => (
                    <a key={fmt} href={reportUrl(scan.id, fmt)} download style={{
                      padding: '4px 10px', borderRadius: 4, fontSize: 11,
                      border: '1px solid #1e2130', background: 'transparent',
                      color: '#6b7280', textDecoration: 'none',
                    }}>{fmt}</a>
                  ))}
                </div>

                {/* Delete */}
                <button
                  onClick={() => handleDelete(scan.id)}
                  disabled={deleting === scan.id}
                  style={{
                    padding: '5px 10px', border: '1px solid #1e2130',
                    background: 'transparent', color: '#6b7280',
                    borderRadius: 6, cursor: 'pointer', fontSize: 12,
                  }}
                >
                  {deleting === scan.id ? '…' : '🗑'}
                </button>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
