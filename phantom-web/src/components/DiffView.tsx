/**
 * VENGAM — Diff View Component
 * Shows version comparison results in the web dashboard
 */
import { useState } from 'react';

interface DiffEntry {
  status:       string;
  title:        string;
  category:     string;
  old_severity: string | null;
  new_severity: string | null;
  score_delta:  number;
}

interface DiffSummary {
  new:       number;
  fixed:     number;
  worsened:  number;
  improved:  number;
  unchanged: number;
}

export interface DiffData {
  old_apk:     string;
  new_apk:     string;
  old_score:   number;
  new_score:   number;
  score_delta: number;
  old_verdict: string;
  new_verdict: string;
  timestamp:   string;
  summary:     DiffSummary;
  diffs:       DiffEntry[];
}

interface Props { data: DiffData; }

const STATUS_COLOR: Record<string, string> = {
  NEW:       '#ff3b5c',
  FIXED:     '#00f593',
  WORSENED:  '#ff8c00',
  IMPROVED:  '#4facfe',
  UNCHANGED: '#6b7280',
};

const STATUS_BG: Record<string, string> = {
  NEW:       'rgba(255,59,92,0.08)',
  FIXED:     'rgba(0,245,147,0.08)',
  WORSENED:  'rgba(255,140,0,0.08)',
  IMPROVED:  'rgba(79,172,254,0.08)',
  UNCHANGED: 'rgba(107,114,128,0.05)',
};

const STATUS_ICON: Record<string, string> = {
  NEW:       '🔴',
  FIXED:     '✅',
  WORSENED:  '⬆️',
  IMPROVED:  '⬇️',
  UNCHANGED: '⚪',
};

const SEV_COLOR: Record<string, string> = {
  CRITICAL: '#ff3b5c',
  HIGH:     '#ff8c00',
  MEDIUM:   '#ffd700',
  LOW:      '#4facfe',
  INFO:     '#6b7280',
};

export default function DiffView({ data }: Props) {
  const [filter, setFilter] = useState<string>('ALL');

  const filtered = filter === 'ALL'
    ? data.diffs
    : data.diffs.filter(d => d.status === filter);

  const deltaSign  = data.score_delta >= 0 ? '+' : '';
  const deltaColor = data.score_delta > 0 ? '#ff3b5c' : data.score_delta < 0 ? '#00f593' : '#6b7280';

  const summaryCards = [
    { label: 'New',       count: data.summary.new,       color: '#ff3b5c', status: 'NEW'       },
    { label: 'Fixed',     count: data.summary.fixed,     color: '#00f593', status: 'FIXED'     },
    { label: 'Worsened',  count: data.summary.worsened,  color: '#ff8c00', status: 'WORSENED'  },
    { label: 'Improved',  count: data.summary.improved,  color: '#4facfe', status: 'IMPROVED'  },
    { label: 'Unchanged', count: data.summary.unchanged, color: '#6b7280', status: 'UNCHANGED' },
  ];

  return (
    <div>
      {/* Header */}
      <div style={{
        background: '#13151c', border: '1px solid #1e2130',
        borderRadius: 10, padding: '20px 24px', marginBottom: 20,
      }}>
        <div style={{ fontSize: 11, color: '#6b7280', textTransform: 'uppercase', letterSpacing: 2, marginBottom: 12 }}>
          Version Comparison
        </div>
        <div style={{ display: 'flex', gap: 32, alignItems: 'center', flexWrap: 'wrap' }}>
          <div>
            <div style={{ fontFamily: 'monospace', fontSize: 12, color: '#6b7280' }}>OLD</div>
            <div style={{ fontWeight: 700 }}>{data.old_apk}</div>
            <div style={{ fontSize: 28, fontWeight: 800, color: '#6b7280' }}>{data.old_score}</div>
          </div>
          <div style={{ fontSize: 28, color: '#1e2130' }}>→</div>
          <div>
            <div style={{ fontFamily: 'monospace', fontSize: 12, color: '#6b7280' }}>NEW</div>
            <div style={{ fontWeight: 700 }}>{data.new_apk}</div>
            <div style={{ fontSize: 28, fontWeight: 800 }}>{data.new_score}</div>
          </div>
          <div style={{ marginLeft: 'auto', textAlign: 'right' }}>
            <div style={{ fontFamily: 'monospace', fontSize: 12, color: '#6b7280' }}>SCORE DELTA</div>
            <div style={{ fontSize: 36, fontWeight: 800, color: deltaColor }}>
              {deltaSign}{data.score_delta}
            </div>
          </div>
        </div>

        {/* Verdict change */}
        <div style={{ display: 'flex', gap: 10, marginTop: 14, alignItems: 'center', flexWrap: 'wrap' }}>
          <span style={{
            padding: '4px 12px', borderRadius: 4, fontSize: 11, fontWeight: 700,
            background: '#1e2130', color: '#6b7280',
          }}>{data.old_verdict}</span>
          <span style={{ color: '#1e2130' }}>→</span>
          <span style={{
            padding: '4px 12px', borderRadius: 4, fontSize: 11, fontWeight: 700,
            background: data.new_verdict === 'BLOCK RELEASE'
              ? 'rgba(255,59,92,.15)' : data.new_verdict.includes('AT RISK')
              ? 'rgba(255,140,0,.15)' : 'rgba(0,245,147,.12)',
            color: data.new_verdict === 'BLOCK RELEASE' ? '#ff3b5c'
              : data.new_verdict.includes('AT RISK') ? '#ff8c00' : '#00f593',
          }}>{data.new_verdict}</span>
        </div>
      </div>

      {/* Summary cards */}
      <div style={{ display: 'flex', gap: 10, marginBottom: 20, flexWrap: 'wrap' }}>
        {summaryCards.map(({ label, count, color, status }) => (
          <div
            key={status}
            onClick={() => setFilter(f => f === status ? 'ALL' : status)}
            style={{
              flex: 1, minWidth: 90,
              background: filter === status ? STATUS_BG[status] : '#13151c',
              border: `1px solid ${filter === status ? color : '#1e2130'}`,
              borderRadius: 10, padding: '14px 18px',
              cursor: 'pointer', transition: 'all 0.15s',
            }}
          >
            <div style={{ fontSize: 26, fontWeight: 800, color }}>{count}</div>
            <div style={{ fontSize: 10, color: '#6b7280', textTransform: 'uppercase', letterSpacing: 1, marginTop: 4 }}>
              {label}
            </div>
          </div>
        ))}
      </div>

      {/* Filter tabs */}
      <div style={{ display: 'flex', gap: 8, marginBottom: 14, flexWrap: 'wrap' }}>
        <button onClick={() => setFilter('ALL')} style={{
          padding: '5px 14px', borderRadius: 20, cursor: 'pointer',
          border: `1px solid ${filter === 'ALL' ? '#4facfe' : '#1e2130'}`,
          background: filter === 'ALL' ? 'rgba(79,172,254,.1)' : 'transparent',
          color: filter === 'ALL' ? '#e8eaf0' : '#6b7280', fontSize: 12,
        }}>All ({data.diffs.length})</button>
        {['NEW','WORSENED','IMPROVED','FIXED','UNCHANGED'].map(s => (
          <button key={s} onClick={() => setFilter(s)} style={{
            padding: '5px 14px', borderRadius: 20, cursor: 'pointer',
            border: `1px solid ${filter === s ? STATUS_COLOR[s] : '#1e2130'}`,
            background: filter === s ? STATUS_BG[s] : 'transparent',
            color: filter === s ? STATUS_COLOR[s] : '#6b7280', fontSize: 12,
          }}>{STATUS_ICON[s]} {s}</button>
        ))}
      </div>

      {/* Diff entries */}
      {filtered.length === 0 ? (
        <p style={{ color: '#6b7280', fontSize: 13 }}>No entries for this filter.</p>
      ) : (
        filtered.map((d, i) => (
          <div key={i} style={{
            background: STATUS_BG[d.status] || '#13151c',
            border: `1px solid ${STATUS_COLOR[d.status] || '#1e2130'}20`,
            borderRadius: 8, padding: '12px 16px', marginBottom: 8,
            display: 'flex', alignItems: 'center', gap: 12,
          }}>
            <span style={{ fontSize: 16, flexShrink: 0 }}>{STATUS_ICON[d.status]}</span>
            <span style={{ fontWeight: 700, fontSize: 13, flex: 1 }}>{d.title}</span>

            {/* Severity change */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11 }}>
              {d.old_severity && (
                <span style={{
                  padding: '2px 8px', borderRadius: 4,
                  background: '#1e2130',
                  color: SEV_COLOR[d.old_severity] || '#6b7280',
                  fontWeight: 700,
                }}>{d.old_severity}</span>
              )}
              {d.old_severity && d.new_severity && (
                <span style={{ color: '#1e2130' }}>→</span>
              )}
              {d.new_severity && (
                <span style={{
                  padding: '2px 8px', borderRadius: 4,
                  background: '#1e2130',
                  color: SEV_COLOR[d.new_severity] || '#6b7280',
                  fontWeight: 700,
                }}>{d.new_severity}</span>
              )}
            </div>

            {/* Score delta */}
            {d.score_delta !== 0 && (
              <span style={{
                fontFamily: 'monospace', fontSize: 11,
                color: d.score_delta > 0 ? '#ff3b5c' : '#00f593',
                background: '#1e2130', padding: '2px 8px', borderRadius: 4,
              }}>
                {d.score_delta > 0 ? '+' : ''}{d.score_delta}pts
              </span>
            )}

            {/* Category */}
            <span style={{
              fontFamily: 'monospace', fontSize: 10,
              color: '#6b7280', background: '#1e2130',
              padding: '2px 8px', borderRadius: 4,
            }}>{d.category}</span>
          </div>
        ))
      )}
    </div>
  );
}
