/**
 * VENGAM — Finding Card Component
 */
import { useState } from 'react';
import type { Finding } from '../api/client';

const SEV_COLOR: Record<string, string> = {
  CRITICAL: '#ff3b5c',
  HIGH:     '#ff8c00',
  MEDIUM:   '#ffd700',
  LOW:      '#4facfe',
  INFO:     '#6b7280',
};

const CAT_STYLE: Record<string, { bg: string; color: string }> = {
  GameEngine: { bg: 'rgba(79,172,254,.15)',  color: '#4facfe' },
  AntiCheat:  { bg: 'rgba(255,59,92,.15)',   color: '#ff3b5c' },
  Economy:    { bg: 'rgba(255,215,0,.12)',   color: '#ffd700' },
  Config:     { bg: 'rgba(167,139,250,.12)', color: '#a78bfa' },
  General:    { bg: '#1e2130',               color: '#6b7280' },
};

interface Props { finding: Finding; index: number; }

export default function FindingCard({ finding, index }: Props) {
  const [open, setOpen] = useState(false);
  const dot   = SEV_COLOR[finding.severity] ?? '#6b7280';
  const cat   = CAT_STYLE[finding.category] ?? CAT_STYLE.General;

  return (
    <div style={{
      background: '#13151c', border: '1px solid #1e2130',
      borderRadius: 10, marginBottom: 10, overflow: 'hidden',
    }}>
      {/* Header */}
      <div
        onClick={() => setOpen(o => !o)}
        style={{
          display: 'flex', alignItems: 'center', gap: 12,
          padding: '13px 18px', cursor: 'pointer',
        }}
      >
        <div style={{
          width: 8, height: 8, borderRadius: '50%',
          background: dot, flexShrink: 0,
          boxShadow: finding.severity === 'CRITICAL' ? `0 0 8px ${dot}` : 'none',
        }} />
        <span style={{ fontWeight: 700, fontSize: 14, flex: 1 }}>{finding.title}</span>
        <span style={{
          fontSize: 10, padding: '2px 8px', borderRadius: 4,
          background: cat.bg, color: cat.color,
        }}>{finding.category}</span>
        <span style={{
          fontFamily: 'monospace', fontSize: 11,
          background: '#1e2130', color: '#6b7280',
          padding: '2px 8px', borderRadius: 4,
        }}>+{finding.score_value}pts</span>
        <span style={{ color: '#6b7280', fontSize: 10 }}>{open ? '▲' : '▼'}</span>
      </div>

      {/* Body */}
      {open && (
        <div style={{ padding: '0 18px 18px', borderTop: '1px solid #1e2130' }}>
          {/* Meta pills */}
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 12 }}>
            {[
              ['Confidence', finding.confidence],
              ['Exploitability', finding.exploitability],
              finding.cwe_id    ? ['CWE', finding.cwe_id]    : null,
              finding.owasp_ref ? ['OWASP', finding.owasp_ref] : null,
            ].filter(Boolean).map(([k, v]) => (
              <span key={k} style={{
                fontFamily: 'monospace', fontSize: 10,
                background: '#1e2130', color: '#9ca3af',
                padding: '3px 8px', borderRadius: 4,
              }}>
                {k}: <span style={{ color: '#e8eaf0' }}>{v}</span>
              </span>
            ))}
          </div>

          <p style={{ fontSize: 13, lineHeight: 1.7, color: '#9ca3af', marginTop: 12 }}>
            {finding.description}
          </p>

          {/* Simulation */}
          <div style={{
            background: '#0f1117', borderLeft: '3px solid #ff3b5c',
            padding: '10px 14px', borderRadius: '0 6px 6px 0',
            marginTop: 10, fontSize: 12, color: '#9ca3af',
          }}>
            ⚔️ {finding.simulation}
          </div>

          {/* Triage */}
          {finding.triage_note && (
            <div style={{
              background: '#0f1319', borderLeft: '3px solid #4facfe',
              padding: '10px 14px', borderRadius: '0 6px 6px 0',
              marginTop: 10, fontSize: 12, color: '#93c5fd',
            }}>
              ▶ {finding.triage_note}
            </div>
          )}

          {/* Locations */}
          {finding.locations.length > 0 && (
            <div style={{ marginTop: 10 }}>
              {finding.locations.map((loc, i) => (
                <div key={i} style={{
                  fontFamily: 'monospace', fontSize: 11, color: '#6b7280',
                  padding: '5px 8px', background: '#0f1117',
                  borderRadius: 4, marginTop: 3,
                  display: 'flex', gap: 10, alignItems: 'center',
                }}>
                  <span style={{ color: '#4facfe', flexShrink: 0 }}>:{loc.line}</span>
                  <span style={{ flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {loc.file}
                  </span>
                  {loc.redacted_match && (
                    <span style={{ color: '#ff8c00', fontSize: 10 }}>{loc.redacted_match}</span>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
