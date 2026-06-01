/**
 * VENGAM — Risk Radar Chart Component
 * Uses Chart.js via CDN (no npm install needed)
 */
import { useEffect, useRef } from 'react';
import type { Finding } from '../api/client';

interface Props { findings: Finding[]; }

const CATEGORIES = ['General', 'GameEngine', 'AntiCheat', 'Economy', 'Config'];

export default function RadarChart({ findings }: Props) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const chartRef  = useRef<any>(null);

  useEffect(() => {
    if (!canvasRef.current) return;
    const scores = CATEGORIES.map(cat =>
      findings
        .filter(f => (f.category || 'General') === cat)
        .reduce((s, f) => s + f.score_value, 0)
    );

    // @ts-ignore — Chart loaded via CDN in index.html
    const Chart = (window as any).Chart;
    if (!Chart) return;

    if (chartRef.current) chartRef.current.destroy();

    chartRef.current = new Chart(canvasRef.current, {
      type: 'radar',
      data: {
        labels: CATEGORIES,
        datasets: [{
          label:           'Risk Score',
          data:            scores,
          backgroundColor: 'rgba(255,59,92,0.15)',
          borderColor:     '#ff3b5c',
          pointBackgroundColor: '#ff3b5c',
          borderWidth:     2,
        }],
      },
      options: {
        responsive: true,
        plugins: { legend: { display: false } },
        scales: {
          r: {
            beginAtZero: true,
            grid:        { color: '#1e2130' },
            angleLines:  { color: '#1e2130' },
            pointLabels: { color: '#9ca3af', font: { size: 11 } },
            ticks:       { color: '#9ca3af', backdropColor: 'transparent', font: { size: 9 } },
          },
        },
      },
    });

    return () => { chartRef.current?.destroy(); };
  }, [findings]);

  return (
    <div style={{
      background: '#13151c', border: '1px solid #1e2130',
      borderRadius: 10, padding: 20,
    }}>
      <div style={{
        fontSize: 11, fontWeight: 700, letterSpacing: 2,
        textTransform: 'uppercase', color: '#6b7280',
        marginBottom: 14, paddingBottom: 8,
        borderBottom: '1px solid #1e2130',
      }}>Risk Radar</div>
      <canvas ref={canvasRef} style={{ maxHeight: 260 }} />
    </div>
  );
}
