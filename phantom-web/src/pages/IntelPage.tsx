/**
 * VENGAM — Intelligence Page
 * Attack Graph + Frida Panel + IL2CPP Explorer tek sayfada
 */
import { useState, useEffect } from 'react';
import AttackGraphView from '../components/AttackGraphView';
import FridaPanel from '../components/FridaPanel';
import Il2CppExplorer from '../components/Il2CppExplorer';
import { getAttackGraph, getFridaScript, getIl2CppData } from '../api/client';
import type { Finding } from '../api/client';

interface Props {
  scanId:   string | null;
  findings: Finding[];
  apkName:  string;
  pkg:      string;
}

type IntelTab = 'graph' | 'frida' | 'il2cpp';

export default function IntelPage({ scanId, findings, apkName, pkg }: Props) {
  const [tab,        setTab]        = useState<IntelTab>('graph');
  const [graphData,  setGraphData]  = useState<any>(null);
  const [il2cppData, setIl2cppData] = useState<any>(null);
  const [loading,    setLoading]    = useState(false);

  useEffect(() => {
    if (!scanId) return;
    setLoading(true);
    Promise.all([
      getAttackGraph(scanId).then(setGraphData),
      getIl2CppData(scanId).then(setIl2cppData),
    ]).finally(() => setLoading(false));
  }, [scanId]);

  const tabs: [IntelTab, string][] = [
    ['graph',  '🕸 Attack Graph'],
    ['frida',  '🔌 Frida Hooks'],
    ['il2cpp', '🎮 IL2CPP'],
  ];

  return (
    <div style={{ padding:'16px 20px', height:'100%', overflow:'auto' }}>
      {/* Tab bar */}
      <div style={{ display:'flex', gap:6, marginBottom:16 }}>
        {tabs.map(([t, label]) => (
          <button key={t} onClick={() => setTab(t)} style={{
            fontFamily:'Share Tech Mono,monospace', fontSize:10,
            letterSpacing:1, padding:'6px 16px', borderRadius:4,
            cursor:'pointer',
            border:`1px solid ${tab===t ? '#00e664' : '#1a2a1a'}`,
            background: tab===t ? 'rgba(0,230,100,0.08)' : 'transparent',
            color: tab===t ? '#00e664' : '#4a6a4a',
          }}>{label}</button>
        ))}
        {loading && (
          <span style={{
            fontFamily:'Share Tech Mono,monospace', fontSize:9,
            color:'#3a6a3a', alignSelf:'center', marginLeft:8,
          }}>Loading intel...</span>
        )}
      </div>

      {/* Content */}
      {tab === 'graph'  && <AttackGraphView data={graphData} />}
      {tab === 'frida'  && (
        <FridaPanel
          findings={findings}
          apkName={apkName}
          packageName={pkg}
        />
      )}
      {tab === 'il2cpp' && <Il2CppExplorer data={il2cppData} />}
    </div>
  );
}
