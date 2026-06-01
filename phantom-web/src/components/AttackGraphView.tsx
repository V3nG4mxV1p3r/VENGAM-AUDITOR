/**
 * VENGAM — Attack Graph Visualization
 * D3.js force-directed graph — backend ilişkilerini görselleştirir.
 * Saldırı zincirlerini, endpoint'leri ve bulguları bağlantılı gösterir.
 */
import { useEffect, useRef, useState } from 'react';

interface GraphNode {
  id:    string;
  label: string;
  type:  string;
  risk:  string;
  color: string;
  size:  number;
  metadata?: Record<string, unknown>;
  x?: number;
  y?: number;
  vx?: number;
  vy?: number;
  fx?: number | null;
  fy?: number | null;
}

interface GraphLink {
  source: string | GraphNode;
  target: string | GraphNode;
  label:  string;
  type:   string;
  color:  string;
}

interface AttackChain {
  id:       string;
  title:    string;
  severity: string;
  steps:    string[];
  impact:   string;
}

interface GraphData {
  nodes:  GraphNode[];
  links:  GraphLink[];
  chains: AttackChain[];
}

interface Props {
  data: GraphData | null;
}

const SEV_COLOR: Record<string, string> = {
  CRITICAL: '#e53935',
  HIGH:     '#ff8c00',
  MEDIUM:   '#ffc107',
  LOW:      '#4caf50',
};

const TYPE_COLOR: Record<string, string> = {
  apk:      '#00e664',
  attacker: '#e53935',
  finding:  '#ff8c00',
  endpoint: '#4facfe',
  service:  '#a78bfa',
};

export default function AttackGraphView({ data }: Props) {
  const svgRef       = useRef<SVGSVGElement>(null);
  const [selected, setSelected] = useState<GraphNode | null>(null);
  const [activeChain, setActiveChain] = useState<string | null>(null);

  useEffect(() => {
    if (!data || !svgRef.current) return;

    const svg    = svgRef.current;
    const W      = svg.clientWidth  || 700;
    const H      = svg.clientHeight || 480;

    // Clear
    while (svg.firstChild) svg.removeChild(svg.firstChild);

    // Defs — glow filter
    const defs = document.createElementNS("http://www.w3.org/2000/svg", "defs");
    const filter = document.createElementNS("http://www.w3.org/2000/svg", "filter");
    filter.setAttribute("id", "glow");
    const blur = document.createElementNS("http://www.w3.org/2000/svg", "feGaussianBlur");
    blur.setAttribute("stdDeviation", "3");
    blur.setAttribute("result", "coloredBlur");
    const merge = document.createElementNS("http://www.w3.org/2000/svg", "feMerge");
    ["coloredBlur","SourceGraphic"].forEach(val => {
      const node = document.createElementNS("http://www.w3.org/2000/svg","feMergeNode");
      node.setAttribute("in", val);
      merge.appendChild(node);
    });
    filter.appendChild(blur);
    filter.appendChild(merge);
    defs.appendChild(filter);
    svg.appendChild(defs);

    // Arrow marker
    const marker = document.createElementNS("http://www.w3.org/2000/svg","marker");
    marker.setAttribute("id","arrow");
    marker.setAttribute("viewBox","0 -5 10 10");
    marker.setAttribute("refX","20");
    marker.setAttribute("refY","0");
    marker.setAttribute("markerWidth","6");
    marker.setAttribute("markerHeight","6");
    marker.setAttribute("orient","auto");
    const arrowPath = document.createElementNS("http://www.w3.org/2000/svg","path");
    arrowPath.setAttribute("d","M0,-5L10,0L0,5");
    arrowPath.setAttribute("fill","#4a6a4a");
    marker.appendChild(arrowPath);
    defs.appendChild(marker);

    // Simple force-layout simulation (manual, no d3 dependency)
    const nodes: GraphNode[] = data.nodes.map((n, i) => ({
      ...n,
      x: W/2 + Math.cos(i * 2*Math.PI/data.nodes.length) * 180,
      y: H/2 + Math.sin(i * 2*Math.PI/data.nodes.length) * 150,
      vx: 0, vy: 0,
    }));

    const nodeById: Record<string, GraphNode> = {};
    nodes.forEach(n => { nodeById[n.id] = n; });

    const links = data.links.map(l => ({
      ...l,
      source: nodeById[typeof l.source === 'string' ? l.source : l.source.id] || nodes[0],
      target: nodeById[typeof l.target === 'string' ? l.target : l.target.id] || nodes[0],
    }));

    // Simple force simulation — 50 iterations
    for (let iter = 0; iter < 80; iter++) {
      // Repulsion
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i+1; j < nodes.length; j++) {
          const dx = (nodes[j].x||0) - (nodes[i].x||0);
          const dy = (nodes[j].y||0) - (nodes[i].y||0);
          const dist = Math.sqrt(dx*dx+dy*dy) || 1;
          const force = 3000 / (dist*dist);
          nodes[i].vx! -= force*dx/dist;
          nodes[i].vy! -= force*dy/dist;
          nodes[j].vx! += force*dx/dist;
          nodes[j].vy! += force*dy/dist;
        }
      }
      // Attraction (links)
      links.forEach(l => {
        const s = l.source as GraphNode;
        const t = l.target as GraphNode;
        const dx = (t.x||0)-(s.x||0);
        const dy = (t.y||0)-(s.y||0);
        const dist = Math.sqrt(dx*dx+dy*dy)||1;
        const force = (dist-120)*0.05;
        s.vx! += force*dx/dist; s.vy! += force*dy/dist;
        t.vx! -= force*dx/dist; t.vy! -= force*dy/dist;
      });
      // Center gravity
      nodes.forEach(n => {
        n.vx! += (W/2 - (n.x||0))*0.01;
        n.vy! += (H/2 - (n.y||0))*0.01;
      });
      // Apply velocity + damping
      nodes.forEach(n => {
        n.vx! *= 0.85; n.vy! *= 0.85;
        n.x = Math.max(30, Math.min(W-30, (n.x||0)+n.vx!));
        n.y = Math.max(30, Math.min(H-30, (n.y||0)+n.vy!));
      });
    }

    const g = document.createElementNS("http://www.w3.org/2000/svg","g");
    svg.appendChild(g);

    // Draw links
    links.forEach(l => {
      const s = l.source as GraphNode;
      const t = l.target as GraphNode;
      const line = document.createElementNS("http://www.w3.org/2000/svg","line");
      line.setAttribute("x1", String(s.x||0));
      line.setAttribute("y1", String(s.y||0));
      line.setAttribute("x2", String(t.x||0));
      line.setAttribute("y2", String(t.y||0));
      line.setAttribute("stroke", l.color || "#2a4a2a");
      line.setAttribute("stroke-width","1.5");
      line.setAttribute("stroke-opacity","0.6");
      line.setAttribute("marker-end","url(#arrow)");
      g.appendChild(line);

      // Link label
      const lx = ((s.x||0)+(t.x||0))/2;
      const ly = ((s.y||0)+(t.y||0))/2;
      const txt = document.createElementNS("http://www.w3.org/2000/svg","text");
      txt.setAttribute("x", String(lx));
      txt.setAttribute("y", String(ly));
      txt.setAttribute("fill","#3a5a3a");
      txt.setAttribute("font-size","8");
      txt.setAttribute("text-anchor","middle");
      txt.setAttribute("font-family","Share Tech Mono,monospace");
      txt.textContent = l.label;
      g.appendChild(txt);
    });

    // Draw nodes
    nodes.forEach(n => {
      const color = TYPE_COLOR[n.type] || SEV_COLOR[n.risk] || '#607d8b';
      const size  = n.size || 15;

      const circle = document.createElementNS("http://www.w3.org/2000/svg","circle");
      circle.setAttribute("cx",   String(n.x||0));
      circle.setAttribute("cy",   String(n.y||0));
      circle.setAttribute("r",    String(size/2));
      circle.setAttribute("fill", color);
      circle.setAttribute("fill-opacity","0.85");
      circle.setAttribute("stroke", color);
      circle.setAttribute("stroke-width","1.5");
      if (n.risk === "CRITICAL") {
        circle.setAttribute("filter","url(#glow)");
      }
      circle.style.cursor = "pointer";
      circle.addEventListener("click", () => setSelected(n));
      g.appendChild(circle);

      // Label
      const txt = document.createElementNS("http://www.w3.org/2000/svg","text");
      txt.setAttribute("x",           String(n.x||0));
      txt.setAttribute("y",           String((n.y||0) + size/2 + 11));
      txt.setAttribute("fill",        "#d0ecd0");
      txt.setAttribute("font-size",   "9");
      txt.setAttribute("text-anchor","middle");
      txt.setAttribute("font-family","Share Tech Mono,monospace");
      txt.textContent = n.label.substring(0,22);
      g.appendChild(txt);
    });

  }, [data]);

  if (!data) return (
    <div style={{
      background:'#0c110c', border:'1px solid #1a2a1a',
      borderRadius:6, padding:'40px 20px', textAlign:'center',
      fontFamily:'Share Tech Mono,monospace', fontSize:11, color:'#2a4a2a',
    }}>
      Scan a target to generate the attack graph.
    </div>
  );

  return (
    <div style={{ display:'flex', flexDirection:'column', gap:12 }}>

      {/* Graph */}
      <div style={{
        background:'#0c110c', border:'1px solid #1a2a1a',
        borderRadius:6, position:'relative', overflow:'hidden',
      }}>
        <div style={{
          padding:'8px 14px', borderBottom:'1px solid #1a2a1a',
          fontFamily:'Share Tech Mono,monospace', fontSize:9,
          letterSpacing:2, color:'#3a6a3a',
          display:'flex', alignItems:'center', gap:10,
        }}>
          ATTACK GRAPH
          <span style={{color:'#2a4a2a'}}>
            {data.nodes.length} nodes · {data.links.length} edges
          </span>
          {selected && (
            <span style={{marginLeft:'auto',color:'#00e664'}}>
              Selected: {selected.label.substring(0,30)}
            </span>
          )}
        </div>
        <svg
          ref={svgRef}
          style={{ width:'100%', height:420, display:'block' }}
        />
      </div>

      {/* Node detail */}
      {selected && (
        <div style={{
          background:'#0c110c', border:`1px solid ${SEV_COLOR[selected.risk]||'#1a2a1a'}`,
          borderRadius:6, padding:'12px 16px',
        }}>
          <div style={{
            fontFamily:'Share Tech Mono,monospace', fontSize:9,
            letterSpacing:2, color:'#3a6a3a', marginBottom:8,
          }}>NODE DETAIL</div>
          <div style={{ display:'flex', gap:12, flexWrap:'wrap' }}>
            {[
              ['Type',     selected.type],
              ['Risk',     selected.risk],
              ['ID',       selected.id.substring(0,30)],
            ].map(([k,v]) => (
              <div key={k} style={{
                fontFamily:'Share Tech Mono,monospace', fontSize:9,
                background:'#141e14', padding:'4px 10px', borderRadius:3,
                color:'#7a9a7a',
              }}>
                {k}: <span style={{color:'#d0ecd0'}}>{v}</span>
              </div>
            ))}
          </div>
          {selected.metadata && Object.keys(selected.metadata).length > 0 && (
            <div style={{
              marginTop:8, fontFamily:'Share Tech Mono,monospace',
              fontSize:9, color:'#4a6a4a', lineHeight:1.7,
            }}>
              {Object.entries(selected.metadata).slice(0,4).map(([k,v]) => (
                <div key={k}>
                  <span style={{color:'#3a6a3a'}}>{k}:</span>{' '}
                  <span style={{color:'#7a9a7a'}}>
                    {typeof v === 'object' ? JSON.stringify(v).substring(0,60) : String(v).substring(0,60)}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Attack chains */}
      {data.chains.length > 0 && (
        <div style={{ display:'flex', flexDirection:'column', gap:6 }}>
          <div style={{
            fontFamily:'Share Tech Mono,monospace', fontSize:9,
            letterSpacing:2, color:'#3a6a3a', paddingBottom:6,
            borderBottom:'1px solid #1a2a1a',
          }}>ATTACK CHAINS ({data.chains.length})</div>
          {data.chains.map(chain => (
            <div key={chain.id} style={{
              background:'#0c110c',
              border:`1px solid ${activeChain===chain.id ? SEV_COLOR[chain.severity]||'#1a2a1a' : '#1a2a1a'}`,
              borderRadius:6, overflow:'hidden', cursor:'pointer',
            }} onClick={() => setActiveChain(
              activeChain === chain.id ? null : chain.id
            )}>
              <div style={{
                padding:'9px 14px', display:'flex',
                alignItems:'center', gap:10,
              }}>
                <div style={{
                  width:7, height:7, borderRadius:'50%',
                  background: SEV_COLOR[chain.severity]||'#607d8b',
                  flexShrink:0,
                  boxShadow: chain.severity==='CRITICAL'
                    ? `0 0 6px ${SEV_COLOR.CRITICAL}` : 'none',
                }}/>
                <span style={{
                  fontFamily:'Share Tech Mono,monospace',
                  fontSize:11, color:'#d0ecd0', flex:1,
                }}>{chain.title}</span>
                <span style={{
                  fontFamily:'Share Tech Mono,monospace', fontSize:8,
                  color: SEV_COLOR[chain.severity]||'#607d8b',
                  background:'#141e14', padding:'2px 8px', borderRadius:3,
                }}>{chain.severity}</span>
                <span style={{color:'#2a4a2a',fontSize:9}}>
                  {activeChain===chain.id?'▲':'▼'}
                </span>
              </div>
              {activeChain===chain.id && (
                <div style={{
                  padding:'0 14px 12px',
                  borderTop:'1px solid #1a2a1a',
                }}>
                  <div style={{marginTop:10}}>
                    {chain.steps.map((step,i) => (
                      <div key={i} style={{
                        display:'flex', gap:10, alignItems:'flex-start',
                        marginBottom:5, fontFamily:'Share Tech Mono,monospace',
                        fontSize:9, color:'#7a9a7a',
                      }}>
                        <span style={{
                          color:'#00e664', flexShrink:0,
                          background:'#0a1e0a',
                          padding:'1px 6px', borderRadius:3,
                        }}>{i+1}</span>
                        {step}
                      </div>
                    ))}
                  </div>
                  <div style={{
                    marginTop:10, padding:'8px 12px',
                    background:'#141e14',
                    borderLeft:`2px solid ${SEV_COLOR[chain.severity]||'#607d8b'}`,
                    borderRadius:'0 4px 4px 0',
                    fontFamily:'Share Tech Mono,monospace',
                    fontSize:9, color:'#4a6a4a',
                  }}>
                    Impact: <span style={{color:'#ff8c00'}}>{chain.impact}</span>
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
