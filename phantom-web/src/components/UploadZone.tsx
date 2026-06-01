/**
 * VENGAM — Upload Zone Component
 * Drag & drop or click to upload APK / IPA
 */
import { useState, useRef } from 'react';

interface Props {
  onFile: (file: File) => void;
  accept: string;
  label: string;
}

export default function UploadZone({ onFile, accept, label }: Props) {
  const [dragging, setDragging]   = useState(false);
  const [fileName, setFileName]   = useState<string | null>(null);
  const inputRef                  = useRef<HTMLInputElement>(null);

  const handleFile = (f: File) => {
    setFileName(f.name);
    onFile(f);
  };

  return (
    <div
      onClick={() => inputRef.current?.click()}
      onDragOver={e => { e.preventDefault(); setDragging(true); }}
      onDragLeave={() => setDragging(false)}
      onDrop={e => {
        e.preventDefault(); setDragging(false);
        const f = e.dataTransfer.files[0];
        if (f) handleFile(f);
      }}
      style={{
        border:       `2px dashed ${dragging ? '#4facfe' : '#1e2130'}`,
        borderRadius: 12,
        padding:      '48px 32px',
        textAlign:    'center',
        cursor:       'pointer',
        background:   dragging ? '#131825' : '#13151c',
        transition:   'all 0.2s',
      }}
    >
      <input
        ref={inputRef}
        type="file"
        accept={accept}
        style={{ display: 'none' }}
        onChange={e => { const f = e.target.files?.[0]; if (f) handleFile(f); }}
      />
      <div style={{ fontSize: 48, marginBottom: 12 }}>🎮</div>
      <h2 style={{ fontSize: 18, fontWeight: 800, marginBottom: 8 }}>{label}</h2>
      <p style={{ color: '#6b7280', fontSize: 13 }}>
        Drop your file here or click to browse
      </p>
      {fileName && (
        <p style={{ marginTop: 12, color: '#00f593', fontFamily: 'monospace', fontSize: 13 }}>
          ✓ {fileName}
        </p>
      )}
    </div>
  );
}
