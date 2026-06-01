/**
 * VENGAM Auditor — API Client v2
 * JWT auth + tüm endpoint'ler
 */

const BASE = import.meta.env.VITE_API_URL ?? 'http://localhost:8000';

// ── Auth ──────────────────────────────────────────────────────────
let _accessToken: string | null = localStorage.getItem('vengam_token');

export function setToken(t: string)  { _accessToken = t; localStorage.setItem('vengam_token', t); }
export function clearToken()         { _accessToken = null; localStorage.removeItem('vengam_token'); }
export function getToken()           { return _accessToken; }
export function isLoggedIn(): boolean { return !!_accessToken; }

async function apiFetch(path: string, init: RequestInit = {}): Promise<Response> {
  const headers: Record<string, string> = {
    ...(init.headers as Record<string, string> || {}),
  };
  if (_accessToken) headers['Authorization'] = `Bearer ${_accessToken}`;
  const res = await fetch(`${BASE}${path}`, { ...init, headers });
  if (res.status === 401) { clearToken(); window.location.href = '/login'; }
  return res;
}

// ── Auth endpoints ────────────────────────────────────────────────
export async function login(username: string, password: string): Promise<boolean> {
  const res = await fetch(`${BASE}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  });
  if (!res.ok) return false;
  const data = await res.json();
  setToken(data.access_token);
  localStorage.setItem('vengam_refresh', data.refresh_token);
  return true;
}

export async function logout(): Promise<void> {
  await apiFetch('/api/auth/logout', { method: 'POST' });
  clearToken();
  localStorage.removeItem('vengam_refresh');
}

export async function getCurrentUser(): Promise<{ username: string; role: string } | null> {
  const res = await apiFetch('/api/auth/me');
  if (!res.ok) return null;
  return res.json();
}

// ── Scan types ────────────────────────────────────────────────────
export interface Finding {
  title:          string;
  severity:       'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  confidence:     string;
  exploitability: string;
  description:    string;
  simulation:     string;
  score_value:    number;
  category:       string;
  triage_note:    string;
  cwe_id:         string;
  owasp_ref:      string;
  cvss_vector:    string;
  secret_type:    string;
  locations:      { file: string; line: number; snippet: string; redacted_match: string }[];
}

export interface ScanResponse {
  scan_id:       string;
  apk_name:      string;
  platform:      string;
  risk_score:    number;
  verdict:       string;
  findings:      Finding[];
  attack_surface:{ auth: string[]; payment: string[]; user_data: string[]; internal_api: string[]; other: string[] };
  engine_stats:  { files_scanned: number; lines_scanned: number; fp_suppressed: number; patterns_run: number; scan_duration_sec: number };
  report_links:  { txt: string; json: string; sarif: string; pdf?: string };
}

export interface ScanSummary {
  id: string; apk_name: string; platform: string;
  scan_timestamp: string; total_score: number;
  verdict: string; duration_sec: number;
}

// ── Scan endpoints ────────────────────────────────────────────────
export async function scanAndroid(file: File, sevFilter?: string, catFilter?: string): Promise<ScanResponse> {
  const fd = new FormData();
  fd.append('file', file);
  if (sevFilter) fd.append('severity_filter', sevFilter);
  if (catFilter) fd.append('category_filter', catFilter);
  const res = await apiFetch('/api/scan/android', { method: 'POST', body: fd });
  if (!res.ok) throw new Error((await res.json()).detail ?? 'Scan failed');
  return res.json();
}

export async function scanIos(file: File, sevFilter?: string): Promise<ScanResponse> {
  const fd = new FormData();
  fd.append('file', file);
  if (sevFilter) fd.append('severity_filter', sevFilter);
  const res = await apiFetch('/api/scan/ios', { method: 'POST', body: fd });
  if (!res.ok) throw new Error((await res.json()).detail ?? 'iOS scan failed');
  return res.json();
}

export async function getScanHistory(limit = 20, offset = 0): Promise<{ total: number; scans: ScanSummary[] }> {
  const res = await apiFetch(`/api/history?limit=${limit}&offset=${offset}`);
  if (!res.ok) throw new Error('Failed to fetch history');
  return res.json();
}

export async function deleteScan(id: string): Promise<void> {
  await apiFetch(`/api/history/${id}`, { method: 'DELETE' });
}

// ── Intel endpoints ───────────────────────────────────────────────
export async function getAttackGraph(scanId: string): Promise<any> {
  const res = await apiFetch(`/api/intel/attack-graph/${scanId}`);
  if (!res.ok) return null;
  return res.json();
}

export async function getFridaScript(scanId: string, mode = 'auto'): Promise<string> {
  const res = await apiFetch(`/api/intel/frida/${scanId}?mode=${mode}`);
  if (!res.ok) return '';
  const data = await res.json();
  return data.script ?? '';
}

export async function getIl2CppData(scanId: string): Promise<any> {
  const res = await apiFetch(`/api/intel/il2cpp/${scanId}`);
  if (!res.ok) return null;
  return res.json();
}

// ── Plugin endpoints ──────────────────────────────────────────────
export async function listPlugins(): Promise<any[]> {
  const res = await apiFetch('/api/plugins');
  if (!res.ok) return [];
  return res.json();
}

// ── Report download URL ───────────────────────────────────────────
export function reportUrl(scanId: string, fmt: string): string {
  return `${BASE}/api/reports/${scanId}/${fmt}`;
}
