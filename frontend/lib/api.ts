export const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://127.0.0.1:8000/api/v1";
const TOKEN_KEY = "surfacewatch_token";
const API_TIMESTAMP_WITH_TIMEZONE = /(?:z|[+-]\d{2}:?\d{2})$/i;

export type Project = {
  id: string;
  company_name: string;
  main_domain: string;
  description?: string | null;
  scan_frequency: string;
  authorization_confirmed: boolean;
  authorization_contact?: string | null;
  authorization_expires_at?: string | null;
  max_scan_profile: string;
  risk_score: number;
  risk_level: string;
  risk_status: string;
  created_at: string;
  updated_at: string;
  last_scan_at?: string | null;
  next_scan_at?: string | null;
};

export type Scan = {
  id: string;
  project_id: string;
  status: string;
  trigger: string;
  scan_profile: string;
  assets_discovered: number;
  assets_scanned: number;
  assets_failed: number;
  findings_created: number;
  checks_completed: number;
  checks_failed: number;
  coverage_percent: number;
  attempt_count: number;
  heartbeat_at: string | null;
  partial_reason: string | null;
  discovery_metadata: Record<string, unknown> | unknown[] | null;
  risk_score: number;
  error_message?: string | null;
  created_at: string;
  started_at?: string | null;
  finished_at?: string | null;
};

export type ScanAssetResult = {
  id: string;
  project_id: string;
  scan_id: string;
  asset_id: string | null;
  hostname: string;
  ip_addresses: string[];
  source: string | null;
  discovery_status: string;
  scan_status: string;
  risk_level: string;
  checks: Record<string, unknown>;
  http_observations: unknown[];
  tls_observations: unknown[];
  port_observations: unknown[];
  header_observations: unknown[];
  technology_observations: unknown[];
  exposure_observations: unknown[];
  finding_observations: unknown[];
  errors: unknown[];
  started_at: string | null;
  finished_at: string | null;
  created_at: string;
  updated_at: string;
};

export type Asset = {
  id: string;
  hostname: string;
  asset_type: string;
  ip_address?: string | null;
  status: string;
  risk_level: string;
  first_seen_at: string;
  last_seen_at: string;
  ports: { port: number; status: string; service_guess?: string | null }[];
  technologies: { name: string; confidence: number }[];
};

export type Finding = {
  id: string;
  title: string;
  description?: string;
  severity: string;
  category: string;
  fingerprint?: string | null;
  confidence: string;
  cvss_score?: number | null;
  evidence_hash?: string | null;
  sla_due_at?: string | null;
  owner?: string | null;
  evidence?: unknown;
  business_impact?: string | null;
  recommendation?: string | null;
  notes?: string | null;
  status: string;
  asset_id?: string | null;
  asset_hostname?: string | null;
  first_seen_at?: string;
  last_seen_at: string;
};

export type FindingNote = {
  id: string;
  finding_id: string;
  user_id?: string | null;
  note: string;
  created_at: string;
};

export type Change = {
  id: string;
  project_id: string;
  scan_id?: string | null;
  asset_id?: string | null;
  change_type: string;
  old_value?: string | null;
  new_value?: string | null;
  severity: string;
  detected_at: string;
};

export type DashboardSummary = {
  project: Project;
  total_assets: number;
  active_subdomains: number;
  open_ports: number;
  critical_high_findings: number;
  expiring_certificates: number;
  missing_security_headers: number;
  recent_changes: { id: string; change_type: string; severity: string; old_value?: string | null; new_value?: string | null; detected_at: string }[];
  recent_scans: { id: string; status: string; started_at?: string | null; risk_score: number; findings_created: number }[];
  severity_counts: Record<string, number>;
};

export type Notification = {
  id: string;
  project_id?: string | null;
  title: string;
  message: string;
  notification_type: string;
  is_read: boolean;
  created_at: string;
};

export type Report = {
  id: string;
  project_id: string;
  scan_id?: string | null;
  scan_profile?: string | null;
  scan_date?: string | null;
  report_type: string;
  status: string;
  file_path?: string | null;
  error_message?: string | null;
  created_at: string;
};

export type ScanLog = {
  id: string;
  level: string;
  message: string;
  created_at: string;
};

export function getToken() {
  if (typeof window === "undefined") return null;
  return window.localStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string) {
  window.localStorage.setItem(TOKEN_KEY, token);
}

export function clearToken() {
  window.localStorage.removeItem(TOKEN_KEY);
}

export function parseApiDate(value: string) {
  const normalized = API_TIMESTAMP_WITH_TIMEZONE.test(value) ? value : `${value}Z`;
  return new Date(normalized);
}

export function formatApiDateTime(value: string) {
  return parseApiDate(value).toLocaleString();
}

export function formatApiDate(value: string) {
  return parseApiDate(value).toLocaleDateString();
}

export function apiDateMs(value: string) {
  return parseApiDate(value).getTime();
}

export async function apiFetch<T>(path: string, options: RequestInit = {}): Promise<T> {
  const token = getToken();
  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...options.headers
    }
  });

  if (!response.ok) {
    let message = `Request failed with status ${response.status}`;
    try {
      const body = await response.json();
      message = body.detail ?? message;
    } catch {
      // Keep the status-based message when the response is not JSON.
    }
    throw new Error(Array.isArray(message) ? message.map((item) => item.msg ?? String(item)).join(", ") : message);
  }

  if (response.status === 204) {
    return undefined as T;
  }
  return response.json() as Promise<T>;
}

export async function login(email: string, password: string) {
  const token = await apiFetch<{ access_token: string }>("/auth/login", {
    method: "POST",
    body: JSON.stringify({ email, password })
  });
  setToken(token.access_token);
  return token;
}

export async function register(fullName: string, email: string, password: string) {
  await apiFetch("/auth/register", {
    method: "POST",
    body: JSON.stringify({ full_name: fullName, email, password })
  });
  return login(email, password);
}

export async function downloadReport(reportId: string) {
  const token = getToken();
  const response = await fetch(`${API_BASE_URL}/reports/${reportId}/download`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {}
  });
  if (!response.ok) {
    throw new Error(`Download failed with status ${response.status}`);
  }
  const blob = await response.blob();
  const disposition = response.headers.get("content-disposition") ?? "";
  const match = /filename="?([^"]+)"?/i.exec(disposition);
  const filename = match?.[1] ?? `surfacewatch-report-${reportId}`;
  const url = window.URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  window.URL.revokeObjectURL(url);
}
