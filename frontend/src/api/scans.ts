import { API_BASE_URL } from "../config/api";

export type ScanType = "semgrep" | "gitleaks" | "trivy" | "syft" | "grype";

export interface CreateScanPayload {
  project_name: string;
  target_path: string;
  scan_types: ScanType[];
  run_immediately: boolean;
}

export interface CreateScanResponse {
  scan_id: string;
  status: string;
}

export interface ScanSummary {
  id: string;
  project_id: string | null;
  project_name: string;
  target_path: string;
  status: string;
  started_at: string | null;
  finished_at: string | null;
  created_at: string;
}

export interface ScanTask {
  id: string;
  scan_id: string;
  task_type: string;
  tool_name: string | null;
  status: string;
  started_at: string | null;
  finished_at: string | null;
  error_message: string | null;
}

export interface ScanProgressCurrentTask {
  id: string;
  task_type: string;
  tool_name: string | null;
  status: string;
}

export interface ScanProgressResponse {
  total_tasks: number;
  completed_tasks: number;
  failed_tasks: number;
  running_tasks: number;
  pending_tasks: number;
  cancelled_tasks: number;
  progress_percent: number;
  current_task: ScanProgressCurrentTask | null;
}

export interface Finding {
  id: string;
  scan_id: string;
  severity: string;
  category: string;
  title: string;
  rule_id: string | null;
  scanner: string;
  file_path: string | null;
  line: number | null;
  cce_id: string | null;
  current_value: string | null;
  expected_value: string | null;
  llm_summary: string | null;
  reference_context?: ReferenceContext[];
  reference_contexts?: ReferenceContext[];
  references?: ReferenceContext[];
}

export interface FindingComparisonSummary {
  total: number;
  by_severity: Record<string, number>;
  by_category: Record<string, number>;
}

export interface ScanComparisonSummary {
  new_findings: FindingComparisonSummary;
  resolved_findings: FindingComparisonSummary;
  persistent_findings: FindingComparisonSummary;
}

export interface ScanComparisonResponse {
  base_scan_id: string;
  target_scan_id: string;
  new_findings: Finding[];
  resolved_findings: Finding[];
  persistent_findings: Finding[];
  summary: ScanComparisonSummary;
}

export interface AnalyzeFindingResponse {
  llm_summary: string;
  reference_context?: ReferenceContext[];
  reference_contexts?: ReferenceContext[];
  references?: ReferenceContext[];
}

export interface ReferenceContext {
  id?: string;
  source_title?: string | null;
  source_path?: string | null;
  source_name?: string | null;
  title?: string | null;
  path?: string | null;
  chunk_index?: number | string | null;
  chunk_summary?: string | null;
  summary?: string | null;
  chunk_text?: string | null;
  content?: string | null;
  text?: string | null;
  metadata?: {
    title?: string | null;
    source_path?: string | null;
    source_name?: string | null;
    chunk_index?: number | string | null;
    summary?: string | null;
  };
}

export interface ScanReportResponse {
  report_path: string;
  content: string;
}

async function requestJson<T>(
  path: string,
  fallbackMessage: string,
  init?: RequestInit,
): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${path}`, init);

  if (!response.ok) {
    let detail = `${fallbackMessage} (${response.status})`;
    try {
      const body = (await response.json()) as { detail?: string };
      if (body.detail) {
        detail = body.detail;
      }
    } catch {
      // Keep the generic status message when the API does not return JSON.
    }
    throw new Error(detail);
  }

  return (await response.json()) as T;
}

export async function createScan(payload: CreateScanPayload): Promise<CreateScanResponse> {
  const response = await fetch(`${API_BASE_URL}/api/scans`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      ...payload,
      llm_enabled: true,
    }),
  });

  if (!response.ok) {
    let detail = `Scan creation failed with status ${response.status}`;
    try {
      const body = (await response.json()) as { detail?: string };
      if (body.detail) {
        detail = body.detail;
      }
    } catch {
      // Keep the generic status message when the API does not return JSON.
    }
    throw new Error(detail);
  }

  return (await response.json()) as CreateScanResponse;
}

export function listScans(): Promise<ScanSummary[]> {
  return requestJson<ScanSummary[]>("/api/scans", "Could not load scans");
}

export function getScan(scanId: string): Promise<ScanSummary> {
  return requestJson<ScanSummary>(`/api/scans/${encodeURIComponent(scanId)}`, "Could not load scan");
}

export function listScanTasks(scanId: string): Promise<ScanTask[]> {
  return requestJson<ScanTask[]>(
    `/api/scans/${encodeURIComponent(scanId)}/tasks`,
    "Could not load scan tasks",
  );
}

export function getScanProgress(scanId: string): Promise<ScanProgressResponse> {
  return requestJson<ScanProgressResponse>(
    `/api/scans/${encodeURIComponent(scanId)}/progress`,
    "Could not load scan progress",
  );
}

export function listScanFindings(scanId: string): Promise<Finding[]> {
  return requestJson<Finding[]>(
    `/api/scans/${encodeURIComponent(scanId)}/findings`,
    "Could not load findings",
  );
}

export function compareScanWithLatest(scanId: string): Promise<ScanComparisonResponse> {
  return requestJson<ScanComparisonResponse>(
    `/api/scans/${encodeURIComponent(scanId)}/compare/latest`,
    "Could not compare scan",
  );
}

export function analyzeFinding(findingId: string): Promise<AnalyzeFindingResponse> {
  return requestJson<AnalyzeFindingResponse>(
    `/api/findings/${encodeURIComponent(findingId)}/analyze`,
    "Could not analyze finding",
    { method: "POST" },
  );
}

export function createScanReport(scanId: string): Promise<ScanReportResponse> {
  return requestJson<ScanReportResponse>(
    `/api/scans/${encodeURIComponent(scanId)}/report`,
    "Could not create report",
    { method: "POST" },
  );
}

export function getScanReport(scanId: string): Promise<ScanReportResponse> {
  return requestJson<ScanReportResponse>(
    `/api/scans/${encodeURIComponent(scanId)}/report`,
    "Could not load report",
  );
}
