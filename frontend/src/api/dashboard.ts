import { API_BASE_URL } from "../config/api";

export interface DashboardRecentScan {
  id: string;
  project_id: string | null;
  project_name: string;
  target_path: string;
  status: string;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  finding_count: number;
}

export interface DashboardProjectLatestScan {
  project_id: string | null;
  project_name: string;
  latest_scan_id: string;
  latest_scan_status: string;
  latest_scan_created_at: string;
}

export interface DashboardSummary {
  recent_scans: DashboardRecentScan[];
  severity_counts: Record<string, number>;
  project_latest_scans: DashboardProjectLatestScan[];
}

export async function getDashboardSummary(): Promise<DashboardSummary> {
  const response = await fetch(`${API_BASE_URL}/api/dashboard/summary`);

  if (!response.ok) {
    let detail = `Could not load dashboard summary (${response.status})`;
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

  return (await response.json()) as DashboardSummary;
}
