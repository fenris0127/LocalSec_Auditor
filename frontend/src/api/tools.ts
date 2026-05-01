import { API_BASE_URL } from "../config/api";

export type ToolName = "semgrep" | "gitleaks" | "trivy";

export interface ToolStatus {
  installed: boolean;
  version: string | null;
  error: string | null;
}

export type ToolsStatusResponse = Record<ToolName, ToolStatus>;

export async function getToolsStatus(): Promise<ToolsStatusResponse> {
  const response = await fetch(`${API_BASE_URL}/api/tools/status`);

  if (!response.ok) {
    let detail = `Could not load tool status (${response.status})`;
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

  return (await response.json()) as ToolsStatusResponse;
}
