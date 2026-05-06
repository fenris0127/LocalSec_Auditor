import { API_BASE_URL } from "../config/api";

export type ToolName = "semgrep" | "gitleaks" | "trivy" | "syft" | "grype" | "lynis" | "openscap";
export type UpdatableToolName = Extract<ToolName, "trivy" | "grype">;

export interface ToolStatus {
  installed: boolean;
  version: string | null;
  error: string | null;
}

export type ToolsStatusResponse = Partial<Record<ToolName, ToolStatus>>;

export interface ToolUpdateResponse {
  command: string[];
  success: boolean;
  stdout: string;
  stderr: string;
  exit_code: number | null;
  timed_out: boolean;
  error_message: string | null;
}

async function readErrorDetail(response: Response, fallback: string): Promise<string> {
  try {
    const body = (await response.json()) as { detail?: string };
    if (body.detail) {
      return body.detail;
    }
  } catch {
    // Keep the generic status message when the API does not return JSON.
  }
  return fallback;
}

export async function getToolsStatus(): Promise<ToolsStatusResponse> {
  const response = await fetch(`${API_BASE_URL}/api/tools/status`);

  if (!response.ok) {
    const detail = await readErrorDetail(
      response,
      `Could not load tool status (${response.status})`,
    );
    throw new Error(detail);
  }

  return (await response.json()) as ToolsStatusResponse;
}

export async function updateTrivyDb(): Promise<ToolUpdateResponse> {
  const response = await fetch(`${API_BASE_URL}/api/tools/trivy/update-db`, {
    method: "POST",
  });

  if (!response.ok) {
    const detail = await readErrorDetail(
      response,
      `Could not update Trivy DB (${response.status})`,
    );
    throw new Error(detail);
  }

  return (await response.json()) as ToolUpdateResponse;
}

export async function updateGrypeDb(): Promise<ToolUpdateResponse> {
  const response = await fetch(`${API_BASE_URL}/api/tools/grype/update-db`, {
    method: "POST",
  });

  if (!response.ok) {
    const detail = await readErrorDetail(
      response,
      `Could not update Grype DB (${response.status})`,
    );
    throw new Error(detail);
  }

  return (await response.json()) as ToolUpdateResponse;
}
