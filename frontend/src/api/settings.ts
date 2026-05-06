import { API_BASE_URL } from "../config/api";

export interface OfflineModeResponse {
  offline_mode: boolean;
  mode: "offline" | "update";
  updates_enabled: boolean;
  env_var: string;
}

export async function getOfflineMode(): Promise<OfflineModeResponse> {
  const response = await fetch(`${API_BASE_URL}/api/settings/offline-mode`);

  if (!response.ok) {
    let detail = `Could not load offline mode (${response.status})`;
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

  return (await response.json()) as OfflineModeResponse;
}
