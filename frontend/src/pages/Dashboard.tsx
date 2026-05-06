import { useEffect, useState } from "react";
import type { ReactElement } from "react";

import { getDashboardSummary } from "../api/dashboard";
import type { DashboardSummary } from "../api/dashboard";
import { getOfflineMode } from "../api/settings";
import type { OfflineModeResponse } from "../api/settings";
import { getToolsStatus, updateGrypeDb, updateTrivyDb } from "../api/tools";
import type { ToolName, ToolsStatusResponse, ToolUpdateResponse, UpdatableToolName } from "../api/tools";

const TOOL_NAMES: ToolName[] = ["semgrep", "gitleaks", "trivy", "syft", "grype", "lynis", "openscap"];
const UPDATABLE_TOOLS: UpdatableToolName[] = ["trivy", "grype"];

interface UpdateStatus {
  isLoading: boolean;
  message: string | null;
  error: string | null;
}

const INITIAL_UPDATE_STATUS: Record<UpdatableToolName, UpdateStatus> = {
  trivy: {
    isLoading: false,
    message: null,
    error: null,
  },
  grype: {
    isLoading: false,
    message: null,
    error: null,
  },
};

function isUpdatableTool(toolName: ToolName): toolName is UpdatableToolName {
  return UPDATABLE_TOOLS.includes(toolName as UpdatableToolName);
}

function formatUpdateResult(result: ToolUpdateResponse): string {
  const command = result.command.join(" ");
  if (result.success) {
    return `Update completed: ${command}`;
  }
  return result.error_message ?? `Update failed with exit code ${result.exit_code ?? "unknown"}`;
}

function formatDate(value: string): string {
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(value));
}

function severityEntries(summary: DashboardSummary | null): [string, number][] {
  if (!summary) {
    return [];
  }
  return Object.entries(summary.severity_counts).sort(([left], [right]) =>
    left.localeCompare(right),
  );
}

function ToolsStatus(): ReactElement {
  const [toolsStatus, setToolsStatus] = useState<ToolsStatusResponse | null>(null);
  const [isLoadingTools, setIsLoadingTools] = useState(true);
  const [toolsError, setToolsError] = useState<string | null>(null);
  const [settings, setSettings] = useState<OfflineModeResponse | null>(null);
  const [isLoadingSettings, setIsLoadingSettings] = useState(true);
  const [settingsError, setSettingsError] = useState<string | null>(null);
  const [updateStatuses, setUpdateStatuses] =
    useState<Record<UpdatableToolName, UpdateStatus>>(INITIAL_UPDATE_STATUS);

  useEffect(() => {
    let isMounted = true;

    async function loadToolsStatus(): Promise<void> {
      setIsLoadingTools(true);
      setToolsError(null);
      try {
        const result = await getToolsStatus();
        if (isMounted) {
          setToolsStatus(result);
        }
      } catch (error) {
        if (isMounted) {
          setToolsError(error instanceof Error ? error.message : "Could not load tool status");
        }
      } finally {
        if (isMounted) {
          setIsLoadingTools(false);
        }
      }
    }

    void loadToolsStatus();

    return () => {
      isMounted = false;
    };
  }, []);

  useEffect(() => {
    let isMounted = true;

    async function loadOfflineMode(): Promise<void> {
      setIsLoadingSettings(true);
      setSettingsError(null);
      try {
        const result = await getOfflineMode();
        if (isMounted) {
          setSettings(result);
        }
      } catch (error) {
        if (isMounted) {
          setSettingsError(error instanceof Error ? error.message : "Could not load offline mode");
        }
      } finally {
        if (isMounted) {
          setIsLoadingSettings(false);
        }
      }
    }

    void loadOfflineMode();

    return () => {
      isMounted = false;
    };
  }, []);

  const updatesEnabled = settings?.updates_enabled === true;

  async function handleUpdate(toolName: UpdatableToolName): Promise<void> {
    setUpdateStatuses((current) => ({
      ...current,
      [toolName]: {
        isLoading: true,
        message: null,
        error: null,
      },
    }));

    try {
      const result = toolName === "trivy" ? await updateTrivyDb() : await updateGrypeDb();
      setUpdateStatuses((current) => ({
        ...current,
        [toolName]: {
          isLoading: false,
          message: result.success ? formatUpdateResult(result) : null,
          error: result.success ? null : formatUpdateResult(result),
        },
      }));
    } catch (error) {
      setUpdateStatuses((current) => ({
        ...current,
        [toolName]: {
          isLoading: false,
          message: null,
          error: error instanceof Error ? error.message : `Could not update ${toolName} DB`,
        },
      }));
    }
  }

  return (
    <div className="summary-panel tools-panel">
      <div className="panel-heading-row">
        <h2>Scanner tools</h2>
        {settings ? (
          <span className={updatesEnabled ? "status-pill success" : "status-pill warning"}>
            {updatesEnabled ? "updates enabled" : "offline mode"}
          </span>
        ) : null}
      </div>

      {isLoadingTools ? (
        <div className="empty-panel compact" role="status">
          <strong>Checking tools</strong>
          <span>Loading local scanner installation status.</span>
        </div>
      ) : null}

      {toolsError ? (
        <div className="status-message error" role="alert">
          <strong>Could not load tool status</strong>
          <span>{toolsError}</span>
        </div>
      ) : null}

      {settingsError ? (
        <div className="status-message error" role="alert">
          <strong>Could not load update mode</strong>
          <span>{settingsError}</span>
        </div>
      ) : null}

      {!isLoadingTools && !toolsError && toolsStatus ? (
        <div className="tools-grid">
          {TOOL_NAMES.map((toolName) => {
            const status = toolsStatus[toolName];
            const isReported = status !== undefined;
            const installed = Boolean(status?.installed);
            const canUpdate = isUpdatableTool(toolName);
            const updateStatus = canUpdate ? updateStatuses[toolName] : null;
            const updateDisabled =
              !canUpdate || !updatesEnabled || isLoadingSettings || Boolean(updateStatus?.isLoading);
            const statusLabel = !isReported ? "not reported" : installed ? "installed" : "missing";

            return (
              <div className={installed ? "tool-card" : "tool-card warning"} key={toolName}>
                <div className="tool-card-header">
                  <strong>{toolName}</strong>
                  <span className={installed ? "status-pill success" : "status-pill warning"}>
                    {statusLabel}
                  </span>
                </div>
                <dl className="tool-meta">
                  <div>
                    <dt>Version</dt>
                    <dd>{status?.version ?? "N/A"}</dd>
                  </div>
                  <div>
                    <dt>Error</dt>
                    <dd>{status?.error ?? (isReported ? "N/A" : "Tool status is not returned by API.")}</dd>
                  </div>
                </dl>
                {canUpdate ? (
                  <div className="tool-update-actions">
                    <button
                      className="secondary-action"
                      disabled={updateDisabled}
                      onClick={() => void handleUpdate(toolName)}
                      type="button"
                    >
                      {updateStatus?.isLoading
                        ? "Updating..."
                        : toolName === "trivy"
                          ? "Update Trivy DB"
                          : "Update Grype DB"}
                    </button>
                    {!updatesEnabled && !isLoadingSettings ? (
                      <p className="muted">Disabled while service is in offline mode.</p>
                    ) : null}
                    {updateStatus?.message ? (
                      <div className="status-message success compact" role="status">
                        <span>{updateStatus.message}</span>
                      </div>
                    ) : null}
                    {updateStatus?.error ? (
                      <div className="status-message error compact" role="alert">
                        <span>{updateStatus.error}</span>
                      </div>
                    ) : null}
                  </div>
                ) : null}
              </div>
            );
          })}
        </div>
      ) : null}
    </div>
  );
}

function OfflineModeStatus(): ReactElement {
  const [settings, setSettings] = useState<OfflineModeResponse | null>(null);
  const [isLoadingSettings, setIsLoadingSettings] = useState(true);
  const [settingsError, setSettingsError] = useState<string | null>(null);

  useEffect(() => {
    let isMounted = true;

    async function loadOfflineMode(): Promise<void> {
      setIsLoadingSettings(true);
      setSettingsError(null);
      try {
        const result = await getOfflineMode();
        if (isMounted) {
          setSettings(result);
        }
      } catch (error) {
        if (isMounted) {
          setSettingsError(error instanceof Error ? error.message : "Could not load offline mode");
        }
      } finally {
        if (isMounted) {
          setIsLoadingSettings(false);
        }
      }
    }

    void loadOfflineMode();

    return () => {
      isMounted = false;
    };
  }, []);

  return (
    <div className="summary-panel settings-panel">
      <div className="panel-heading-row">
        <h2>Service mode</h2>
        {settings ? (
          <span className={settings.offline_mode ? "status-pill warning" : "status-pill success"}>
            {settings.mode}
          </span>
        ) : null}
      </div>

      {isLoadingSettings ? (
        <div className="empty-panel compact" role="status">
          <strong>Loading mode</strong>
          <span>Checking local service mode.</span>
        </div>
      ) : null}

      {settingsError ? (
        <div className="status-message error" role="alert">
          <strong>Could not load service mode</strong>
          <span>{settingsError}</span>
        </div>
      ) : null}

      {!isLoadingSettings && !settingsError && settings ? (
        <dl className="settings-meta">
          <div>
            <dt>Environment</dt>
            <dd>{settings.env_var}</dd>
          </div>
          <div>
            <dt>Updates</dt>
            <dd>{settings.updates_enabled ? "enabled" : "disabled"}</dd>
          </div>
        </dl>
      ) : null}
    </div>
  );
}

export function Dashboard(): ReactElement {
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  useEffect(() => {
    let isMounted = true;

    async function loadSummary(): Promise<void> {
      setIsLoading(true);
      setErrorMessage(null);
      try {
        const result = await getDashboardSummary();
        if (isMounted) {
          setSummary(result);
        }
      } catch (error) {
        if (isMounted) {
          setErrorMessage(error instanceof Error ? error.message : "Could not load dashboard summary");
        }
      } finally {
        if (isMounted) {
          setIsLoading(false);
        }
      }
    }

    void loadSummary();

    return () => {
      isMounted = false;
    };
  }, []);

  return (
    <section className="page-section">
      <div className="section-header">
        <p className="eyebrow">Dashboard</p>
        <h1>Scan overview</h1>
        <p className="section-copy">Review created scans and open a scan to inspect tasks and findings.</p>
      </div>

      <OfflineModeStatus />

      <div className="summary-panel dashboard-summary-panel">
        <h2>Risk trend summary</h2>

        {isLoading ? (
          <div className="empty-panel compact" role="status">
            <strong>Loading summary</strong>
            <span>Fetching recent scans and finding counts.</span>
          </div>
        ) : null}

        {errorMessage ? (
          <div className="status-message error" role="alert">
            <strong>Could not load dashboard summary</strong>
            <span>{errorMessage}</span>
          </div>
        ) : null}

        {!isLoading && !errorMessage && summary ? (
          <>
            <div className="severity-card-grid">
              {severityEntries(summary).length > 0 ? (
                severityEntries(summary).map(([severity, count]) => (
                  <div className="severity-card" key={severity}>
                    <strong>{severity}</strong>
                    <span>{count}</span>
                  </div>
                ))
              ) : (
                <p className="muted">No findings counted yet.</p>
              )}
            </div>

            <div className="dashboard-grid">
              <div className="dashboard-subsection">
                <h3>Recent scans</h3>
                {summary.recent_scans.length > 0 ? (
                  <div className="table-panel compact">
                    <table>
                      <thead>
                        <tr>
                          <th>Scan ID</th>
                          <th>Project</th>
                          <th>Status</th>
                          <th>Findings</th>
                          <th>Created</th>
                        </tr>
                      </thead>
                      <tbody>
                        {summary.recent_scans.map((scan) => (
                          <tr key={scan.id}>
                            <td>
                              <a className="table-link" href={`#/scans/${encodeURIComponent(scan.id)}`}>
                                {scan.id}
                              </a>
                            </td>
                            <td>{scan.project_name}</td>
                            <td>
                              <span className="status-pill">{scan.status}</span>
                            </td>
                            <td>{scan.finding_count}</td>
                            <td>{formatDate(scan.created_at)}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <p className="muted">No recent scans.</p>
                )}
              </div>

              <div className="dashboard-subsection">
                <h3>Project latest status</h3>
                {summary.project_latest_scans.length > 0 ? (
                  <div className="table-panel compact">
                    <table>
                      <thead>
                        <tr>
                          <th>Project</th>
                          <th>Latest scan</th>
                          <th>Status</th>
                          <th>Created</th>
                        </tr>
                      </thead>
                      <tbody>
                        {summary.project_latest_scans.map((project) => (
                          <tr key={project.project_id ?? project.project_name}>
                            <td>{project.project_name}</td>
                            <td>
                              <a
                                className="table-link"
                                href={`#/scans/${encodeURIComponent(project.latest_scan_id)}`}
                              >
                                {project.latest_scan_id}
                              </a>
                            </td>
                            <td>
                              <span className="status-pill">{project.latest_scan_status}</span>
                            </td>
                            <td>{formatDate(project.latest_scan_created_at)}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <p className="muted">No project status available.</p>
                )}
              </div>
            </div>
          </>
        ) : null}
      </div>

      <ToolsStatus />
    </section>
  );
}
