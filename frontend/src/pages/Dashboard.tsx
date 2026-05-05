import { useEffect, useState } from "react";
import type { ReactElement } from "react";

import { getDashboardSummary } from "../api/dashboard";
import type { DashboardSummary } from "../api/dashboard";
import { getToolsStatus } from "../api/tools";
import type { ToolName, ToolsStatusResponse } from "../api/tools";

const TOOL_NAMES: ToolName[] = ["semgrep", "gitleaks", "trivy", "syft", "grype"];

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

  return (
    <div className="summary-panel tools-panel">
      <h2>Scanner tools</h2>

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

      {!isLoadingTools && !toolsError && toolsStatus ? (
        <div className="tools-grid">
          {TOOL_NAMES.map((toolName) => {
            const status = toolsStatus[toolName];
            const installed = Boolean(status?.installed);

            return (
              <div className={installed ? "tool-card" : "tool-card warning"} key={toolName}>
                <div className="tool-card-header">
                  <strong>{toolName}</strong>
                  <span className={installed ? "status-pill success" : "status-pill warning"}>
                    {installed ? "installed" : "missing"}
                  </span>
                </div>
                <dl className="tool-meta">
                  <div>
                    <dt>Version</dt>
                    <dd>{status?.version ?? "N/A"}</dd>
                  </div>
                  <div>
                    <dt>Error</dt>
                    <dd>{status?.error ?? "N/A"}</dd>
                  </div>
                </dl>
              </div>
            );
          })}
        </div>
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
