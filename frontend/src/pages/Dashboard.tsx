import { useEffect, useState } from "react";
import type { ReactElement } from "react";

import { listScans } from "../api/scans";
import type { ScanSummary } from "../api/scans";
import { getToolsStatus } from "../api/tools";
import type { ToolName, ToolsStatusResponse } from "../api/tools";

const TOOL_NAMES: ToolName[] = ["semgrep", "gitleaks", "trivy", "syft", "grype"];

function formatDate(value: string): string {
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(value));
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
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  useEffect(() => {
    let isMounted = true;

    async function loadScans(): Promise<void> {
      setIsLoading(true);
      setErrorMessage(null);
      try {
        const result = await listScans();
        if (isMounted) {
          setScans(result);
        }
      } catch (error) {
        if (isMounted) {
          setErrorMessage(error instanceof Error ? error.message : "Could not load scans");
        }
      } finally {
        if (isMounted) {
          setIsLoading(false);
        }
      }
    }

    void loadScans();

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

      <ToolsStatus />

      {isLoading ? (
        <div className="empty-panel" role="status">
          <strong>Loading scans</strong>
          <span>Fetching scan history from the backend.</span>
        </div>
      ) : null}

      {errorMessage ? (
        <div className="status-message error" role="alert">
          <strong>Could not load scans</strong>
          <span>{errorMessage}</span>
        </div>
      ) : null}

      {!isLoading && !errorMessage && scans.length === 0 ? (
        <div className="empty-panel">
          <strong>No scans yet</strong>
          <span>Create a scan from the New Scan page.</span>
        </div>
      ) : null}

      {!isLoading && !errorMessage && scans.length > 0 ? (
        <div className="table-panel">
          <table>
            <thead>
              <tr>
                <th>Scan ID</th>
                <th>Project</th>
                <th>Status</th>
                <th>Created</th>
              </tr>
            </thead>
            <tbody>
              {scans.map((scan) => (
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
                  <td>{formatDate(scan.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
    </section>
  );
}
