import { Fragment, useEffect, useState } from "react";
import type { ReactElement } from "react";

import {
  analyzeFinding,
  createScanReport,
  getScan,
  getScanReport,
  listScanFindings,
  listScanTasks,
} from "../api/scans";
import type { Finding, ScanSummary, ScanTask } from "../api/scans";

interface ScanDetailProps {
  scanId: string | null;
}

function display(value: string | number | null): string {
  if (value === null || value === "") {
    return "N/A";
  }
  return String(value);
}

function formatDate(value: string | null): string {
  if (!value) {
    return "N/A";
  }
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(value));
}

export function ScanDetail({ scanId }: ScanDetailProps): ReactElement {
  const [scan, setScan] = useState<ScanSummary | null>(null);
  const [tasks, setTasks] = useState<ScanTask[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [scanError, setScanError] = useState<string | null>(null);
  const [findingsError, setFindingsError] = useState<string | null>(null);
  const [analyzingFindingIds, setAnalyzingFindingIds] = useState<Record<string, boolean>>({});
  const [analysisErrors, setAnalysisErrors] = useState<Record<string, string>>({});
  const [reportContent, setReportContent] = useState<string | null>(null);
  const [reportPath, setReportPath] = useState<string | null>(null);
  const [isCreatingReport, setIsCreatingReport] = useState(false);
  const [isLoadingReport, setIsLoadingReport] = useState(false);
  const [reportError, setReportError] = useState<string | null>(null);

  useEffect(() => {
    let isMounted = true;

    async function loadScanDetail(id: string): Promise<void> {
      setIsLoading(true);
      setScanError(null);
      setFindingsError(null);
      setAnalyzingFindingIds({});
      setAnalysisErrors({});
      setReportContent(null);
      setReportPath(null);
      setReportError(null);
      setScan(null);
      setTasks([]);
      setFindings([]);

      try {
        const [scanResult, taskResult] = await Promise.all([getScan(id), listScanTasks(id)]);
        if (isMounted) {
          setScan(scanResult);
          setTasks(taskResult);
        }
      } catch (error) {
        if (isMounted) {
          setScanError(error instanceof Error ? error.message : "Could not load scan detail");
        }
        return;
      } finally {
        if (isMounted) {
          setIsLoading(false);
        }
      }

      try {
        const findingResult = await listScanFindings(id);
        if (isMounted) {
          setFindings(findingResult);
        }
      } catch (error) {
        if (isMounted) {
          setFindingsError(error instanceof Error ? error.message : "Could not load findings");
        }
      }
    }

    if (scanId) {
      void loadScanDetail(scanId);
    }

    return () => {
      isMounted = false;
    };
  }, [scanId]);

  async function handleAnalyzeFinding(findingId: string): Promise<void> {
    setAnalyzingFindingIds((current) => ({ ...current, [findingId]: true }));
    setAnalysisErrors((current) => {
      const next = { ...current };
      delete next[findingId];
      return next;
    });

    try {
      const result = await analyzeFinding(findingId);
      setFindings((current) =>
        current.map((finding) =>
          finding.id === findingId ? { ...finding, llm_summary: result.llm_summary } : finding,
        ),
      );
    } catch (error) {
      setAnalysisErrors((current) => ({
        ...current,
        [findingId]: error instanceof Error ? error.message : "Could not analyze finding",
      }));
    } finally {
      setAnalyzingFindingIds((current) => ({ ...current, [findingId]: false }));
    }
  }

  async function handleCreateReport(id: string): Promise<void> {
    setIsCreatingReport(true);
    setReportError(null);

    try {
      const created = await createScanReport(id);
      const loaded = await getScanReport(id);
      setReportPath(loaded.report_path || created.report_path);
      setReportContent(loaded.content);
    } catch (error) {
      setReportError(error instanceof Error ? error.message : "Could not create report");
    } finally {
      setIsCreatingReport(false);
    }
  }

  async function handleLoadReport(id: string): Promise<void> {
    setIsLoadingReport(true);
    setReportError(null);

    try {
      const report = await getScanReport(id);
      setReportPath(report.report_path);
      setReportContent(report.content);
    } catch (error) {
      setReportError(error instanceof Error ? error.message : "Could not load report");
    } finally {
      setIsLoadingReport(false);
    }
  }

  if (!scanId) {
    return (
      <section className="page-section">
        <div className="section-header">
          <p className="eyebrow">Scan Detail</p>
          <h1>Scan detail</h1>
          <p className="section-copy">Select a scan from the dashboard to view details.</p>
        </div>
      </section>
    );
  }

  return (
    <section className="page-section">
      <div className="section-header">
        <p className="eyebrow">Scan Detail</p>
        <h1>{scan?.project_name ?? scanId}</h1>
        <p className="section-copy">Inspect scan metadata, task progress, and normalized findings.</p>
      </div>

      {isLoading ? (
        <div className="empty-panel" role="status">
          <strong>Loading scan</strong>
          <span>Fetching scan detail and tasks.</span>
        </div>
      ) : null}

      {scanError ? (
        <div className="status-message error" role="alert">
          <strong>Could not load scan detail</strong>
          <span>{scanError}</span>
        </div>
      ) : null}

      {scan ? (
        <div className="detail-grid">
          <div className="summary-panel">
            <h2>Scan</h2>
            <dl>
              <div>
                <dt>Scan ID</dt>
                <dd>{scan.id}</dd>
              </div>
              <div>
                <dt>Status</dt>
                <dd>
                  <span className="status-pill">{scan.status}</span>
                </dd>
              </div>
              <div>
                <dt>Target path</dt>
                <dd>{scan.target_path}</dd>
              </div>
              <div>
                <dt>Created</dt>
                <dd>{formatDate(scan.created_at)}</dd>
              </div>
              <div>
                <dt>Started</dt>
                <dd>{formatDate(scan.started_at)}</dd>
              </div>
              <div>
                <dt>Finished</dt>
                <dd>{formatDate(scan.finished_at)}</dd>
              </div>
            </dl>
          </div>

          <div className="summary-panel">
            <h2>Tasks</h2>
            {tasks.length > 0 ? (
              <div className="table-panel compact">
                <table>
                  <thead>
                    <tr>
                      <th>Tool</th>
                      <th>Status</th>
                      <th>Error</th>
                    </tr>
                  </thead>
                  <tbody>
                    {tasks.map((task) => (
                      <tr key={task.id}>
                        <td>{display(task.tool_name)}</td>
                        <td>
                          <span className="status-pill">{task.status}</span>
                        </td>
                        <td>{display(task.error_message)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <p className="muted">No tasks found.</p>
            )}
          </div>
        </div>
      ) : null}

      {scan ? (
        <div className="summary-panel">
          <h2>Findings</h2>
          {findingsError ? (
            <div className="status-message error" role="alert">
              <strong>Could not load findings</strong>
              <span>{findingsError}</span>
            </div>
          ) : null}

          {!findingsError && findings.length === 0 ? <p className="muted">No findings found.</p> : null}

          {!findingsError && findings.length > 0 ? (
            <div className="table-panel">
              <table>
                <thead>
                  <tr>
                    <th>Severity</th>
                    <th>Category</th>
                    <th>Title</th>
                    <th>Scanner</th>
                    <th>File</th>
                    <th>Line</th>
                    <th>AI</th>
                  </tr>
                </thead>
                <tbody>
                  {findings.map((finding) => {
                    const isAnalyzing = Boolean(analyzingFindingIds[finding.id]);
                    const analysisError = analysisErrors[finding.id];

                    return (
                      <Fragment key={finding.id}>
                        <tr>
                          <td>
                            <span className="status-pill">{finding.severity}</span>
                          </td>
                          <td>{finding.category}</td>
                          <td>{finding.title}</td>
                          <td>{finding.scanner}</td>
                          <td>{display(finding.file_path)}</td>
                          <td>{display(finding.line)}</td>
                          <td>
                            <button
                              className="inline-action"
                              disabled={isAnalyzing}
                              type="button"
                              onClick={() => {
                                void handleAnalyzeFinding(finding.id);
                              }}
                            >
                              {isAnalyzing ? "분석 중" : "AI 분석"}
                            </button>
                          </td>
                        </tr>
                        {analysisError || finding.llm_summary ? (
                          <tr key={`${finding.id}-analysis`}>
                            <td className="analysis-cell" colSpan={7}>
                              {analysisError ? (
                                <div className="status-message error" role="alert">
                                  <strong>AI analysis failed</strong>
                                  <span>{analysisError}</span>
                                </div>
                              ) : null}
                              {finding.llm_summary ? (
                                <div className="analysis-summary">
                                  <strong>AI summary</strong>
                                  <p>{finding.llm_summary}</p>
                                </div>
                              ) : null}
                            </td>
                          </tr>
                        ) : null}
                      </Fragment>
                    );
                  })}
                </tbody>
              </table>
            </div>
          ) : null}
        </div>
      ) : null}

      {scan ? (
        <div className="summary-panel">
          <div className="panel-heading-row">
            <h2>Report</h2>
            <div className="button-row">
              <button
                className="inline-action"
                disabled={isCreatingReport || isLoadingReport}
                type="button"
                onClick={() => {
                  void handleCreateReport(scan.id);
                }}
              >
                {isCreatingReport ? "Generating" : "Report 생성"}
              </button>
              <button
                className="secondary-action"
                disabled={isCreatingReport || isLoadingReport}
                type="button"
                onClick={() => {
                  void handleLoadReport(scan.id);
                }}
              >
                {isLoadingReport ? "Loading" : "Report 조회"}
              </button>
            </div>
          </div>

          {reportError ? (
            <div className="status-message error" role="alert">
              <strong>Could not load report</strong>
              <span>{reportError}</span>
            </div>
          ) : null}

          {reportPath ? <p className="muted">Report path: {reportPath}</p> : null}

          {reportContent ? (
            <pre className="report-content">{reportContent}</pre>
          ) : (
            <p className="muted">No report loaded.</p>
          )}
        </div>
      ) : null}
    </section>
  );
}
