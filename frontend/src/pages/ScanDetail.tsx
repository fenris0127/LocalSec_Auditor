import { Fragment, useEffect, useState } from "react";
import type { ReactElement } from "react";

import {
  analyzeFinding,
  compareScanWithLatest,
  createScanReport,
  getScan,
  getScanReport,
  listScanFindings,
  listScanTasks,
} from "../api/scans";
import type {
  AnalyzeFindingResponse,
  Finding,
  FindingComparisonSummary,
  ReferenceContext,
  ScanComparisonResponse,
  ScanSummary,
  ScanTask,
} from "../api/scans";

interface ScanDetailProps {
  scanId: string | null;
}

function display(value: string | number | null): string {
  if (value === null || value === "") {
    return "N/A";
  }
  return String(value);
}

function maskSecretText(value: string): string {
  return value
    .replace(/sk_(?:test|live)_[A-Za-z0-9_=-]+/g, "[REDACTED_SECRET]")
    .replace(/ghp_[A-Za-z0-9_]+/g, "[REDACTED_SECRET]")
    .replace(
      /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
      "[REDACTED_SECRET]",
    )
    .replace(/("Secret"\s*:\s*")[^"]+(")/gi, "$1[REDACTED_SECRET]$2");
}

function referenceDisplay(value: string | number | null): string {
  return maskSecretText(display(value));
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

function referenceContextsFrom(value: Finding | AnalyzeFindingResponse): ReferenceContext[] {
  return value.reference_context ?? value.reference_contexts ?? value.references ?? [];
}

function referenceSource(context: ReferenceContext): string {
  return referenceDisplay(
    context.source_title ??
      context.title ??
      context.metadata?.title ??
      context.source_path ??
      context.path ??
      context.metadata?.source_path ??
      context.source_name ??
      context.metadata?.source_name ??
      null,
  );
}

function referencePath(context: ReferenceContext): string | null {
  return (
    context.source_path ??
    context.path ??
    context.metadata?.source_path ??
    context.source_name ??
    context.metadata?.source_name ??
    null
  );
}

function referenceChunkIndex(context: ReferenceContext): string | null {
  const index = context.chunk_index ?? context.metadata?.chunk_index ?? null;
  return index === null ? null : String(index);
}

function referenceSummary(context: ReferenceContext): string | null {
  return context.chunk_summary ?? context.summary ?? context.metadata?.summary ?? null;
}

function referenceText(context: ReferenceContext): string | null {
  return context.chunk_text ?? context.content ?? context.text ?? null;
}

function isConfigFinding(finding: Finding): boolean {
  const category = finding.category.toLowerCase();
  return category === "cce" || category === "config";
}

function sortedSummaryEntries(values: Record<string, number>): [string, number][] {
  return Object.entries(values).sort(([left], [right]) => left.localeCompare(right));
}

function ComparisonSummaryBlock({
  label,
  summary,
}: {
  label: string;
  summary: FindingComparisonSummary;
}): ReactElement {
  const severityEntries = sortedSummaryEntries(summary.by_severity);

  return (
    <div className="comparison-summary-card">
      <strong>{label}</strong>
      <span>{summary.total}</span>
      {severityEntries.length > 0 ? (
        <div className="severity-summary-list">
          {severityEntries.map(([severity, count]) => (
            <span className="status-pill" key={severity}>
              {severity}: {count}
            </span>
          ))}
        </div>
      ) : (
        <p className="muted">No severity counts.</p>
      )}
    </div>
  );
}

function ComparisonFindingTable({
  title,
  findings,
}: {
  title: string;
  findings: Finding[];
}): ReactElement {
  return (
    <div className="comparison-finding-group">
      <h3>{title}</h3>
      {findings.length === 0 ? (
        <p className="muted">No findings.</p>
      ) : (
        <div className="table-panel compact">
          <table className="comparison-table">
            <thead>
              <tr>
                <th>Severity</th>
                <th>Category</th>
                <th>Title</th>
                <th>Scanner</th>
              </tr>
            </thead>
            <tbody>
              {findings.map((finding) => (
                <tr key={finding.id}>
                  <td>
                    <span className="status-pill">{finding.severity}</span>
                  </td>
                  <td>
                    <span className={isConfigFinding(finding) ? "category-pill config" : "category-pill"}>
                      {finding.category}
                    </span>
                  </td>
                  <td>{finding.title}</td>
                  <td>{finding.scanner}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function ScanComparisonPanel({
  comparison,
}: {
  comparison: ScanComparisonResponse;
}): ReactElement {
  return (
    <div className="comparison-results">
      <p className="muted">
        Base scan: {comparison.base_scan_id} / Current scan: {comparison.target_scan_id}
      </p>
      <div className="comparison-summary-grid">
        <ComparisonSummaryBlock label="New findings" summary={comparison.summary.new_findings} />
        <ComparisonSummaryBlock label="Resolved findings" summary={comparison.summary.resolved_findings} />
        <ComparisonSummaryBlock label="Persistent findings" summary={comparison.summary.persistent_findings} />
      </div>
      <div className="comparison-groups">
        <ComparisonFindingTable title="New findings" findings={comparison.new_findings} />
        <ComparisonFindingTable title="Resolved findings" findings={comparison.resolved_findings} />
        <ComparisonFindingTable title="Persistent findings" findings={comparison.persistent_findings} />
      </div>
    </div>
  );
}

function CceFindingDetails({ finding }: { finding: Finding }): ReactElement | null {
  if (!isConfigFinding(finding)) {
    return null;
  }

  return (
    <div className="config-finding-detail">
      <strong>System configuration detail</strong>
      <dl className="config-value-grid">
        <div>
          <dt>Rule ID</dt>
          <dd>{display(finding.rule_id)}</dd>
        </div>
        <div>
          <dt>CCE ID</dt>
          <dd>{display(finding.cce_id)}</dd>
        </div>
        <div>
          <dt>Current value</dt>
          <dd>{display(finding.current_value)}</dd>
        </div>
        <div>
          <dt>Expected value</dt>
          <dd>{display(finding.expected_value)}</dd>
        </div>
      </dl>
      <div className="config-guidance">
        <strong>Rollback / Verification</strong>
        <p>
          Record the current setting before any reviewed manual change. Verify by re-running the same
          scanner/profile and keep the original value available for rollback.
        </p>
      </div>
    </div>
  );
}

function ReferenceDocuments({ contexts }: { contexts: ReferenceContext[] }): ReactElement | null {
  if (contexts.length === 0) {
    return null;
  }

  return (
    <div className="reference-contexts">
      <strong>Reference context</strong>
      <div className="reference-list">
        {contexts.map((context, index) => {
          const path = referencePath(context);
          const chunkIndex = referenceChunkIndex(context);
          const summary = referenceSummary(context);
          const text = referenceText(context);
          const shouldCollapse = Boolean(text && text.length > 360);

          return (
            <article className="reference-item" key={context.id ?? `${referenceSource(context)}-${index}`}>
              <div className="reference-meta">
                <span>{referenceSource(context)}</span>
                {path ? <code>{referenceDisplay(path)}</code> : null}
                {chunkIndex ? <small>Chunk {referenceDisplay(chunkIndex)}</small> : null}
              </div>
              {summary ? <p>{maskSecretText(summary)}</p> : null}
              {text && shouldCollapse ? (
                <details className="reference-chunk">
                  <summary>Chunk text</summary>
                  <p>{maskSecretText(text)}</p>
                </details>
              ) : null}
              {text && !shouldCollapse && !summary ? <p>{maskSecretText(text)}</p> : null}
            </article>
          );
        })}
      </div>
    </div>
  );
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
  const [comparison, setComparison] = useState<ScanComparisonResponse | null>(null);
  const [isLoadingComparison, setIsLoadingComparison] = useState(false);
  const [comparisonError, setComparisonError] = useState<string | null>(null);
  const [comparisonNotice, setComparisonNotice] = useState<string | null>(null);

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
      setComparison(null);
      setComparisonError(null);
      setComparisonNotice(null);
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
          finding.id === findingId
            ? {
                ...finding,
                llm_summary: result.llm_summary,
                reference_context: referenceContextsFrom(result),
              }
            : finding,
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

  async function handleCompareWithLatest(id: string): Promise<void> {
    setIsLoadingComparison(true);
    setComparison(null);
    setComparisonError(null);
    setComparisonNotice(null);

    try {
      const result = await compareScanWithLatest(id);
      setComparison(result);
    } catch (error) {
      const message = error instanceof Error ? error.message : "Could not compare scan";
      if (message === "Previous scan not found") {
        setComparisonNotice("No previous scan is available for this project.");
      } else {
        setComparisonError(message);
      }
    } finally {
      setIsLoadingComparison(false);
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
          <div className="panel-heading-row">
            <h2>Scan comparison</h2>
            <button
              className="inline-action"
              disabled={isLoadingComparison}
              type="button"
              onClick={() => {
                void handleCompareWithLatest(scan.id);
              }}
            >
              {isLoadingComparison ? "Comparing" : "Compare previous scan"}
            </button>
          </div>

          {isLoadingComparison ? (
            <div className="empty-panel compact" role="status">
              <strong>Loading comparison</strong>
              <span>Fetching changes from the latest previous scan.</span>
            </div>
          ) : null}

          {comparisonNotice ? (
            <div className="empty-panel compact">
              <strong>No previous scan</strong>
              <span>{comparisonNotice}</span>
            </div>
          ) : null}

          {comparisonError ? (
            <div className="status-message error" role="alert">
              <strong>Could not compare scans</strong>
              <span>{comparisonError}</span>
            </div>
          ) : null}

          {comparison ? <ScanComparisonPanel comparison={comparison} /> : null}
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
                    const referenceContexts = referenceContextsFrom(finding);
                    const isConfigurationFinding = isConfigFinding(finding);

                    return (
                      <Fragment key={finding.id}>
                        <tr className={isConfigurationFinding ? "config-finding-row" : undefined}>
                          <td>
                            <span className="status-pill">{finding.severity}</span>
                          </td>
                          <td>
                            <span className={isConfigurationFinding ? "category-pill config" : "category-pill"}>
                              {finding.category}
                            </span>
                          </td>
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
                        {analysisError ||
                        finding.llm_summary ||
                        referenceContexts.length > 0 ||
                        isConfigurationFinding ? (
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
                              <CceFindingDetails finding={finding} />
                              <ReferenceDocuments contexts={referenceContexts} />
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
