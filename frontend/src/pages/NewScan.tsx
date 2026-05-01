import { FormEvent, useMemo, useState } from "react";
import type { ChangeEvent, ReactElement } from "react";

import { createScan } from "../api/scans";
import type { ScanType } from "../api/scans";

const SCAN_TYPES: ScanType[] = ["semgrep", "gitleaks", "trivy"];

export function NewScan(): ReactElement {
  const [projectName, setProjectName] = useState("");
  const [targetPath, setTargetPath] = useState("");
  const [selectedScanTypes, setSelectedScanTypes] = useState<ScanType[]>([
    "semgrep",
    "gitleaks",
    "trivy",
  ]);
  const [runImmediately, setRunImmediately] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [createdScanId, setCreatedScanId] = useState<string | null>(null);
  const [createdStatus, setCreatedStatus] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const canSubmit = useMemo(
    () =>
      projectName.trim().length > 0 &&
      targetPath.trim().length > 0 &&
      selectedScanTypes.length > 0 &&
      !isSubmitting,
    [isSubmitting, projectName, selectedScanTypes.length, targetPath],
  );

  function handleScanTypeChange(event: ChangeEvent<HTMLInputElement>): void {
    const scanType = event.target.value as ScanType;
    setSelectedScanTypes((current) => {
      if (event.target.checked) {
        return current.includes(scanType) ? current : [...current, scanType];
      }
      return current.filter((item) => item !== scanType);
    });
  }

  async function handleSubmit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (!canSubmit) {
      return;
    }

    setIsSubmitting(true);
    setCreatedScanId(null);
    setCreatedStatus(null);
    setErrorMessage(null);

    try {
      const result = await createScan({
        project_name: projectName.trim(),
        target_path: targetPath.trim(),
        scan_types: selectedScanTypes,
        run_immediately: runImmediately,
      });
      setCreatedScanId(result.scan_id);
      setCreatedStatus(result.status);
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : "Scan creation failed");
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <section className="page-section">
      <div className="section-header">
        <p className="eyebrow">New Scan</p>
        <h1>Create scan</h1>
        <p className="section-copy">
          Start a local scan by choosing the target path and scanners to queue.
        </p>
      </div>

      <form className="scan-form" onSubmit={handleSubmit}>
        <label>
          Project name
          <input
            type="text"
            value={projectName}
            onChange={(event) => setProjectName(event.target.value)}
            placeholder="demo"
            disabled={isSubmitting}
            required
          />
        </label>

        <label>
          Target path
          <input
            type="text"
            value={targetPath}
            onChange={(event) => setTargetPath(event.target.value)}
            placeholder="C:/AI/projects/demo"
            disabled={isSubmitting}
            required
          />
        </label>

        <fieldset>
          <legend>Scan types</legend>
          <div className="checkbox-grid">
            {SCAN_TYPES.map((scanType) => (
              <label className="checkbox-row" key={scanType}>
                <input
                  type="checkbox"
                  value={scanType}
                  checked={selectedScanTypes.includes(scanType)}
                  onChange={handleScanTypeChange}
                  disabled={isSubmitting}
                />
                <span>{scanType}</span>
              </label>
            ))}
          </div>
        </fieldset>

        <label className="checkbox-row">
          <input
            type="checkbox"
            checked={runImmediately}
            onChange={(event) => setRunImmediately(event.target.checked)}
            disabled={isSubmitting}
          />
          <span>Run immediately</span>
        </label>

        <button type="submit" disabled={!canSubmit}>
          {isSubmitting ? "Creating..." : "Create scan"}
        </button>

        {createdScanId ? (
          <div className="status-message success" role="status">
            <strong>Scan created</strong>
            <span>
              {createdScanId} ({createdStatus})
            </span>
          </div>
        ) : null}

        {errorMessage ? (
          <div className="status-message error" role="alert">
            <strong>Could not create scan</strong>
            <span>{errorMessage}</span>
          </div>
        ) : null}
      </form>
    </section>
  );
}
