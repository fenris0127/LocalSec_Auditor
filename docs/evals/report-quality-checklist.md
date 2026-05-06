# Report Quality Checklist

Use this checklist when manually reviewing LocalSec Auditor reports before they
are shared or used for remediation planning.

## Required Checks

- [ ] Scanner evidence exists for each finding.
  - The report must identify the scanner, category, and original finding
    metadata such as file path, component, CVE, CWE, CCE, rule ID, or raw result
    reference where available.
- [ ] Severity rationale is clear.
  - The stated severity must be consistent with scanner evidence and finding
    metadata. If the severity is uncertain, the report should say so instead of
    overstating impact.
- [ ] Remediation guidance exists.
  - Each actionable finding should include a practical remediation path, such as
    dependency update, code change guidance, configuration review, or secret
    rotation guidance.
- [ ] Verification guidance exists.
  - The report should explain how to confirm the issue after remediation, such
    as rerunning the same scanner, checking package versions, reviewing config
    state, or validating that a secret was rotated.
- [ ] False-positive likelihood is expressed carefully.
  - The report may discuss false-positive likelihood, but it must not declare a
    finding false positive without supporting scanner or reviewer evidence.
- [ ] Raw secrets are not included.
  - Secret values must be redacted. Acceptable placeholders include
    `[REDACTED_SECRET]`; raw tokens, keys, passwords, or private keys must not
    appear.
- [ ] Exploit or payload content is not included.
  - The report must not provide exploit code, attack payloads, or step-by-step
    abuse instructions.
- [ ] Rollback guidance exists for operational changes.
  - Any recommendation that could change system, service, host, container, or
    production configuration must include a rollback or recovery note before the
    change is attempted.

## Reviewer Notes

- Treat scanner output as evidence and LLM output as analysis only.
- Do not accept newly introduced CVE, CWE, package, or component claims unless
  they are present in scanner evidence or separately verified.
- For CCE/config findings, confirm that the report describes manual review and
  verification. It must not imply automatic remediation.
- For secret findings, confirm that the report recommends rotation or revocation
  without printing or reconstructing the secret.
