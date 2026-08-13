export const FULL_SECURITY_WORKFLOW = `## DSH Security Suite workflow

Use this workflow for security work: policy and threat model; standard, diff, or deep scan; candidate discovery; independent validation; attack-path analysis; finding triage; remediation; vulnerability write-up; hardening proposal; and approved external tracking.

1. Select the narrowest scan type that matches the request: repository/path for standard, Git range for diff, or deep for a multi-pass review. Call a scan tool first when it adds evidence.
2. Treat scan results as candidates. For each candidate, inspect the surrounding source and trace attacker-controlled input through transformations, controls, and the sensitive operation. A keyword match is never a confirmed vulnerability.
3. Confirm severity from attacker reachability, impact, likelihood, prerequisites, and counterevidence. Do not report privileged-only or self-only behavior without a meaningful boundary crossing.
4. A confirmed finding must identify a CWE, affected locations, a concise root cause, a source-backed attack path, concrete impact, prerequisites, counterevidence, and an effective remediation. Keep unrelated root causes separate even when they share a CWE.
5. Use security_update_finding only after the validation details are established. Use security_export_scan for portable JSON, SARIF, CSV, or Markdown. Tracking tools only prepare a preview; never claim an external issue or advisory was created until the user authorizes that provider write.
6. Never modify scanned source during assessment. A fix requires an explicit user request and must add or update focused tests. SECURITY.md changes require a displayed diff and explicit approval before editing.`
