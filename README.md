# DSH Security Suite

`dsh-security-suite` is an independent, native security assessment suite for [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness).

> DeepSeek Harness is in developer preview; its plugin API may introduce breaking changes.

The plugin owns its scan orchestration, evidence model, persistent workbench, export formats, remediation workflow, and DSH tool surface. It has no external security-engine SDK, CLI, credential, or hosted runtime dependency.

Deep workers are DSH-native child agents. Their scoped tool view is restricted to the immutable worklist, bounded source reads whose digest matches that worklist, candidate submission, and coverage closure. They cannot use remediation, tracking, validation, or general plugin tools during delegated discovery.

## Capability Matrix

| Workflow | DSH Security Suite capability |
| --- | --- |
| Standard, scoped, diff, and deep scans | Native `security_scan`, patch-aware `security_review_diff`, deep multi-pass analysis, and resumable bulk jobs |
| Threat model and security policy | Native source-evidenced threat model, policy, and invariant tools |
| Discovery, validation, attack paths, triage | Native evidence-backed findings and persistent validation state |
| Scan history, rerun, semantic match, comparison | Native workbench records and scan comparison |
| JSON, CSV, SARIF, and Markdown exports | Native canonical artifact exporter |
| Candidate validation and remediation | Isolated command evidence plus snapshot-checked, user-approved patch and verification workflow |
| Bulk scans and pre-commit hook | Native bounded scheduler and Git hook installer |
| Threat model, attack-path write-up, DSH-local reports | `security_threat_model_template`, `security_finding_writeup`, and state tools |
| GitHub, Jira, Linear tracking | Exact preview, GitHub duplicate lookup, and explicit one-at-a-time creation with durable receipts |

The plugin does not require an external security vendor credential. Any future GitHub, Jira, or Linear write integration remains explicitly approval-gated and must use the user-configured provider credentials.

Deep delegated discovery is available only through DSH's native agent runtime. `security_deep_discovery_capability` reports whether the active profile can provide that runtime. `security_start_deep_discovery` creates exactly six independent worker agents per round. All workers receive one immutable, exhaustive source worklist and must submit an independent threat model, a closure for every worklist row, source-backed candidates, and explicit deferrals. The suite saves worker artifacts, coverage ledger, reconciliation records, and absorbed-candidate provenance before it can record saturation after a fully completed zero-novelty round. DSH call cancellation disposes active workers and records a cancelled, incomplete round without merging its candidates; `security_resume_deep_discovery` starts fresh independent workers and merges only completed-round evidence. If the installed DSH profile cannot create or drive subagents, the job fails explicitly; it does not substitute a local static pass or any external agent runtime.

## Native Operation

The scanner inventories eligible source files deterministically, skips dependency and generated directories, records a SHA-256 receipt for each reviewed file, and seals every saved scan record. It runs a native preflight that records discovered manifests, languages, suggested local test commands, external-state availability, and coverage limitations. Default threat models are generated from local route, caller-input, authorization, parser, storage, secret, and outbound-network signals; supplied context is retained as an explicit assumption rather than presented as source fact. Standard scans run the baseline rule set. Deep scans run separate baseline, injection, and trust-boundary passes before reducing duplicate observations to stable fingerprints. JS/TS AST analysis follows request-derived values through local assignments, wrapper functions, and scanned relative ES-module imports into dynamic execution, command, filesystem, and outbound-request sinks; each cross-module result records both propagation and sink locations. Python analysis provides equivalent parameter-to-sink summaries across local function wrappers and unambiguous scanned imports. Go analysis traces local functions across same-directory, same-package source files. Java, C#, PHP, Ruby, C, C++, and Rust analysis records parameter-to-sink summaries through local functions and same-directory helper files for command, filesystem, and selected outbound-request sinks. This parser intentionally requires ordinary multiline function declarations; external packages, dynamic imports, CommonJS resolution, framework reflection, cross-package Go calls, and unresolved aliases remain explicitly unproven until source or runtime evidence is available. The current rule set also covers disabled TLS verification, likely hardcoded credentials, unsafe deserialization, query construction, XML parser hazards, JWT verification, CORS, missing local authorization markers, and unsafe object merge patterns.

`security_start_investigation` creates a durable DSH-native workbench. `security_claim_audit_task` returns an ownership token and a local task-evidence reference; validation and attack-path receipts may only be submitted with that token. `security_run_validation` runs an explicit command in a disposable copy of the target and records output, timeout, exit code, and snapshot evidence. `security_plan_candidate_validation` derives a read-only plan only from scan-time project preflight; after the reviewer gives explicit approval, `security_run_candidate_validation_plan` runs each planned local command in one disposable copy and retains every pass, failure, timeout, and skip as candidate evidence. Validation commands receive the owning DSH tool-call cancellation signal: interruption terminates the disposable process and creates no failed-test receipt. Neither validation path infers a vulnerability conclusion from command status. Patch-aware diff review analyzes added code, follows added JS/TS, Python, Go, Java, C#, PHP, Ruby, C, C++, and Rust request paths through unchanged local wrappers to sensitive sinks, detects deleted explicit authorization or input-validation controls, and structurally examines changed GitHub Actions workflows for `pull_request_target` shell interpolation, broad permissions, mutable action references, and a pull-request-head checkout followed by command execution. It preserves the changed-file receipt, evidence anchored to the added or removed line, and the proof gap that no equivalent replacement is established. Remediation proposals carry the source snapshot and file digests. Only narrowly defined TLS and JWT verification boolean controls are marked safe for automatic application; semantic fixes remain review-only. `security_apply_remediation` requires explicit approval, rejects stale content, saves an exact rollback record, rescans after applying, and preserves the verification scan id. `security_rollback_remediation` is also approval-gated and refuses to overwrite an altered applied state before restoring the original bytes and rescanning. Imported third-party findings remain evidence until local triage establishes impact. The workbench persists findings, evidence, lifecycle, scan recipe, coverage, activity, and integrity seal outside the scanned repository. It intentionally exposes this task protocol instead of assuming an undocumented DSH subagent API. `security_compare_scans` compares stable fingerprints rather than volatile line numbers. CSV values are escaped correctly; SARIF exports include rule metadata, locations, fingerprints, confidence, status, and the scan seal.

## Tool Surface

- `security_scan`, `security_assess`, `security_review_diff`, `security_bulk_scan`, `security_bulk_scan_csv`, `security_resume_bulk_scan`, `security_rerun_scan`
- `security_scan_history`, `security_get_scan`, `security_compare_scans`, `security_export_scan`
- `security_threat_model_template`, `security_import_findings`, `security_triage_imported_finding`, `security_finding_writeup`, `security_hardening_proposal`
- `security_cancel_investigation` and `security_resume_investigation` preserve task recovery; claims use expiring leases.
- `security_run_validation` executes a simple command in a disposable copy and saves its receipt; `security_remediation_plan`, `security_apply_remediation`, and `security_rollback_remediation` provide an approval-gated, stale-safe and reversible repair lifecycle.
- `security_run_candidate_validation` binds one disposable test/build receipt to a claimed candidate-validation task and its ledger. It records evidence only; the final validation conclusion remains an explicit source-backed review step.
- `security_plan_candidate_validation` previews preflight-derived commands; `security_run_candidate_validation_plan` approval-gates their isolated execution and preserves every per-command receipt.
- `security_install_precommit_hook` changes a repository only when `approved: true` is explicitly supplied; it preserves an existing hook.
- `security_tracking_preview` builds the exact GitHub, Jira, or Linear issue and can perform provider-scoped, read-only duplicate lookup. `security_create_tracking_issue` requires approval, blocks duplicate local writes, verifies every successful provider write by readback, and saves a token-free receipt.

## Install

Build the package, then add it to every profile where it should be available:

```sh
npm install
npm run build
dsh plugin --profile web add /absolute/path/to/dsh-security-suite
dsh plugin --profile headless add /absolute/path/to/dsh-security-suite
```

Verify the profile composition and run a scan:

```sh
dsh --profile web --dump-config
dsh run "Run a deep security scan, validate candidates, trace attack paths, and produce a report for this workspace."
```

## Configuration

The bundle row accepts these settings:

```yaml
config:
  enabled: true
  maxFiles: 500
  maxFileBytes: 262144
```

The native engine confines repository and knowledge-base arguments to the active workspace, forwards cancellation, seals canonical artifacts, and places state under `DSH_SECURITY_SUITE_STATE_DIR` or `stateDir` (default: `~/.dsh-security-suite`).

## Attribution

This project is implemented as a standalone DSH plugin. It contains no third-party security-runtime source code or dependency.

## License

Apache-2.0.
