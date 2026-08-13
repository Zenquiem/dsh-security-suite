# DSH Security Suite

`dsh-security-suite` is an independent, native security assessment suite for [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness).

> DeepSeek Harness is in developer preview; its plugin API may introduce breaking changes.

The plugin owns its scan orchestration, evidence model, persistent workbench, export formats, remediation workflow, and DSH tool surface. It has no external security-engine SDK, CLI, credential, or hosted runtime dependency.

## Capability Matrix

| Workflow | DSH Security Suite capability |
| --- | --- |
| Standard, scoped, diff, and deep scans | Native `security_scan`, `security_review_diff`, and deep-scan planning tools |
| Threat model and security policy | Native threat-model, policy, and invariant tools |
| Discovery, validation, attack paths, triage | Native evidence-backed findings and persistent validation state |
| Scan history, rerun, semantic match, comparison | Native workbench records and scan comparison |
| JSON, CSV, SARIF, and Markdown exports | Native canonical artifact exporter |
| Candidate validation and remediation | Native validation and user-approved patch workflow |
| Bulk scans and pre-commit hook | Native bounded scheduler and Git hook installer |
| Threat model, attack-path write-up, DSH-local reports | `security_threat_model_template`, `security_finding_writeup`, and state tools |
| GitHub, Jira, Linear tracking | `security_tracking_preview`; external connector writes remain intentionally approval-gated. |

The plugin does not require an external security vendor credential. Any future GitHub, Jira, or Linear write integration remains explicitly approval-gated and must use the user-configured provider credentials.

## Native Operation

The scanner inventories eligible source files deterministically, skips dependency and generated directories, records a SHA-256 receipt for each reviewed file, and seals every saved scan record. Standard scans run the baseline rule set. Deep scans run separate baseline, injection, and trust-boundary passes before reducing duplicate observations to stable fingerprints. The current local rule set covers dynamic execution, shell construction, filesystem traversal sinks, disabled TLS verification, likely hardcoded credentials, unsafe deserialization, request-derived outbound requests, and weak randomness in security-sensitive contexts.

`security_update_finding` requires validation evidence before a candidate can be recorded as confirmed or as a false positive. The workbench persists findings, evidence, lifecycle, scan recipe, coverage, activity, and integrity seal outside the scanned repository. `security_compare_scans` compares stable fingerprints rather than volatile line numbers. CSV values are escaped correctly; SARIF exports include rule metadata, locations, fingerprints, confidence, status, and the scan seal.

## Tool Surface

- `security_scan`, `security_assess`, `security_review_diff`, `security_bulk_scan`, `security_rerun_scan`
- `security_scan_history`, `security_get_scan`, `security_compare_scans`, `security_export_scan`
- `security_threat_model_template`, `security_update_finding`, `security_finding_writeup`
- `security_remediation_plan` generates a review-required patch proposal without editing source.
- `security_install_precommit_hook` changes a repository only when `approved: true` is explicitly supplied; it preserves an existing hook.
- `security_tracking_preview` prepares, but does not create, tracker issues.

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
