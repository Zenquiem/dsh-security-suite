# Migration: codex-security architecture alignment

This document tracks the migration of `dsh-security-suite` from a
deterministic-static-analysis-first architecture toward the OpenAI
`codex-security` (Apache-2.0, cloned at `/tmp/codex-security`) architecture:
**LLM-subagent-driven discovery** with a canonical scan contract, semantic
reduction, and a workbench.

Source of borrowed material: https://github.com/openai/codex-security (Apache-2.0).
Borrowed content (prompt templates, JSON-schema field trees, workflow prose)
must keep attribution per the Apache-2.0 license in README `## Attribution`.

## 1. Why

The hand-written cross-language AST/flow engine produces deterministic but
low-precision candidates. codex-security deliberately skips an analysis engine:
discovery is performed by LLM workers guided by carefully written prompts; its
Python/TypeScript code only handles deterministic scaffolding (ranking input,
normalization, workbench persistence, contract sealing). Migration = adopt that
discovery philosophy while keeping the DSH evidence/receipt chain that is
stronger than codex-security's.

## 2. Capability matrix

Legend: ✅ already present in dsh-security-suite · 🔄 present, needs alignment ·
🆕 missing, to add · ❌ N/A in DSH (Codex-CLI-bound) · ⚖️ optional

| codex-security capability | DSH plugin | Notes |
| --- | --- | --- |
| `scan` standard repository/path scan | 🔄 `security_scan` | Discovery must become LLM-driven (baseline + investigators); deterministic engine stays as ranking/pre-filter signals |
| `--path` scoped scan | ✅ `path` param | |
| `--diff` / `--working-tree` | ✅ `security_review_diff` | Align with compact review-items contract |
| `--knowledge-base PATH` | 🆕 | Read-only kb docs, override generated assumptions |
| `--scan-prompt-file` / `--post-scan-prompt-file` | 🆕 | Extra shared scan instructions |
| `--mode deep` (workers, subagents, stop_after_no_new, max_discovery_runs, max_time_hours) | 🔄 deep tools | Add stop_after_no_new / max_discovery_runs / max_time_hours config |
| Deep worker threat models + semantic reduction | 🔄 `deep-discovery.ts` | Upgrade worker briefs; add reducer/dedup |
| Preflight (config preflight, capability profiles) | ✅ `Preflight` | Align check ids |
| SECURITY.md policy resolution | ✅ `policyFiles` | |
| Threat model / define-security-policy | ✅ `security_threat_model_template` | |
| `validation` (source-backed, runtime) | ✅ validation tools | Align field contracts |
| `attack-path-analysis` | ✅ `security_record_attack_path` | Align facts/severity-policy prose |
| `triage-finding` (GitHub REST / ticket intake) | ✅ import/triage tools | |
| `track-findings` (GitHub/Jira/Linear, advisories) | ✅ tracking tools | |
| `fix-finding` | ✅ `security_fix_finding` | |
| `propose-security-hardening` | ✅ `security_hardening_proposal` | |
| `vulnerability-writeup` | ✅ `security_finding_writeup` | Align report format |
| Canonical `scan-manifest.json` / `findings.json` / `coverage.json` | 🔄 `contracts.ts` + artifacts | **Align field trees + seal + digest** |
| Finding identity (ruleId/anchor/instance) + fingerprint | 🔄 `Finding.identity` | Align fingerprint algorithm |
| Coverage (mode/inventoryStrategy/disposition/label) | 🔄 `Coverage` | Align values |
| Target kinds + snapshot digest | 🔄 `TargetSnapshot` | Align digest format `codex-security-snapshot/v1:sha256:` |
| `scans list/show/logs/rerun/match/compare` | 🔄 history/compare tools | Add false-positive + match persistence |
| `findings list` / `findings false-positive` | 🆕 | `security_finding_false_positive` |
| `export` sarif/csv/json | ✅ `security_export_scan` | |
| `install-hook` | ✅ `security_install_precommit_hook` | |
| `bulk-scan` (CSV) | ✅ bulk tools | Interactive GitHub discovery optional |
| `--fail-on-severity` | 🆕 | Result flag / tool gate |
| `--max-cost`, cost tracking | ⚖️ | Needs token accounting; best-effort |
| `validate` / `patch` standalone | ✅ covered by validation/fix tools | |
| MCP server | ❌ | DSH tools are the interface |
| Docker/apparmor/seccomp container | ❌ | DSH runs in-process |
| Codex runtime/plugin loading/auth/trusted-executable | ❌ | Cordis is the equivalent |

## 3. Target module layout

New modules (kept separate from the existing deterministic engine so the old
path remains available as a pre-filter and fallback):

```
src/llm/
  prompts.ts     Ported worker prompts (baseline auditor, focused investigator,
                 deep worker, file-review, validation, attack-path, triage,
                 writeup, fix) parameterized with DSH tool names.
  rank.ts        Rank-input generation from scan receipts (attack-surface
                 signals → ordered source regions), mirrors generate_rank_input.py.
  discovery.ts   Standard-scan LLM discovery: threat map, investigation packets,
                 baseline + investigator orchestration via DSH agents.create().
  deep.ts        Deep worker orchestration: codex-security deep worker brief,
                 worker threat models, terminal-manifest semantics.
  reducer.ts     Semantic reduction: dedup by fingerprint/recurrence across
                 workers, canonical validation threat model synthesis.
  canonical.ts   Canonical artifact assembly: scan-manifest/findings/coverage
                 field trees, seal, snapshot digests; mirrors finalize_scan_contract.py.
  workbench.ts   Workbench schema alignment (scans/findings/occurrences/triage/
                 remediation/comparisons), mirrors workbench_*.py tables.
```

## 4. Migration order and status

| Step | Status |
| --- | --- |
| 1. Contracts: codex-security field trees (taxonomy, provenance, remediation string, coverage inventoryStrategy/completeness, manifest target-kind conditions, size limits) | ✅ done (`state.ts` projections + `verifyScanBundle`) |
| 2. Prompts + discovery: baseline/investigator/deep worker prompts ported to `src/llm/prompts.ts`; standard-scan LLM discovery in `src/llm/discovery.ts` with 5 worker-only tools; `security_scan` defaults to `discovery: llm`; **diff scan LLM file review** in `src/llm/diff.ts` (4 worker-only tools; `security_review_diff` defaults to `discovery: llm`, one restricted file-review subagent per changed file) | ✅ done |
| 3. Deep alignment: six distinct review lenses, `stop_after_no_new` from `[deep_scan]` config, codex-security deep worker discipline in the worker brief, **semantic reducer** (one independent LLM reducer subagent per completed round merges equivalent candidates across workers, absorbing provenance into the target) | ✅ done |
| 4. Workbench: triage annotations and scan comparison already align (new/persisting/resolved/unknown + coverage gate); semantics verified; **deterministic severity engine** (`src/llm/severity.ts`: impact x likelihood matrix, network-scope weighting, critical criteria, hard suppressions, P0-P3, confidence ladder) implements severity-policy.md | ✅ done |
| 5. Capability gaps: knowledge base (`src/llm/knowledge-base.ts` + `knowledgeBase` config) and scan prompt (`scanPrompt` config) wired into LLM discovery; fail-on-severity remains optional (result flags, not CLI exit codes) | ✅ done |
| 6. Tests: `tests/llm-discovery.test.ts` (4) + `tests/llm-diff.test.ts` (2) + `tests/severity.test.ts` (7) + reducer merge test; all 236 tests green | ✅ done |

## 5. Licensing

All borrowed material is Apache-2.0. Keep the `LICENSE` header and update
README `## Attribution` to state that worker prompts and JSON-schema field
trees are adapted from `openai/codex-security` (Apache-2.0).

## 6. Deep-migration status (post-core)

| Deep capability | Status |
| --- | --- |
| 1. Validation deep: 28-class proof tuple table + routing (`proofTupleFor`), bounded validation rubric, codex numerical confidence ladder (1.0/0.9/0.8/0.3/0.0), instance-preserving suppression rules — `src/llm/validation.ts` + `security_validation_guidance` tool | ✅ done |
| 2. Attack-path facts: 20+ field structured model, mechanical final policy pass (hard suppression -> network-scope weighting -> matrix + critical escalation -> reportability), seven-dimension counterevidence checklist, markdown facts renderer — `src/llm/attack-path.ts` + `security_attack_path_guidance` tool | ✅ done |
| 3. Workbench state machines: triage close_reason + append-only decisions log, remediation 8-state machine + optimistic lock, comparison `reopened` | ⏳ next |
| 4. Ranking/normalization byte-level: generate_rank_input exclusions/preview/shards/pool plan, normalize_candidates identity hash (algorithm parity, DSH namespace) | ⏳ next |
| 5. vulnerability-writeup seven-section format + single-finding drafting prompt into disclosure | ⏳ next |
