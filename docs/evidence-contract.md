# Evidence Contract

This document is the detailed evidence and coverage contract of DSH Security
Suite. It was moved out of the README so the README can stay concise; nothing
here is softened. Every claim below is enforced by the plugin's receipts,
seals, and fail-closed checks.

> Adapted in part from [openai/codex-security](https://github.com/openai/codex-security)
> (Apache-2.0) worker and contract semantics.

## Scan lifecycle and findings

Every scan entry point, including the exported library functions, creates an
open investigation. Static analysis can only create discovery candidates and
durable validation tasks; a reportable finding requires a claim-token-bound
validation receipt and then a separately claimed attack-path receipt before
finalization. There is no automatic-static-validation option. Post-remediation
detection scans are likewise open investigations, not automatic resolution
proof.

TLS configuration candidates require a client-use evidence chain. Python must
pass `verify=False` or an expanded local `{"verify": False}` map to a supported
`requests` or `httpx` call. Go must bind local
`tls.Config{InsecureSkipVerify: true}` through `http.Transport` and
`http.Client`, then invoke that client. Standalone settings, unconsumed maps,
opaque construction, and unrelated functions remain unproven.

PHP cURL TLS candidates follow the same rule: a locally initialized cURL handle
must receive `CURLOPT_SSL_VERIFYPEER` as `false` or `0` and later be passed to
`curl_exec()` in the same local block. A setting that is never executed, or is
applied to a different handle, remains unproven.

Native C/C++ libcurl candidates similarly require one locally initialized
`CURL*` handle to receive `CURLOPT_SSL_VERIFYPEER` as `false` or `0`, then
reach `curl_easy_perform()` on that same handle in the same local block.

Embedded-credential candidates require a direct assignment of a
non-placeholder string literal to a credential-named field. Environment or
secret-manager lookups, comments, examples, placeholder values, and ordinary
strings are excluded. As with every static candidate, this records source
exposure for validation; it does not claim the literal is active, privileged,
or reachable in production.

Deep workers are DSH-native child agents. Their scoped tool view is restricted
to the immutable worklist, bounded source reads whose digest matches that
worklist, candidate submission, and coverage closure. They cannot use
remediation, tracking, validation, or general plugin tools during delegated
discovery. The published package imports only DSH/Cordis interfaces and its own
local analysis modules; no second assistant runtime or security-engine process
participates in scans.

## Deep discovery

Deep delegated discovery is available only through DSH's native agent runtime.
`security_deep_discovery_capability` reports whether the active profile can
provide that runtime. `security_start_deep_discovery` creates exactly six
independent worker agents per round, each with a distinct attack-surface review
lens. The immutable, exhaustive source worklist is frozen from scan receipts as
200-line source regions, ordered by local attack-surface signals; signals guide
review but never constitute a finding. A worker can read only a frozen region
by its work-item id, every candidate must land inside one such region, and
every region must be reviewed or explicitly deferred. The coverage ledger
records `file:start-end` closure per worker. The suite saves worker artifacts,
coverage ledger, reconciliation records, and absorbed-candidate provenance
before it can record saturation after a fully completed zero-novelty round. An
incomplete round is retained solely as process evidence: its provisional
candidates cannot enter canonical reconciliation, scan findings, or
saturation. It then synthesizes one canonical validation threat model from only
the complete worker reports. `security_start_deep_closure` runs a separate
six-worker centralized validation or attack-path phase: workers claim durable
tasks, can read only scan-receipted source snapshots, and must submit the
normal claim-token-bound ledger receipts. A closure job binds the exact
threat-model artifact and digest, then fails closed on drift.
`security_run_deep_investigation` composes those phases into one durable
workflow and finalizes the canonical report only after discovery, validation,
and attack-path tasks have all closed; `security_resume_deep_investigation`
resumes an interrupted phase from its retained job records. Concurrent closure
workers claim and write scan tasks through a serialized scan ledger, so their
receipts cannot overwrite each other. Cancellation preserves completed
receipts; resumption uses fresh worker identities and processes only remaining
tasks. If the installed DSH profile cannot create or drive subagents, these
jobs fail explicitly; they do not substitute a local static pass or any
external agent runtime. Each completed round also runs one semantic reducer
subagent that merges equivalent candidates across workers and preserves
provenance; independently reachable sibling instances stay separate.

## Native operation

The scanner inventories eligible source files deterministically, skips
dependency and generated directories, records a SHA-256 receipt for each
reviewed file, and seals every saved scan record. It runs a native preflight
that records discovered manifests, languages, suggested local test commands,
external-state availability, and coverage limitations. Default threat models
are generated from local route, caller-input, authorization, parser, storage,
secret, and outbound-network signals; supplied context is retained as an
explicit assumption rather than presented as source fact. Standard scans run
the baseline rule set. Deep scans run separate baseline, injection, and
trust-boundary passes before reducing duplicate observations to stable
fingerprints. Public scan, diff, bulk, and rerun entry points produce durable
candidate investigations, never auto-confirm a static match, and require
independent source-backed validation plus attack-path evidence before a
reportable result can be sealed.

JS/TS AST analysis follows request-derived values through local assignments,
wrapper functions, and scanned relative ES-module imports plus static relative
CommonJS `require()` bindings, including named, object, namespace, and
default-function exports, into dynamic execution, command, filesystem,
outbound-request, supported `Object.assign`/`_.merge`/`lodash.merge`
source-object arguments, and known database query-text sinks; each
cross-module result records both propagation and sink locations. A
request-derived merge target alone, static source object, or arbitrary function
merely named `merge` remains unproven.

SQL analysis recognizes request-derived query text at supported
JavaScript/TypeScript, Python, Go, Java, C#, PHP, Ruby, C, C++, and Rust
database APIs, while parameter/binding arguments to a fixed query text remain
unproven. Python deserialization analysis follows request-derived bytes through
local wrappers and unambiguous scanned imports into `pickle.loads` and
`yaml.load`; an explicit `SafeLoader` suppresses the YAML candidate, while
other loaders remain validation-required candidates. Java deserialization
analysis follows request-derived `InputStream` values through same-directory
local wrappers into `new ObjectInputStream(...)` and the matching receiver's
`readObject()` call; trusted fixed streams, unrelated `readObject` methods,
deserialization APIs outside this form, and dynamic object construction remain
unproven. SSRF analysis is parameter-aware: it follows request-derived URL,
URI, host, and endpoint arguments through supported outbound APIs while not
treating bodies, headers, or opaque request objects as a proven destination.

Express-style state-changing route analysis structurally recognizes inline
request handlers, explicit local middleware, preceding receiver-global
middleware, and authorization-protected parent-router mounts. FastAPI-style
analysis recognizes explicit `Depends(...)` authorization dependencies in route
declarations, nearby decorators, handler parameters, protected
`APIRouter(...)` construction, and same-file `include_router(...)` mounts with
explicit authorization dependencies. Spring-style analysis recognizes
method-level `@PreAuthorize`, `@Secured`, and `@RolesAllowed` annotations
contiguous with write-operation mappings, plus the enclosing class's contiguous
authorization annotations. These analyses emit only discovery candidates when
no supported control is found. They do not infer protection from later
middleware, dynamic middleware composition, nested routers without explicit
mounts, cross-file framework configuration, framework reflection, or a control
implementation's semantics.

Diff review structurally analyzes GitHub Actions `pull_request_target`
workflows for direct event interpolation, same-step and same-job
event-to-`env`-to-shell paths, direct event-to-`GITHUB_ENV` writes followed by
a later same-job shell use, broad write permissions, mutable action
references, and pull-request-head checkout followed by execution; it retains
entrypoint and sink locations and only reports when an added line anchors the
new path. It does not infer cross-job environment/data passing, generated
workflow content, same-step `GITHUB_ENV` reads, `GITHUB_OUTPUT` effects,
command substitutions, transformed expressions, or expression semantics beyond
these explicit forms. Those structured entrypoint, propagation, root-control,
and sink locations are retained on the canonical finding, exposed by exports,
and rendered in reports while preserving the sensitive operation as the
primary diff anchor.

Python analysis provides equivalent parameter-to-sink summaries across local
function wrappers and unambiguous scanned imports. Go analysis traces local
functions across same-directory, same-package source files and static imports
into scanned packages under the nearest local `go.mod` module path; external
modules and ambiguous package aliases remain unproven. Java, C#, PHP, Ruby, C,
C++, and Rust analysis records parameter-to-sink summaries through local
functions and same-directory helper files for command, filesystem, selected
outbound-request, and known database query-text sinks. Configuration analysis
reconstructs multi-line JWT, CORS, and Java XML parser factory blocks to
identify disabled JWT checks, credentialed wildcard/reflected CORS policies,
and XML factories that create parsers without recognized external-entity
hardening; paired control locations are retained with each candidate. This
parser intentionally requires ordinary multiline function declarations;
external packages, dynamic imports, framework reflection, unresolved aliases,
and deserialization APIs outside those supported Python and Java forms remain
explicitly unproven until source or runtime evidence is available. The current
rule set also covers disabled TLS verification, likely hardcoded credentials,
source-evidenced unsafe Python and Java deserialization, prototype-polluting
JavaScript object merges, SQL query construction, and structural route
authorization gaps.

## Per-language analysis boundaries

- **JS/TS request destructuring** is a supported source form: aliases
  introduced by `const { body } = req` or `const { query: q } = request`
  participate in local and relative-module flow summaries. Destructuring from a
  non-request object does not establish attacker control.
- **JS/TS weak randomness** is AST-based: `Math.random()` after supported local
  value transformations is a candidate only when it reaches a named security
  field (token, session, nonce, reset, verification, OTP, or code
  assignments). General-purpose values such as UI colors are not candidates;
  other languages, dynamic property names, and unmodeled random APIs remain
  unproven.
- **JS/TS embedded credentials** are AST-based: a non-placeholder string
  literal must be assigned to a named API key, access key, secret, password,
  token, private key, or credential field. Environment-derived and other
  dynamic values, ordinary strings, and recognized sample or replacement
  values remain unproven. Other supported source languages retain their
  literal rule coverage.
- **JS/TS TLS verification** is AST-based: `rejectUnauthorized: false` must be
  in an inline or local named configuration object that reaches a supported
  TLS/HTTPS client call. Unused, logged, or unrelated objects do not establish
  a client path.
- For JS/TS, Python, Go, Java, C#, PHP, Ruby, C, C++, and Rust, supported
  command, filesystem, outbound-request, and SQL candidates are emitted only by
  the native request-source-to-sink analyses. Textual appearances of those
  APIs without a resolved supported request source are not candidates; a
  language-rule pair without structured support remains explicitly unproven
  rather than being promoted by keyword matching.
- **Python JWT verification** is call-scoped: an explicit `verify=False`,
  unsigned `none` algorithm, or `verify_signature=False` local options
  dictionary must be used by a supported `jwt.decode()` or `jwt.verify()` call.
  Unused dictionaries and unrelated verification settings are not candidates.
- **JS/TS CORS** is AST-based: a wildcard or reflected origin and credential
  support must be paired in one configuration object passed directly or by
  local binding to `cors()`. Unused objects, logging calls, and fixed origin
  lists are not candidates.
- **Java XML parser** discovery scopes a factory, recognized hardening calls,
  and parser creation to one local code block. A recognized hardening call
  before parser creation suppresses that block; controls in another block or
  after parser creation do not establish protection.
- **Ruby deserialization** follows request-derived values through
  same-directory local wrappers into `YAML.load`, `Psych.load`, and
  `Marshal.load`. `safe_load`, static data, and unrelated parser methods remain
  unproven.
- **PHP deserialization** follows request-derived values through same-directory
  local wrappers into `unserialize()`. It recognizes the explicit
  `allowed_classes => false` control; other allowlists, wrappers, and parser
  APIs remain validation-required.
- **.NET deserialization** follows request-derived values through
  same-directory local wrappers into an instance constructed with
  `new BinaryFormatter()` and then used for `Deserialize(...)`. Other
  `Deserialize` methods, serializer types, and dynamic formatter construction
  remain unproven.

## Validation and remediation

`security_start_investigation` creates a durable DSH-native workbench.
`security_claim_audit_task` returns an ownership token and a local
task-evidence reference; validation and attack-path receipts may only be
submitted with that token. `security_run_validation` runs an explicit command
in a disposable copy of the target and records output, timeout, exit code, and
snapshot evidence. `security_plan_candidate_validation` derives a read-only
plan only from scan-time project preflight.
`security_run_candidate_runtime_validation` can execute one explicitly
reviewed local interface reproduction, non-interactive debugger trace, or
sanitizer/memory-check command when every fixture path is scan-receipted, the
full snapshot remains unchanged, the command stays within method-specific
bounds, and DSH grants one-shot approval. It rejects direct non-loopback URL
arguments, interactive debugger invocations, unmarked memory-check commands,
unscanned fixtures, and diff-only source snapshots. The disposable copy
protects the source tree from writes, but it is not a network sandbox;
approval must cover the local environment and invoked fixture. A final
`runtime` or `hybrid` validation must cite one or more exact receipts from
that candidate; foreign or missing receipt references fail closed. Its result
is evidence only, never an automatic vulnerability conclusion.
`security_run_candidate_validation_plan` runs only the bounded planned commands
in one disposable copy and retains every pass, failure, timeout, and skip as
candidate evidence. `security_run_remediation_verification` applies the same
restriction to an already-applied, snapshot-bound patch: it runs only commands
frozen in the original scan preflight, retains every result in the remediation
record, and never closes the original finding from a passing test alone.
Validation commands receive the owning DSH tool-call cancellation signal:
interruption terminates the disposable process and creates no failed-test
receipt.

## Artifacts and tooling notes

SARIF imports retain their rule id, CWE, message, severity, and physical
file/line. Imported triage returns `affected` only when a compatible native
local-analysis candidate matches that cited location; a readable file alone is
never confirmation. Every completed scan with reportable findings also
generates a derived `hardening/hardening.md` and `hardening/hardening.json`
portfolio from those findings and their detailed reports. The main report
links that derived portfolio; canonical bundle verification remains independent
of derived projections, while `verifyScanProjections` detects a missing or
stale report, write-up, or hardening artifact and `regenerateScanProjections`
restores them deterministically.

Detailed per-tool semantics:

- `security_start_disclosure_campaign` turns supplied vulnerability notes and a
  selected local source snapshot into one isolated DSH writer assignment per
  vulnerability. Writers can read only their assigned receipt-bound source,
  must submit a source-cited report with counterevidence, limitations,
  remediation, and reproduction status, and cannot claim executed reproduction
  unless the campaign explicitly authorizes controlled experiments. An
  authorized campaign can freeze an already existing user-supplied local
  experiment artifact, but the plugin never generates, modifies, or executes
  it; an execution claim must cite that frozen artifact and fails on evidence
  drift.
- `security_cancel_investigation` and `security_resume_investigation` preserve
  task recovery; claims use expiring leases.
- `security_start_deep_closure`, `security_resume_deep_closure`, and
  `security_read_scan_source` close a deep investigation through centralized,
  restricted DSH validation and attack-path workers. They preserve source
  receipts, task claims, cancellation state, and completed evidence across
  recovery.
- `security_run_validation` executes a simple command in a disposable copy and
  saves its receipt; `security_remediation_plan`, `security_apply_remediation`,
  and `security_rollback_remediation` provide an approval-gated, stale-safe and
  reversible repair lifecycle.
- `security_run_candidate_validation` binds one approval-gated disposable
  test/build receipt to a claimed candidate-validation task and its ledger.
  `security_run_candidate_runtime_validation` adds reviewed local interface,
  non-interactive debugger, and sanitizer evidence with frozen fixture paths
  and a snapshot-bound receipt. Both record evidence only; the final validation
  conclusion remains an explicit source-backed review step.
- `security_plan_candidate_validation` previews preflight-derived commands;
  `security_run_candidate_validation_plan` requires both reviewed
  acknowledgement and DSH one-shot user approval before isolated execution,
  then preserves every per-command receipt.
- `security_install_precommit_hook`, `security_apply_remediation`, and
  `security_rollback_remediation` require both reviewed acknowledgement and DSH
  one-shot user approval for each write; a missing approval route fails closed.
- `security_tracking_preview` builds the exact GitHub, Jira, or Linear issue
  and can perform provider-scoped, read-only duplicate lookup.
  `security_create_tracking_issue` requires reviewed acknowledgement plus DSH
  one-shot user approval, blocks duplicate local writes, verifies every
  successful provider write by readback, and saves a token-free receipt.
- `security_tracking_advisory_preview` and
  `security_create_github_security_advisory` are a separate GitHub
  private-draft advisory flow. They require a completed clean GitHub-worktree
  scan with an immutable verified source revision, never fall back to Issues,
  never update or publish, use only GitHub's repository-advisory REST
  endpoints, and fail closed when duplicate lookup or exact draft readback
  cannot establish the required state.
- `security_import_github_findings` reads only an explicitly selected GitHub
  REST family: code scanning, Dependabot, repository security
  advisories/private reports, or all. `security_import_ticket_findings`
  performs an explicit caller-scoped, read-only Jira or Linear ticket query.
  Both treat every returned field as untrusted evidence.
  `security_triage_finding_backlog` preserves one result per imported item,
  reruns local static evidence, records policy and supported-boundary proof
  gaps, classifies `confirmed`, `not_actionable`, or `needs_review`, and ranks
  the confirmed and needs-review queues independently. It does not deduplicate
  inputs or write to any provider.
