import type { Context } from '@deepseek-ai/cordis'
import type {} from '@deepseek-ai/dsh-system-prompt'
import { defineTool as defineDshTool, type JsonValue } from '@deepseek-ai/dsh-tools'
import { Config, type Config as PluginConfig } from './config.js'
import { SECURITY_REVIEW_GUIDANCE } from './prompt.js'
import { FULL_SECURITY_WORKFLOW } from './workflows.js'
import { generateSourceThreatModel, runDiffScan, runScan, resolveSafeTarget } from './scanner.js'
import { finalizeAndSaveScan, getStateDir, listScans, loadScan, persistInvestigationArtifacts, renderCsv, renderMarkdownReport, saveTriageAnnotation, saveScan, toSarif, verifyScanBundle } from './state.js'
import { applyRemediationProposal, bulkScan, installPreCommitHook, planCandidateValidation, remediationPlan, rerunSavedScan, resumeBulkJob, rollbackRemediationProposal, runCandidateValidation, runCandidateValidationPlan, runIsolatedValidation, startBulkCsvJob } from './operations.js'
import { cancelInvestigation, claimAuditTask, completeScan, pendingCandidates, recordAttackPath, recordValidation, resumeInvestigation } from './workbench.js'
import { generateHardeningPortfolio, importFindings, triageImportedFinding } from './analysis.js'
import { createTracking, previewTracking } from './tracking.js'
import { createDeepDiscoveryJob, deepDiscoveryCapability, getDeepWorklist, readDeepSource, reportDeepCandidate, reportDeepWorker, runDeepDiscovery } from './deep-discovery.js'

export const name = 'dsh-security-suite'
export const inject = ['tools', 'systemPrompt']
export { Config }

/**
 * DSH's value-schema DSL represents object requiredness on each property,
 * whereas JSON Schema represents it as an object-level list. Keep the tool
 * contracts strict while translating the originally authored output shapes.
 */
function adaptOutputSchema(schema: unknown): unknown {
  if (!schema || typeof schema !== 'object' || Array.isArray(schema)) return schema
  const value = schema as Record<string, unknown>
  if (Array.isArray(value.oneOf)) return { ...value, oneOf: value.oneOf.map(adaptOutputSchema) }
  if (value.type === 'array') return { ...value, ...(value.items ? { items: adaptOutputSchema(value.items) } : {}) }
  if (value.type !== 'object') return value
  const required = new Set(Array.isArray(value.required) ? value.required.filter((name): name is string => typeof name === 'string') : [])
  const properties = value.properties && typeof value.properties === 'object' && !Array.isArray(value.properties)
    ? Object.fromEntries(Object.entries(value.properties as Record<string, unknown>).map(([name, property]) => [name, { ...(adaptOutputSchema(property) as Record<string, unknown>), ...(required.has(name) ? { required: true } : {}) }]))
    : undefined
  const { required: _required, ...rest } = value
  return { ...rest, ...(properties ? { properties } : {}) }
}

const defineTool = ((options: unknown) => {
  const tool = options as { output: { schema: unknown } }
  return defineDshTool({ ...tool, output: { ...tool.output, schema: adaptOutputSchema(tool.output.schema) } } as never)
}) as typeof defineDshTool

export function apply(ctx: Context, config: PluginConfig): void {
  if (!config.enabled) return

  ctx.systemPrompt.section({
    name: 'dsh-security-suite:review-guidance',
    order: 160,
    text: SECURITY_REVIEW_GUIDANCE,
  })
  ctx.systemPrompt.section({ name: 'dsh-security-suite:workflow', order: 161, text: FULL_SECURITY_WORKFLOW })

  ctx.tools.register(defineTool({
    name: 'security_deep_discovery_capability', description: 'Report whether this DSH profile exposes the native agent runtime required for six-worker delegated deep discovery. This performs no scan and creates no agent.', parameters: {},
    output: { schema: { type: 'object', properties: { available: { type: 'boolean' }, workersPerRound: { type: 'number' }, reason: { type: 'string' } }, required: ['available', 'workersPerRound'], additionalProperties: false }, render: (_args, value) => [{ type: 'text', text: JSON.stringify(value) }] },
    async execute() { return deepDiscoveryCapability(ctx) },
  }))

  ctx.tools.register(defineTool({
    name: 'security_start_deep_discovery', description: 'Create and run a genuine six-worker-per-round DSH delegated discovery job for an open deep investigation. Every worker receives the same neutral brief, must submit source-backed candidates, and the job reaches saturation only after a complete round adds no new candidates.', parameters: { scan_id: { type: 'string', required: true, description: 'Open deep investigation scan identifier.' }, max_rounds: { type: 'number', description: 'Maximum complete independent discovery rounds from 1 to 10; default 10.' } },
    output: { schema: { type: 'object', properties: { id: { type: 'string' }, lifecycle: { type: 'string' }, rounds: { type: 'array', items: { type: 'object', properties: { number: { type: 'number' }, candidateCount: { type: 'number' }, novelty: { type: 'number' }, status: { type: 'string' } }, required: ['number', 'candidateCount', 'novelty', 'status'], additionalProperties: false } }, candidates: { type: 'array', items: { type: 'object', properties: { id: { type: 'string' }, workerId: { type: 'string' }, ruleId: { type: 'string' }, file: { type: 'string' }, line: { type: 'number' } }, required: ['id', 'workerId', 'ruleId', 'file', 'line'], additionalProperties: false } } }, required: ['id', 'lifecycle', 'rounds', 'candidates'], additionalProperties: false }, render: (_args, value) => [{ type: 'text', text: JSON.stringify(value) }] },
    async execute(args) { const job = await createDeepDiscoveryJob(config, args.scan_id, args.max_rounds ?? 10); return runDeepDiscovery(ctx, config, job.id) },
  }))

  ctx.tools.register(defineTool({
    name: 'security_deep_report_candidate', description: 'Submit one source-backed candidate for the active delegated deep-discovery worker. This is accepted only from the worker-specific job, worker id, and claim token issued by security_start_deep_discovery.', parameters: { job_id: { type: 'string', required: true, description: 'Deep discovery job identifier.' }, worker_id: { type: 'string', required: true, description: 'Worker identifier from the assignment.' }, claim_token: { type: 'string', required: true, description: 'Worker claim token from the assignment.' }, rule_id: { type: 'string', required: true, description: 'Stable vulnerability-family rule id.' }, title: { type: 'string', required: true, description: 'Concise candidate title.' }, severity: { type: 'string', required: true, enum: ['critical', 'high', 'medium', 'low'], description: 'Provisional severity.' }, cwe: { type: 'string', required: true, description: 'CWE identifier.' }, file: { type: 'string', required: true, description: 'Target-relative source path.' }, line: { type: 'number', required: true, description: 'Concrete source line.' }, root_cause: { type: 'string', required: true, description: 'Source-backed explanation of the suspected broken control.' } },
    output: { schema: { type: 'object', properties: { id: { type: 'string' }, workerId: { type: 'string' }, ruleId: { type: 'string' }, file: { type: 'string' }, line: { type: 'number' } }, required: ['id', 'workerId', 'ruleId', 'file', 'line'], additionalProperties: false }, render: (_args, value) => [{ type: 'text', text: JSON.stringify(value) }] },
    async execute(args) { return reportDeepCandidate(config, args.job_id, args.worker_id, args.claim_token, { ruleId: args.rule_id, title: args.title, severity: args.severity as 'critical' | 'high' | 'medium' | 'low', cwe: args.cwe, file: args.file, line: args.line, rootCause: args.root_cause }) },
  }))

  ctx.tools.register(defineTool({
    name: 'security_deep_report_worker', description: 'Close one DSH delegated deep-discovery worker only after every authoritative worklist path is reviewed or explicitly deferred. It persists the worker-specific threat model and coverage receipt; missing closure makes the discovery round incomplete.', parameters: { job_id: { type: 'string', required: true, description: 'Deep discovery job identifier.' }, worker_id: { type: 'string', required: true, description: 'Worker identifier from the assignment.' }, claim_token: { type: 'string', required: true, description: 'Worker claim token from the assignment.' }, threat_model: { type: 'string', required: true, description: 'Independent source-evidenced worker threat model.' }, reviewed_paths: { type: 'array', required: true, items: { type: 'string' }, description: 'Every authoritative worklist path reviewed by this worker.' }, deferred: { type: 'array', required: true, items: { type: 'object', properties: { path: { type: 'string', required: true }, reason: { type: 'string', required: true } }, additionalProperties: false }, description: 'Authoritative worklist paths not reviewed, with concrete reasons.' }, coverage_summary: { type: 'string', required: true, description: 'Concise coverage closure and proof-gap summary.' } },
    output: { schema: { type: 'object', properties: { reviewedPaths: { type: 'array', items: { type: 'string' } }, deferred: { type: 'array', items: { type: 'object', properties: { path: { type: 'string' }, reason: { type: 'string' } }, required: ['path', 'reason'], additionalProperties: false } }, reportedAt: { type: 'string' } }, required: ['reviewedPaths', 'deferred', 'reportedAt'], additionalProperties: false }, render: (_args, value) => [{ type: 'text', text: JSON.stringify(value) }] },
    async execute(args) { return reportDeepWorker(config, args.job_id, args.worker_id, args.claim_token, { threatModel: args.threat_model, reviewedPaths: args.reviewed_paths, deferred: args.deferred.map(item => ({ path: item.path, reason: item.reason })), coverageSummary: args.coverage_summary }) },
  }))

  ctx.tools.register(defineTool({
    name: 'security_deep_get_worklist', description: 'Read the immutable authoritative source worklist for one claimed DSH delegated deep-discovery worker. This tool is available only to active workers.', parameters: { job_id: { type: 'string', required: true }, worker_id: { type: 'string', required: true }, claim_token: { type: 'string', required: true } },
    output: { schema: { type: 'object', properties: { digest: { type: 'string' }, items: { type: 'array', items: { type: 'object', properties: { path: { type: 'string' }, sha256: { type: 'string' }, language: { type: 'string' } }, required: ['path', 'sha256', 'language'], additionalProperties: false } } }, required: ['digest', 'items'], additionalProperties: false }, render: (_args, value) => [{ type: 'text', text: JSON.stringify(value) }] },
    async execute(args) { return getDeepWorklist(config, args.job_id, args.worker_id, args.claim_token) },
  }))

  ctx.tools.register(defineTool({
    name: 'security_deep_read_source', description: 'Read a bounded line range from one authoritative deep-discovery source file. The file digest must match the immutable worklist snapshot; this tool is available only to active workers.', parameters: { job_id: { type: 'string', required: true }, worker_id: { type: 'string', required: true }, claim_token: { type: 'string', required: true }, path: { type: 'string', required: true }, start_line: { type: 'number' }, end_line: { type: 'number' } },
    output: { schema: { type: 'object', properties: { path: { type: 'string' }, startLine: { type: 'number' }, endLine: { type: 'number' }, content: { type: 'string' }, sha256: { type: 'string' } }, required: ['path', 'startLine', 'endLine', 'content', 'sha256'], additionalProperties: false }, render: (_args, value) => [{ type: 'text', text: value.content ?? '' }] },
    async execute(args) { return readDeepSource(config, args.job_id, args.worker_id, args.claim_token, args.path, args.start_line, args.end_line) },
  }))

  ctx.tools.register(defineTool({
    name: 'security_import_findings', description: 'Import JSON or text security findings from a workspace file. Imported material is treated as untrusted evidence and must be triaged against local source before it becomes a repository-impact conclusion.', parameters: { path: { type: 'string', required: true, description: 'Workspace-relative JSON or text finding file.' } },
    output: { schema: { type: 'array', items: { type: 'object', properties: { id: { type: 'string' }, title: { type: 'string' }, description: { type: 'string' }, sourcePath: { type: 'string' }, sourceSha256: { type: 'string' } }, required: ['id', 'title', 'description', 'sourcePath', 'sourceSha256'], additionalProperties: false } }, render: (_args, value) => [{ type: 'text', text: JSON.stringify(value) }] },
    async execute(args) { return importFindings(process.cwd(), args.path) },
  }))

  ctx.tools.register(defineTool({
    name: 'security_triage_imported_finding', description: 'Triage one imported finding against local source. It returns affected, not_affected, or needs_information with source evidence and limitations; it does not silently convert third-party text into a confirmed finding.', parameters: { imported_finding: { type: 'object', required: true, additionalProperties: true, description: 'One object returned by security_import_findings.' } },
    output: { schema: { type: 'object', properties: { id: { type: 'string' }, importedFindingId: { type: 'string' }, status: { type: 'string' }, confidence: { type: 'string' }, rationale: { type: 'string' }, evidence: { type: 'array', items: { type: 'string' } }, limitations: { type: 'array', items: { type: 'string' } } }, required: ['id', 'importedFindingId', 'status', 'confidence', 'rationale', 'evidence', 'limitations'], additionalProperties: false }, render: (_args, value) => [{ type: 'text', text: JSON.stringify(value) }] },
    async execute(args) { return triageImportedFinding(process.cwd(), config, args.imported_finding as unknown as Parameters<typeof triageImportedFinding>[2]) },
  }))

  ctx.tools.register(defineTool({
    name: 'security_hardening_proposal', description: 'Generate a source- and scan-evidence-backed hardening portfolio. It distinguishes structural opportunities from cases where local remediation is proportionate, and records options with explicit tradeoffs.', parameters: { scan_id: { type: 'string', required: true, description: 'Completed saved scan identifier.' } },
    output: { schema: { type: 'object', properties: { id: { type: 'string' }, scanId: { type: 'string' }, outcome: { type: 'string' }, portfolio: { type: 'string' }, structured: { type: 'string' }, opportunities: { type: 'array', items: { type: 'number' } } }, required: ['id', 'scanId', 'outcome', 'portfolio', 'structured', 'opportunities'], additionalProperties: false }, render: (_args, value) => [{ type: 'text', text: JSON.stringify(value) }] },
    async execute(args) { return generateHardeningPortfolio(config, args.scan_id) },
  }))

  ctx.tools.register(defineTool({
    name: 'security_run_validation', description: 'Run one explicit test or build command in an isolated temporary copy of a saved scan target. The source tree is never modified; stdout, stderr, timeout, snapshot, and exit code are retained as evidence.', parameters: { scan_id: { type: 'string', required: true, description: 'Saved scan identifier.' }, command: { type: 'string', required: true, description: 'Simple test or build command without shell operators.' }, timeout_ms: { type: 'number', description: 'Timeout from 1,000 to 600,000 ms; default 120,000.' } },
    output: { schema: { type: 'object', properties: { id: { type: 'string' }, command: { type: 'string' }, exitCode: { type: 'number' }, timedOut: { type: 'boolean' }, durationMs: { type: 'number' }, stdout: { type: 'string' }, stderr: { type: 'string' }, snapshotDigest: { type: 'string' }, artifactRef: { type: 'string' } }, required: ['id', 'command', 'timedOut', 'durationMs', 'stdout', 'stderr', 'snapshotDigest'], additionalProperties: false }, render: (_args, value) => [{ type: 'text', text: JSON.stringify(value) }] },
    async execute(args) { return runIsolatedValidation(process.cwd(), config, args.scan_id, args.command, args.timeout_ms ?? 120_000) },
  }))

  ctx.tools.register(defineTool({
    name: 'security_run_candidate_validation', description: 'Run a bounded test or build command in a disposable copy and attach its receipt to one claimed candidate-validation task. This records evidence only; use security_record_validation to make the final source-backed conclusion.', parameters: { scan_id: { type: 'string', required: true, description: 'Open investigation scan identifier.' }, candidate_id: { type: 'string', required: true, description: 'Candidate identifier from security_claim_audit_task.' }, claim_token: { type: 'string', required: true, description: 'Validation task claim token.' }, command: { type: 'string', required: true, description: 'Simple test or build command without shell operators.' }, timeout_ms: { type: 'number', description: 'Timeout from 1,000 to 600,000 ms; default 120,000.' } },
    output: { schema: { type: 'object', properties: { id: { type: 'string' }, command: { type: 'string' }, exitCode: { type: 'number' }, timedOut: { type: 'boolean' }, durationMs: { type: 'number' }, stdout: { type: 'string' }, stderr: { type: 'string' }, snapshotDigest: { type: 'string' }, artifactRef: { type: 'string' } }, required: ['id', 'command', 'timedOut', 'durationMs', 'stdout', 'stderr', 'snapshotDigest', 'artifactRef'], additionalProperties: false }, render: (_args, value) => [{ type: 'text', text: JSON.stringify(value) }] },
    async execute(args) { return runCandidateValidation(process.cwd(), config, args.scan_id, args.candidate_id, args.claim_token, args.command, args.timeout_ms ?? 120_000) },
  }))

  ctx.tools.register(defineTool({
    name: 'security_plan_candidate_validation', description: 'Preview a read-only, candidate-specific validation plan from the scan-time project preflight. It contains only bounded local commands already derived from the detected manifest and does not execute anything.', parameters: { scan_id: { type: 'string', required: true, description: 'Investigation scan identifier.' }, candidate_id: { type: 'string', required: true, description: 'Candidate identifier.' } },
    output: { schema: { type: 'object', properties: { id: { type: 'string' }, scanId: { type: 'string' }, candidateId: { type: 'string' }, snapshotDigest: { type: 'string' }, projectFiles: { type: 'array', items: { type: 'string' } }, commands: { type: 'array', items: { type: 'object', properties: { command: { type: 'string' }, reason: { type: 'string' } }, required: ['command', 'reason'], additionalProperties: false } }, skipped: { type: 'array', items: { type: 'object', properties: { reason: { type: 'string' } }, required: ['reason'], additionalProperties: false } }, createdAt: { type: 'string' } }, required: ['id', 'scanId', 'candidateId', 'snapshotDigest', 'projectFiles', 'commands', 'skipped', 'createdAt'], additionalProperties: false }, render: (_args, value) => [{ type: 'text', text: JSON.stringify(value) }] },
    async execute(args) { return planCandidateValidation(config, args.scan_id, args.candidate_id) },
  }))

  ctx.tools.register(defineTool({
    name: 'security_run_candidate_validation_plan', description: 'Execute the scan-time preflight validation commands in one disposable copy and attach every command outcome to one claimed candidate task. Requires explicit approval and records evidence only; it never infers the final security conclusion.', parameters: { scan_id: { type: 'string', required: true, description: 'Open investigation scan identifier.' }, candidate_id: { type: 'string', required: true, description: 'Candidate identifier.' }, claim_token: { type: 'string', required: true, description: 'Validation task claim token.' }, approved: { type: 'boolean', required: true, description: 'Set true only after reviewing security_plan_candidate_validation output.' }, timeout_ms: { type: 'number', description: 'Per-command timeout from 1,000 to 600,000 ms; default 120,000.' } },
    output: { schema: { type: 'object', properties: { id: { type: 'string' }, scanId: { type: 'string' }, candidateId: { type: 'string' }, snapshotDigest: { type: 'string' }, commands: { type: 'array', items: { type: 'object', properties: { command: { type: 'string' }, reason: { type: 'string' } }, required: ['command', 'reason'], additionalProperties: false } }, receipts: { type: 'array', items: { type: 'object', properties: { id: { type: 'string' }, command: { type: 'string' }, timedOut: { type: 'boolean' }, durationMs: { type: 'number' }, stdout: { type: 'string' }, stderr: { type: 'string' }, snapshotDigest: { type: 'string' }, artifactRef: { type: 'string' } }, required: ['id', 'command', 'timedOut', 'durationMs', 'stdout', 'stderr', 'snapshotDigest', 'artifactRef'], additionalProperties: false } }, artifactRef: { type: 'string' } }, required: ['id', 'scanId', 'candidateId', 'snapshotDigest', 'commands', 'receipts', 'artifactRef'], additionalProperties: false }, render: (_args, value) => [{ type: 'text', text: JSON.stringify(value) }] },
    async execute(args) { return runCandidateValidationPlan(process.cwd(), config, args.scan_id, args.candidate_id, args.claim_token, args.approved, args.timeout_ms ?? 120_000) },
  }))

  ctx.tools.register(defineTool({
    name: 'security_assess',
    description: 'Perform a read-only security candidate scan of a directory inside the current workspace.',
    parameters: {
      path: { type: 'string', description: 'Optional workspace-relative directory. Defaults to the current workspace root.' },
    },
    output: {
      schema: {
        type: 'object',
        properties: {
          filesScanned: { type: 'number' },
          filesSkipped: { type: 'number' },
          candidates: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                rule: { type: 'string' },
                severity: { type: 'string' },
                file: { type: 'string' },
                line: { type: 'number' },
                excerpt: { type: 'string' },
                rationale: { type: 'string' },
              },
              required: ['rule', 'severity', 'file', 'line', 'excerpt', 'rationale'],
              additionalProperties: false,
            },
          },
        },
        required: ['filesScanned', 'filesSkipped', 'candidates'],
        additionalProperties: false,
      },
      render: (_args, value) => [{ type: 'text', text: JSON.stringify(value) }],
    },
    async execute(args) {
      const workspace = process.cwd()
      const target = resolveSafeTarget(workspace, args.path)
      const scan = await runScan(target, config, 'standard', '', args.path !== undefined, config.stateDir)
      await finalizeAndSaveScan(getStateDir(config.stateDir), scan)
      return { filesScanned: scan.coverage.reviewedFiles, filesSkipped: scan.coverage.skippedFiles, candidates: scan.findings.map(finding => ({ rule: finding.ruleId, severity: finding.severity, file: finding.locations[0].file, line: finding.locations[0].line, excerpt: finding.locations[0].excerpt, rationale: finding.rootCause })) }
    },
  }))

  ctx.tools.register(defineTool({
    name: 'security_claim_audit_task', description: 'Claim the next durable validation or attack-path task. Claims expire after a bounded lease so interrupted DSH reviewers cannot permanently block the work queue.', parameters: { scan_id: { type: 'string', required: true, description: 'Investigation scan identifier.' }, owner: { type: 'string', required: true, description: 'DSH worker or reviewer identifier.' }, phase: { type: 'string', enum: ['validation', 'attack_path'], description: 'Optional task phase to claim.' }, lease_ms: { type: 'number', description: 'Claim lease from 60,000 to 14,400,000 ms; default 30 minutes.' } },
    output: { schema: { oneOf: [{ type: 'object', properties: { taskId: { type: 'string' }, candidateId: { type: 'string' }, phase: { type: 'string' }, focus: { type: 'string' }, claimToken: { type: 'string' }, artifactRef: { type: 'string' } }, required: ['taskId', 'candidateId', 'phase', 'focus', 'claimToken', 'artifactRef'], additionalProperties: false }, { type: 'null' }] }, render: (_args, value) => [{ type: 'text', text: JSON.stringify(value) }] },
    async execute(args) { return claimAuditTask(config, args.scan_id, args.owner, args.phase as 'validation' | 'attack_path' | undefined, args.lease_ms ?? 30 * 60_000) },
  }))

  ctx.tools.register(defineTool({
    name: 'security_start_investigation', description: 'Create a durable standard or deep scan in discovery/validation state. It records candidates and evidence artifacts but does not auto-close them, enabling structured DSH or human review.', parameters: { path: { type: 'string', description: 'Optional workspace-relative scan scope.' }, mode: { type: 'string', enum: ['standard', 'deep'], description: 'Scan depth.' }, threat_model: { type: 'string', description: 'Threat-model context.' } },
    output: { schema: { type: 'object', properties: { scanId: { type: 'string' }, candidates: { type: 'number' }, lifecycle: { type: 'string' } }, required: ['scanId', 'candidates', 'lifecycle'], additionalProperties: false }, render: (_args, value) => [{ type: 'text', text: JSON.stringify(value) }] },
    async execute(args) { const scan = await runScan(resolveSafeTarget(process.cwd(), args.path), config, args.mode === 'deep' ? 'deep' : 'standard', args.threat_model ?? '', args.path !== undefined, config.stateDir, false); await persistInvestigationArtifacts(getStateDir(config.stateDir), scan); await saveScan(getStateDir(config.stateDir), scan); return { scanId: scan.id, candidates: scan.findings.length, lifecycle: scan.lifecycle } },
  }))

  ctx.tools.register(defineTool({
    name: 'security_pending_candidates', description: 'List candidate findings that have not yet received a structured validation receipt.', parameters: { scan_id: { type: 'string', required: true, description: 'Investigation scan identifier.' } },
    output: { schema: { type: 'array', items: { type: 'object', properties: { candidateId: { type: 'string' }, title: { type: 'string' }, disposition: { type: 'string' }, stages: { type: 'array', items: { type: 'string' } } }, required: ['candidateId', 'title', 'disposition', 'stages'], additionalProperties: false } }, render: (_args, value) => [{ type: 'text', text: JSON.stringify(value) }] },
    async execute(args) { return pendingCandidates(config, args.scan_id) },
  }))

  ctx.tools.register(defineTool({
    name: 'security_record_validation', description: 'Record structured source, test, runtime, or hybrid validation evidence for one claimed candidate task. Every field is persisted in the candidate ledger.', parameters: { scan_id: { type: 'string', required: true, description: 'Investigation scan identifier.' }, candidate_id: { type: 'string', required: true, description: 'Candidate identifier.' }, claim_token: { type: 'string', required: true, description: 'Token returned by security_claim_audit_task.' }, conclusion: { type: 'string', required: true, enum: ['reportable', 'suppressed', 'deferred', 'not_applicable'], description: 'Validation conclusion.' }, method: { type: 'string', required: true, enum: ['static', 'test', 'runtime', 'hybrid'], description: 'Validation method.' }, attacker: { type: 'string', required: true, description: 'Realistic attacker capability.' }, entry_point: { type: 'string', required: true, description: 'Entrypoint evidence.' }, trust_boundary: { type: 'string', required: true, description: 'Boundary crossed.' }, root_control: { type: 'string', required: true, description: 'Broken control or sink.' }, sink: { type: 'string', required: true, description: 'Sensitive operation.' }, impact: { type: 'string', required: true, description: 'Concrete impact.' }, direct_evidence: { type: 'string', required: true, description: 'Source/test/runtime proof.' }, counterevidence: { type: 'string', required: true, description: 'Controls considered and why they do or do not prevent impact.' }, limitations: { type: 'string', required: true, description: 'Remaining evidence gap.' }, confidence: { type: 'string', required: true, enum: ['high', 'medium', 'low'], description: 'Calibrated confidence.' } },
    output: { schema: { type: 'object', properties: { scanId: { type: 'string' }, candidateId: { type: 'string' }, lifecycle: { type: 'string' } }, required: ['scanId', 'candidateId', 'lifecycle'], additionalProperties: false }, render: (_args, value) => [{ type: 'text', text: JSON.stringify(value) }] },
    async execute(args) { const scan = await recordValidation(config, args.scan_id, args.candidate_id, { conclusion: args.conclusion as 'reportable' | 'suppressed' | 'deferred' | 'not_applicable', method: args.method as 'static' | 'test' | 'runtime' | 'hybrid', attacker: args.attacker, entryPoint: args.entry_point, trustBoundary: args.trust_boundary, rootControl: args.root_control, sink: args.sink, impact: args.impact, directEvidence: args.direct_evidence, counterevidence: args.counterevidence, limitations: args.limitations, confidence: args.confidence as 'high' | 'medium' | 'low' }, args.claim_token); return { scanId: scan.id, candidateId: args.candidate_id, lifecycle: scan.lifecycle } },
  }))

  ctx.tools.register(defineTool({
    name: 'security_record_attack_path', description: 'Record attack-path evidence for one claimed reportable candidate task.', parameters: { scan_id: { type: 'string', required: true, description: 'Investigation scan identifier.' }, candidate_id: { type: 'string', required: true, description: 'Candidate identifier.' }, claim_token: { type: 'string', required: true, description: 'Token returned by security_claim_audit_task.' }, attacker: { type: 'string', required: true, description: 'Attacker.' }, entry_point: { type: 'string', required: true, description: 'Entrypoint.' }, preconditions: { type: 'string', required: true, description: 'Required conditions.' }, dataflow: { type: 'string', required: true, description: 'Source-to-sink path.' }, outcome: { type: 'string', required: true, description: 'Attacker outcome.' }, severity_rationale: { type: 'string', required: true, description: 'Severity calibration.' }, change_conditions: { type: 'string', required: true, description: 'Evidence that changes severity or confidence.' } },
    output: { schema: { type: 'object', properties: { scanId: { type: 'string' }, candidateId: { type: 'string' }, lifecycle: { type: 'string' } }, required: ['scanId', 'candidateId', 'lifecycle'], additionalProperties: false }, render: (_args, value) => [{ type: 'text', text: JSON.stringify(value) }] },
    async execute(args) { const scan = await recordAttackPath(config, args.scan_id, args.candidate_id, { attacker: args.attacker, entryPoint: args.entry_point, preconditions: args.preconditions, dataflow: args.dataflow, outcome: args.outcome, severityRationale: args.severity_rationale, changeConditions: args.change_conditions }, args.claim_token); return { scanId: scan.id, candidateId: args.candidate_id, lifecycle: scan.lifecycle } },
  }))

  ctx.tools.register(defineTool({
    name: 'security_finalize_investigation', description: 'Seal a manually investigated scan only when every discovered candidate has a validation receipt and each reportable candidate has attack-path evidence.', parameters: { scan_id: { type: 'string', required: true, description: 'Investigation scan identifier.' } },
    output: { schema: { type: 'object', properties: { scanId: { type: 'string' }, lifecycle: { type: 'string' }, findings: { type: 'number' } }, required: ['scanId', 'lifecycle', 'findings'], additionalProperties: false }, render: (_args, value) => [{ type: 'text', text: JSON.stringify(value) }] },
    async execute(args) { const scan = await completeScan(config, args.scan_id); return { scanId: scan.id, lifecycle: scan.lifecycle, findings: scan.findings.filter(finding => finding.disposition === 'reportable').length } },
  }))

  ctx.tools.register(defineTool({
    name: 'security_cancel_investigation', description: 'Cancel an open investigation and release all active tasks with a durable reason. Completed bundles cannot be cancelled.', parameters: { scan_id: { type: 'string', required: true, description: 'Investigation scan identifier.' }, reason: { type: 'string', required: true, description: 'Why the investigation is being cancelled.' } },
    output: { schema: { type: 'object', properties: { scanId: { type: 'string' }, lifecycle: { type: 'string' } }, required: ['scanId', 'lifecycle'], additionalProperties: false }, render: (_args, value) => [{ type: 'text', text: JSON.stringify(value) }] },
    async execute(args) { const scan = await cancelInvestigation(config, args.scan_id, args.reason); return { scanId: scan.id, lifecycle: scan.lifecycle } },
  }))

  ctx.tools.register(defineTool({
    name: 'security_resume_investigation', description: 'Resume a previously cancelled investigation, returning unfinished tasks to the pending queue.', parameters: { scan_id: { type: 'string', required: true, description: 'Cancelled investigation scan identifier.' } },
    output: { schema: { type: 'object', properties: { scanId: { type: 'string' }, lifecycle: { type: 'string' } }, required: ['scanId', 'lifecycle'], additionalProperties: false }, render: (_args, value) => [{ type: 'text', text: JSON.stringify(value) }] },
    async execute(args) { const scan = await resumeInvestigation(config, args.scan_id); return { scanId: scan.id, lifecycle: scan.lifecycle } },
  }))

  ctx.tools.register(defineTool({
    name: 'security_rerun_scan', description: 'Rerun a saved standard or deep scan recipe in the active workspace. The prior target must remain inside that workspace.', parameters: { scan_id: { type: 'string', required: true, description: 'Saved standard or deep scan identifier.' } },
    output: { schema: { type: 'object', properties: { scanId: { type: 'string' }, findings: { type: 'number' }, complete: { type: 'boolean' } }, required: ['scanId', 'findings', 'complete'], additionalProperties: false }, render: (_args, value) => [{ type: 'text', text: JSON.stringify(value) }] },
    async execute(args) { const scan = await rerunSavedScan(process.cwd(), config, args.scan_id); return { scanId: scan.id, findings: scan.findings.length, complete: scan.coverage.complete } },
  }))

  ctx.tools.register(defineTool({
    name: 'security_bulk_scan', description: 'Run bounded-concurrency native scans for workspace-relative paths and persist each result. This is read-only.', parameters: { paths: { type: 'array', required: true, items: { type: 'string' }, description: 'Workspace-relative directories to scan.' }, mode: { type: 'string', enum: ['standard', 'deep'], description: 'Native scan depth.' }, concurrency: { type: 'number', description: 'Parallel scans from 1 to 4; defaults to 2.' }, threat_model: { type: 'string', description: 'Shared threat-model notes.' } },
    output: { schema: { type: 'array', items: { type: 'object', properties: { path: { type: 'string' }, scanId: { type: 'string' }, findings: { type: 'number' }, error: { type: 'string' } }, required: ['path'], additionalProperties: false } }, render: (_args, value) => [{ type: 'text', text: JSON.stringify(value) }] },
    async execute(args) { return bulkScan(process.cwd(), config, args.paths, args.mode === 'deep' ? 'deep' : 'standard', args.threat_model ?? '', args.concurrency ?? 2) },
  }))

  ctx.tools.register(defineTool({
    name: 'security_bulk_scan_csv', description: 'Start a resumable native bulk scan from a workspace CSV. The first column or a path header supplies workspace-relative directories; every target stores attempts, outcome, and scan id.', parameters: { csv_path: { type: 'string', required: true, description: 'Workspace-relative CSV path.' }, mode: { type: 'string', enum: ['standard', 'deep'], description: 'Scan depth.' }, concurrency: { type: 'number', description: 'Parallel scans from 1 to 4; defaults to 2.' }, threat_model: { type: 'string', description: 'Shared threat-model notes.' } },
    output: { schema: { type: 'object', properties: { id: { type: 'string' }, entries: { type: 'array', items: { type: 'object', properties: { path: { type: 'string' }, status: { type: 'string' }, attempts: { type: 'number' }, scanId: { type: 'string' }, findings: { type: 'number' }, error: { type: 'string' } }, required: ['path', 'status', 'attempts'], additionalProperties: false } } }, required: ['id', 'entries'], additionalProperties: false }, render: (_args, value) => [{ type: 'text', text: JSON.stringify(value) }] },
    async execute(args) { return startBulkCsvJob(process.cwd(), config, args.csv_path, args.mode === 'deep' ? 'deep' : 'standard', args.threat_model ?? '', args.concurrency ?? 2) },
  }))

  ctx.tools.register(defineTool({
    name: 'security_resume_bulk_scan', description: 'Resume a saved bulk job. Completed targets are retained; failed or pending targets are retried and their attempt count is incremented.', parameters: { job_id: { type: 'string', required: true, description: 'Bulk job identifier.' }, concurrency: { type: 'number', description: 'Parallel scans from 1 to 4; defaults to 2.' } },
    output: { schema: { type: 'object', properties: { id: { type: 'string' }, entries: { type: 'array', items: { type: 'object', properties: { path: { type: 'string' }, status: { type: 'string' }, attempts: { type: 'number' }, scanId: { type: 'string' }, findings: { type: 'number' }, error: { type: 'string' } }, required: ['path', 'status', 'attempts'], additionalProperties: false } } }, required: ['id', 'entries'], additionalProperties: false }, render: (_args, value) => [{ type: 'text', text: JSON.stringify(value) }] },
    async execute(args) { return resumeBulkJob(process.cwd(), config, args.job_id, args.concurrency ?? 2) },
  }))

  ctx.tools.register(defineTool({
    name: 'security_threat_model_template', description: 'Generate a source-evidenced threat model for a repository or component. It records observed architecture signals separately from deployment assumptions and open questions.', parameters: { scope: { type: 'string', description: 'Repository-relative system or component scope.' }, context: { type: 'string', description: 'Known deployment, actors, assets, or constraints supplied by the user.' } },
    output: { schema: { type: 'object', properties: { markdown: { type: 'string' } }, required: ['markdown'], additionalProperties: false }, render: (_args, value) => [{ type: 'text', text: value.markdown ?? '' }] },
    async execute(args) { const target = resolveSafeTarget(process.cwd(), args.scope); return { markdown: await generateSourceThreatModel(target, config, args.context ?? '') } },
  }))

  ctx.tools.register(defineTool({
    name: 'security_finding_writeup', description: 'Render a complete vulnerability report from a validated saved finding. It preserves unresolved proof gaps rather than inventing exploitation.', parameters: { scan_id: { type: 'string', required: true, description: 'Saved scan identifier.' }, finding_id: { type: 'string', required: true, description: 'Finding identifier.' } },
    output: { schema: { type: 'object', properties: { markdown: { type: 'string' } }, required: ['markdown'], additionalProperties: false }, render: (_args, value) => [{ type: 'text', text: value.markdown ?? '' }] },
    async execute(args) { const scan = await loadScan(getStateDir(config.stateDir), args.scan_id); const finding = scan.findings.find(item => item.id === args.finding_id); if (!finding) throw new Error('Finding was not found in this scan.'); const location = finding.locations[0]; return { markdown: `# ${finding.title}\n\n## Summary\n${finding.rootCause}\n\n## Severity and Confidence\n- Severity: ${finding.severity}\n- Confidence: ${finding.confidence}\n- CWE: ${finding.cwe}\n\n## Affected Location\n\`${location.file}:${location.line}\`\n\n\`\`\`\n${location.excerpt}\n\`\`\`\n\n## Validation\n${finding.validation}\n\n## Attack Path and Preconditions\n${finding.attackPath}\n\n## Impact\n${finding.impact}\n\n## Counterevidence and Limitations\n${finding.counterevidence}\n\n## Remediation\n${finding.remediation}\n` } },
  }))

  ctx.tools.register(defineTool({
    name: 'security_compare_scans', description: 'Compare two saved scans by stable finding fingerprint and classify findings as new, persisting, resolved, or unknown when coverage is incomplete.', parameters: { before_scan_id: { type: 'string', required: true, description: 'Earlier scan identifier.' }, after_scan_id: { type: 'string', required: true, description: 'Later scan identifier.' } },
    output: { schema: { type: 'object', properties: { new: { type: 'array', items: { type: 'string' } }, persisting: { type: 'array', items: { type: 'string' } }, resolved: { type: 'array', items: { type: 'string' } }, unknown: { type: 'array', items: { type: 'string' } } }, required: ['new', 'persisting', 'resolved', 'unknown'], additionalProperties: false }, render: (_args, value) => [{ type: 'text', text: JSON.stringify(value) }] },
    async execute(args) { const stateDir = getStateDir(config.stateDir); const [before, after] = await Promise.all([loadScan(stateDir, args.before_scan_id), loadScan(stateDir, args.after_scan_id)]); const previous = new Map(before.findings.map(finding => [finding.fingerprint, finding])); const current = new Map(after.findings.map(finding => [finding.fingerprint, finding])); const result = { new: [...current.values()].filter(finding => !previous.has(finding.fingerprint)).map(finding => finding.id), persisting: [...current.values()].filter(finding => previous.has(finding.fingerprint)).map(finding => finding.id), resolved: [] as string[], unknown: [] as string[] }; for (const finding of previous.values()) { if (!current.has(finding.fingerprint)) (after.coverage.complete ? result.resolved : result.unknown).push(finding.id) } return result },
  }))

  ctx.tools.register(defineTool({
    name: 'security_review_diff',
    description: 'Perform a read-only native Git diff security review. It analyzes added code and added JS/TS, Python, Go, Java, C#, PHP, Ruby, C, C++, or Rust call paths into local sink wrappers, detects deleted authorization or input-validation controls, and preserves changed-file receipts and static evidence.',
    parameters: {
      base: { type: 'string', description: 'Optional Git base ref. Defaults to the working tree diff.' },
    },
    output: {
      schema: {
        type: 'object',
        properties: {
          mode: { type: 'string' },
          diff: { type: 'string' },
          truncated: { type: 'boolean' },
        },
        required: ['mode', 'diff', 'truncated'],
        additionalProperties: false,
      },
      render: (_args, value) => [{ type: 'text', text: value.diff ?? '' }],
    },
    async execute(args) {
      const scan = await runDiffScan(process.cwd(), args.base, '', config.stateDir)
      await finalizeAndSaveScan(getStateDir(config.stateDir), scan)
      const diff = scan.findings.map(finding => `${finding.locations[0].file}:${finding.locations[0].line} ${finding.ruleId}: ${finding.locations[0].excerpt}`).join('\n')
      return { mode: scan.mode, diff, truncated: !scan.coverage.complete }
    },
  }))

  ctx.tools.register(defineTool({
    name: 'security_scan', description: 'Run a standard or deep read-only native scan and save canonical findings outside the target repository.',
    parameters: { path: { type: 'string', description: 'Optional workspace-relative scan scope.' }, mode: { type: 'string', enum: ['standard', 'deep'], description: 'standard performs one rule pass; deep executes independent injection and trust-boundary rule passes before reduction.' }, threat_model: { type: 'string', description: 'Optional security assumptions and protected assets.' } },
    output: { schema: { type: 'object', properties: { scanId: { type: 'string' }, findings: { type: 'number' }, reviewedFiles: { type: 'number' }, complete: { type: 'boolean' } }, required: ['scanId', 'findings', 'reviewedFiles', 'complete'], additionalProperties: false }, render: (_args, value) => [{ type: 'text', text: JSON.stringify(value) }] },
    async execute(args) { const scan = await runScan(resolveSafeTarget(process.cwd(), args.path), config, args.mode === 'deep' ? 'deep' : 'standard', args.threat_model ?? '', args.path !== undefined, config.stateDir); await finalizeAndSaveScan(getStateDir(config.stateDir), scan); return { scanId: scan.id, findings: scan.findings.filter(finding => finding.disposition === 'reportable').length, reviewedFiles: scan.coverage.reviewedFiles, complete: scan.coverage.complete } },
  }))

  ctx.tools.register(defineTool({
    name: 'security_scan_history', description: 'List saved DSH Security Suite scans without accessing the target repository.', parameters: {},
    output: { schema: { type: 'array', items: { type: 'object', properties: { id: { type: 'string' }, mode: { type: 'string' }, completedAt: { type: 'string' }, findings: { type: 'number' } }, required: ['id', 'mode', 'completedAt', 'findings'], additionalProperties: false } }, render: (_args, value) => [{ type: 'text', text: JSON.stringify(value) }] },
    async execute() { return (await listScans(getStateDir(config.stateDir))).map(scan => ({ id: scan.id, mode: scan.mode, completedAt: scan.completedAt, findings: scan.findings.length })) },
  }))

  ctx.tools.register(defineTool({
    name: 'security_get_scan', description: 'Load one canonical scan record, including coverage and findings.', parameters: { scan_id: { type: 'string', required: true, description: 'Saved scan identifier.' } },
    output: { schema: { type: 'object', additionalProperties: true }, render: (_args, value) => [{ type: 'text', text: JSON.stringify(value) }] },
    async execute(args) { return JSON.parse(JSON.stringify(await loadScan(getStateDir(config.stateDir), args.scan_id))) as Record<string, JsonValue> },
  }))

  ctx.tools.register(defineTool({
    name: 'security_export_scan', description: 'Render a saved scan as Markdown, JSON, SARIF, or CSV content. The caller chooses where to save it.', parameters: { scan_id: { type: 'string', required: true, description: 'Saved scan identifier.' }, format: { type: 'string', required: true, enum: ['markdown', 'json', 'sarif', 'csv'], description: 'Portable output format.' } },
    output: { schema: { type: 'object', properties: { format: { type: 'string' }, content: { type: 'string' } }, required: ['format', 'content'], additionalProperties: false }, render: (_args, value) => [{ type: 'text', text: value.content ?? '' }] },
    async execute(args) { const scan = await loadScan(getStateDir(config.stateDir), args.scan_id); const content = args.format === 'markdown' ? renderMarkdownReport(scan) : args.format === 'sarif' ? JSON.stringify(toSarif(scan), null, 2) : args.format === 'csv' ? renderCsv(scan) : JSON.stringify(scan, null, 2); return { format: args.format, content } },
  }))

  ctx.tools.register(defineTool({
    name: 'security_update_finding', description: 'Persist a validated finding status and source-backed analysis. Use only after review establishes the fields.', parameters: { scan_id: { type: 'string', required: true, description: 'Saved scan identifier.' }, finding_id: { type: 'string', required: true, description: 'Finding identifier.' }, status: { type: 'string', required: true, enum: ['open', 'false_positive', 'resolved', 'unknown'], description: 'Validated disposition.' }, validation: { type: 'string', description: 'Source-backed validation and counterevidence.' }, attack_path: { type: 'string', description: 'Attacker-to-sink path and prerequisites.' }, impact: { type: 'string', description: 'Concrete security impact.' }, remediation: { type: 'string', description: 'Focused remediation.' }, severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low'], description: 'Calibrated severity.' }, confidence: { type: 'string', enum: ['high', 'medium', 'low'], description: 'Confidence after validation.' } },
    output: { schema: { type: 'object', properties: { updated: { type: 'boolean' }, findingId: { type: 'string' } }, required: ['updated', 'findingId'], additionalProperties: false }, render: (_args, value) => [{ type: 'text', text: JSON.stringify(value) }] },
    async execute(args) { const stateDir = getStateDir(config.stateDir); const scan = await loadScan(stateDir, args.scan_id); const original = scan.findings.find(item => item.id === args.finding_id); if (!original) throw new Error('Finding was not found in this scan.'); if (args.status === 'false_positive' && !args.validation) throw new Error('A false-positive disposition requires source-backed validation or counterevidence.'); if (args.status === 'open' && (!args.validation || !args.attack_path || !args.impact)) throw new Error('An open validated finding requires validation, attack path, and impact evidence.'); const finding = structuredClone(original); finding.status = args.status as typeof finding.status; if (args.validation) { finding.validation = args.validation; finding.evidence.push({ kind: args.status === 'false_positive' ? 'counterevidence' : 'validation', detail: args.validation }) }; if (args.attack_path) finding.attackPath = args.attack_path; if (args.impact) finding.impact = args.impact; if (args.remediation) finding.remediation = args.remediation; if (args.severity) finding.severity = args.severity as typeof finding.severity; if (args.confidence) finding.confidence = args.confidence as typeof finding.confidence; await saveTriageAnnotation(stateDir, scan, finding); return { updated: true, findingId: finding.id } },
  }))

  ctx.tools.register(defineTool({
    name: 'security_verify_scan_bundle', description: 'Verify scan-state integrity, canonical artifacts, and the discovery/validation/attack-path ledger receipts for a saved scan.', parameters: { scan_id: { type: 'string', required: true, description: 'Saved scan identifier.' } },
    output: { schema: { type: 'object', properties: { valid: { type: 'boolean' }, errors: { type: 'array', items: { type: 'string' } } }, required: ['valid', 'errors'], additionalProperties: false }, render: (_args, value) => [{ type: 'text', text: JSON.stringify(value) }] },
    async execute(args) { return verifyScanBundle(await loadScan(getStateDir(config.stateDir), args.scan_id)) },
  }))

  ctx.tools.register(defineTool({
    name: 'security_remediation_plan', description: 'Generate a review-required patch proposal for one saved finding. It never modifies source files.', parameters: { scan_id: { type: 'string', required: true, description: 'Saved scan identifier.' }, finding_id: { type: 'string', required: true, description: 'Finding identifier.' } },
    output: { schema: { type: 'object', properties: { id: { type: 'string' }, findingId: { type: 'string' }, file: { type: 'string' }, line: { type: 'number' }, patch: { type: 'string' }, baseSnapshotDigest: { type: 'string' }, status: { type: 'string' }, requiresApproval: { type: 'boolean' }, requiresReview: { type: 'boolean' }, safeToApply: { type: 'boolean' }, rationale: { type: 'string' } }, required: ['id', 'findingId', 'file', 'line', 'patch', 'baseSnapshotDigest', 'status', 'requiresApproval', 'requiresReview', 'safeToApply', 'rationale'], additionalProperties: false }, render: (_args, value) => [{ type: 'text', text: value.patch ?? '' }] },
    async execute(args) { return remediationPlan(process.cwd(), config, args.scan_id, args.finding_id) },
  }))

  ctx.tools.register(defineTool({
    name: 'security_apply_remediation', description: 'Apply one explicitly reviewable safe remediation only after approval. It rejects stale targets, saves an exact rollback record, rescans, and records the verification scan.', parameters: { scan_id: { type: 'string', required: true, description: 'Source scan identifier.' }, remediation_id: { type: 'string', required: true, description: 'Identifier from security_remediation_plan.' }, approved: { type: 'boolean', required: true, description: 'Set true only after reviewing the patch and approving the source change.' } },
    output: { schema: { type: 'object', properties: { id: { type: 'string' }, findingId: { type: 'string' }, status: { type: 'string' }, appliedAt: { type: 'string' }, verificationScanId: { type: 'string' }, rollbackId: { type: 'string' } }, required: ['id', 'findingId', 'status'], additionalProperties: false }, render: (_args, value) => [{ type: 'text', text: JSON.stringify(value) }] },
    async execute(args) { return applyRemediationProposal(process.cwd(), config, args.scan_id, args.remediation_id, args.approved) },
  }))

  ctx.tools.register(defineTool({
    name: 'security_rollback_remediation', description: 'Restore the exact pre-application content for one approved remediation only after explicit approval. It refuses a changed applied state, then runs a verification rescan and saves the rollback receipt.', parameters: { scan_id: { type: 'string', required: true, description: 'Source scan identifier.' }, remediation_id: { type: 'string', required: true, description: 'Applied remediation identifier.' }, approved: { type: 'boolean', required: true, description: 'Set true only after reviewing the rollback record and approving the source change.' } },
    output: { schema: { type: 'object', properties: { id: { type: 'string' }, remediationId: { type: 'string' }, scanId: { type: 'string' }, file: { type: 'string' }, status: { type: 'string' }, rolledBackAt: { type: 'string' }, verificationScanId: { type: 'string' } }, required: ['id', 'remediationId', 'scanId', 'file', 'status'], additionalProperties: false }, render: (_args, value) => [{ type: 'text', text: JSON.stringify(value) }] },
    async execute(args) { return rollbackRemediationProposal(process.cwd(), config, args.scan_id, args.remediation_id, args.approved) },
  }))

  ctx.tools.register(defineTool({
    name: 'security_install_precommit_hook', description: 'Install the suite pre-commit review hook only after explicit approval. It preserves an existing hook and never overwrites it.', parameters: { approved: { type: 'boolean', required: true, description: 'Set true only after reviewing and approving the repository change.' } },
    output: { schema: { type: 'object', properties: { installed: { type: 'boolean' }, path: { type: 'string' }, reason: { type: 'string' } }, required: ['installed', 'path'], additionalProperties: false }, render: (_args, value) => [{ type: 'text', text: JSON.stringify(value) }] },
    async execute(args) { return installPreCommitHook(process.cwd(), args.approved) },
  }))

  ctx.tools.register(defineTool({
    name: 'security_tracking_preview', description: 'Build an exact GitHub, Jira, or Linear issue preview. With a provider token it performs a provider-scoped, read-only duplicate lookup and returns its receipt; it never creates an external issue.', parameters: { scan_id: { type: 'string', required: true, description: 'Saved scan identifier.' }, finding_id: { type: 'string', required: true, description: 'Reportable finding identifier.' }, provider: { type: 'string', required: true, enum: ['github', 'jira', 'linear'], description: 'External tracker.' }, repository: { type: 'string', description: 'GitHub repository owner/name.' }, endpoint: { type: 'string', description: 'Jira base URL or Linear GraphQL endpoint.' }, project: { type: 'string', description: 'Jira project key or Linear team id.' }, token: { type: 'string', description: 'Optional provider token, used only for the read-only duplicate lookup.' } },
    output: { schema: { type: 'object', additionalProperties: true }, render: (_args, value) => [{ type: 'text', text: `${(value as { title?: string }).title ?? ''}\n\n${(value as { body?: string }).body ?? ''}` }] },
    async execute(args) { return JSON.parse(JSON.stringify(await previewTracking(config, { provider: args.provider as 'github' | 'jira' | 'linear', scanId: args.scan_id, findingId: args.finding_id, repository: args.repository, endpoint: args.endpoint, project: args.project, token: args.token }))) as Record<string, JsonValue> },
  }))

  ctx.tools.register(defineTool({
    name: 'security_create_tracking_issue', description: 'Create exactly one GitHub, Jira, or Linear issue only after explicit approval. It performs provider-scoped duplicate detection, prevents duplicate local writes, verifies the created issue by readback, and persists a token-free receipt.', parameters: { scan_id: { type: 'string', required: true, description: 'Saved scan identifier.' }, finding_id: { type: 'string', required: true, description: 'Reportable finding identifier.' }, provider: { type: 'string', required: true, enum: ['github', 'jira', 'linear'], description: 'External tracker.' }, token: { type: 'string', required: true, description: 'Provider credential used only for this request.' }, repository: { type: 'string', description: 'GitHub repository owner/name.' }, endpoint: { type: 'string', description: 'Jira base URL or Linear GraphQL endpoint.' }, project: { type: 'string', description: 'Jira project key or Linear team id.' }, approved: { type: 'boolean', required: true, description: 'Set true only after reviewing security_tracking_preview output.' } },
    output: { schema: { type: 'object', properties: { id: { type: 'string' }, provider: { type: 'string' }, status: { type: 'string' }, writeSucceeded: { type: 'boolean' }, externalId: { type: 'string' }, url: { type: 'string' }, duplicateOf: { type: 'string' }, error: { type: 'string' } }, required: ['id', 'provider', 'status'], additionalProperties: false }, render: (_args, value) => [{ type: 'text', text: JSON.stringify(value) }] },
    async execute(args) { return createTracking(config, { provider: args.provider as 'github' | 'jira' | 'linear', scanId: args.scan_id, findingId: args.finding_id, token: args.token, repository: args.repository, endpoint: args.endpoint, project: args.project, approved: args.approved }) },
  }))
}
