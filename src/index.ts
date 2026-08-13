import type { Context } from '@deepseek-ai/cordis'
import type {} from '@deepseek-ai/dsh-system-prompt'
import { defineTool, type JsonValue } from '@deepseek-ai/dsh-tools'
import { Config, type Config as PluginConfig } from './config.js'
import { SECURITY_REVIEW_GUIDANCE } from './prompt.js'
import { FULL_SECURITY_WORKFLOW } from './workflows.js'
import { generateSourceThreatModel, runDiffScan, runScan, resolveSafeTarget } from './scanner.js'
import { finalizeAndSaveScan, getStateDir, listScans, loadScan, persistInvestigationArtifacts, renderCsv, renderMarkdownReport, saveTriageAnnotation, saveScan, toSarif, verifyScanBundle } from './state.js'
import { bulkScan, installPreCommitHook, remediationPlan, rerunSavedScan } from './operations.js'
import { claimAuditTask, completeScan, pendingCandidates, recordAttackPath, recordValidation } from './workbench.js'

export const name = 'dsh-security-suite'
export const inject = ['tools', 'systemPrompt']
export { Config }

export function apply(ctx: Context, config: PluginConfig): void {
  if (!config.enabled) return

  ctx.systemPrompt.section({
    name: 'dsh-security-suite:review-guidance',
    order: 160,
    text: SECURITY_REVIEW_GUIDANCE,
  })
  ctx.systemPrompt.section({ name: 'dsh-security-suite:workflow', order: 161, text: FULL_SECURITY_WORKFLOW })

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
    name: 'security_claim_audit_task', description: 'Claim the next durable validation or attack-path task. Only the returned claim token can submit that task receipt, preventing duplicated or conflicting worker conclusions.', parameters: { scan_id: { type: 'string', required: true, description: 'Investigation scan identifier.' }, owner: { type: 'string', required: true, description: 'DSH worker or reviewer identifier.' }, phase: { type: 'string', enum: ['validation', 'attack_path'], description: 'Optional task phase to claim.' } },
    output: { schema: { oneOf: [{ type: 'object', properties: { taskId: { type: 'string' }, candidateId: { type: 'string' }, phase: { type: 'string' }, focus: { type: 'string' }, claimToken: { type: 'string' }, artifactRef: { type: 'string' } }, required: ['taskId', 'candidateId', 'phase', 'focus', 'claimToken', 'artifactRef'], additionalProperties: false }, { type: 'null' }] }, render: (_args, value) => [{ type: 'text', text: JSON.stringify(value) }] },
    async execute(args) { return claimAuditTask(config, args.scan_id, args.owner, args.phase as 'validation' | 'attack_path' | undefined) },
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
    description: 'Read a Git diff in the current workspace and return it with security-review instructions. This is read-only.',
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
    async execute(args) { const stateDir = getStateDir(config.stateDir); const scan = await loadScan(stateDir, args.scan_id); const finding = scan.findings.find(item => item.id === args.finding_id); if (!finding) throw new Error('Finding was not found in this scan.'); if (args.status === 'false_positive' && !args.validation) throw new Error('A false-positive disposition requires source-backed validation or counterevidence.'); if (args.status === 'open' && (!args.validation || !args.attack_path || !args.impact)) throw new Error('An open validated finding requires validation, attack path, and impact evidence.'); finding.status = args.status as typeof finding.status; if (args.validation) { finding.validation = args.validation; finding.evidence.push({ kind: args.status === 'false_positive' ? 'counterevidence' : 'validation', detail: args.validation }) }; if (args.attack_path) finding.attackPath = args.attack_path; if (args.impact) finding.impact = args.impact; if (args.remediation) finding.remediation = args.remediation; if (args.severity) finding.severity = args.severity as typeof finding.severity; if (args.confidence) finding.confidence = args.confidence as typeof finding.confidence; await saveTriageAnnotation(stateDir, scan, finding); return { updated: true, findingId: finding.id } },
  }))

  ctx.tools.register(defineTool({
    name: 'security_verify_scan_bundle', description: 'Verify scan-state integrity, canonical artifacts, and the discovery/validation/attack-path ledger receipts for a saved scan.', parameters: { scan_id: { type: 'string', required: true, description: 'Saved scan identifier.' } },
    output: { schema: { type: 'object', properties: { valid: { type: 'boolean' }, errors: { type: 'array', items: { type: 'string' } } }, required: ['valid', 'errors'], additionalProperties: false }, render: (_args, value) => [{ type: 'text', text: JSON.stringify(value) }] },
    async execute(args) { return verifyScanBundle(await loadScan(getStateDir(config.stateDir), args.scan_id)) },
  }))

  ctx.tools.register(defineTool({
    name: 'security_remediation_plan', description: 'Generate a review-required patch proposal for one saved finding. It never modifies source files.', parameters: { scan_id: { type: 'string', required: true, description: 'Saved scan identifier.' }, finding_id: { type: 'string', required: true, description: 'Finding identifier.' } },
    output: { schema: { type: 'object', properties: { findingId: { type: 'string' }, file: { type: 'string' }, line: { type: 'number' }, patch: { type: 'string' }, requiresReview: { type: 'boolean' } }, required: ['findingId', 'file', 'line', 'patch', 'requiresReview'], additionalProperties: false }, render: (_args, value) => [{ type: 'text', text: value.patch ?? '' }] },
    async execute(args) { return remediationPlan(process.cwd(), config, args.scan_id, args.finding_id) },
  }))

  ctx.tools.register(defineTool({
    name: 'security_install_precommit_hook', description: 'Install the suite pre-commit review hook only after explicit approval. It preserves an existing hook and never overwrites it.', parameters: { approved: { type: 'boolean', required: true, description: 'Set true only after reviewing and approving the repository change.' } },
    output: { schema: { type: 'object', properties: { installed: { type: 'boolean' }, path: { type: 'string' }, reason: { type: 'string' } }, required: ['installed', 'path'], additionalProperties: false }, render: (_args, value) => [{ type: 'text', text: JSON.stringify(value) }] },
    async execute(args) { return installPreCommitHook(process.cwd(), args.approved) },
  }))

  ctx.tools.register(defineTool({
    name: 'security_tracking_preview', description: 'Create an exact Markdown preview for a GitHub, Jira, or Linear finding ticket. This tool never creates an external issue.', parameters: { scan_id: { type: 'string', required: true, description: 'Saved scan identifier.' }, finding_id: { type: 'string', required: true, description: 'Finding identifier.' }, provider: { type: 'string', required: true, enum: ['github', 'jira', 'linear'], description: 'Proposed external tracker.' } },
    output: { schema: { type: 'object', properties: { provider: { type: 'string' }, title: { type: 'string' }, body: { type: 'string' }, requiresApproval: { type: 'boolean' } }, required: ['provider', 'title', 'body', 'requiresApproval'], additionalProperties: false }, render: (_args, value) => [{ type: 'text', text: `${value.title ?? ''}\n\n${value.body ?? ''}` }] },
    async execute(args) { const scan = await loadScan(getStateDir(config.stateDir), args.scan_id); const finding = scan.findings.find(item => item.id === args.finding_id); if (!finding) throw new Error('Finding was not found in this scan.'); const body = `## ${finding.title}\n\n- Severity: ${finding.severity}\n- CWE: ${finding.cwe}\n- Confidence: ${finding.confidence}\n- Location: ${finding.locations[0].file}:${finding.locations[0].line}\n\n${finding.rootCause}\n\n### Attack Path\n${finding.attackPath}\n\n### Impact\n${finding.impact}\n\n### Remediation\n${finding.remediation}`; return { provider: args.provider, title: `[${finding.severity.toUpperCase()}] ${finding.title}`, body, requiresApproval: true } },
  }))
}
