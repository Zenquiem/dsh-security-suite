import { access, cp, mkdir, mkdtemp, readFile, rename, rm, writeFile } from 'node:fs/promises'
import { execFile } from 'node:child_process'
import { constants } from 'node:fs'
import { isAbsolute, join, relative, resolve, sep } from 'node:path'
import { tmpdir } from 'node:os'
import { promisify } from 'node:util'
import { createHash, randomUUID } from 'node:crypto'
import type { Config } from './config.js'
import type { Finding, ScanRecord } from './contracts.js'
import { runScan, resolveSafeTarget, snapshotDigestForDirectory } from './scanner.js'
import { finalizeAndSaveScan, getStateDir, loadScan, persistInvestigationArtifacts, saveScan, sha256, writeArtifact } from './state.js'

const execFileAsync = promisify(execFile)
const MAX_COMMAND_OUTPUT = 256_000
const VALIDATION_COMMAND = /^[A-Za-z0-9_./:@=+%, -]+$/
const RUNTIME_METHODS = ['realistic_interface_reproduction', 'debugger_trace', 'sanitizer_or_memory_checker'] as const

export interface CommandReceipt { id: string; command: string; cwd: string; exitCode?: number; timedOut: boolean; durationMs: number; stdout: string; stderr: string; snapshotDigest: string; artifactRef?: string }
export type RuntimeValidationMethod = typeof RUNTIME_METHODS[number]
export interface RuntimeValidationReceipt extends CommandReceipt { method: RuntimeValidationMethod; fixturePaths: string[]; setupSummary: string; limitation: string }
export interface ValidationStrategy { method: 'isolated_project_checks' | 'realistic_interface_reproduction' | 'debugger_trace' | 'sanitizer_or_memory_checker' | 'source_trace'; status: 'runnable_with_approval' | 'requires_explicit_setup' | 'not_applicable' | 'available_without_execution'; rationale: string; requiredEvidence: string[] }
export interface CandidateValidationPlan { id: string; scanId: string; candidateId: string; snapshotDigest: string; projectFiles: string[]; commands: Array<{ command: string; reason: string }>; strategies: ValidationStrategy[]; skipped: Array<{ reason: string }>; createdAt: string }
export interface CandidateValidationPlanRun extends CandidateValidationPlan { approved: true; executedAt: string; receipts: CommandReceipt[]; artifactRef: string }
export interface RemediationReplacement { file: string; startLine: number; endLine: number; expectedText: string; replacementText: string }
export interface RemediationFileSnapshot { file: string; sha256: string }
export interface RemediationRollbackFile extends RemediationFileSnapshot { beforeContent: string; appliedSha256: string }
export interface RemediationVerification { scanId: string; status: 'not_detected' | 'still_detected'; ruleId: string; file: string; matchingFindingIds: string[]; observedAt: string; limitation: string }
export interface RemediationVerificationRun { id: string; remediationId: string; sourceScanId: string; snapshotDigest: string; commands: Array<{ command: string; reason: string }>; receipts: CommandReceipt[]; outcome: 'passed' | 'failed'; executedAt: string; artifactRef: string; limitation: string }
export interface RemediationProposal { id: string; findingId: string; file: string; line: number; patch: string; baseSnapshotDigest: string; baseFileSha256: string; baseFiles?: RemediationFileSnapshot[]; createdAt: string; status: 'proposed' | 'applied' | 'rolled_back' | 'stale' | 'superseded'; requiresApproval: true; requiresReview: true; safeToApply: boolean; rationale: string; testPlan?: string; replacement?: RemediationReplacement; replacements?: RemediationReplacement[]; appliedAt?: string; verificationScanId?: string; verification?: RemediationVerification; postApplyVerification?: RemediationVerificationRun; rollbackId?: string }
export interface RemediationRollback { id: string; remediationId: string; scanId: string; file: string; beforeContent: string; beforeSha256: string; appliedSha256: string; files?: RemediationRollbackFile[]; appliedSnapshotDigest: string; createdAt: string; status: 'available' | 'rolled_back' | 'stale'; rolledBackAt?: string; verificationScanId?: string }

export interface BulkResult { path: string; scanId?: string; findings?: number; error?: string }
export interface BulkJob { id: string; createdAt: string; updatedAt: string; mode: 'standard' | 'deep'; threatModel: string; entries: Array<BulkResult & { status: 'pending' | 'completed' | 'failed'; attempts: number }> }

function inside(root: string, target: string): boolean { const rel = relative(root, target); return rel === '' || (!rel.startsWith('..') && !isAbsolute(rel)) }
function safeCommand(command: string): string { const value = command.trim(); if (!value || value.length > 500 || !VALIDATION_COMMAND.test(value)) throw new Error('Validation command contains unsupported shell syntax. Use a simple executable and arguments only.'); return value }
function splitCommand(command: string): string[] { return safeCommand(command).split(/\s+/).filter(Boolean) }
function commandExecutable(command: string): string { return splitCommand(command)[0]?.split('/').at(-1)?.toLowerCase() ?? '' }
function isLoopbackUrl(value: string): boolean { try { const url = new URL(value); return ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname) } catch { return false } }
function safeRuntimeCommand(method: RuntimeValidationMethod, command: string): string {
  const value = safeCommand(command); const args = splitCommand(value); const executable = commandExecutable(value)
  if (args.some(argument => /^(?:https?|ftp|ssh):\/\//i.test(argument) && !isLoopbackUrl(argument))) throw new Error('Runtime validation only accepts loopback URLs as direct command arguments; the disposable copy is not a network sandbox.')
  if (method === 'debugger_trace') {
    if (executable === 'gdb' && (args.includes('-batch') || args.includes('--batch')) && args.filter(argument => argument === '-ex' || argument === '--ex').length >= 2) return value
    if (executable === 'lldb' && args.includes('-b') && args.filter(argument => argument === '-o' || argument === '--one-line').length >= 2) return value
    throw new Error('Debugger validation requires non-interactive gdb (-batch with commands) or lldb (-b with commands).')
  }
  if (method === 'sanitizer_or_memory_checker') {
    if (/(?:asan|ubsan|msan|tsan|valgrind|sanitize)/i.test(value)) return value
    throw new Error('Sanitizer validation command must explicitly invoke a sanitizer or memory checker.')
  }
  if (!['node', 'nodejs', 'npm', 'pnpm', 'yarn', 'bun', 'python', 'python3', 'pytest', 'ruby', 'php', 'java', 'dotnet', 'go', 'cargo', 'mvn', 'gradle', 'gradlew'].includes(executable)) throw new Error('Interface validation command must use a supported local runtime or test runner.')
  return value
}
function runtimeMethod(value: string): RuntimeValidationMethod { if ((RUNTIME_METHODS as readonly string[]).includes(value)) return value as RuntimeValidationMethod; throw new Error('Runtime validation method is not supported.') }
function digest(value: string): string { return createHash('sha256').update(value).digest('hex') }
function proposalPath(stateDir: string, id: string): string { if (!/^rem_[0-9a-f-]+$/.test(id)) throw new Error('Invalid remediation id.'); return join(stateDir, 'remediations', `${id}.json`) }
function rollbackPath(stateDir: string, id: string): string { if (!/^rollback_[0-9a-f-]+$/.test(id)) throw new Error('Invalid remediation rollback id.'); return join(stateDir, 'remediation-rollbacks', `${id}.json`) }
async function atomicWrite(path: string, content: string): Promise<void> { const temporary = `${path}.${randomUUID()}.tmp`; await mkdir(resolve(path, '..'), { recursive: true }); await writeFile(temporary, content, 'utf8'); await rename(temporary, path) }
async function saveProposal(stateDir: string, proposal: RemediationProposal): Promise<void> { await atomicWrite(proposalPath(stateDir, proposal.id), `${JSON.stringify(proposal, null, 2)}\n`) }
export async function loadRemediationProposal(stateDir: string, id: string): Promise<RemediationProposal> { return JSON.parse(await readFile(proposalPath(stateDir, id), 'utf8')) as RemediationProposal }
async function saveRollback(stateDir: string, rollback: RemediationRollback): Promise<void> { await atomicWrite(rollbackPath(stateDir, rollback.id), `${JSON.stringify(rollback, null, 2)}\n`) }
export async function loadRemediationRollback(stateDir: string, id: string): Promise<RemediationRollback> { return JSON.parse(await readFile(rollbackPath(stateDir, id), 'utf8')) as RemediationRollback }
function bulkJobPath(stateDir: string, id: string): string { if (!/^bulk_[0-9a-f-]+$/.test(id)) throw new Error('Invalid bulk job id.'); return join(stateDir, 'bulk-jobs', `${id}.json`) }
async function saveBulkJob(stateDir: string, job: BulkJob): Promise<void> { job.updatedAt = new Date().toISOString(); await atomicWrite(bulkJobPath(stateDir, job.id), `${JSON.stringify(job, null, 2)}\n`) }
export async function loadBulkJob(stateDir: string, id: string): Promise<BulkJob> { return JSON.parse(await readFile(bulkJobPath(stateDir, id), 'utf8')) as BulkJob }

function rethrowIfCancelled(signal: AbortSignal | undefined, error?: unknown): void {
  if (signal?.aborted || (error as { name?: string } | undefined)?.name === 'AbortError') throw error ?? new DOMException('Validation was cancelled.', 'AbortError')
}

export async function runIsolatedValidation(workspace: string, config: Config, scanId: string, command: string, timeoutMs = 120_000, signal?: AbortSignal): Promise<CommandReceipt> {
  signal?.throwIfAborted()
  const scan = await loadScan(getStateDir(config.stateDir), scanId); const root = resolve(workspace); const target = resolve(scan.target)
  if (!inside(root, target)) throw new Error('Saved scan target is outside the active workspace.')
  const args = splitCommand(command); const timeout = Math.max(1_000, Math.min(timeoutMs, 600_000)); const copyRoot = await mkdtemp(join(tmpdir(), 'dsh-security-suite-validation-'))
  const copyTarget = join(copyRoot, 'target')
  const started = Date.now(); let stdout = ''; let stderr = ''; let exitCode: number | undefined; let timedOut = false
  try {
    signal?.throwIfAborted()
    await cp(target, copyTarget, { recursive: true, dereference: false, filter: source => !source.split(sep).some(part => ['.git', 'node_modules', 'dist', 'build', 'coverage'].includes(part)) })
    signal?.throwIfAborted()
    try { const result = await execFileAsync(args[0], args.slice(1), { cwd: copyTarget, timeout, maxBuffer: MAX_COMMAND_OUTPUT, encoding: 'utf8', windowsHide: true, signal }); stdout = result.stdout; stderr = result.stderr; exitCode = 0 } catch (error: unknown) { rethrowIfCancelled(signal, error); const value = error as { stdout?: string; stderr?: string; code?: number | string; killed?: boolean }; stdout = value.stdout ?? ''; stderr = value.stderr ?? ''; exitCode = typeof value.code === 'number' ? value.code : undefined; timedOut = Boolean(value.killed) }
    const receipt: CommandReceipt = { id: `cmd_${randomUUID()}`, command: args.join(' '), cwd: '.', exitCode, timedOut, durationMs: Date.now() - started, stdout: stdout.slice(0, MAX_COMMAND_OUTPUT), stderr: stderr.slice(0, MAX_COMMAND_OUTPUT), snapshotDigest: await snapshotDigestForDirectory(target, config) }
    const receiptPath = join(getStateDir(config.stateDir), 'validation-receipts', `${receipt.id}.json`)
    await atomicWrite(receiptPath, `${JSON.stringify(receipt, null, 2)}\n`)
    receipt.artifactRef = receiptPath
    await atomicWrite(receiptPath, `${JSON.stringify(receipt, null, 2)}\n`)
    return receipt
  } finally { await rm(copyRoot, { recursive: true, force: true }) }
}

/**
 * Bind a disposable test/build execution to one claimed validation task.
 * A command receipt is evidence only; the reviewer still records the final
 * source/runtime conclusion with recordValidation.
 */
export async function runCandidateValidation(workspace: string, config: Config, scanId: string, candidateId: string, claimToken: string, command: string, timeoutMs = 120_000, signal?: AbortSignal): Promise<CommandReceipt> {
  signal?.throwIfAborted()
  const state = getStateDir(config.stateDir); const scan = await loadScan(state, scanId)
  if (scan.lifecycle === 'completed') throw new Error('Completed scans cannot accept new validation evidence.')
  const finding = scan.findings.find(item => item.candidateId === candidateId); if (!finding) throw new Error('Candidate was not found in this scan.')
  const task = scan.tasks.find(item => item.candidateId === candidateId && item.phase === 'validation' && item.status === 'claimed')
  if (!task || task.claim?.token !== claimToken) throw new Error('Claim token does not own this candidate validation task.')
  const currentSnapshot = await snapshotDigestForDirectory(scan.target, config); if (currentSnapshot !== scan.targetSnapshot.snapshotDigest) throw new Error('Target changed since this scan. Create a follow-up scan before attaching validation evidence.')
  const receipt = await runIsolatedValidation(workspace, config, scanId, command, timeoutMs, signal)
  if (receipt.snapshotDigest !== scan.targetSnapshot.snapshotDigest) throw new Error('Target changed during isolated validation; the receipt was retained externally but was not attached to this scan.')
  const reloaded = await loadScan(state, scanId); const currentFinding = reloaded.findings.find(item => item.candidateId === candidateId); const currentTask = reloaded.tasks.find(item => item.id === task.id)
  if (!currentFinding || !currentTask || currentTask.status !== 'claimed' || currentTask.claim?.token !== claimToken) throw new Error('Candidate validation task changed while the command was running; the receipt was retained externally but was not attached.')
  const artifactRef = `artifacts/05_findings/${candidateId}/validation_artifacts/${receipt.id}.json`
  const attached = { ...receipt, artifactRef }
  await writeArtifact(reloaded, artifactRef, `${JSON.stringify(attached, null, 2)}\n`)
  const outcome = receipt.timedOut ? 'timed out' : receipt.exitCode === 0 ? 'completed successfully' : `exited with ${receipt.exitCode ?? 'an unknown status'}`
  currentFinding.evidence.push({ kind: 'test', detail: `Isolated validation command \`${receipt.command}\` ${outcome}; interpret this receipt with source and runtime context.`, artifactRef })
  currentFinding.ledger.push({ at: new Date().toISOString(), phase: 'validation', disposition: 'discovered', summary: `Attached isolated validation receipt ${receipt.id}: ${outcome}. Final validation conclusion remains pending.`, artifactRef })
  currentTask.receipt = `test:${receipt.id}`
  await persistInvestigationArtifacts(state, reloaded); await saveScan(state, reloaded)
  return attached
}

/**
 * Run a reviewed local interface, debugger, or sanitizer command in a
 * disposable target copy. The receipt is runtime evidence only: it cannot
 * independently promote, suppress, or resolve the candidate.
 */
export async function runCandidateRuntimeValidation(workspace: string, config: Config, scanId: string, candidateId: string, claimToken: string, methodInput: string, command: string, fixturePaths: string[], setupSummary: string, approved: boolean, timeoutMs = 120_000, signal?: AbortSignal): Promise<RuntimeValidationReceipt> {
  signal?.throwIfAborted()
  if (!approved) throw new Error('Runtime validation can execute a reviewed local interface, debugger, or sanitizer command. Set approved to true only after reviewing its fixture paths and command.')
  const method = runtimeMethod(methodInput); const boundedCommand = safeRuntimeCommand(method, command)
  const setup = setupSummary.trim(); if (!setup || setup.length > 20_000) throw new Error('Runtime validation requires a bounded setup summary.')
  const fixtures = [...new Set(fixturePaths.map(path => path.trim()))]
  if (!fixtures.length || fixtures.length > 20 || fixtures.some(path => !path || isAbsolute(path) || path.split(/[\\/]+/).includes('..'))) throw new Error('Runtime validation requires one to twenty workspace-relative fixture paths.')
  const state = getStateDir(config.stateDir); const scan = await loadScan(state, scanId)
  if (scan.mode === 'diff') throw new Error('Runtime validation needs a full source snapshot; create a standard or deep follow-up scan for a diff candidate.')
  if (scan.lifecycle === 'completed') throw new Error('Completed scans cannot accept new validation evidence.')
  const finding = scan.findings.find(item => item.candidateId === candidateId); if (!finding) throw new Error('Candidate was not found in this scan.')
  const task = scan.tasks.find(item => item.candidateId === candidateId && item.phase === 'validation' && item.status === 'claimed')
  if (!task || task.claim?.token !== claimToken) throw new Error('Claim token does not own this candidate validation task.')
  const receiptPaths = new Set(scan.coverage.receipts.map(receipt => receipt.path))
  if (fixtures.some(path => !receiptPaths.has(path))) throw new Error('Every runtime validation fixture must be a scan-receipted source path.')
  const before = await snapshotDigestForDirectory(scan.target, config); if (before !== scan.targetSnapshot.snapshotDigest) throw new Error('Target changed since this scan. Create a follow-up scan before attaching runtime evidence.')
  const commandReceipt = await runIsolatedValidation(workspace, config, scanId, boundedCommand, timeoutMs, signal)
  if (commandReceipt.snapshotDigest !== scan.targetSnapshot.snapshotDigest) throw new Error('Target changed during runtime validation; the receipt was retained externally but was not attached to this scan.')
  const reloaded = await loadScan(state, scanId); const currentFinding = reloaded.findings.find(item => item.candidateId === candidateId); const currentTask = reloaded.tasks.find(item => item.id === task.id)
  if (!currentFinding || !currentTask || currentTask.status !== 'claimed' || currentTask.claim?.token !== claimToken) throw new Error('Candidate validation task changed while runtime validation was running; the receipt was retained externally but was not attached.')
  const artifactRef = `artifacts/05_findings/${candidateId}/validation_artifacts/runtime_${commandReceipt.id}.json`
  const receipt: RuntimeValidationReceipt = { ...commandReceipt, method, fixturePaths: fixtures.sort(), setupSummary: setup, limitation: 'This controlled, disposable-copy execution is runtime evidence only. It does not establish production reachability, prove all attacker paths, or automatically decide the candidate disposition. The copy prevents source-tree writes but is not a network sandbox; review the local environment and invoked fixture before approval.', artifactRef }
  await writeArtifact(reloaded, artifactRef, `${JSON.stringify(receipt, null, 2)}\n`)
  const outcome = receipt.timedOut ? 'timed out' : receipt.exitCode === 0 ? 'completed successfully' : `exited with ${receipt.exitCode ?? 'an unknown status'}`
  currentFinding.evidence.push({ kind: 'runtime', detail: `${method} command \`${receipt.command}\` ${outcome}; fixture paths: ${receipt.fixturePaths.join(', ')}. Interpret this receipt with source and runtime context.`, artifactRef })
  currentFinding.ledger.push({ at: new Date().toISOString(), phase: 'validation', disposition: 'discovered', summary: `Attached ${method} runtime receipt ${receipt.id}: ${outcome}. Final validation conclusion remains pending.`, artifactRef })
  currentTask.receipt = `runtime:${receipt.id}`
  await persistInvestigationArtifacts(state, reloaded); await saveScan(state, reloaded)
  return receipt
}

/**
 * Create a read-only validation plan from scan-time preflight evidence. It never
 * invents commands or reads a changed target to decide what should execute.
 */
export async function planCandidateValidation(config: Config, scanId: string, candidateId: string): Promise<CandidateValidationPlan> {
  const scan = await loadScan(getStateDir(config.stateDir), scanId)
  const finding = scan.findings.find(item => item.candidateId === candidateId); if (!finding) throw new Error('Candidate was not found in this scan.')
  const commands = [...new Set(scan.preflight.suggestedCommands.map(command => safeCommand(command)))].map(command => ({ command, reason: `Suggested by scan-time project preflight for ${scan.preflight.projectFiles.join(', ')}.` }))
  const languages = new Set(scan.preflight.languages); const compiled = ['c', 'cpp', 'rust', 'go', 'java', 'csharp'].some(language => languages.has(language))
  const interfaceEvidence = finding.locations.some(location => /(?:route|handler|controller|api|server|cli|command|parser|plugin)/i.test(location.file)) || /(?:request|route|handler|http|cli|parser|plugin)/i.test(`${finding.rootCause}\n${finding.validation}`)
  const strategies: ValidationStrategy[] = [
    { method: 'isolated_project_checks', status: commands.length ? 'runnable_with_approval' : 'not_applicable', rationale: commands.length ? 'The scan-time manifest supplies bounded test/build commands that can run in a disposable copy.' : 'No scan-time manifest mapped to a bounded local test or build command.', requiredEvidence: commands.length ? ['DSH one-shot user approval', 'unchanged scan snapshot'] : ['a recognized project manifest with a bounded command'] },
    { method: 'realistic_interface_reproduction', status: interfaceEvidence ? 'requires_explicit_setup' : 'not_applicable', rationale: interfaceEvidence ? 'Source evidence suggests a user-reachable interface, but the scan does not establish a safe command, test fixture, credentials, or service configuration.' : 'The retained finding evidence does not establish a concrete user-reachable interface.', requiredEvidence: interfaceEvidence ? ['explicit local interface command', 'safe fixture or disposable environment', 'unchanged scan snapshot'] : ['source evidence of a concrete interface'] },
    { method: 'debugger_trace', status: compiled ? 'requires_explicit_setup' : 'not_applicable', rationale: compiled ? 'A compiled stack is present, but the scan does not prove that a debugger is installed or that a non-interactive trace is proportionate.' : 'No compiled stack was recorded by scan preflight.', requiredEvidence: compiled ? ['non-interactive debugger command', 'debug symbols or traceable build', 'explicit local environment authorization'] : ['compiled source language'] },
    { method: 'sanitizer_or_memory_checker', status: compiled ? 'requires_explicit_setup' : 'not_applicable', rationale: compiled ? 'A compiled stack is present, but no sanitizer, memory checker, or compatible build configuration was detected from frozen scan context.' : 'No compiled stack was recorded by scan preflight.', requiredEvidence: compiled ? ['explicit sanitizer or checker command', 'compatible instrumented build', 'safe disposable workload'] : ['compiled source language'] },
    { method: 'source_trace', status: 'available_without_execution', rationale: 'Reopen the scan-receipted source to prove attacker, entry point, boundary, control, sink, impact, counterevidence, and remaining proof gaps without asserting runtime behavior.', requiredEvidence: ['scan-receipted source', 'validation receipt with counterevidence and limitations'] },
  ]
  const skipped = commands.length ? [] : [{ reason: scan.preflight.projectFiles.length ? 'Recognized project manifests did not map to a bounded local validation command.' : 'No recognized project manifest was present during scan preflight.' }]
  return { id: `plan_${randomUUID()}`, scanId, candidateId, snapshotDigest: scan.targetSnapshot.snapshotDigest, projectFiles: [...scan.preflight.projectFiles], commands, strategies, skipped, createdAt: new Date().toISOString() }
}

async function executeValidationCommands(target: string, commands: string[], timeoutMs: number, snapshotDigest: string, signal?: AbortSignal): Promise<CommandReceipt[]> {
  const timeout = Math.max(1_000, Math.min(timeoutMs, 600_000)); const copyRoot = await mkdtemp(join(tmpdir(), 'dsh-security-suite-validation-plan-')); const copyTarget = join(copyRoot, 'target')
  try {
    signal?.throwIfAborted()
    await cp(target, copyTarget, { recursive: true, dereference: false, filter: source => !source.split(sep).some(part => ['.git', 'node_modules', 'dist', 'build', 'coverage'].includes(part)) })
    const receipts: CommandReceipt[] = []
    for (const command of commands) {
      signal?.throwIfAborted()
      const args = splitCommand(command); const started = Date.now(); let stdout = ''; let stderr = ''; let exitCode: number | undefined; let timedOut = false
      try { const result = await execFileAsync(args[0], args.slice(1), { cwd: copyTarget, timeout, maxBuffer: MAX_COMMAND_OUTPUT, encoding: 'utf8', windowsHide: true, signal }); stdout = result.stdout; stderr = result.stderr; exitCode = 0 } catch (error: unknown) { rethrowIfCancelled(signal, error); const value = error as { stdout?: string; stderr?: string; code?: number | string; killed?: boolean; message?: string }; stdout = value.stdout ?? ''; stderr = value.stderr ?? (value.message ?? ''); exitCode = typeof value.code === 'number' ? value.code : undefined; timedOut = Boolean(value.killed) }
      receipts.push({ id: `cmd_${randomUUID()}`, command: args.join(' '), cwd: '.', exitCode, timedOut, durationMs: Date.now() - started, stdout: stdout.slice(0, MAX_COMMAND_OUTPUT), stderr: stderr.slice(0, MAX_COMMAND_OUTPUT), snapshotDigest })
    }
    return receipts
  } finally { await rm(copyRoot, { recursive: true, force: true }) }
}

/** Execute only a persisted-preflight plan, retaining every command outcome as candidate evidence. */
export async function runCandidateValidationPlan(workspace: string, config: Config, scanId: string, candidateId: string, claimToken: string, approved: boolean, timeoutMs = 120_000, signal?: AbortSignal): Promise<CandidateValidationPlanRun> {
  signal?.throwIfAborted()
  if (!approved) throw new Error('Executing a validation plan can run project test/build scripts. Set approved to true only after reviewing the planned commands.')
  const state = getStateDir(config.stateDir); const scan = await loadScan(state, scanId)
  if (scan.lifecycle === 'completed') throw new Error('Completed scans cannot accept new validation evidence.')
  const finding = scan.findings.find(item => item.candidateId === candidateId); if (!finding) throw new Error('Candidate was not found in this scan.')
  const task = scan.tasks.find(item => item.candidateId === candidateId && item.phase === 'validation' && item.status === 'claimed')
  if (!task || task.claim?.token !== claimToken) throw new Error('Claim token does not own this candidate validation task.')
  const plan = await planCandidateValidation(config, scanId, candidateId)
  if (!plan.commands.length) throw new Error(`No bounded validation command is available: ${plan.skipped.map(item => item.reason).join(' ')}`)
  const before = await snapshotDigestForDirectory(scan.target, config); if (before !== plan.snapshotDigest) throw new Error('Target changed since this scan. Create a follow-up scan before executing validation.')
  const receipts = await executeValidationCommands(resolve(scan.target), plan.commands.map(item => item.command), timeoutMs, plan.snapshotDigest, signal)
  const after = await snapshotDigestForDirectory(scan.target, config); if (after !== plan.snapshotDigest) throw new Error('Target changed during isolated validation; receipts were not attached to this scan.')
  const reloaded = await loadScan(state, scanId); const currentFinding = reloaded.findings.find(item => item.candidateId === candidateId); const currentTask = reloaded.tasks.find(item => item.id === task.id)
  if (!currentFinding || !currentTask || currentTask.status !== 'claimed' || currentTask.claim?.token !== claimToken) throw new Error('Candidate validation task changed while commands were running; receipts were not attached.')
  const attached = receipts.map(receipt => ({ ...receipt, artifactRef: `artifacts/05_findings/${candidateId}/validation_artifacts/${receipt.id}.json` }))
  for (const receipt of attached) await writeArtifact(reloaded, receipt.artifactRef!, `${JSON.stringify(receipt, null, 2)}\n`)
  const artifactRef = `artifacts/05_findings/${candidateId}/validation_artifacts/${plan.id}.json`; const run: CandidateValidationPlanRun = { ...plan, approved: true, executedAt: new Date().toISOString(), receipts: attached, artifactRef }
  await writeArtifact(reloaded, artifactRef, `${JSON.stringify(run, null, 2)}\n`)
  const outcomes = attached.map(receipt => receipt.timedOut ? `${receipt.command}: timed out` : receipt.exitCode === 0 ? `${receipt.command}: passed` : `${receipt.command}: failed`).join('; ')
  for (const receipt of attached) currentFinding.evidence.push({ kind: 'test', detail: `Planned isolated validation command \`${receipt.command}\` ${receipt.timedOut ? 'timed out' : receipt.exitCode === 0 ? 'completed successfully' : `exited with ${receipt.exitCode ?? 'an unknown status'}`}; interpret this receipt with source and runtime context.`, artifactRef: receipt.artifactRef })
  currentFinding.ledger.push({ at: new Date().toISOString(), phase: 'validation', disposition: 'discovered', summary: `Executed preflight-derived validation plan ${plan.id}: ${outcomes}. Final validation conclusion remains pending.`, artifactRef })
  currentTask.receipt = `validation-plan:${plan.id}`
  await persistInvestigationArtifacts(state, reloaded); await saveScan(state, reloaded)
  return run
}

export async function rerunSavedScan(workspace: string, config: Config, scanId: string): Promise<ScanRecord> {
  const previous = await loadScan(getStateDir(config.stateDir), scanId)
  if (previous.mode === 'diff') throw new Error('Diff scans must be rerun with security_review_diff so the requested base can be supplied explicitly.')
  const root = resolve(workspace); const target = resolve(previous.target)
  if (!inside(root, target)) throw new Error('Saved scan target is outside the active workspace.')
  const scan = await runScan(target, config, previous.mode, previous.threatModel, previous.recipe.scopeRequested, config.stateDir, false)
  await persistInvestigationArtifacts(getStateDir(config.stateDir), scan); await saveScan(getStateDir(config.stateDir), scan)
  return scan
}

export async function bulkScan(workspace: string, config: Config, paths: string[], mode: 'standard' | 'deep', threatModel: string, concurrency: number): Promise<BulkResult[]> {
  const unique = [...new Set(paths)].sort()
  if (unique.length === 0) throw new Error('At least one workspace-relative path is required.')
  const capped = Math.max(1, Math.min(concurrency, 4)); const output: BulkResult[] = new Array(unique.length); let cursor = 0
  const worker = async (): Promise<void> => {
    while (true) {
      const index = cursor++; if (index >= unique.length) return
      const item = unique[index]
      try { const scan = await runScan(resolveSafeTarget(workspace, item), config, mode, threatModel, true, config.stateDir, false); await persistInvestigationArtifacts(getStateDir(config.stateDir), scan); await saveScan(getStateDir(config.stateDir), scan); output[index] = { path: item, scanId: scan.id, findings: scan.findings.length } } catch (error) { output[index] = { path: item, error: error instanceof Error ? error.message : String(error) } }
    }
  }
  await Promise.all(Array.from({ length: Math.min(capped, unique.length) }, worker)); return output
}

function csvPaths(content: string): string[] {
  const lines = content.split(/\r?\n/).map(line => line.trim()).filter(Boolean); if (!lines.length) throw new Error('CSV input contains no target paths.')
  const first = lines[0].split(',').map(value => value.trim().replace(/^"|"$/g, '')); const pathColumn = first.findIndex(value => /^path$/i.test(value)); const start = pathColumn >= 0 ? 1 : 0; const column = pathColumn >= 0 ? pathColumn : 0
  return lines.slice(start).map(line => line.split(',')[column]?.trim().replace(/^"|"$/g, '') ?? '').filter(Boolean)
}

async function executeBulkJob(workspace: string, config: Config, job: BulkJob, concurrency: number): Promise<BulkJob> {
  const capped = Math.max(1, Math.min(concurrency, 4)); let cursor = 0; const state = getStateDir(config.stateDir)
  const worker = async (): Promise<void> => {
    while (true) {
      const index = cursor++; const entry = job.entries[index]; if (!entry) return; if (entry.status === 'completed') continue
      entry.attempts++; entry.error = undefined
      try { const target = resolveSafeTarget(workspace, entry.path); const targetInfo = await access(target).then(() => true).catch(() => false); if (!targetInfo) throw new Error('Bulk target directory does not exist or cannot be accessed.'); const scan = await runScan(target, config, job.mode, job.threatModel, true, config.stateDir, false); await persistInvestigationArtifacts(state, scan); await saveScan(state, scan); entry.scanId = scan.id; entry.findings = scan.findings.length; entry.status = 'completed' } catch (error) { entry.status = 'failed'; entry.error = error instanceof Error ? error.message : String(error) }
      await saveBulkJob(state, job)
    }
  }
  await Promise.all(Array.from({ length: Math.min(capped, job.entries.length) }, worker)); return job
}

export async function startBulkCsvJob(workspace: string, config: Config, csvPath: string, mode: 'standard' | 'deep', threatModel: string, concurrency: number): Promise<BulkJob> {
  const root = resolve(workspace); const source = resolve(root, csvPath); if (!inside(root, source)) throw new Error('CSV input must remain inside the active workspace.')
  const paths = [...new Set(csvPaths(await readFile(source, 'utf8')))].sort(); const now = new Date().toISOString(); const job: BulkJob = { id: `bulk_${randomUUID()}`, createdAt: now, updatedAt: now, mode, threatModel, entries: paths.map(path => ({ path, status: 'pending', attempts: 0 })) }
  await saveBulkJob(getStateDir(config.stateDir), job); return executeBulkJob(root, config, job, concurrency)
}

export async function resumeBulkJob(workspace: string, config: Config, jobId: string, concurrency: number): Promise<BulkJob> { const job = await loadBulkJob(getStateDir(config.stateDir), jobId); return executeBulkJob(resolve(workspace), config, job, concurrency) }

export async function installPreCommitHook(workspace: string, approved: boolean): Promise<{ installed: boolean; path: string; reason?: string }> {
  if (!approved) throw new Error('Installing a Git hook changes the repository. Set approved to true only after the hook content has been reviewed.')
  const root = resolve(workspace); const hookDirectory = join(root, '.git', 'hooks'); const hookPath = join(hookDirectory, 'pre-commit')
  try { await access(hookPath, constants.F_OK); return { installed: false, path: hookPath, reason: 'An existing pre-commit hook was preserved.' } } catch { /* absent is expected */ }
  await mkdir(hookDirectory, { recursive: true })
  const content = `#!/bin/sh\n# Installed by dsh-security-suite. Run DSH security review before committing.\n# This hook intentionally does not modify files or send data off-machine.\nif command -v dsh >/dev/null 2>&1; then\n  dsh run "Review the current Git diff for security findings using security_review_diff. Report high-confidence issues only." || exit $?\nfi\n`
  await writeFile(hookPath, content, { encoding: 'utf8', mode: 0o755 })
  return { installed: true, path: hookPath }
}

function replacementFor(finding: Finding, source: string): { content: string; rationale: string } | undefined {
  if (finding.ruleId === 'tls.verification.disabled') {
    const content = source.replace(/rejectUnauthorized\s*:\s*false/g, 'rejectUnauthorized: true').replace(/verify\s*=\s*False/g, 'verify = True').replace(/InsecureSkipVerify\s*:\s*true/g, 'InsecureSkipVerify: false').replace(/CURLOPT_SSL_VERIFYPEER\s*,\s*(?:false|0)/g, 'CURLOPT_SSL_VERIFYPEER, 1')
    return content === source ? undefined : { content, rationale: 'This proposal changes only an explicit TLS certificate-verification disablement to its enabled boolean value.' }
  }
  if (finding.ruleId === 'jwt.verification.disabled') {
    const content = source.replace(/(["']?verify_signature["']?\s*[:=]\s*)False/g, '$1True')
    return content === source ? undefined : { content, rationale: 'This proposal changes only an explicit JWT signature-verification disablement to enabled.' }
  }
  return undefined
}

function lineReplacement(source: string, replacement: RemediationReplacement): string | undefined {
  const lines = source.split(/\r?\n/); const start = replacement.startLine - 1; const end = replacement.endLine
  if (start < 0 || end < replacement.startLine || end > lines.length) return undefined
  const expected = lines.slice(start, end).join('\n')
  if (expected !== replacement.expectedText) return undefined
  return [...lines.slice(0, start), ...replacement.replacementText.split('\n'), ...lines.slice(end)].join('\n')
}

function patchFor(file: string, replacement: RemediationReplacement): string {
  return `--- a/${file}\n+++ b/${file}\n@@ lines ${replacement.startLine}-${replacement.endLine} @@\n${replacement.expectedText.split('\n').map(line => `- ${line}`).join('\n')}\n${replacement.replacementText.split('\n').map(line => `+ ${line}`).join('\n')}`
}

function proposalReplacements(proposal: RemediationProposal): RemediationReplacement[] {
  const values = proposal.replacements?.length ? proposal.replacements : proposal.replacement ? [proposal.replacement] : []
  return values.map(replacement => ({ ...replacement, file: replacement.file || proposal.file }))
}

function proposalFiles(proposal: RemediationProposal): RemediationFileSnapshot[] {
  return proposal.baseFiles?.length ? proposal.baseFiles : [{ file: proposal.file, sha256: proposal.baseFileSha256 }]
}

function rollbackFiles(rollback: RemediationRollback): RemediationRollbackFile[] {
  if (rollback.files?.length) return rollback.files
  return [{ file: rollback.file, sha256: rollback.beforeSha256, beforeContent: rollback.beforeContent, appliedSha256: rollback.appliedSha256 }]
}

function reviewedChanges(input: { changes?: Array<{ file: string; startLine: number; endLine: number; expectedText: string; replacementText: string }>; file?: string; startLine?: number; endLine?: number; expectedText?: string; replacementText?: string }): RemediationReplacement[] {
  const changes = input.changes?.length ? input.changes : input.file !== undefined && input.startLine !== undefined && input.endLine !== undefined && input.expectedText !== undefined && input.replacementText !== undefined ? [{ file: input.file, startLine: input.startLine, endLine: input.endLine, expectedText: input.expectedText, replacementText: input.replacementText }] : []
  if (!changes.length || changes.length > 20) throw new Error('A reviewed remediation requires one to twenty bounded source changes.')
  if (new Set(changes.map(change => change.file)).size !== changes.length) throw new Error('A reviewed remediation supports one bounded replacement per file; combine adjacent changes before proposing.')
  return changes.map(change => ({ file: change.file, startLine: change.startLine, endLine: change.endLine, expectedText: change.expectedText, replacementText: change.replacementText }))
}

function remediationVerification(scan: ScanRecord, original: Finding): RemediationVerification {
  const matching = scan.findings.filter(finding => finding.ruleId === original.ruleId && finding.locations.some(location => location.file === original.locations[0]?.file))
  return { scanId: scan.id, status: matching.length ? 'still_detected' : 'not_detected', ruleId: original.ruleId, file: original.locations[0]?.file ?? '', matchingFindingIds: matching.map(finding => finding.id), observedAt: new Date().toISOString(), limitation: 'This is a post-change native-analysis observation, not proof that all exploit paths, runtime configurations, or regressions are resolved. Run the proposal test plan and complete source-backed review.' }
}

/**
 * Persist a reviewed, bounded source replacement for a reportable finding.
 * This is deliberately not an arbitrary shell patch: application requires an
 * exact snapshot and exact original source region, then performs the existing
 * rollback and verification workflow.
 */
export async function proposeReviewedRemediation(workspace: string, config: Config, scanId: string, findingId: string, input: { changes?: Array<{ file: string; startLine: number; endLine: number; expectedText: string; replacementText: string }>; file?: string; startLine?: number; endLine?: number; expectedText?: string; replacementText?: string; rationale: string; testPlan: string }): Promise<RemediationProposal> {
  const state = getStateDir(config.stateDir); const scan = await loadScan(state, scanId); const finding = scan.findings.find(item => item.id === findingId)
  if (!finding) throw new Error('Finding was not found in this scan.')
  if (finding.disposition !== 'reportable' || finding.validationRecord?.conclusion !== 'reportable') throw new Error('A reviewed remediation proposal requires a reportable finding with a structured reportable validation receipt.')
  if (input.rationale.trim().length < 20 || input.testPlan.trim().length < 10) throw new Error('A reviewed remediation requires a substantive rationale and test plan.')
  const replacements = reviewedChanges(input); const findingFile = finding.locations[0]?.file
  if (!findingFile || !replacements.some(replacement => replacement.file === findingFile)) throw new Error('A reviewed remediation must include a bounded replacement in the reportable finding source file.')
  const receiptPaths = new Set(scan.coverage.receipts.map(receipt => receipt.path)); const root = resolve(workspace); const snapshots: RemediationFileSnapshot[] = []
  for (const replacement of replacements) {
    if (!Number.isInteger(replacement.startLine) || !Number.isInteger(replacement.endLine) || replacement.startLine < 1 || replacement.endLine < replacement.startLine || replacement.endLine - replacement.startLine > 199) throw new Error('Replacement ranges must be inclusive source ranges of at most 200 lines.')
    if (!receiptPaths.has(replacement.file)) throw new Error(`Reviewed remediation file is outside the immutable scan receipt set: ${replacement.file}`)
    if (!replacement.expectedText || replacement.expectedText.length > 100_000 || !replacement.replacementText || replacement.replacementText.length > 100_000 || replacement.expectedText.includes('\r') || replacement.replacementText.includes('\r')) throw new Error('Replacement text must be non-empty LF text within the bounded size limit.')
    const file = resolve(scan.target, replacement.file); if (!inside(root, file)) throw new Error('Reviewed remediation file is outside the active workspace.')
    const source = await readFile(file, 'utf8'); if (lineReplacement(source, replacement) === undefined) throw new Error(`The expected source text does not exactly match ${replacement.file}:${replacement.startLine}-${replacement.endLine}.`)
    snapshots.push({ file: replacement.file, sha256: sha256(source) })
  }
  const findingReplacement = replacements.find(replacement => replacement.file === findingFile)!; const proposal: RemediationProposal = { id: `rem_${randomUUID()}`, findingId, file: findingReplacement.file, line: findingReplacement.startLine, patch: replacements.map(replacement => patchFor(replacement.file, replacement)).join('\n'), baseSnapshotDigest: scan.targetSnapshot.snapshotDigest, baseFileSha256: snapshots.find(snapshot => snapshot.file === findingReplacement.file)!.sha256, baseFiles: snapshots, createdAt: new Date().toISOString(), status: 'proposed', requiresApproval: true, requiresReview: true, safeToApply: true, rationale: input.rationale.trim().slice(0, 20_000), testPlan: input.testPlan.trim().slice(0, 20_000), replacement: findingReplacement, replacements }
  await saveProposal(state, proposal); return proposal
}

export async function remediationPlan(workspace: string, config: Config, scanId: string, findingId: string): Promise<RemediationProposal> {
  const scan = await loadScan(getStateDir(config.stateDir), scanId); const finding = scan.findings.find(item => item.id === findingId)
  if (!finding) throw new Error('Finding was not found in this scan.')
  const location = finding.locations[0]; const file = resolve(scan.target, location.file); const root = resolve(workspace)
  if (!inside(root, file)) throw new Error('Finding location is outside the active workspace.')
  const before = await readFile(file, 'utf8'); const generated = replacementFor(finding, before); const replacement = generated && { file: location.file, startLine: 1, endLine: before.split(/\r?\n/).length, expectedText: before, replacementText: generated.content }
  const patch = replacement ? patchFor(location.file, replacement) : `No mechanically safe replacement is available for ${finding.ruleId}.\nReview ${location.file}:${location.line} and implement: ${finding.remediation}`
  const proposal: RemediationProposal = { id: `rem_${randomUUID()}`, findingId: finding.id, file: location.file, line: location.line, patch, baseSnapshotDigest: scan.targetSnapshot.snapshotDigest, baseFileSha256: sha256(before), baseFiles: [{ file: location.file, sha256: sha256(before) }], createdAt: new Date().toISOString(), status: 'proposed', requiresApproval: true, requiresReview: true, safeToApply: Boolean(replacement), rationale: generated?.rationale ?? 'The finding requires application-specific review; no semantics-preserving automatic replacement is available.', replacement, replacements: replacement ? [replacement] : undefined }
  await saveProposal(getStateDir(config.stateDir), proposal)
  await atomicWrite(join(getStateDir(config.stateDir), 'remediations', `${proposal.id}.json`), `${JSON.stringify(proposal, null, 2)}\n`)
  return proposal
}

export async function applyRemediationProposal(workspace: string, config: Config, scanId: string, remediationId: string, approved: boolean): Promise<RemediationProposal> {
  if (!approved) throw new Error('Applying a remediation changes source files. Set approved to true only after reviewing the exact proposal.')
  const scan = await loadScan(getStateDir(config.stateDir), scanId); const proposal = await loadRemediationProposal(getStateDir(config.stateDir), remediationId)
  if (proposal.findingId !== scan.findings.find(finding => finding.id === proposal.findingId)?.id) throw new Error('Remediation proposal does not belong to this scan.')
  if (proposal.status !== 'proposed') throw new Error(`Remediation is ${proposal.status} and cannot be applied.`)
  const root = resolve(workspace); const replacements = proposalReplacements(proposal); const snapshots = proposalFiles(proposal)
  if (!proposal.safeToApply || !replacements.length || replacements.length !== snapshots.length) throw new Error('No mechanically safe replacement is available for this proposal.')
  const [currentSnapshot, sources] = await Promise.all([snapshotDigestForDirectory(scan.target, config), Promise.all(snapshots.map(async snapshot => { const file = resolve(scan.target, snapshot.file); if (!inside(root, file)) throw new Error('Remediation target is outside the active workspace.'); return { snapshot, file, source: await readFile(file, 'utf8') } }))])
  if (currentSnapshot !== proposal.baseSnapshotDigest || sources.some(item => sha256(item.source) !== item.snapshot.sha256)) { proposal.status = 'stale'; await saveProposal(getStateDir(config.stateDir), proposal); throw new Error('Remediation proposal is stale because the target snapshot or a proposed file changed. Generate a new proposal.') }
  const finding = scan.findings.find(item => item.id === proposal.findingId); if (!finding) throw new Error('Finding was not found in this scan.')
  const changes = sources.map(item => { const replacement = replacements.find(value => value.file === item.snapshot.file); const content = replacement && lineReplacement(item.source, replacement); if (!content || content === item.source) throw new Error(`No mechanically safe replacement is available for ${item.snapshot.file}.`); return { ...item, content } })
  const written: typeof changes = []
  try { for (const change of changes) { await writeFile(change.file, change.content, 'utf8'); written.push(change) } } catch (error) { await Promise.all(written.map(change => writeFile(change.file, change.source, 'utf8'))); throw error }
  const appliedSnapshotDigest = await snapshotDigestForDirectory(scan.target, config); const rollbackFiles: RemediationRollbackFile[] = changes.map(change => ({ file: change.snapshot.file, sha256: sha256(change.source), beforeContent: change.source, appliedSha256: sha256(change.content) })); const primary = rollbackFiles.find(item => item.file === proposal.file)!; const rollback: RemediationRollback = { id: `rollback_${randomUUID()}`, remediationId: proposal.id, scanId, file: primary.file, beforeContent: primary.beforeContent, beforeSha256: primary.sha256, appliedSha256: primary.appliedSha256, files: rollbackFiles, appliedSnapshotDigest, createdAt: new Date().toISOString(), status: 'available' }
  await saveRollback(getStateDir(config.stateDir), rollback); proposal.status = 'applied'; proposal.appliedAt = new Date().toISOString(); proposal.rollbackId = rollback.id
  const verification = await runScan(scan.target, config, 'standard', scan.threatModel, scan.recipe.scopeRequested, config.stateDir, false)
  await persistInvestigationArtifacts(getStateDir(config.stateDir), verification); await saveScan(getStateDir(config.stateDir), verification); proposal.verificationScanId = verification.id; proposal.verification = remediationVerification(verification, finding); await saveProposal(getStateDir(config.stateDir), proposal)
  return proposal
}

/**
 * Run only scan-time preflight commands against an already-applied exact patch.
 * Command success is retained as repair evidence, never as an automatic finding
 * resolution or a substitute for an attacker-path revalidation.
 */
export async function runRemediationVerification(workspace: string, config: Config, scanId: string, remediationId: string, approved: boolean, timeoutMs = 120_000, signal?: AbortSignal): Promise<RemediationVerificationRun> {
  signal?.throwIfAborted()
  if (!approved) throw new Error('Running remediation verification can execute project test/build scripts. Set approved to true only after reviewing the scan-time commands.')
  const state = getStateDir(config.stateDir); const scan = await loadScan(state, scanId); const proposal = await loadRemediationProposal(state, remediationId)
  if (proposal.findingId !== scan.findings.find(finding => finding.id === proposal.findingId)?.id) throw new Error('Remediation proposal does not belong to this scan.')
  if (proposal.status !== 'applied' || !proposal.rollbackId) throw new Error('Only an applied remediation with an available rollback record can be verified.')
  const rollback = await loadRemediationRollback(state, proposal.rollbackId)
  if (rollback.status !== 'available' || rollback.remediationId !== proposal.id || rollback.scanId !== scanId) throw new Error('The applied remediation rollback record is unavailable.')
  const root = resolve(workspace); for (const item of rollbackFiles(rollback)) if (!inside(root, resolve(scan.target, item.file))) throw new Error('Remediation target is outside the active workspace.')
  const commands = [...new Set(scan.preflight.suggestedCommands.map(command => safeCommand(command)))].map(command => ({ command, reason: `Suggested by source scan ${scan.id} preflight for ${scan.preflight.projectFiles.join(', ')}.` }))
  if (!commands.length) throw new Error('No bounded remediation verification command is available from the source scan preflight.')
  const [snapshotDigest, sources] = await Promise.all([snapshotDigestForDirectory(scan.target, config), Promise.all(rollbackFiles(rollback).map(async item => ({ item, source: await readFile(resolve(scan.target, item.file), 'utf8') })))])
  if (snapshotDigest !== rollback.appliedSnapshotDigest || sources.some(source => sha256(source.source) !== source.item.appliedSha256)) throw new Error('Applied remediation changed since application. Create a follow-up scan before verification.')
  const receipts = await executeValidationCommands(scan.target, commands.map(item => item.command), timeoutMs, snapshotDigest, signal)
  const after = await snapshotDigestForDirectory(scan.target, config)
  if (after !== snapshotDigest) throw new Error('Target changed during remediation verification; receipts were not attached.')
  const id = `remverify_${randomUUID()}`; const artifactRef = join(state, 'remediation-verification', `${id}.json`)
  const run: RemediationVerificationRun = { id, remediationId: proposal.id, sourceScanId: scan.id, snapshotDigest, commands, receipts, outcome: receipts.every(receipt => !receipt.timedOut && receipt.exitCode === 0) ? 'passed' : 'failed', executedAt: new Date().toISOString(), artifactRef, limitation: 'These isolated project-check receipts do not prove that the original attacker path is closed, that production configuration is safe, or that the original finding is resolved. Revalidate the source-to-sink path and preserved behavior separately.' }
  await atomicWrite(artifactRef, `${JSON.stringify(run, null, 2)}\n`)
  proposal.postApplyVerification = run; await saveProposal(state, proposal)
  return run
}

/** Restore one proposal's exact pre-application content only when its applied state remains intact. */
export async function rollbackRemediationProposal(workspace: string, config: Config, scanId: string, remediationId: string, approved: boolean): Promise<RemediationRollback> {
  if (!approved) throw new Error('Rolling back a remediation changes source files. Set approved to true only after reviewing the rollback record.')
  const state = getStateDir(config.stateDir); const scan = await loadScan(state, scanId); const proposal = await loadRemediationProposal(state, remediationId)
  if (proposal.status !== 'applied' || !proposal.rollbackId) throw new Error('Only an applied remediation with an available rollback record can be rolled back.')
  const rollback = await loadRemediationRollback(state, proposal.rollbackId); if (rollback.remediationId !== proposal.id || rollback.scanId !== scanId || rollback.status !== 'available') throw new Error('Rollback record is unavailable or does not belong to this remediation.')
  const root = resolve(workspace); const files = rollbackFiles(rollback); const [snapshot, sources] = await Promise.all([snapshotDigestForDirectory(scan.target, config), Promise.all(files.map(async item => { const file = resolve(scan.target, item.file); if (!inside(root, file)) throw new Error('Rollback target is outside the active workspace.'); return { item, file, source: await readFile(file, 'utf8') } }))])
  if (snapshot !== rollback.appliedSnapshotDigest || sources.some(source => sha256(source.source) !== source.item.appliedSha256)) { rollback.status = 'stale'; await saveRollback(state, rollback); throw new Error('Rollback record is stale because an applied file or target snapshot changed.') }
  const restored: typeof sources = []
  try { for (const source of sources) { await writeFile(source.file, source.item.beforeContent, 'utf8'); restored.push(source) } } catch (error) { await Promise.all(restored.map(source => writeFile(source.file, source.source, 'utf8'))); throw error }
  rollback.status = 'rolled_back'; rollback.rolledBackAt = new Date().toISOString()
  const verification = await runScan(scan.target, config, 'standard', scan.threatModel, scan.recipe.scopeRequested, config.stateDir, false); await persistInvestigationArtifacts(state, verification); await saveScan(state, verification); rollback.verificationScanId = verification.id; proposal.status = 'rolled_back'; await saveRollback(state, rollback); await saveProposal(state, proposal)
  return rollback
}
