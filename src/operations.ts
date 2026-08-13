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
import { finalizeAndSaveScan, getStateDir, loadScan, saveScan, sha256, writeArtifact } from './state.js'

const execFileAsync = promisify(execFile)
const MAX_COMMAND_OUTPUT = 256_000
const VALIDATION_COMMAND = /^[A-Za-z0-9_./:@=+%, -]+$/

export interface CommandReceipt { id: string; command: string; cwd: string; exitCode?: number; timedOut: boolean; durationMs: number; stdout: string; stderr: string; snapshotDigest: string; artifactRef?: string }
export interface RemediationProposal { id: string; findingId: string; file: string; line: number; patch: string; baseSnapshotDigest: string; baseFileSha256: string; createdAt: string; status: 'proposed' | 'applied' | 'stale' | 'superseded'; requiresApproval: true; requiresReview: true; appliedAt?: string; verificationScanId?: string }

export interface BulkResult { path: string; scanId?: string; findings?: number; error?: string }

function inside(root: string, target: string): boolean { const rel = relative(root, target); return rel === '' || (!rel.startsWith('..') && !isAbsolute(rel)) }
function safeCommand(command: string): string { const value = command.trim(); if (!value || value.length > 500 || !VALIDATION_COMMAND.test(value)) throw new Error('Validation command contains unsupported shell syntax. Use a simple executable and arguments only.'); return value }
function splitCommand(command: string): string[] { return safeCommand(command).split(/\s+/).filter(Boolean) }
function digest(value: string): string { return createHash('sha256').update(value).digest('hex') }
function proposalPath(stateDir: string, id: string): string { if (!/^rem_[0-9a-f-]+$/.test(id)) throw new Error('Invalid remediation id.'); return join(stateDir, 'remediations', `${id}.json`) }
async function atomicWrite(path: string, content: string): Promise<void> { const temporary = `${path}.${randomUUID()}.tmp`; await mkdir(resolve(path, '..'), { recursive: true }); await writeFile(temporary, content, 'utf8'); await rename(temporary, path) }
async function saveProposal(stateDir: string, proposal: RemediationProposal): Promise<void> { await atomicWrite(proposalPath(stateDir, proposal.id), `${JSON.stringify(proposal, null, 2)}\n`) }
export async function loadRemediationProposal(stateDir: string, id: string): Promise<RemediationProposal> { return JSON.parse(await readFile(proposalPath(stateDir, id), 'utf8')) as RemediationProposal }

export async function runIsolatedValidation(workspace: string, config: Config, scanId: string, command: string, timeoutMs = 120_000): Promise<CommandReceipt> {
  const scan = await loadScan(getStateDir(config.stateDir), scanId); const root = resolve(workspace); const target = resolve(scan.target)
  if (!inside(root, target)) throw new Error('Saved scan target is outside the active workspace.')
  const args = splitCommand(command); const timeout = Math.max(1_000, Math.min(timeoutMs, 600_000)); const copyRoot = await mkdtemp(join(tmpdir(), 'dsh-security-suite-validation-'))
  const copyTarget = join(copyRoot, 'target')
  const started = Date.now(); let stdout = ''; let stderr = ''; let exitCode: number | undefined; let timedOut = false
  try {
    await cp(target, copyTarget, { recursive: true, dereference: false, filter: source => !source.split(sep).some(part => ['.git', 'node_modules', 'dist', 'build', 'coverage'].includes(part)) })
    try { const result = await execFileAsync(args[0], args.slice(1), { cwd: copyTarget, timeout, maxBuffer: MAX_COMMAND_OUTPUT, encoding: 'utf8', windowsHide: true }); stdout = result.stdout; stderr = result.stderr; exitCode = 0 } catch (error: unknown) { const value = error as { stdout?: string; stderr?: string; code?: number | string; killed?: boolean }; stdout = value.stdout ?? ''; stderr = value.stderr ?? ''; exitCode = typeof value.code === 'number' ? value.code : undefined; timedOut = Boolean(value.killed) }
    const receipt: CommandReceipt = { id: `cmd_${randomUUID()}`, command: args.join(' '), cwd: '.', exitCode, timedOut, durationMs: Date.now() - started, stdout: stdout.slice(0, MAX_COMMAND_OUTPUT), stderr: stderr.slice(0, MAX_COMMAND_OUTPUT), snapshotDigest: await snapshotDigestForDirectory(target, config) }
    receipt.artifactRef = await writeArtifact(scan, `artifacts/05_findings/validation_artifacts/${receipt.id}.json`, `${JSON.stringify(receipt, null, 2)}\n`)
    return receipt
  } finally { await rm(copyRoot, { recursive: true, force: true }) }
}

export async function rerunSavedScan(workspace: string, config: Config, scanId: string): Promise<ScanRecord> {
  const previous = await loadScan(getStateDir(config.stateDir), scanId)
  if (previous.mode === 'diff') throw new Error('Diff scans must be rerun with security_review_diff so the requested base can be supplied explicitly.')
  const root = resolve(workspace); const target = resolve(previous.target)
  if (!inside(root, target)) throw new Error('Saved scan target is outside the active workspace.')
  const scan = await runScan(target, config, previous.mode, previous.threatModel, previous.recipe.scopeRequested, config.stateDir)
  await finalizeAndSaveScan(getStateDir(config.stateDir), scan)
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
      try { const scan = await runScan(resolveSafeTarget(workspace, item), config, mode, threatModel, true, config.stateDir); await finalizeAndSaveScan(getStateDir(config.stateDir), scan); output[index] = { path: item, scanId: scan.id, findings: scan.findings.filter(finding => finding.disposition === 'reportable').length } } catch (error) { output[index] = { path: item, error: error instanceof Error ? error.message : String(error) } }
    }
  }
  await Promise.all(Array.from({ length: Math.min(capped, unique.length) }, worker)); return output
}

export async function installPreCommitHook(workspace: string, approved: boolean): Promise<{ installed: boolean; path: string; reason?: string }> {
  if (!approved) throw new Error('Installing a Git hook changes the repository. Set approved to true only after the hook content has been reviewed.')
  const root = resolve(workspace); const hookDirectory = join(root, '.git', 'hooks'); const hookPath = join(hookDirectory, 'pre-commit')
  try { await access(hookPath, constants.F_OK); return { installed: false, path: hookPath, reason: 'An existing pre-commit hook was preserved.' } } catch { /* absent is expected */ }
  await mkdir(hookDirectory, { recursive: true })
  const content = `#!/bin/sh\n# Installed by dsh-security-suite. Run DSH security review before committing.\n# This hook intentionally does not modify files or send data off-machine.\nif command -v dsh >/dev/null 2>&1; then\n  dsh run "Review the current Git diff for security findings using security_review_diff. Report high-confidence issues only." || exit $?\nfi\n`
  await writeFile(hookPath, content, { encoding: 'utf8', mode: 0o755 })
  return { installed: true, path: hookPath }
}

function replacementFor(finding: Finding, source: string): string | undefined {
  if (finding.ruleId === 'tls.verification.disabled') return source.replace(/rejectUnauthorized\s*:\s*false/, 'rejectUnauthorized: true').replace(/verify\s*=\s*False/, 'verify = True').replace(/InsecureSkipVerify\s*:\s*true/, 'InsecureSkipVerify: false')
  if (finding.ruleId === 'dangerous.dynamic.code') return source.replace(/\beval\s*\(([^)]*)\)/, '/* Replace dynamic evaluation with a fixed operation over validated input: $1 */')
  if (finding.ruleId === 'hardcoded.secret.marker') return source.replace(/((?:api[_-]?key|secret|password|token|private[_-]?key)\s*[:=]\s*)["'][^"']+["']/i, '$1process.env.APP_SECRET')
  return undefined
}

export async function remediationPlan(workspace: string, config: Config, scanId: string, findingId: string): Promise<RemediationProposal> {
  const scan = await loadScan(getStateDir(config.stateDir), scanId); const finding = scan.findings.find(item => item.id === findingId)
  if (!finding) throw new Error('Finding was not found in this scan.')
  const location = finding.locations[0]; const file = resolve(scan.target, location.file); const root = resolve(workspace)
  if (!inside(root, file)) throw new Error('Finding location is outside the active workspace.')
  const before = await readFile(file, 'utf8'); const after = replacementFor(finding, before)
  const patch = after && after !== before ? `--- a/${location.file}\n+++ b/${location.file}\n@@ line ${location.line} @@\n- ${location.excerpt}\n+ ${after.split(/\r?\n/)[location.line - 1]?.trim() ?? '<review replacement>'}` : `No mechanically safe replacement is available for ${finding.ruleId}.\nReview ${location.file}:${location.line} and implement: ${finding.remediation}`
  const proposal: RemediationProposal = { id: `rem_${randomUUID()}`, findingId: finding.id, file: location.file, line: location.line, patch, baseSnapshotDigest: scan.targetSnapshot.snapshotDigest, baseFileSha256: sha256(before), createdAt: new Date().toISOString(), status: 'proposed', requiresApproval: true, requiresReview: true }
  await saveProposal(getStateDir(config.stateDir), proposal)
  await writeArtifact(scan, `artifacts/06_remediation/${proposal.id}.json`, `${JSON.stringify(proposal, null, 2)}\n`)
  return proposal
}

export async function applyRemediationProposal(workspace: string, config: Config, scanId: string, remediationId: string, approved: boolean): Promise<RemediationProposal> {
  if (!approved) throw new Error('Applying a remediation changes source files. Set approved to true only after reviewing the exact proposal.')
  const scan = await loadScan(getStateDir(config.stateDir), scanId); const proposal = await loadRemediationProposal(getStateDir(config.stateDir), remediationId)
  if (proposal.findingId !== scan.findings.find(finding => finding.id === proposal.findingId)?.id) throw new Error('Remediation proposal does not belong to this scan.')
  if (proposal.status !== 'proposed') throw new Error(`Remediation is ${proposal.status} and cannot be applied.`)
  const root = resolve(workspace); const file = resolve(scan.target, proposal.file); if (!inside(root, file)) throw new Error('Remediation target is outside the active workspace.')
  const [current, currentSnapshot] = await Promise.all([readFile(file, 'utf8'), snapshotDigestForDirectory(scan.target, config)])
  if (sha256(current) !== proposal.baseFileSha256 || currentSnapshot !== proposal.baseSnapshotDigest) { proposal.status = 'stale'; await saveProposal(getStateDir(config.stateDir), proposal); throw new Error('Remediation proposal is stale because the target snapshot or file changed. Generate a new proposal.') }
  const finding = scan.findings.find(item => item.id === proposal.findingId); if (!finding) throw new Error('Finding was not found in this scan.')
  const after = replacementFor(finding, current); if (!after || after === current) throw new Error('No mechanically safe replacement is available for this proposal.')
  await writeFile(file, after, 'utf8'); proposal.status = 'applied'; proposal.appliedAt = new Date().toISOString()
  const verification = await runScan(scan.target, config, 'standard', scan.threatModel, scan.recipe.scopeRequested, config.stateDir)
  await finalizeAndSaveScan(getStateDir(config.stateDir), verification); proposal.verificationScanId = verification.id; await saveProposal(getStateDir(config.stateDir), proposal)
  return proposal
}
