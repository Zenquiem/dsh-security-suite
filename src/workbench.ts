import type { AttackPathRecord, CandidateDisposition, Finding, ScanRecord, ValidationRecord } from './contracts.js'
import { finalizeAndSaveScan, getStateDir, loadScan, persistInvestigationArtifacts, saveScan } from './state.js'
import { randomUUID } from 'node:crypto'
import type { Config } from './config.js'

export interface ValidationInput {
  conclusion: CandidateDisposition
  method: 'static' | 'test' | 'runtime' | 'hybrid'
  attacker: string
  entryPoint: string
  trustBoundary: string
  rootControl: string
  sink: string
  impact: string
  directEvidence: string
  counterevidence: string
  limitations: string
  confidence: 'high' | 'medium' | 'low'
}

export interface AttackPathInput {
  attacker: string
  entryPoint: string
  preconditions: string
  dataflow: string
  outcome: string
  severityRationale: string
  changeConditions: string
}

function requireReportable(value: CandidateDisposition): asserts value is 'reportable' { if (value !== 'reportable') throw new Error('Attack-path analysis is only allowed for a reportable validated candidate.') }
function candidate(scan: ScanRecord, candidateId: string): Finding { const value = scan.findings.find(item => item.candidateId === candidateId); if (!value) throw new Error('Candidate was not found in this scan.'); return value }
function required(value: string, label: string): string { const text = value.trim(); if (!text) throw new Error(`${label} is required.`); return text }

function releaseExpiredClaims(scan: ScanRecord): number { const now = Date.now(); let released = 0; for (const task of scan.tasks) if (task.status === 'claimed' && task.claim && Date.parse(task.claim.expiresAt) <= now) { task.status = 'pending'; task.claim = undefined; released++ } return released }

export async function claimAuditTask(config: Config, scanId: string, owner: string, phase?: 'validation' | 'attack_path', leaseMs = 30 * 60_000): Promise<{ taskId: string; candidateId: string; phase: 'validation' | 'attack_path'; focus: string; claimToken: string; artifactRef: string } | null> {
  const state = getStateDir(config.stateDir); const scan = await loadScan(state, scanId)
  const released = releaseExpiredClaims(scan)
  const task = scan.tasks.find(item => item.status === 'pending' && (phase === undefined || item.phase === phase))
  if (!task) { if (released) { await persistInvestigationArtifacts(state, scan); await saveScan(state, scan) }; return null }
  const claimToken = randomUUID(); const claimedAt = new Date(); task.status = 'claimed'; task.claim = { owner: required(owner, 'owner'), token: claimToken, claimedAt: claimedAt.toISOString(), expiresAt: new Date(claimedAt.getTime() + Math.max(60_000, Math.min(leaseMs, 4 * 60 * 60_000))).toISOString() }; await persistInvestigationArtifacts(state, scan); await saveScan(state, scan)
  return { taskId: task.id, candidateId: task.candidateId, phase: task.phase, focus: task.focus, claimToken, artifactRef: `artifacts/04_reconciliation/tasks/${task.id}.md` }
}

export async function cancelInvestigation(config: Config, scanId: string, reason: string): Promise<ScanRecord> {
  const state = getStateDir(config.stateDir); const scan = await loadScan(state, scanId); if (scan.lifecycle === 'completed') throw new Error('Completed scans are immutable.')
  const message = required(reason, 'reason'); for (const task of scan.tasks) if (task.status === 'pending' || task.status === 'claimed') { task.status = 'cancelled'; task.receipt = `cancelled: ${message}` }
  scan.lifecycle = 'cancelled'; scan.activity.push({ at: new Date().toISOString(), phase: 'reporting', message: `Investigation cancelled: ${message}` }); await persistInvestigationArtifacts(state, scan); await saveScan(state, scan); return scan
}

export async function resumeInvestigation(config: Config, scanId: string): Promise<ScanRecord> {
  const state = getStateDir(config.stateDir); const scan = await loadScan(state, scanId); if (scan.lifecycle !== 'cancelled') throw new Error('Only cancelled investigations can be resumed.')
  for (const task of scan.tasks) if (task.status === 'cancelled' && !scan.findings.find(finding => finding.candidateId === task.candidateId)?.ledger.some(row => row.phase === task.phase)) { task.status = 'pending'; task.receipt = undefined }
  scan.lifecycle = 'validation'; scan.activity.push({ at: new Date().toISOString(), phase: 'validation', message: 'Investigation resumed; unfinished tasks were returned to the pending queue.' }); await persistInvestigationArtifacts(state, scan); await saveScan(state, scan); return scan
}

function completeTask(scan: ScanRecord, candidateId: string, phase: 'validation' | 'attack_path', token?: string): void {
  const task = scan.tasks.find(item => item.candidateId === candidateId && item.phase === phase && item.status === 'claimed')
  if (!task) return
  if (!token || task.claim?.token !== token) throw new Error('Task claim token does not own this audit task.')
  task.status = 'completed'; task.completedAt = new Date().toISOString(); task.receipt = phase
}

export async function pendingCandidates(config: Config, scanId: string): Promise<Array<{ candidateId: string; title: string; disposition: CandidateDisposition; stages: string[] }>> {
  const scan = await loadScan(getStateDir(config.stateDir), scanId)
  return scan.findings.filter(finding => !finding.ledger.some(row => row.phase === 'validation')).map(finding => ({ candidateId: finding.candidateId, title: finding.title, disposition: finding.disposition, stages: finding.ledger.map(row => row.phase) }))
}

export async function recordValidation(config: Config, scanId: string, candidateId: string, input: ValidationInput, claimToken?: string): Promise<ScanRecord> {
  const state = getStateDir(config.stateDir); const scan = await loadScan(state, scanId); if (scan.lifecycle === 'completed') throw new Error('Completed scans are immutable. Create a follow-up scan for new validation evidence.')
  const finding = candidate(scan, candidateId)
  for (const [label, value] of Object.entries(input)) required(String(value), label)
  if (!['reportable', 'suppressed', 'deferred', 'not_applicable'].includes(input.conclusion)) throw new Error('Validation conclusion is invalid.')
  const record: ValidationRecord = { ...input, conclusion: input.conclusion as ValidationRecord['conclusion'], recordedAt: new Date().toISOString() }
  finding.validationRecord = record; finding.disposition = input.conclusion; finding.confidence = input.confidence; finding.validation = `${input.method} validation: ${input.directEvidence}`; finding.impact = input.impact; finding.counterevidence = input.counterevidence; finding.evidence.push({ kind: input.method === 'runtime' ? 'runtime' : input.method === 'test' ? 'test' : 'validation', detail: input.directEvidence, location: finding.locations[0] }); finding.ledger.push({ at: new Date().toISOString(), phase: 'validation', disposition: input.conclusion, summary: finding.validation })
  completeTask(scan, candidateId, 'validation', claimToken)
  if (input.conclusion === 'reportable') scan.tasks.push({ id: `task_${randomUUID()}`, candidateId, phase: 'attack_path', focus: `Trace the attacker-to-outcome path for ${finding.title} and calibrate severity from evidence.`, status: 'pending' })
  scan.lifecycle = input.conclusion === 'reportable' ? 'attack_path' : 'validation'; await persistInvestigationArtifacts(state, scan); await saveScan(state, scan); return scan
}

export async function recordAttackPath(config: Config, scanId: string, candidateId: string, input: AttackPathInput, claimToken?: string): Promise<ScanRecord> {
  const state = getStateDir(config.stateDir); const scan = await loadScan(state, scanId); if (scan.lifecycle === 'completed') throw new Error('Completed scans are immutable. Create a follow-up scan for new attack-path evidence.')
  const finding = candidate(scan, candidateId); requireReportable(finding.disposition)
  for (const [label, value] of Object.entries(input)) required(value, label)
  const record: AttackPathRecord = { ...input, recordedAt: new Date().toISOString() }; finding.attackPathRecord = record; finding.attackPath = `${input.dataflow}\n\nAttacker: ${input.attacker}\nOutcome: ${input.outcome}`; finding.ledger.push({ at: new Date().toISOString(), phase: 'attack_path', disposition: 'reportable', summary: input.dataflow }); finding.evidence.push({ kind: 'attack_path', detail: input.dataflow, location: finding.locations[0] }); completeTask(scan, candidateId, 'attack_path', claimToken); scan.lifecycle = 'reporting'; await persistInvestigationArtifacts(state, scan); await saveScan(state, scan); return scan
}

export async function completeScan(config: Config, scanId: string): Promise<ScanRecord> {
  const state = getStateDir(config.stateDir); const scan = await loadScan(state, scanId); if (scan.lifecycle === 'completed') return scan
  const missing = scan.findings.filter(finding => !finding.ledger.some(row => row.phase === 'validation') || (finding.disposition === 'reportable' && !finding.ledger.some(row => row.phase === 'attack_path')))
  if (missing.length) throw new Error(`Cannot finalize while candidate receipts are incomplete: ${missing.map(item => item.candidateId).join(', ')}`)
  const activeTasks = scan.tasks.filter(task => task.status === 'pending' || task.status === 'claimed'); if (activeTasks.length) throw new Error(`Cannot finalize while audit tasks remain: ${activeTasks.map(task => task.id).join(', ')}`)
  scan.lifecycle = scan.coverage.complete ? 'completed' : 'incomplete'; scan.completedAt = new Date().toISOString(); scan.activity.push({ at: scan.completedAt, phase: 'reporting', message: 'Canonical scan bundle finalized after all candidate ledgers closed.' }); await finalizeAndSaveScan(state, scan); return scan
}
