import type { AttackPathRecord, CandidateDisposition, EvidenceKind, Finding, Location, LocationRole, ReceiptSourceReference, ScanRecord, ValidationRecord } from './contracts.js'
import { finalizeAndSaveScan, getStateDir, loadScan, persistInvestigationArtifacts, saveScan } from './state.js'
import { randomUUID } from 'node:crypto'
import type { Config } from './config.js'

const scanWrites = new Map<string, Promise<void>>()

/** Serialize state transitions made by concurrent DSH closure workers for one scan. */
async function updateScan<T>(config: Config, scanId: string, update: (scan: ScanRecord) => Promise<T> | T): Promise<T> {
  const previous = scanWrites.get(scanId) ?? Promise.resolve()
  let release!: () => void
  const barrier = new Promise<void>(resolveBarrier => { release = resolveBarrier })
  const chained = previous.then(() => barrier)
  scanWrites.set(scanId, chained)
  await previous
  try {
    const state = getStateDir(config.stateDir)
    const scan = await loadScan(state, scanId)
    const value = await update(scan)
    await persistInvestigationArtifacts(state, scan)
    await saveScan(state, scan)
    return value
  } finally {
    release()
    if (scanWrites.get(scanId) === chained) scanWrites.delete(scanId)
  }
}

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
  sourceReferences: ReceiptSourceReference[]
  runtimeReceiptRefs?: string[]
}

export interface AttackPathInput {
  attacker: string
  entryPoint: string
  preconditions: string
  dataflow: string
  outcome: string
  severityRationale: string
  changeConditions: string
  sourceReferences: ReceiptSourceReference[]
}

function requireReportable(value: CandidateDisposition): asserts value is 'reportable' { if (value !== 'reportable') throw new Error('Attack-path analysis is only allowed for a reportable validated candidate.') }
function candidate(scan: ScanRecord, candidateId: string): Finding { const value = scan.findings.find(item => item.candidateId === candidateId); if (!value) throw new Error('Candidate was not found in this scan.'); return value }
function required(value: string, label: string): string { const text = value.trim(); if (!text) throw new Error(`${label} is required.`); return text }

function locationRole(location: Location): LocationRole { return location.role ?? 'root_control' }

/** Resolve receipt citations only against the scan's frozen, finding-local source locations. */
function resolveSourceReferences(finding: Finding, references: ReceiptSourceReference[]): Location[] {
  if (!Array.isArray(references) || references.length === 0) throw new Error('At least one source reference is required.')
  const seen = new Set<string>(); const resolved: Location[] = []
  for (const reference of references) {
    if (!reference || typeof reference.file !== 'string' || !reference.file.trim() || !Number.isInteger(reference.line) || reference.line < 1 || !['entrypoint', 'wrapper', 'propagation', 'root_control', 'sink', 'outcome', 'expected_control'].includes(reference.role)) throw new Error('Each source reference requires a snapshot file, positive line, and recognized role.')
    const key = `${reference.file}:${reference.line}:${reference.role}`
    if (seen.has(key)) throw new Error(`Duplicate source reference: ${key}.`)
    const location = finding.locations.find(item => item.file === reference.file && item.line === reference.line && locationRole(item) === reference.role)
    if (!location) throw new Error(`Source reference is not a retained location in this finding snapshot: ${key}.`)
    seen.add(key); resolved.push(location)
  }
  return resolved
}

function requireReportableValidationReferences(references: Location[]): void {
  if (!references.some(reference => locationRole(reference) === 'root_control' || locationRole(reference) === 'sink')) throw new Error('A reportable validation requires a cited root_control or sink source reference.')
}

function requireAttackPathEndpointReferences(finding: Finding, references: Location[]): void {
  const roles = new Set(finding.locations.map(locationRole))
  if (roles.has('entrypoint') && roles.has('sink')) {
    const cited = new Set(references.map(locationRole))
    if (!cited.has('entrypoint') || !cited.has('sink')) throw new Error('An attack path with retained entrypoint and sink locations must cite both endpoint roles.')
  }
}

function resolveRuntimeReceiptRefs(finding: Finding, method: ValidationInput['method'], references: string[] | undefined): string[] | undefined {
  const values = [...new Set((references ?? []).map(value => value.trim()))]
  if (values.some(value => !value || value.length > 1_000)) throw new Error('Each runtime receipt reference must be a bounded artifact path.')
  if (method !== 'runtime' && method !== 'hybrid') {
    if (values.length) throw new Error('Runtime receipt references are only valid for runtime or hybrid validation.')
    return undefined
  }
  if (!values.length) throw new Error('Runtime or hybrid validation requires at least one candidate-bound runtime receipt reference.')
  const available = new Set(finding.evidence.filter(item => item.kind === 'runtime' && item.artifactRef).map(item => item.artifactRef!))
  if (values.some(value => !available.has(value))) throw new Error('Runtime receipt reference is not retained runtime evidence for this candidate.')
  return values.sort()
}

function releaseExpiredClaims(scan: ScanRecord): number { const now = Date.now(); let released = 0; for (const task of scan.tasks) if (task.status === 'claimed' && task.claim && Date.parse(task.claim.expiresAt) <= now) { task.status = 'pending'; task.claim = undefined; released++ } return released }

export async function claimAuditTask(config: Config, scanId: string, owner: string, phase?: 'validation' | 'attack_path', leaseMs = 30 * 60_000): Promise<{ taskId: string; candidateId: string; phase: 'validation' | 'attack_path'; focus: string; claimToken: string; artifactRef: string } | null> {
  return updateScan(config, scanId, scan => {
    releaseExpiredClaims(scan)
    const task = scan.tasks.find(item => item.status === 'pending' && (phase === undefined || item.phase === phase))
    if (!task) return null
    const claimToken = randomUUID(); const claimedAt = new Date(); task.status = 'claimed'; task.claim = { owner: required(owner, 'owner'), token: claimToken, claimedAt: claimedAt.toISOString(), expiresAt: new Date(claimedAt.getTime() + Math.max(60_000, Math.min(leaseMs, 4 * 60 * 60_000))).toISOString() }
    return { taskId: task.id, candidateId: task.candidateId, phase: task.phase, focus: task.focus, claimToken, artifactRef: `artifacts/04_reconciliation/tasks/${task.id}.md` }
  })
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

function requireTaskClaim(scan: ScanRecord, candidateId: string, phase: 'validation' | 'attack_path', token?: string): void {
  const task = scan.tasks.find(item => item.candidateId === candidateId && item.phase === phase)
  if (!task || task.status !== 'claimed' || !task.claim) throw new Error(`A ${phase} receipt requires an active claimed audit task.`)
  if (!token || task.claim.token !== token) throw new Error('Task claim token does not own this audit task.')
}

function completeTask(scan: ScanRecord, candidateId: string, phase: 'validation' | 'attack_path', token?: string): void {
  requireTaskClaim(scan, candidateId, phase, token)
  const task = scan.tasks.find(item => item.candidateId === candidateId && item.phase === phase && item.status === 'claimed')!
  task.status = 'completed'; task.completedAt = new Date().toISOString(); task.receipt = phase
}

export async function pendingCandidates(config: Config, scanId: string): Promise<Array<{ candidateId: string; title: string; disposition: CandidateDisposition; stages: string[] }>> {
  const scan = await loadScan(getStateDir(config.stateDir), scanId)
  return scan.findings.filter(finding => !finding.ledger.some(row => row.phase === 'validation')).map(finding => ({ candidateId: finding.candidateId, title: finding.title, disposition: finding.disposition, stages: finding.ledger.map(row => row.phase) }))
}

export async function recordValidation(config: Config, scanId: string, candidateId: string, input: ValidationInput, claimToken?: string): Promise<ScanRecord> {
  return updateScan(config, scanId, scan => {
    if (scan.lifecycle === 'completed') throw new Error('Completed scans are immutable. Create a follow-up scan for new validation evidence.')
    const finding = candidate(scan, candidateId)
    requireTaskClaim(scan, candidateId, 'validation', claimToken)
    for (const [label, value] of Object.entries(input)) if (label !== 'sourceReferences') required(String(value), label)
    if (!['reportable', 'suppressed', 'deferred', 'not_applicable'].includes(input.conclusion)) throw new Error('Validation conclusion is invalid.')
    const citedLocations = resolveSourceReferences(finding, input.sourceReferences)
    if (input.conclusion === 'reportable') requireReportableValidationReferences(citedLocations)
    const runtimeReceiptRefs = resolveRuntimeReceiptRefs(finding, input.method, input.runtimeReceiptRefs)
    const record: ValidationRecord = { ...input, ...(runtimeReceiptRefs ? { runtimeReceiptRefs } : {}), conclusion: input.conclusion as ValidationRecord['conclusion'], recordedAt: new Date().toISOString() }
    const evidenceKind: EvidenceKind = input.method === 'runtime' ? 'runtime' : input.method === 'test' ? 'test' : 'validation'
    finding.validationRecord = record; finding.disposition = input.conclusion; finding.confidence = input.confidence; finding.validation = `${input.method} validation: ${input.directEvidence}`; finding.impact = input.impact; finding.counterevidence = input.counterevidence; finding.evidence.push(...citedLocations.map((location, index) => ({ kind: evidenceKind, detail: `${input.directEvidence} [receipt citation ${index + 1}/${citedLocations.length}]`, location }))); finding.ledger.push({ at: new Date().toISOString(), phase: 'validation', disposition: input.conclusion, summary: finding.validation })
    completeTask(scan, candidateId, 'validation', claimToken)
    if (input.conclusion === 'reportable') scan.tasks.push({ id: `task_${randomUUID()}`, candidateId, phase: 'attack_path', focus: `Trace the attacker-to-outcome path for ${finding.title} and calibrate severity from evidence.`, status: 'pending' })
    scan.lifecycle = input.conclusion === 'reportable' ? 'attack_path' : 'validation'
    return scan
  })
}

export async function recordAttackPath(config: Config, scanId: string, candidateId: string, input: AttackPathInput, claimToken?: string): Promise<ScanRecord> {
  return updateScan(config, scanId, scan => {
    if (scan.lifecycle === 'completed') throw new Error('Completed scans are immutable. Create a follow-up scan for new attack-path evidence.')
    const finding = candidate(scan, candidateId); requireReportable(finding.disposition)
    requireTaskClaim(scan, candidateId, 'attack_path', claimToken)
    for (const [label, value] of Object.entries(input)) if (label !== 'sourceReferences') required(value as string, label)
    const citedLocations = resolveSourceReferences(finding, input.sourceReferences); requireAttackPathEndpointReferences(finding, citedLocations)
    const record: AttackPathRecord = { ...input, recordedAt: new Date().toISOString() }; finding.attackPathRecord = record; finding.attackPath = `${input.dataflow}\n\nAttacker: ${input.attacker}\nOutcome: ${input.outcome}`; finding.ledger.push({ at: new Date().toISOString(), phase: 'attack_path', disposition: 'reportable', summary: input.dataflow }); finding.evidence.push(...citedLocations.map((location, index) => ({ kind: 'attack_path' as const, detail: `${input.dataflow} [receipt citation ${index + 1}/${citedLocations.length}]`, location }))); completeTask(scan, candidateId, 'attack_path', claimToken); scan.lifecycle = 'reporting'
    return scan
  })
}

export async function completeScan(config: Config, scanId: string): Promise<ScanRecord> {
  const state = getStateDir(config.stateDir); const scan = await loadScan(state, scanId); if (scan.lifecycle === 'completed') return scan
  const missing = scan.findings.filter(finding => !finding.ledger.some(row => row.phase === 'validation') || (finding.disposition === 'reportable' && !finding.ledger.some(row => row.phase === 'attack_path')))
  if (missing.length) throw new Error(`Cannot finalize while candidate receipts are incomplete: ${missing.map(item => item.candidateId).join(', ')}`)
  const activeTasks = scan.tasks.filter(task => task.status === 'pending' || task.status === 'claimed'); if (activeTasks.length) throw new Error(`Cannot finalize while audit tasks remain: ${activeTasks.map(task => task.id).join(', ')}`)
  scan.lifecycle = scan.coverage.complete ? 'completed' : 'incomplete'; scan.completedAt = new Date().toISOString(); scan.activity.push({ at: scan.completedAt, phase: 'reporting', message: 'Canonical scan bundle finalized after all candidate ledgers closed.' }); await finalizeAndSaveScan(state, scan); return scan
}
