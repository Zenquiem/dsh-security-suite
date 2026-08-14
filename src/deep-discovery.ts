import { mkdir, readFile, rename, writeFile } from 'node:fs/promises'
import { isAbsolute, join, relative, resolve } from 'node:path'
import { randomUUID } from 'node:crypto'
import type { Context } from '@deepseek-ai/cordis'
import { createUserMessage } from '@deepseek-ai/dsh-llm'
import { SessionId } from '@deepseek-ai/dsh-session'
import type {} from '@deepseek-ai/dsh-agent'
import type {} from '@deepseek-ai/dsh-tools'
import type {} from '@deepseek-ai/dsh-system-prompt'
import type { Config } from './config.js'
import type { Finding, ScanRecord, Severity } from './contracts.js'
import { assignFindingIdentity, candidateId, findingId, getStateDir, loadScan, persistInvestigationArtifacts, saveScan, sha256, writeArtifact } from './state.js'

const WORKERS_PER_ROUND = 6
const jobWrites = new Map<string, Promise<void>>()
export interface DeepCandidateInput { ruleId: string; title: string; severity: Severity; cwe: string; file: string; line: number; rootCause: string; remediationIdentity?: string }
export interface DeepCandidate extends DeepCandidateInput { id: string; workerId: string; workerIds: string[]; reportIds: string[]; excerpt: string; fingerprint: string; remediationSubsumption: { remediationIdentity: string; decision: 'not_merged' | 'merged_equivalent_reports'; rationale: string; absorbedReportIds: string[] }; reportedAt: string; /** Set by the semantic reducer: this candidate was absorbed into the target candidate. */
  absorbedBy?: string }
export interface DeepWorkerReport { threatModel: string; reviewedWorkItemIds: string[]; deferred: Array<{ workItemId: string; reason: string }>; coverageSummary: string; reportedAt: string }
/**
 * Distinct attack-surface review lenses (codex-security investigator
 * perspectives, adapted): each worker receives its own lens, so the six
 * workers of a round do not all run the identical brief.
 */
export const DEEP_REVIEW_LENSES: Array<{ id: string; label: string; brief: string }> = [
  { id: 'forward', label: 'Forward dataflow', brief: 'Follow attacker-controlled input, identity, trust boundaries, and controls toward sensitive operations.' },
  { id: 'backward', label: 'Backward from sinks', brief: 'Start at sensitive operations, parsers, execution, credential issuance, or protected assets and trace callers back to a plausible attacker.' },
  { id: 'authorization', label: 'Authorization and business logic', brief: 'Inspect ownership, tenants, permissions, sessions, capabilities, lifecycle transitions, and guard differences across sibling operations.' },
  { id: 'open-ended', label: 'Open-ended source review', brief: 'Investigate promising source-backed security evidence without restricting the search to a predefined vulnerability class or component.' },
  { id: 'parsers', label: 'Parsers and deserialization', brief: 'Focus on parsing, deserialization, template expansion, code generation, interpretation, and representation-change boundaries.' },
  { id: 'secrets', label: 'Secrets and cryptography', brief: 'Focus on credential issuance, key handling, cryptographic misuse, and sensitive-data exposure paths.' },
]
/** Each worker receives its distinct review lens and the immutable worklist. */
export interface DeepWorker { id: string; round: number; lens?: string; status: 'pending' | 'running' | 'completed' | 'cancelled' | 'failed'; token: string; sessionId?: string; transcript?: string; error?: string; candidateIds: string[]; report?: DeepWorkerReport }
export interface DeepRound { number: number; workerIds: string[]; candidateCount: number; novelty: number; status: 'running' | 'complete' | 'incomplete'; artifactRefs?: string[] }
/** An immutable, bounded source region. IDs deliberately bind file, snapshot, and range. */
export interface DeepWorkItem { id: string; path: string; sha256: string; language: string; startLine: number; endLine: number; priority: number; riskSignals: string[] }
export interface CanonicalThreatModel { artifactRef: string; digest: string; workerIds: string[]; createdAt: string }
/** One semantic-merge decision produced by the LLM reducer for a round. */
export interface DeepReducerMerge { targetId: string; absorbedIds: string[]; rationale: string }
export interface DeepReducer { id: string; round: number; status: 'pending' | 'running' | 'completed' | 'failed'; token: string; transcript?: string; error?: string; merges: DeepReducerMerge[] }
export interface DeepDiscoveryJob { id: string; scanId: string; target: string; createdAt: string; updatedAt: string; lifecycle: 'queued' | 'running' | 'saturated' | 'capped' | 'incomplete' | 'cancelled' | 'failed'; maxRounds: number; worklist: DeepWorkItem[]; worklistDigest: string; rounds: DeepRound[]; workers: DeepWorker[]; candidates: DeepCandidate[]; canonicalThreatModel?: CanonicalThreatModel; /** codex-security stop_after_no_new accounting: consecutive complete rounds with zero novelty. */
  consecutiveNoNew?: number; /** Semantic reducers, one per completed round (codex-security deep_scan_dedup). */
  reducers?: DeepReducer[] }

type NativeAgents = { create?: unknown }

function nativeAgents(ctx: Context): NativeAgents | undefined {
  const get = (ctx as Context & { get?: (name: string) => unknown }).get
  return (typeof get === 'function' ? get.call(ctx, 'agents') : (ctx as Context & { agents?: NativeAgents }).agents) as NativeAgents | undefined
}

/** This suite delegates only through the public DSH agent registry. */
export function deepDiscoveryCapability(ctx: Context): { available: boolean; workersPerRound: number; reason?: string } {
  const agents = nativeAgents(ctx)
  if (!agents || typeof agents.create !== 'function') return { available: false, workersPerRound: WORKERS_PER_ROUND, reason: 'The active DSH profile has no native agent-creation service.' }
  return { available: true, workersPerRound: WORKERS_PER_ROUND }
}

function inside(root: string, path: string): boolean { const item = relative(root, path); return item === '' || (!item.startsWith('..') && !isAbsolute(item)) }
function slug(value: string): string { return value.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '') || 'root-control' }

function jobPath(state: string, id: string): string { if (!/^deep_[0-9a-f-]+$/.test(id)) throw new Error('Invalid deep discovery job id.'); return join(state, 'deep-discovery', `${id}.json`) }
async function atomic(path: string, content: string): Promise<void> { await mkdir(resolve(path, '..'), { recursive: true }); const temp = `${path}.${randomUUID()}.tmp`; await writeFile(temp, content, 'utf8'); await rename(temp, path) }
async function save(state: string, job: DeepDiscoveryJob): Promise<void> { job.updatedAt = new Date().toISOString(); await atomic(jobPath(state, job.id), `${JSON.stringify(job, null, 2)}\n`) }
export async function loadDeepDiscoveryJob(config: Config, id: string): Promise<DeepDiscoveryJob> {
  const job = JSON.parse(await readFile(jobPath(getStateDir(config.stateDir), id), 'utf8')) as DeepDiscoveryJob
  // Old path-level jobs cannot provide region-level closure, so make their gap explicit.
  if (job.worklist.some(item => !item.id || !Number.isInteger(item.startLine) || !Number.isInteger(item.endLine))) throw new Error('This deep-discovery job predates region-level coverage. Start a new deep discovery job from the saved scan.')
  job.worklist = job.worklist.map(item => ({ ...item, priority: Number.isFinite(item.priority) ? item.priority : 0, riskSignals: Array.isArray(item.riskSignals) ? item.riskSignals : [] }))
  return job
}

/** Serialize read-modify-write transitions because workers report concurrently. */
async function updateJob<T>(config: Config, id: string, update: (job: DeepDiscoveryJob) => Promise<T> | T): Promise<T> {
  const previous = jobWrites.get(id) ?? Promise.resolve()
  let release!: () => void
  const barrier = new Promise<void>(resolveBarrier => { release = resolveBarrier })
  const chained = previous.then(() => barrier)
  jobWrites.set(id, chained)
  await previous
  try {
    const job = await loadDeepDiscoveryJob(config, id)
    const value = await update(job)
    await save(getStateDir(config.stateDir), job)
    return value
  } finally {
    release()
    if (jobWrites.get(id) === chained) jobWrites.delete(id)
  }
}

function riskSignals(path: string, content: string): string[] {
  const signals: string[] = []; const value = `${path}\n${content}`
  if (/(?:^|\/)(?:routes?|controllers?|handlers?|api|server|middleware)(?:\/|\.|$)|\b(?:app|router)\.(?:get|post|put|delete|use)\b/i.test(value)) signals.push('externally reachable request surface')
  if (/\b(?:eval|Function|exec(?:File)?|spawn|system|child_process|Runtime\.getRuntime)\b|\b(?:SELECT|INSERT|UPDATE|DELETE)\b/i.test(value)) signals.push('execution or query sink')
  if (/\b(?:fetch|axios|request|http\.request|https\.request|urlopen|net\.Dial)\b|rejectUnauthorized\s*:\s*false|InsecureSkipVerify/i.test(value)) signals.push('outbound network or transport control')
  if (/\b(?:auth|authori[sz]|permission|role|session|jwt|token|oauth)\b/i.test(value)) signals.push('authorization or identity control')
  if (/\b(?:secret|password|api[_-]?key|private[_-]?key|credential)\b/i.test(value)) signals.push('credential or key material')
  if (/(?:^|\/)(?:\.github\/workflows|Dockerfile|package(?:-lock)?\.json|pnpm-lock\.yaml|yarn\.lock|Cargo\.lock|go\.sum)(?:$|\/)/i.test(path)) signals.push('build or supply-chain control')
  if (/\b(?:deserialize|pickle|yaml\.load|XMLParser|ObjectInputStream|unserialize)\b/i.test(value)) signals.push('parser or deserialization boundary')
  return [...new Set(signals)]
}

async function prioritizedWorklist(scan: ScanRecord): Promise<DeepWorkItem[]> {
  const rows = await Promise.all(scan.coverage.receipts.map(async receipt => {
    const source = resolve(scan.target, receipt.path); if (!inside(scan.target, source)) throw new Error('Scan receipt path is outside the scan target.')
    const content = await readFile(source, 'utf8'); if (sha256(content) !== receipt.sha256) throw new Error(`Source file changed after scan receipt: ${receipt.path}. Create a follow-up scan before deep discovery.`)
    const lines = content.split(/\r?\n/); if (lines.length > 1 && lines.at(-1) === '') lines.pop(); const regions: DeepWorkItem[] = []
    for (let start = 1; start <= Math.max(1, lines.length); start += 200) {
      const end = Math.min(lines.length || 1, start + 199); const region = lines.slice(start - 1, end).join('\n'); const signals = riskSignals(receipt.path, region)
      regions.push({ id: `region_${sha256(`${receipt.path}:${receipt.sha256}:${start}:${end}`).slice(0, 24)}`, path: receipt.path, sha256: receipt.sha256, language: receipt.language, startLine: start, endLine: end, priority: signals.length * 100 + (start === 1 ? 1 : 0), riskSignals: signals })
    }
    return regions
  }))
  return rows.flat().sort((left, right) => right.priority - left.priority || left.path.localeCompare(right.path) || left.startLine - right.startLine)
}

export async function createDeepDiscoveryJob(config: Config, scanId: string, maxRounds = 10): Promise<DeepDiscoveryJob> {
  const state = getStateDir(config.stateDir); const scan = await loadScan(state, scanId); if (scan.mode !== 'deep') throw new Error('Delegated deep discovery requires a scan started in deep mode.'); if (scan.lifecycle === 'completed') throw new Error('Completed scans cannot accept new discovery candidates.')
  const worklist = await prioritizedWorklist(scan)
  const now = new Date().toISOString(); const job: DeepDiscoveryJob = { id: `deep_${randomUUID()}`, scanId, target: scan.target, createdAt: now, updatedAt: now, lifecycle: 'queued', maxRounds: Math.max(1, Math.min(maxRounds, 10)), worklist, worklistDigest: sha256(JSON.stringify(worklist)), rounds: [], workers: [], candidates: [] }
  await persistInvestigationArtifacts(state, scan)
  await writeArtifact(scan, 'artifacts/02_discovery/rank_input.jsonl', `${worklist.map(item => JSON.stringify(item)).join('\n')}\n`)
  await writeArtifact(scan, 'artifacts/02_discovery/deep_review_input.jsonl', `${worklist.map(item => JSON.stringify(item)).join('\n')}\n`)
  await writeArtifact(scan, 'artifacts/02_discovery/work_ledger.jsonl', '')
  await saveScan(state, scan); await save(state, job); return job
}

export async function reportDeepCandidate(config: Config, jobId: string, workerId: string, token: string, input: DeepCandidateInput): Promise<DeepCandidate> {
  return updateJob(config, jobId, async job => {
    if (job.lifecycle !== 'running') throw new Error('Deep discovery job is not accepting candidates.')
    const worker = job.workers.find(item => item.id === workerId); if (!worker || worker.token !== token || worker.status !== 'running') throw new Error('Deep discovery worker claim is invalid.')
    if (!/^[a-z][a-z0-9.-]{2,100}$/.test(input.ruleId) || !input.title.trim() || !input.cwe.trim() || !Number.isInteger(input.line) || input.line < 1) throw new Error('Candidate fields are invalid.')
    const workItem = job.worklist.find(item => item.path === input.file && input.line >= item.startLine && input.line <= item.endLine); if (!workItem) throw new Error('Candidate location is outside the authoritative deep-discovery worklist region.')
    const source = resolve(job.target, input.file); if (!inside(job.target, source)) throw new Error('Candidate location is outside the deep-scan target.')
    const content = await readFile(source, 'utf8'); if (sha256(content) !== workItem.sha256) throw new Error('Source file changed after the authoritative deep-discovery worklist was created.')
    const lines = content.split(/\r?\n/); const excerpt = lines[input.line - 1]?.trim().slice(0, 240); if (!excerpt) throw new Error('Candidate location does not identify a readable source line.')
    const remediationIdentity = (input.remediationIdentity?.trim() || `root-control:${input.rootCause.replace(/\s+/g, ' ').toLowerCase()}`).slice(0, 240)
    if (remediationIdentity.length < 8) throw new Error('Candidate remediation identity must be a substantive description of the one control change that closes the claim.')
    const fingerprint = sha256(`${input.ruleId}:${input.file}:${input.line}:${excerpt.replace(/\s+/g, ' ')}:${remediationIdentity}`); const reportId = `deepreport_${sha256(`${job.id}:${workerId}:${fingerprint}`).slice(0, 24)}`; const existing = job.candidates.find(item => item.fingerprint === fingerprint)
    if (existing) { if (!existing.workerIds.includes(workerId)) existing.workerIds.push(workerId); if (!existing.reportIds.includes(reportId)) existing.reportIds.push(reportId); existing.remediationSubsumption.decision = 'merged_equivalent_reports'; existing.remediationSubsumption.absorbedReportIds = existing.reportIds; existing.remediationSubsumption.rationale = 'Merged only equivalent reports sharing the exact rule, source line, excerpt, and stated remediation identity; one identified control change closes every absorbed report.'; if (!worker.candidateIds.includes(existing.id)) worker.candidateIds.push(existing.id); return existing }
    const candidate: DeepCandidate = { ...input, remediationIdentity, id: `deepcand_${sha256(`${job.id}:${workerId}:${fingerprint}`).slice(0, 24)}`, workerId, workerIds: [workerId], reportIds: [reportId], excerpt, fingerprint, remediationSubsumption: { remediationIdentity, decision: 'not_merged', rationale: 'No other report has established the same remediation identity. This candidate remains separately attackable until a single closing control is evidenced.', absorbedReportIds: [reportId] }, reportedAt: new Date().toISOString() }; job.candidates.push(candidate); worker.candidateIds.push(candidate.id); return candidate
  })
}

export async function reportDeepWorker(config: Config, jobId: string, workerId: string, token: string, input: { threatModel: string; reviewedWorkItemIds: string[]; deferred: Array<{ workItemId: string; reason: string }>; coverageSummary: string }): Promise<DeepWorkerReport> {
  return updateJob(config, jobId, job => {
    if (job.lifecycle !== 'running') throw new Error('Deep discovery job is not accepting worker reports.')
    const worker = job.workers.find(item => item.id === workerId); if (!worker || worker.token !== token || worker.status !== 'running') throw new Error('Deep discovery worker claim is invalid.')
    if (input.threatModel.trim().length < 40 || input.coverageSummary.trim().length < 10) throw new Error('Worker threat model and coverage summary must contain substantive evidence.')
    const required = new Set(job.worklist.map(item => item.id)); const reviewed = new Set(input.reviewedWorkItemIds)
    const deferred = new Map(input.deferred.map(item => [item.workItemId, item.reason.trim()] as const))
    if ([...reviewed].some(id => !required.has(id)) || [...deferred.keys()].some(id => !required.has(id))) throw new Error('Worker coverage report contains a region outside the authoritative worklist.')
    for (const id of required) if (!reviewed.has(id) && !deferred.has(id)) throw new Error(`Worker coverage report leaves authoritative worklist region unclosed: ${id}`)
    if ([...deferred.values()].some(reason => reason.length < 3)) throw new Error('Deferred worklist regions require a concrete reason.')
    const report: DeepWorkerReport = { threatModel: input.threatModel.trim().slice(0, 100_000), reviewedWorkItemIds: [...reviewed].sort(), deferred: [...deferred.entries()].map(([workItemId, reason]) => ({ workItemId, reason })).sort((left, right) => left.workItemId.localeCompare(right.workItemId)), coverageSummary: input.coverageSummary.trim().slice(0, 20_000), reportedAt: new Date().toISOString() }
    worker.report = report; return report
  })
}

function activeWorker(job: DeepDiscoveryJob, workerId: string, token: string): DeepWorker {
  if (job.lifecycle !== 'running') throw new Error('Deep discovery job is not active.')
  const worker = job.workers.find(item => item.id === workerId)
  if (!worker || worker.token !== token || worker.status !== 'running') throw new Error('Deep discovery worker claim is invalid.')
  return worker
}

export async function getDeepWorklist(config: Config, jobId: string, workerId: string, token: string): Promise<{ digest: string; items: DeepWorkItem[] }> {
  const job = await loadDeepDiscoveryJob(config, jobId); activeWorker(job, workerId, token)
  return { digest: job.worklistDigest, items: job.worklist }
}

export async function readDeepSource(config: Config, jobId: string, workerId: string, token: string, workItemId: string): Promise<{ id: string; path: string; startLine: number; endLine: number; content: string; sha256: string }> {
  const job = await loadDeepDiscoveryJob(config, jobId); activeWorker(job, workerId, token)
  const item = job.worklist.find(row => row.id === workItemId); if (!item) throw new Error('Source region is not in the authoritative deep-discovery worklist.')
  const source = resolve(job.target, item.path); if (!inside(job.target, source)) throw new Error('Source path is outside the deep-scan target.')
  const content = await readFile(source, 'utf8'); const digest = sha256(content); if (digest !== item.sha256) throw new Error('Source file changed after the authoritative deep-discovery worklist was created.')
  const lines = content.split(/\r?\n/); return { id: item.id, path: item.path, startLine: item.startLine, endLine: item.endLine, content: lines.slice(item.startLine - 1, item.endLine).join('\n'), sha256: digest }
}

/** Read a bounded, scan-receipted source range for centralized deep validation or attack-path workers. */
export async function readScanSource(config: Config, scanId: string, path: string, startLine = 1, endLine = 400): Promise<{ path: string; startLine: number; endLine: number; content: string; sha256: string }> {
  const scan = await loadScan(getStateDir(config.stateDir), scanId)
  const item = scan.coverage.receipts.find(row => row.path === path); if (!item) throw new Error('Source path is not in the scan coverage receipt.')
  const start = Math.max(1, Math.floor(startLine)); const end = Math.max(start, Math.min(start + 399, Math.floor(endLine)))
  const source = resolve(scan.target, item.path); if (!inside(scan.target, source)) throw new Error('Source path is outside the scan target.')
  const content = await readFile(source, 'utf8'); const digest = sha256(content); if (digest !== item.sha256) throw new Error('Source file changed after this scan; create a follow-up scan before centralized review.')
  const lines = content.split(/\r?\n/); return { path: item.path, startLine: start, endLine: Math.min(end, lines.length), content: lines.slice(start - 1, end).join('\n'), sha256: digest }
}

function transcript(agent: { session: { deriveMessages(): Array<{ role: string; content: Array<{ type: string; text?: string }> }> } }): string { return agent.session.deriveMessages().filter(message => message.role === 'assistant').flatMap(message => message.content.filter(block => block.type === 'text' || block.type === 'reasoning').map(block => block.text ?? '')).join('\n\n').slice(-200_000) }
function brief(job: DeepDiscoveryJob, worker: DeepWorker): string {
  const lens = DEEP_REVIEW_LENSES.find(item => item.id === worker.lens)
  const lensParagraph = lens ? `\n\nYour distinct review lens is ${lens.label}: ${lens.brief} Use it as the starting perspective for your region reviews, while still tracing supporting evidence anywhere in the authorized source.` : ''
  return `You are one of six independent DSH security discovery workers, each with a distinct review lens. You have exactly four DSH tools: security_deep_get_worklist, security_deep_read_source, security_deep_report_candidate, and security_deep_report_worker. Do not modify source, validate or fix findings, or use external services. Call security_deep_get_worklist with job_id ${job.id}, worker_id ${worker.id}, claim_token ${worker.token}; confirm its digest is ${job.worklistDigest}; then inspect every returned immutable source region with security_deep_read_source by work_item_id in descending priority order, using risk signals as review leads rather than proof. Read every assigned region from start to finish; do not stop reviewing a region after finding one bug. Preserve exact source-backed hints: a nearby finding with the same CWE does not close a different seeded control, and independently reachable vulnerable operations stay separate even when they share a helper. Independently create a source-evidenced worker threat model; do not use another worker's analysis. For every distinct candidate with a concrete local source line, call security_deep_report_candidate with job_id ${job.id}, worker_id ${worker.id}, claim_token ${worker.token}, stable rule_id, title, severity, CWE, workspace-relative file, line, and root_cause; include the actual entry point, closest broken control, and sensitive sink as affected candidate locations. When all worklist regions are closed, call security_deep_report_worker with job_id ${job.id}, worker_id ${worker.id}, claim_token ${worker.token}, your worker threat model, every reviewed_work_item_id, explicit deferred work_item_id rows with reasons, and a coverage summary. A worker run without that report is incomplete. Report only candidates you can support with source evidence.${lensParagraph}`
}

function cancelled(signal: AbortSignal | undefined): boolean { return signal?.aborted === true }

async function runWorker(ctx: Context, config: Config, job: DeepDiscoveryJob, worker: DeepWorker, signal?: AbortSignal): Promise<void> {
  const sessionId = SessionId(`dsh-security-deep-${randomUUID()}`)
  await updateJob(config, job.id, current => { const record = current.workers.find(item => item.id === worker.id); if (!record) throw new Error('Deep discovery worker was not created.'); record.status = 'running'; record.sessionId = sessionId as unknown as string })
  let handle: Awaited<ReturnType<typeof ctx.agents.create>> | undefined
  let disposePromise: Promise<void> | undefined
  const dispose = (): Promise<void> => handle ? (disposePromise ??= handle.dispose().catch(() => undefined)) : Promise.resolve()
  let cancelledByCaller = cancelled(signal)
  const onAbort = (): void => { cancelledByCaller = true; void dispose() }
  signal?.addEventListener('abort', onAbort, { once: true })
  try {
    if (cancelledByCaller) return
    const agents = nativeAgents(ctx) as typeof ctx.agents | undefined
    if (!agents || typeof agents.create !== 'function') throw new Error('The active DSH profile has no native agent-creation service.')
    handle = await agents.create({ sessionId, meta: { cwd: resolve(job.target), origin: 'subagent', delegationDepth: 1 }, setup(agentCtx) {
      agentCtx.tools.restrict({ allow: ['security_deep_get_worklist', 'security_deep_read_source', 'security_deep_report_candidate', 'security_deep_report_worker'] })
      agentCtx.systemPrompt.section({ name: `dsh-security-suite:deep-worker:${worker.id}`, order: 162, text: brief(job, worker) })
    } })
    if (cancelledByCaller) return
    handle.agent.followup(createUserMessage({ content: [{ type: 'text', text: brief(job, worker) }], source: { kind: 'plugin', plugin: 'dsh-security-suite', form: 'relay' } }))
    if (signal) {
      let removeAbortWait = (): void => undefined
      const aborted = new Promise<void>(resolveAbort => { const wake = (): void => resolveAbort(); signal.addEventListener('abort', wake, { once: true }); removeAbortWait = (): void => signal.removeEventListener('abort', wake) })
      try { await Promise.race([handle.agent.whenIdle(), aborted]) } finally { removeAbortWait() }
    } else await handle.agent.whenIdle()
    if (cancelledByCaller) return
    const workerTranscript = transcript(handle.agent)
    await updateJob(config, job.id, current => { const record = current.workers.find(item => item.id === worker.id); if (record) { record.transcript = workerTranscript; record.status = 'completed' } })
  } catch (error) {
    if (cancelledByCaller) return
    const message = error instanceof Error ? error.message : String(error)
    await updateJob(config, job.id, current => { const record = current.workers.find(item => item.id === worker.id); if (record) { record.status = 'failed'; record.error = message } })
  } finally {
    signal?.removeEventListener('abort', onAbort)
    if (cancelledByCaller) await updateJob(config, job.id, current => { const record = current.workers.find(item => item.id === worker.id); if (record && record.status !== 'completed') { record.status = 'cancelled'; record.error = 'Cancelled by the owning DSH tool call.' } })
    await dispose()
  }
}

/** The worker-bound tool view for the semantic reducer (codex-security dedup worker). */
export const DEEP_REDUCER_TOOLS = ['security_deep_get_reducer_input', 'security_deep_report_reducer'] as const

function activeReducer(job: DeepDiscoveryJob, reducerId: string, token: string): DeepReducer {
  if (job.lifecycle !== 'running') throw new Error('Deep discovery job is not running.')
  const reducer = job.reducers?.find(item => item.id === reducerId)
  if (!reducer) throw new Error('Reducer is not part of this deep discovery job.')
  if (reducer.status !== 'running') throw new Error('Reducer is not active for this deep discovery job.')
  if (reducer.token !== token) throw new Error('Reducer claim token does not own this reducer.')
  return reducer
}

/** Read the semantic-merge input for one active reducer: this round's candidates and the authoritative worklist. */
export async function getDeepReducerInput(config: Config, jobId: string, reducerId: string, token: string): Promise<{ jobId: string; scanId: string; worklistDigest: string; round: number; candidates: Array<{ id: string; ruleId: string; title: string; severity: Severity; cwe: string; file: string; line: number; rootCause: string; remediationIdentity: string; workerIds: string[]; reportIds: string[]; excerpt: string }> }> {
  const job = await loadDeepDiscoveryJob(config, jobId)
  const reducer = activeReducer(job, reducerId, token)
  const roundWorkers = new Set(job.rounds.find(round => round.number === reducer.round)?.workerIds ?? [])
  const candidates = job.candidates.filter(candidate => candidate.workerIds.some(workerId => roundWorkers.has(workerId)) && !candidate.absorbedBy).map(candidate => ({ id: candidate.id, ruleId: candidate.ruleId, title: candidate.title, severity: candidate.severity, cwe: candidate.cwe, file: candidate.file, line: candidate.line, rootCause: candidate.rootCause, remediationIdentity: candidate.remediationSubsumption.remediationIdentity, workerIds: candidate.workerIds, reportIds: candidate.reportIds, excerpt: candidate.excerpt }))
  return { jobId, scanId: job.scanId, worklistDigest: job.worklistDigest, round: reducer.round, candidates }
}

/** Apply one batch of semantic-merge decisions: absorbed candidates union into the target and are excluded from canonical reconciliation. */
export async function reportDeepReducer(config: Config, jobId: string, reducerId: string, token: string, merges: Array<{ targetId: string; absorbedIds: string[]; rationale: string }>): Promise<{ merged: number; absorbed: number }> {
  let merged = 0
  let absorbed = 0
  await updateJob(config, jobId, async current => {
    const reducer = activeReducer(current, reducerId, token)
    for (const merge of merges) {
      if (!merge.targetId || !Array.isArray(merge.absorbedIds) || !merge.rationale.trim()) throw new Error('Reducer merge requires a targetId, absorbedIds, and a concrete rationale.')
      const target = current.candidates.find(candidate => candidate.id === merge.targetId)
      if (!target) throw new Error(`Reducer merge target ${merge.targetId} does not exist.`)
      if (target.absorbedBy) throw new Error(`Reducer merge target ${merge.targetId} is itself absorbed.`)
      const absorbedSet = new Set<string>()
      for (const absorbedId of merge.absorbedIds) {
        const source = current.candidates.find(candidate => candidate.id === absorbedId)
        if (!source || source.id === target.id) throw new Error(`Reducer merge source ${absorbedId} does not exist.`)
        if (source.absorbedBy) throw new Error(`Reducer merge source ${absorbedId} was already absorbed.`)
        source.absorbedBy = target.id
        absorbedSet.add(source.id)
        absorbed++
      }
      if (!absorbedSet.size) continue
      target.workerIds = [...new Set([...target.workerIds, ...merges.find(m => m.targetId === target.id)?.absorbedIds.flatMap(id => current.candidates.find(candidate => candidate.id === id)?.workerIds ?? []) ?? []])]
      target.reportIds = [...new Set([...target.reportIds, ...current.candidates.filter(candidate => absorbedSet.has(candidate.id)).flatMap(candidate => candidate.reportIds)])]
      target.remediationSubsumption = { remediationIdentity: target.remediationSubsumption.remediationIdentity, decision: 'merged_equivalent_reports', rationale: `${target.remediationSubsumption.rationale} Semantic reducer merged ${[...absorbedSet].join(', ')} because ${merge.rationale}`, absorbedReportIds: [...new Set([...target.remediationSubsumption.absorbedReportIds, ...current.candidates.filter(candidate => absorbedSet.has(candidate.id)).flatMap(candidate => candidate.reportIds)])] }
      merged++
    }
    reducer.merges = merges
  })
  return { merged, absorbed }
}

async function runDeepReducer(ctx: Context, config: Config, job: DeepDiscoveryJob, reducer: DeepReducer, signal?: AbortSignal): Promise<void> {
  const sessionId = SessionId(`dsh-security-deep-reducer-${randomUUID()}`)
  await updateJob(config, job.id, current => { const record = current.reducers?.find(item => item.id === reducer.id); if (!record) throw new Error('Deep reducer was not created.'); record.status = 'running' })
  let handle: Awaited<ReturnType<typeof ctx.agents.create>> | undefined
  let disposePromise: Promise<void> | undefined
  const dispose = (): Promise<void> => handle ? (disposePromise ??= handle.dispose().catch(() => undefined)) : Promise.resolve()
  let cancelledByCaller = cancelled(signal)
  const onAbort = (): void => { cancelledByCaller = true; void dispose() }
  signal?.addEventListener('abort', onAbort, { once: true })
  try {
    if (cancelledByCaller) return
    const agents = nativeAgents(ctx) as typeof ctx.agents | undefined
    if (!agents || typeof agents.create !== 'function') throw new Error('The active DSH profile has no native agent-creation service.')
    const { deepReducerPrompt } = await import('./llm/prompts.js')
    const prompt = deepReducerPrompt({ jobId: job.id, reducerId: reducer.id, token: reducer.token, round: reducer.round, worklistDigest: job.worklistDigest })
    handle = await agents.create({ sessionId, meta: { cwd: resolve(job.target), origin: 'subagent', delegationDepth: 1 }, setup(agentCtx) {
      agentCtx.tools.restrict({ allow: [...DEEP_REDUCER_TOOLS] })
      agentCtx.systemPrompt.section({ name: `dsh-security-suite:deep-reducer:${reducer.id}`, order: 162, text: prompt })
    } })
    if (cancelledByCaller) return
    handle.agent.followup(createUserMessage({ content: [{ type: 'text', text: prompt }], source: { kind: 'plugin', plugin: 'dsh-security-suite', form: 'relay' } }))
    if (signal) {
      let removeAbortWait = (): void => undefined
      const aborted = new Promise<void>(resolveAbort => { const wake = (): void => resolveAbort(); signal.addEventListener('abort', wake, { once: true }); removeAbortWait = (): void => signal.removeEventListener('abort', wake) })
      try { await Promise.race([handle.agent.whenIdle(), aborted]) } finally { removeAbortWait() }
    } else await handle.agent.whenIdle()
    if (cancelledByCaller) return
    const reducerTranscript = transcript(handle.agent)
    await updateJob(config, job.id, current => { const record = current.reducers?.find(item => item.id === reducer.id); if (record && record.status === 'running') { record.transcript = reducerTranscript; record.status = 'completed' } })
  } catch (error) {
    if (cancelledByCaller) return
    const message = error instanceof Error ? error.message : String(error)
    await updateJob(config, job.id, current => { const record = current.reducers?.find(item => item.id === reducer.id); if (record && record.status === 'running') { record.status = 'failed'; record.error = message } })
  } finally {
    signal?.removeEventListener('abort', onAbort)
    if (cancelledByCaller) await updateJob(config, job.id, current => { const record = current.reducers?.find(item => item.id === reducer.id); if (record && record.status !== 'completed') { record.status = 'failed'; record.error = 'Cancelled by the owning DSH tool call.' } })
    await dispose()
  }
}

function addCandidate(scan: ScanRecord, candidate: DeepCandidate): void {
  const anchor = slug(`${candidate.ruleId}-${candidate.excerpt}`); const id = candidateId(candidate.ruleId, candidate.file, candidate.line); const reporters = candidate.workerIds.join(', '); const finding: Finding = { id: findingId('discovery', candidate.ruleId, anchor), candidateId: id, fingerprint: candidate.fingerprint, ruleId: candidate.ruleId, identity: { anchor }, title: candidate.title, severity: candidate.severity, confidence: 'low', cwe: candidate.cwe, status: 'open', disposition: 'discovered', locations: [{ file: candidate.file, line: candidate.line, excerpt: candidate.excerpt, role: 'root_control' }], rootCause: candidate.rootCause, validation: 'Discovery-only delegated candidate. Validate source, closest control, sink, reachability, impact, and counterevidence.', attackPath: 'Not established.', impact: 'Not established.', remediation: 'Determine the narrowest effective control after validation.', counterevidence: 'No validation has been completed.', evidence: [{ kind: 'pattern', detail: `Independent delegated discovery workers ${reporters} reported this candidate; absorbed report ids: ${candidate.reportIds.join(', ')}.`, location: { file: candidate.file, line: candidate.line, excerpt: candidate.excerpt, role: 'root_control' } }], ledger: [{ at: candidate.reportedAt, phase: 'discovery', disposition: 'discovered', summary: `Delegated workers ${reporters} reported ${candidate.ruleId}; absorbed reports: ${candidate.reportIds.join(', ')}.` }] }
  assignFindingIdentity(finding, scan.targetSnapshot.targetId, new Set(scan.findings.map(item => `${item.ruleId}:${item.identity.anchor}:${item.identity.instance ?? ''}`)))
  if (scan.findings.some(existing => existing.fingerprint === finding.fingerprint)) return
  scan.findings.push(finding); scan.tasks.push({ id: `task_${sha256(`${scan.id}:${id}:validation`).slice(0, 24)}`, candidateId: id, phase: 'validation', focus: `Validate delegated discovery candidate ${finding.title}: establish attacker, entrypoint, control, sink, impact, and counterevidence.`, status: 'pending' })
}

function completeWorkerIds(job: DeepDiscoveryJob): Set<string> {
  return new Set(job.rounds.filter(round => round.status === 'complete').flatMap(round => round.workerIds))
}

function canonicalCandidates(job: DeepDiscoveryJob): DeepCandidate[] {
  const complete = completeWorkerIds(job)
  return job.candidates.filter(candidate => !candidate.absorbedBy && candidate.workerIds.some(workerId => complete.has(workerId)))
}

async function persistRoundArtifacts(scan: ScanRecord, job: DeepDiscoveryJob, round: DeepRound): Promise<string[]> {
  const workers = round.workerIds.map(id => job.workers.find(worker => worker.id === id)).filter((worker): worker is DeepWorker => Boolean(worker))
  const refs: string[] = []
  for (const worker of workers) {
    const base = `artifacts/02_discovery/deep/round-${String(round.number).padStart(2, '0')}/${worker.id}`; const report = worker.report
    if (!report) continue
    refs.push(await writeArtifact(scan, `${base}/threat_model.md`, `${report.threatModel}\n`))
    refs.push(await writeArtifact(scan, `${base}/coverage.json`, `${JSON.stringify({ worklistDigest: job.worklistDigest, reviewedWorkItemIds: report.reviewedWorkItemIds, deferred: report.deferred, summary: report.coverageSummary }, null, 2)}\n`))
    const candidates = job.candidates.filter(candidate => candidate.workerIds.includes(worker.id))
    refs.push(await writeArtifact(scan, `${base}/candidates.jsonl`, `${candidates.map(candidate => JSON.stringify(candidate)).join('\n')}\n`))
    refs.push(await writeArtifact(scan, `${base}/summary.md`, `# Deep Discovery Worker ${worker.id}\n\n- Status: ${worker.status}\n- Reviewed regions: ${report.reviewedWorkItemIds.length}\n- Deferred regions: ${report.deferred.length}\n- Candidates: ${candidates.length}\n\n${report.coverageSummary}\n`))
    if (worker.transcript) refs.push(await writeArtifact(scan, `${base}/transcript.md`, `${worker.transcript}\n`))
  }
  const ledger = job.workers.filter(worker => worker.round <= round.number).map(worker => JSON.stringify({ round: worker.round, workerId: worker.id, status: worker.status, hasReport: Boolean(worker.report), reviewedRegions: worker.report?.reviewedWorkItemIds.length ?? 0, deferredRegions: worker.report?.deferred.length ?? 0, candidateIds: worker.candidateIds })).join('\n')
  refs.push(await writeArtifact(scan, 'artifacts/02_discovery/work_ledger.jsonl', `${ledger}\n`))
  const roundCandidates = job.candidates.filter(candidate => workers.some(worker => candidate.workerIds.includes(worker.id)))
  if (round.status !== 'complete') {
    refs.push(await writeArtifact(scan, `artifacts/04_reconciliation/deep-round-${String(round.number).padStart(2, '0')}-incomplete.json`, `${JSON.stringify({ jobId: job.id, round: round.number, status: round.status, workers: workers.map(worker => ({ id: worker.id, status: worker.status, report: Boolean(worker.report), candidateIds: worker.candidateIds })), provisionalCandidateIds: roundCandidates.map(candidate => candidate.id), note: 'This incomplete round is retained only as process evidence. Its candidates are excluded from canonical reconciliation, scan findings, and saturation.' }, null, 2)}\n`))
    return refs
  }
  const canonical = canonicalCandidates(job).map(candidate => ({ id: candidate.id, fingerprint: candidate.fingerprint, ruleId: candidate.ruleId, title: candidate.title, file: candidate.file, line: candidate.line, workerIds: candidate.workerIds, reportIds: candidate.reportIds, remediationSubsumption: candidate.remediationSubsumption }))
  const merge = { jobId: job.id, round: round.number, status: round.status, workers: workers.map(worker => ({ id: worker.id, status: worker.status, report: Boolean(worker.report), candidateIds: worker.candidateIds })), canonicalCandidates: canonical, novelty: round.novelty }
  refs.push(await writeArtifact(scan, `artifacts/04_reconciliation/deep-round-${String(round.number).padStart(2, '0')}-merge.json`, `${JSON.stringify(merge, null, 2)}\n`))
  refs.push(await writeArtifact(scan, 'artifacts/04_reconciliation/deduped_candidates.jsonl', `${canonical.map(candidate => JSON.stringify(candidate)).join('\n')}\n`))
  refs.push(await writeArtifact(scan, 'artifacts/04_reconciliation/dedupe_report.md', `# Deep Discovery Reconciliation\n\n- Job: \`${job.id}\`\n- Completed rounds: ${job.rounds.filter(item => item.status === 'complete').length}\n- Canonical candidates: ${canonical.length}\n\n${canonical.map(candidate => `- \`${candidate.id}\`: ${candidate.ruleId} at ${candidate.file}:${candidate.line}; ${candidate.remediationSubsumption.decision === 'merged_equivalent_reports' ? `absorbed workers ${candidate.workerIds.join(', ')} because ${candidate.remediationSubsumption.rationale}` : 'retained separately because no remediation-subsumption proof exists.'}`).join('\n')}\n`))
  const closures = job.worklist.map(item => {
    const completed = workers.filter(worker => worker.report?.reviewedWorkItemIds.includes(item.id)).map(worker => worker.id)
    const deferred = workers.flatMap(worker => worker.report?.deferred.filter(row => row.workItemId === item.id).map(row => `${worker.id}: ${row.reason}`) ?? [])
    return `| \`${item.path}:${item.startLine}-${item.endLine}\` | ${item.language} | ${item.riskSignals.join(', ') || 'none'} | ${completed.length}/${workers.length} | ${deferred.length ? deferred.join('; ') : 'none'} |`
  })
  refs.push(await writeArtifact(scan, 'artifacts/03_coverage/repository_coverage_ledger.md', `# Repository Coverage Ledger\n\n- Authoritative worklist digest: \`${job.worklistDigest}\`\n- Round: ${round.number}\n\n| Source region | Language | Risk signals | Worker closures | Deferred |\n| --- | --- | --- | --- | --- |\n${closures.join('\n')}\n`))
  refs.push(await writeArtifact(scan, 'artifacts/03_coverage/reviewed_surfaces.md', `# Reviewed Surfaces\n\n${job.worklist.map(item => `- \`${item.path}:${item.startLine}-${item.endLine}\` (${item.language}): reviewed by ${workers.filter(worker => worker.report?.reviewedWorkItemIds.includes(item.id)).length}/${workers.length} workers.`).join('\n')}\n`))
  return refs
}

export async function runDeepDiscovery(ctx: Context, config: Config, jobId: string, signal?: AbortSignal): Promise<DeepDiscoveryJob> {
  const state = getStateDir(config.stateDir); let job = await loadDeepDiscoveryJob(config, jobId); if (!['queued', 'cancelled', 'incomplete'].includes(job.lifecycle)) throw new Error('Deep discovery job has already completed or failed.')
  const capability = deepDiscoveryCapability(ctx)
  if (!capability.available) {
    job.lifecycle = 'failed'; await save(state, job)
    throw new Error(capability.reason)
  }
  if (cancelled(signal)) { job.lifecycle = 'cancelled'; await save(state, job); return job }
  job.lifecycle = 'running'; await save(state, job)
  const completedWorkerIds = completeWorkerIds(job); const known = new Set(job.candidates.filter(candidate => candidate.workerIds.some(workerId => completedWorkerIds.has(workerId))).map(candidate => candidate.fingerprint)); let completedRounds = job.rounds.filter(round => round.status === 'complete').length; let number = Math.max(0, ...job.rounds.map(round => round.number))
  while (completedRounds < job.maxRounds) {
    number++
    if (cancelled(signal)) { job.lifecycle = 'cancelled'; await save(state, job); return job }
    const workers = Array.from({ length: WORKERS_PER_ROUND }, (_, index): DeepWorker => ({ id: `worker_${number}_${index + 1}`, round: number, lens: DEEP_REVIEW_LENSES[index % DEEP_REVIEW_LENSES.length].id, status: 'pending', token: randomUUID(), candidateIds: [] })); job.workers.push(...workers); const round: DeepRound = { number, workerIds: workers.map(worker => worker.id), candidateCount: 0, novelty: 0, status: 'running' }; job.rounds.push(round); await save(state, job)
    await Promise.all(workers.map(worker => runWorker(ctx, config, job, worker, signal)))
    job = await loadDeepDiscoveryJob(config, jobId)
    const completedRound = job.rounds.find(item => item.number === number); if (!completedRound) throw new Error('Deep discovery round state is missing.')
    const incomplete = workers.some(worker => { const record = job.workers.find(item => item.id === worker.id); return record?.status !== 'completed' || !record.report }); const candidates = job.candidates.filter(candidate => workers.some(worker => candidate.workerIds.includes(worker.id))); completedRound.candidateCount = candidates.length; completedRound.novelty = incomplete ? 0 : candidates.filter(candidate => !known.has(candidate.fingerprint)).length; if (!incomplete) for (const candidate of candidates) known.add(candidate.fingerprint); completedRound.status = incomplete ? 'incomplete' : 'complete'
    const source = await loadScan(state, job.scanId); completedRound.artifactRefs = await persistRoundArtifacts(source, job, completedRound); await save(state, job)
    if (cancelled(signal)) { job.lifecycle = 'cancelled'; await save(state, job); return job }
    if (incomplete) { job.lifecycle = 'incomplete'; await save(state, job); return job }
    // Semantic reduction (codex-security dedup): one independent reducer per
    // completed round merges equivalent candidates across workers.
    const reducer: DeepReducer = { id: `reducer_${number}`, round: number, status: 'pending', token: randomUUID(), merges: [] }
    await updateJob(config, jobId, current => { current.reducers = [...(current.reducers ?? []), reducer] })
    await runDeepReducer(ctx, config, job, reducer, signal)
    job = await loadDeepDiscoveryJob(config, jobId)
    const reducerRecord = job.reducers?.find(item => item.id === reducer.id)
    if (reducerRecord?.status === 'failed') { job.lifecycle = 'incomplete'; await save(state, job); return job }
    // codex-security stop_after_no_new: saturate only after that many
    // consecutive complete rounds with zero novelty; default 6.
    job.consecutiveNoNew = completedRound.novelty === 0 ? (job.consecutiveNoNew ?? 0) + 1 : 0
    const stopAfterNoNew = Math.max(1, config.deepScan?.stopAfterNoNew ?? 6)
    if (completedRound.novelty === 0 && job.consecutiveNoNew >= stopAfterNoNew) { job.lifecycle = 'saturated'; await save(state, job); break }
    completedRounds++
    if (completedRounds === job.maxRounds) job.lifecycle = 'capped'
  }
  const eligibleWorkers = completeWorkerIds(job); const eligibleCandidates = canonicalCandidates(job); const scan = await loadScan(state, job.scanId); for (const candidate of eligibleCandidates) addCandidate(scan, candidate)
  const reports = job.workers.filter(worker => eligibleWorkers.has(worker.id) && worker.report).map(worker => ({ worker, report: worker.report! }))
  if (reports.length !== WORKERS_PER_ROUND * job.rounds.filter(round => round.status === 'complete').length) throw new Error('A terminal deep discovery job is missing a completed worker threat model.')
  const model = ['# Canonical Deep Validation Threat Model', '', `- Discovery job: \`${job.id}\``, `- Immutable worklist digest: \`${job.worklistDigest}\``, `- Completed workers: ${reports.map(({ worker }) => `\`${worker.id}\``).join(', ')}`, '', 'This model is synthesized from independent DSH worker reports. Worker statements are evidence leads, not proof; validation must reopen scan-receipted source and record counterevidence.', '', ...reports.flatMap(({ worker, report }) => [`## ${worker.id}`, '', report.threatModel.trim(), ''])].join('\n').trim() + '\n'
  scan.threatModel = model
  const artifactRef = await writeArtifact(scan, 'artifacts/01_context/deep_canonical_threat_model.md', model); job.canonicalThreatModel = { artifactRef, digest: sha256(model), workerIds: reports.map(({ worker }) => worker.id), createdAt: new Date().toISOString() }
  scan.activity.push({ at: new Date().toISOString(), phase: 'threat_model', message: `Synthesized a canonical deep validation threat model from ${reports.length} independent worker reports.` }); scan.activity.push({ at: new Date().toISOString(), phase: 'discovery', message: `Delegated deep discovery ${job.lifecycle}: ${job.rounds.filter(round => round.status === 'complete').length} complete rounds, ${eligibleCandidates.length} eligible worker candidates.` }); await persistInvestigationArtifacts(state, scan); await saveScan(state, scan); await save(state, job); return job
}

export interface DeepClosureJob { id: string; scanId: string; phase: 'validation' | 'attack_path'; createdAt: string; updatedAt: string; lifecycle: 'queued' | 'running' | 'completed' | 'incomplete' | 'cancelled' | 'failed'; workers: Array<{ id: string; status: 'pending' | 'running' | 'completed' | 'cancelled' | 'failed'; sessionId?: string; transcript?: string; error?: string }>; completedTaskIds: string[]; threatModel: { artifactRef: string; digest: string; source: 'canonical_deep_discovery' | 'scan_preflight' } }
const closureWrites = new Map<string, Promise<void>>()
function closurePath(state: string, id: string): string { if (!/^deepclose_[0-9a-f-]+$/.test(id)) throw new Error('Invalid deep closure job id.'); return join(state, 'deep-closure', `${id}.json`) }
async function saveClosure(state: string, job: DeepClosureJob): Promise<void> { job.updatedAt = new Date().toISOString(); await atomic(closurePath(state, job.id), `${JSON.stringify(job, null, 2)}\n`) }
export async function loadDeepClosureJob(config: Config, id: string): Promise<DeepClosureJob> { return JSON.parse(await readFile(closurePath(getStateDir(config.stateDir), id), 'utf8')) as DeepClosureJob }
async function updateClosure<T>(config: Config, id: string, update: (job: DeepClosureJob) => Promise<T> | T): Promise<T> {
  const previous = closureWrites.get(id) ?? Promise.resolve(); let release!: () => void; const barrier = new Promise<void>(resolveBarrier => { release = resolveBarrier }); const chained = previous.then(() => barrier); closureWrites.set(id, chained); await previous
  try { const job = await loadDeepClosureJob(config, id); const value = await update(job); await saveClosure(getStateDir(config.stateDir), job); return value } finally { release(); if (closureWrites.get(id) === chained) closureWrites.delete(id) }
}
async function verifyClosureThreatModel(config: Config, job: DeepClosureJob): Promise<void> {
  const scan = await loadScan(getStateDir(config.stateDir), job.scanId)
  if (sha256(scan.threatModel) !== job.threatModel.digest) throw new Error('The bound deep closure threat model changed after job creation. Create a new closure job from the current scan state.')
  const artifact = join(scan.artifacts.directory, job.threatModel.artifactRef)
  const content = await readFile(artifact, 'utf8').catch(() => { throw new Error('The bound deep closure threat-model artifact is unavailable. Create a new closure job from the current scan state.') })
  if (sha256(content) !== job.threatModel.digest) throw new Error('The bound deep closure threat-model artifact no longer matches the current scan model. Create a new closure job.')
}
export async function createDeepClosureJob(config: Config, scanId: string, phase: 'validation' | 'attack_path'): Promise<DeepClosureJob> {
  const state = getStateDir(config.stateDir); const scan = await loadScan(state, scanId); if (scan.mode !== 'deep') throw new Error('Centralized deep closure requires a deep scan.'); if (scan.lifecycle === 'completed') throw new Error('Completed scans cannot accept centralized review evidence.')
  const existing = scan.tasks.filter(task => task.phase === phase && (task.status === 'pending' || task.status === 'claimed')).length; if (!existing) throw new Error(`No pending ${phase} tasks are available for centralized deep closure.`)
  // A workbench scan may have been saved without its mutable artifacts; materialize
  // the exact current model before freezing the closure's evidence binding.
  await persistInvestigationArtifacts(state, scan); await saveScan(state, scan)
  const canonicalPath = join(scan.artifacts.directory, 'artifacts/01_context/deep_canonical_threat_model.md'); let canonical = false
  try { canonical = sha256(await readFile(canonicalPath, 'utf8')) === sha256(scan.threatModel) } catch { /* A direct deep workbench can legitimately use its scan-time threat model. */ }
  const now = new Date().toISOString(); const job: DeepClosureJob = { id: `deepclose_${randomUUID()}`, scanId, phase, createdAt: now, updatedAt: now, lifecycle: 'queued', workers: [], completedTaskIds: [], threatModel: { artifactRef: canonical ? 'artifacts/01_context/deep_canonical_threat_model.md' : 'artifacts/01_context/threat_model.md', digest: sha256(scan.threatModel), source: canonical ? 'canonical_deep_discovery' : 'scan_preflight' } }; await saveClosure(state, job); return job
}
function closureBrief(job: DeepClosureJob, workerId: string): string {
  const common = `You are a centralized DSH deep ${job.phase} worker. The required threat model is ${job.threatModel.source} at ${job.threatModel.artifactRef} with digest ${job.threatModel.digest}. Retrieve security_get_scan first and verify its threat model digest before reviewing. You may use only security_claim_audit_task, security_get_scan, security_read_scan_source, ${job.phase === 'validation' ? 'security_record_validation' : 'security_record_attack_path'}. Work only on tasks you claim. Do not modify source, run commands, use external services, create findings, or access unreceipted paths. Claim ${job.phase} tasks using scan_id ${job.scanId}, owner ${workerId}; for each claimed task, read its scan record and cited source through security_read_scan_source, then submit a complete source-evidenced ${job.phase} receipt with the returned claim token. Continue until security_claim_audit_task returns null. Do not infer a runtime test that was not performed.`
  return job.phase === 'validation' ? `${common} A reportable conclusion requires a plausible attacker, concrete entry point, trust boundary, root control, sink, impact, counterevidence, limitations, and calibrated confidence. Otherwise use suppressed, deferred, or not_applicable with the exact proof gap.` : `${common} Attack-path work is only for reportable findings. Preserve the root-control location and explain attacker, entry point, preconditions, source-to-sink dataflow, outcome, severity rationale, and conditions that would change the conclusion.`
}
async function runClosureWorker(ctx: Context, config: Config, job: DeepClosureJob, worker: DeepClosureJob['workers'][number], signal?: AbortSignal): Promise<void> {
  const sessionId = SessionId(`dsh-security-deep-close-${randomUUID()}`); await updateClosure(config, job.id, current => { const row = current.workers.find(item => item.id === worker.id); if (!row) throw new Error('Deep closure worker was not created.'); row.status = 'running'; row.sessionId = sessionId as unknown as string })
  let handle: Awaited<ReturnType<typeof ctx.agents.create>> | undefined; let disposed: Promise<void> | undefined; let cancelledByCaller = cancelled(signal); const dispose = (): Promise<void> => handle ? (disposed ??= handle.dispose().catch(() => undefined)) : Promise.resolve(); const onAbort = (): void => { cancelledByCaller = true; void dispose() }; signal?.addEventListener('abort', onAbort, { once: true })
  try {
    if (cancelledByCaller) return; const agents = nativeAgents(ctx) as typeof ctx.agents | undefined; if (!agents || typeof agents.create !== 'function') throw new Error('The active DSH profile has no native agent-creation service.')
    const allowed = job.phase === 'validation' ? ['security_claim_audit_task', 'security_get_scan', 'security_read_scan_source', 'security_record_validation'] : ['security_claim_audit_task', 'security_get_scan', 'security_read_scan_source', 'security_record_attack_path']
    handle = await agents.create({ sessionId, meta: { cwd: process.cwd(), origin: 'subagent', delegationDepth: 1 }, setup(agentCtx) { agentCtx.tools.restrict({ allow: allowed }); agentCtx.systemPrompt.section({ name: `dsh-security-suite:deep-close:${job.id}:${worker.id}`, order: 163, text: closureBrief(job, worker.id) }) } })
    if (cancelledByCaller) return; handle.agent.followup(createUserMessage({ content: [{ type: 'text', text: closureBrief(job, worker.id) }], source: { kind: 'plugin', plugin: 'dsh-security-suite', form: 'relay' } }))
    if (signal) { let remove = (): void => undefined; const aborted = new Promise<void>(wake => { const listener = (): void => wake(); signal.addEventListener('abort', listener, { once: true }); remove = (): void => signal.removeEventListener('abort', listener) }); try { await Promise.race([handle.agent.whenIdle(), aborted]) } finally { remove() } } else await handle.agent.whenIdle()
    if (cancelledByCaller) return; const value = transcript(handle.agent); await updateClosure(config, job.id, current => { const row = current.workers.find(item => item.id === worker.id); if (row) { row.status = 'completed'; row.transcript = value } })
  } catch (error) { if (!cancelledByCaller) await updateClosure(config, job.id, current => { const row = current.workers.find(item => item.id === worker.id); if (row) { row.status = 'failed'; row.error = error instanceof Error ? error.message : String(error) } }) } finally { signal?.removeEventListener('abort', onAbort); if (cancelledByCaller) await updateClosure(config, job.id, current => { const row = current.workers.find(item => item.id === worker.id); if (row && row.status !== 'completed') { row.status = 'cancelled'; row.error = 'Cancelled by the owning DSH tool call.' } }); await dispose() }
}
/** Run a six-worker centralized closure phase. Incomplete worker rounds never claim completion. */
export async function runDeepClosure(ctx: Context, config: Config, jobId: string, signal?: AbortSignal): Promise<DeepClosureJob> {
  let job = await loadDeepClosureJob(config, jobId); if (!['queued', 'cancelled', 'incomplete'].includes(job.lifecycle)) throw new Error('Deep closure job has already completed or failed.'); const capability = deepDiscoveryCapability(ctx); if (!capability.available) { job.lifecycle = 'failed'; await saveClosure(getStateDir(config.stateDir), job); throw new Error(capability.reason) }
  try { await verifyClosureThreatModel(config, job) } catch (error) { job.lifecycle = 'failed'; await saveClosure(getStateDir(config.stateDir), job); throw error }
  if (cancelled(signal)) { job.lifecycle = 'cancelled'; await saveClosure(getStateDir(config.stateDir), job); return job }
  job.lifecycle = 'running'; const round = job.workers.length / WORKERS_PER_ROUND + 1; const workers = Array.from({ length: WORKERS_PER_ROUND }, (_, index) => ({ id: `closure_${job.phase}_${round}_${index + 1}`, status: 'pending' as const })); job.workers.push(...workers); await saveClosure(getStateDir(config.stateDir), job); await Promise.all(workers.map(worker => runClosureWorker(ctx, config, job, worker, signal))); job = await loadDeepClosureJob(config, jobId)
  if (cancelled(signal)) { job.lifecycle = 'cancelled'; await saveClosure(getStateDir(config.stateDir), job); return job }
  const completeWorkers = workers.every(worker => job.workers.find(row => row.id === worker.id)?.status === 'completed'); const scan = await loadScan(getStateDir(config.stateDir), job.scanId); const remaining = scan.tasks.filter(task => task.phase === job.phase && (task.status === 'pending' || task.status === 'claimed'))
  job.completedTaskIds = scan.tasks.filter(task => task.phase === job.phase && task.status === 'completed').map(task => task.id); job.lifecycle = completeWorkers && remaining.length === 0 ? 'completed' : 'incomplete'; await writeArtifact(scan, `artifacts/04_reconciliation/deep-${job.phase}-closure-${job.id}.json`, `${JSON.stringify({ jobId: job.id, phase: job.phase, lifecycle: job.lifecycle, threatModel: job.threatModel, workers: job.workers, completedTaskIds: job.completedTaskIds, remainingTaskIds: remaining.map(task => task.id) }, null, 2)}\n`); scan.activity.push({ at: new Date().toISOString(), phase: job.phase, message: `Centralized deep ${job.phase} closure ${job.lifecycle}: ${job.completedTaskIds.length} completed task(s), ${remaining.length} remaining.` }); await persistInvestigationArtifacts(getStateDir(config.stateDir), scan); await saveScan(getStateDir(config.stateDir), scan); await saveClosure(getStateDir(config.stateDir), job); return job
}
