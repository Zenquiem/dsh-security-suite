import { readFileSync } from 'node:fs'
import { createHash, randomUUID } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { join, relative, resolve } from 'node:path'
import type { Context } from '@deepseek-ai/cordis'
import type { Config } from '../config.js'
import type { ScanRecord } from '../contracts.js'
import { getStateDir, loadScan, persistInvestigationArtifacts, saveScan, sha256, writeArtifact } from '../state.js'
import { loadKnowledgeBase } from './knowledge-base.js'

/**
 * Standard-scan LLM discovery, aligned with the codex-security `security-scan`
 * skill (Apache-2.0, adapted): one independent baseline auditor worker plus
 * focused investigator workers over source-backed investigation packets,
 * followed by one source-backed validation pass. Deterministic engine receipts
 * remain the immutable evidence baseline: every LLM candidate must cite a
 * receipted in-scope location.
 */

export const LLM_DISCOVERY_WORKERS_PER_SCAN = 6

export type LlmDiscoveryLifecycle = 'queued' | 'running' | 'completed' | 'incomplete' | 'cancelled' | 'failed'
export type LlmWorkerKind = 'baseline' | 'investigator'

export interface LlmWorkerLens {
  /** Distinct review perspective for this worker, codex-security investigator perspectives. */
  id: string
  label: string
  brief: string
}

export const INVESTIGATOR_LENSES: LlmWorkerLens[] = [
  { id: 'forward', label: 'Forward dataflow', brief: 'Follow attacker-controlled input, identity, trust boundaries, and controls toward sensitive operations.' },
  { id: 'backward', label: 'Backward from sinks', brief: 'Start at sensitive operations, parsers, execution, credential issuance, or protected assets and trace callers back to a plausible attacker.' },
  { id: 'authorization', label: 'Authorization and business logic', brief: 'Inspect ownership, tenants, permissions, sessions, capabilities, lifecycle transitions, and guard differences across sibling operations.' },
  { id: 'open-ended', label: 'Open-ended source review', brief: 'Investigate promising source-backed security evidence without restricting the search to a predefined vulnerability class or component.' },
]

export interface LlmSourceLocation { path: string; startLine: number; endLine?: number; role?: string }

export interface LlmCandidate {
  /** Stable lowercase vulnerability-family rule id, e.g. path-traversal.archive-extraction. */
  ruleId: string
  title: string
  summary: string
  cwe: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  confidence: 'high' | 'medium' | 'low'
  attacker: string
  violatedInvariant: string
  sourceToSink: string
  impact: string
  remediation: string
  counterevidence: string
  locations: LlmSourceLocation[]
  evidence: Array<{ location: LlmSourceLocation; explanation: string }>
}

export interface LlmWorkerReport {
  findings: LlmCandidate[]
  resolvedQuestions: string[]
  fullyReviewedFileCount: number
}

export interface LlmWorkerState {
  id: string
  kind: LlmWorkerKind
  lens?: string
  packetId?: string
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled'
  token: string
  candidateIds: string[]
  report?: LlmWorkerReport
  error?: string
  transcript?: string
}

export interface LlmPacket {
  id: string
  attacker: string
  protectedAsset: string
  expectedControls: string[]
  entryPoints: string[]
  sensitiveOperations: string[]
  paths: string[]
  questions: string[]
}

export interface LlmDiscoveryJob {
  id: string
  scanId: string
  target: string
  lifecycle: LlmDiscoveryLifecycle
  createdAt: string
  updatedAt: string
  worklistDigest: string
  /** In-scope source paths frozen from scan receipts, ordered by attack-surface signal. */
  worklist: Array<{ path: string; sha256: string; language: string; riskSignals: string[]; priority: number }>
  threatModel: string
  userContext: string
  policyGuidance: string
  knowledgeBasePromptText: string
  baseline: LlmWorkerState
  packets: LlmPacket[]
  investigators: LlmWorkerState[]
  candidates: Array<LlmCandidate & { id: string; workerId: string; workerKind: LlmWorkerKind; packetId?: string; fingerprint: string }>
  notes: string[]
}

/** Risk-signal review leads (mirrors deep-discovery riskSignals). */
function riskSignals(path: string, content: string): string[] {
  const signals: string[] = []
  const value = `${path}\n${content}`
  if (/(?:^|\/)(?:routes?|controllers?|handlers?|api|server|middleware)(?:\/|\.|$)|\b(?:app|router)\.(?:get|post|put|delete|use)\b/i.test(value)) signals.push('externally reachable request surface')
  if (/\b(?:eval|Function|exec(?:File)?|spawn|system|child_process|Runtime\.getRuntime)\b|\b(?:SELECT|INSERT|UPDATE|DELETE)\b/i.test(value)) signals.push('execution or query sink')
  if (/\b(?:fetch|axios|request|http\.request|https\.request|urlopen|net\.Dial)\b|rejectUnauthorized\s*:\s*false|InsecureSkipVerify/i.test(value)) signals.push('outbound network or transport control')
  if (/\b(?:auth|authori[sz]|permission|role|session|jwt|token|oauth)\b/i.test(value)) signals.push('authorization or identity control')
  if (/\b(?:secret|password|api[_-]?key|private[_-]?key|credential)\b/i.test(value)) signals.push('credential or key material')
  if (/\b(?:deserialize|pickle|yaml\.load|XMLParser|ObjectInputStream|unserialize)\b/i.test(value)) signals.push('parser or deserialization boundary')
  return [...new Set(signals)]
}

function inside(workspace: string, path: string): boolean {
  const rel = relative(resolve(workspace), resolve(path))
  return rel === '' || (!rel.startsWith('..') && !resolve(rel).startsWith('..'))
}

/** Deterministically partition in-scope files into source-backed investigation packets. */
export function buildInvestigationPackets(worklist: LlmDiscoveryJob['worklist'], target: string, contentOf: (path: string) => string): LlmPacket[] {
  const byArea: Map<string, string[]> = new Map()
  for (const item of worklist) {
    const area = item.riskSignals[0] ?? 'open-ended'
    byArea.set(area, [...(byArea.get(area) ?? []), item.path])
  }
  const packets: LlmPacket[] = []
  let index = 0
  for (const [area, paths] of byArea) {
    const example = paths[0]
    const snippet = example ? contentOf(example).slice(0, 400) : ''
    const attacker = area.includes('request') || area.includes('authorization') ? 'unauthenticated or lower-trust caller' : 'caller or lower-trust component'
    packets.push({
      id: `packet_${index + 1}`,
      attacker,
      protectedAsset: 'security-sensitive state and operations in scope',
      expectedControls: area.includes('authorization') ? ['authentication and authorization guards before protected operations'] : ['input validation, allowlisting, and containment at the trust boundary'],
      entryPoints: paths.slice(0, 3),
      sensitiveOperations: area.includes('sink') || area.includes('boundary') ? ['execution, query, filesystem, or deserialization sinks'] : ['protected state changes and sensitive operations'],
      paths,
      questions: [
        `Does attacker-controlled input reach ${area.replaceAll('-', ' ')} behavior in these paths without an effective control?`,
        `Are sibling routes or operations guarded differently?${snippet ? `\n\nSource lead (${example}):\n\`\`\`\n${snippet}\n\`\`\`` : ''}`,
      ],
    })
    index++
  }
  if (!packets.length) packets.push({ id: 'packet_1', attacker: 'unauthenticated or lower-trust caller', protectedAsset: 'security-sensitive state and operations in scope', expectedControls: [], entryPoints: [], sensitiveOperations: [], paths: [], questions: ['Review the in-scope source for attacker-controlled input reaching security-sensitive operations.'] })
  return packets
}

function pathFor(state: string, id: string): string {
  if (!/^llmdiscovery_[0-9a-f-]+$/.test(id)) throw new Error('Invalid LLM discovery job id.')
  return join(state, 'llm-discovery', `${id}.json`)
}

async function atomicWrite(path: string, content: string): Promise<void> {
  const { mkdir, rename, writeFile } = await import('node:fs/promises')
  await mkdir(resolve(path, '..'), { recursive: true })
  const temporary = `${path}.${randomUUID()}.tmp`
  await writeFile(temporary, content, 'utf8')
  await rename(temporary, path)
}

const jobWrites = new Map<string, Promise<unknown>>()

async function updateJob(config: Config, id: string, update: (job: LlmDiscoveryJob) => void | Promise<void>): Promise<LlmDiscoveryJob> {
  const previous = jobWrites.get(id) ?? Promise.resolve()
  const barrier = previous.then(async () => {
    const job = await loadLlmDiscoveryJob(config, id)
    await update(job)
    job.updatedAt = new Date().toISOString()
    await atomicWrite(pathFor(getStateDir(config.stateDir), id), `${JSON.stringify(job, null, 2)}\n`)
    return job
  })
  jobWrites.set(id, barrier)
  await previous
  try { return await barrier } finally { if (jobWrites.get(id) === barrier) jobWrites.delete(id) }
}

export async function loadLlmDiscoveryJob(config: Config, id: string): Promise<LlmDiscoveryJob> {
  const { readFile } = await import('node:fs/promises')
  return JSON.parse(await readFile(pathFor(getStateDir(config.stateDir), id), 'utf8')) as LlmDiscoveryJob
}

export async function createLlmDiscoveryJob(config: Config, scanId: string, userContext = ''): Promise<LlmDiscoveryJob> {
  const state = getStateDir(config.stateDir)
  const scan = await loadScan(state, scanId)
  const kb = await loadKnowledgeBase(scan.target, config.knowledgeBase ?? [])
  const rows = await Promise.all(scan.coverage.receipts.map(async receipt => {
    const source = resolve(scan.target, receipt.path)
    if (!inside(scan.target, source)) throw new Error('Scan receipt path is outside the scan target.')
    const content = await readFile(source, 'utf8')
    if (sha256(content) !== receipt.sha256) throw new Error(`Source file changed after scan receipt: ${receipt.path}. Create a follow-up scan before LLM discovery.`)
    const signals = riskSignals(receipt.path, content)
    return { path: receipt.path, sha256: receipt.sha256, language: receipt.language, riskSignals: signals, priority: signals.length * 100 + (receipt.path.includes('/') ? 0 : 10) }
  }))
  const worklist = rows.sort((left, right) => right.priority - left.priority || left.path.localeCompare(right.path))
  const contentOf = (path: string): string => worklist.find(item => item.path === path)?.riskSignals.join(', ') ?? ''
  const packets = buildInvestigationPackets(worklist, scan.target, contentOf)
  const now = new Date().toISOString()
  const job: LlmDiscoveryJob = {
    id: `llmdiscovery_${randomUUID()}`,
    scanId, target: scan.target,
    lifecycle: 'queued', createdAt: now, updatedAt: now,
    worklistDigest: sha256(JSON.stringify(worklist)),
    worklist, threatModel: scan.threatModel, userContext, policyGuidance: scan.policyGuidance,
    knowledgeBasePromptText: kb.promptText,
    baseline: { id: `baseline_1`, kind: 'baseline', status: 'pending', token: randomUUID(), candidateIds: [] },
    packets, investigators: [],
    candidates: [], notes: kb.skipped.length ? [`Knowledge base skipped ${kb.skipped.length} document(s): ${kb.skipped.map(item => `${item.path} (${item.reason})`).join('; ')}`] : [],
  }
  await atomicWrite(pathFor(state, job.id), `${JSON.stringify(job, null, 2)}\n`)
  return job
}

export function activeWorker(job: LlmDiscoveryJob, workerId: string, token: string): LlmWorkerState {
  if (job.lifecycle !== 'running') throw new Error('LLM discovery job is not running.')
  const worker = job.baseline.id === workerId ? job.baseline : job.investigators.find(item => item.id === workerId)
  if (!worker) throw new Error('Worker is not part of this LLM discovery job.')
  if (worker.status !== 'running') throw new Error('Worker is not active for this LLM discovery job.')
  if (worker.token !== token) throw new Error('Worker claim token does not own this worker.')
  return worker
}

export function getLlmScope(config: Config, jobId: string, workerId: string, token: string): { jobId: string; scanId: string; target: string; worklistDigest: string; worklist: Array<{ path: string; language: string; riskSignals: string[] }>; threatModel: string; userContext: string; policyGuidance: string; knowledgeBasePromptText: string; packet?: LlmPacket; lens?: string } {
  const job = loadLlmDiscoveryJobSync(config, jobId)
  const worker = activeWorker(job, workerId, token)
  return {
    jobId, scanId: job.scanId, target: job.target, worklistDigest: job.worklistDigest,
    worklist: job.worklist.map(item => ({ path: item.path, language: item.language, riskSignals: item.riskSignals })),
    threatModel: job.threatModel, userContext: job.userContext, policyGuidance: job.policyGuidance,
    knowledgeBasePromptText: job.knowledgeBasePromptText,
    ...(worker.kind === 'investigator' ? { packet: job.packets.find(packet => packet.id === worker.packetId), lens: worker.lens } : {}),
  }
}

export async function readLlmSource(config: Config, jobId: string, workerId: string, token: string, path: string, startLine?: number, endLine?: number): Promise<{ path: string; sha256: string; startLine: number; endLine: number; content: string }> {
  const job = await loadLlmDiscoveryJob(config, jobId)
  activeWorker(job, workerId, token)
  const item = job.worklist.find(entry => entry.path === path)
  if (!item) throw new Error('Path is not in the LLM discovery in-scope worklist.')
  const source = resolve(job.target, item.path)
  if (!inside(job.target, source)) throw new Error('Path is outside the scan target.')
  const content = await readFile(source, 'utf8')
  if (sha256(content) !== item.sha256) throw new Error('Source file changed after the LLM discovery worklist was created.')
  const lines = content.split(/\r?\n/)
  const from = startLine ?? 1
  const to = endLine ?? Math.min(lines.length || 1, from + 199)
  if (from < 1 || to < from) throw new Error('Invalid source line range.')
  return { path: item.path, sha256: item.sha256, startLine: from, endLine: to, content: lines.slice(from - 1, to).join('\n') }
}

/** Deterministic ripgrep-style regex search over receipted in-scope files. */
export async function searchLlmSource(config: Config, jobId: string, workerId: string, token: string, pattern: string, maxResults = 50): Promise<Array<{ path: string; line: number; text: string }>> {
  const job = await loadLlmDiscoveryJob(config, jobId)
  activeWorker(job, workerId, token)
  let regex: RegExp
  try { regex = new RegExp(pattern, 'i') } catch { throw new Error('Search pattern is not a valid regular expression.') }
  const results: Array<{ path: string; line: number; text: string }> = []
  for (const item of job.worklist) {
    const source = resolve(job.target, item.path)
    if (!inside(job.target, source)) continue
    const content = await readFile(source, 'utf8')
    if (sha256(content) !== item.sha256) throw new Error(`Source file changed after the LLM discovery worklist was created: ${item.path}.`)
    const lines = content.split(/\r?\n/)
    for (let index = 0; index < lines.length && results.length < maxResults; index++) {
      regex.lastIndex = 0
      if (regex.test(lines[index])) results.push({ path: item.path, line: index + 1, text: lines[index].slice(0, 300) })
    }
    if (results.length >= maxResults) break
  }
  return results
}

export interface ReportedLlmCandidateInput {
  ruleId: string
  title: string
  summary: string
  cwe: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  confidence: 'high' | 'medium' | 'low'
  attacker: string
  violatedInvariant: string
  sourceToSink: string
  impact: string
  remediation: string
  counterevidence: string
  locations: Array<{ path: string; startLine: number; endLine?: number; role?: string }>
  evidence: Array<{ location: { path: string; startLine: number; endLine?: number; role?: string }; explanation: string }>
}

function validateLlmCandidate(config: Config, job: LlmDiscoveryJob, candidate: ReportedLlmCandidateInput): LlmCandidate {
  if (!/^[a-z0-9][a-z0-9._/-]*$/.test(candidate.ruleId)) throw new Error('ruleId must be a stable lowercase slug, e.g. path-traversal.archive-extraction.')
  if (!candidate.locations.length) throw new Error('Candidate requires at least one concrete source location.')
  for (const location of candidate.locations) {
    const item = job.worklist.find(entry => entry.path === location.path)
    if (!item) throw new Error(`Candidate location ${location.path} is outside the in-scope worklist.`)
    if (!Number.isInteger(location.startLine) || location.startLine < 1) throw new Error(`Candidate location ${location.path} has an invalid startLine.`)
  }
  return { ...candidate, severity: candidate.severity, confidence: candidate.confidence }
}

export async function reportLlmCandidates(config: Config, jobId: string, workerId: string, token: string, candidates: ReportedLlmCandidateInput[]): Promise<{ recorded: number; candidateIds: string[] }> {
  const state = getStateDir(config.stateDir)
  const scan = await loadScan(state, (await loadLlmDiscoveryJob(config, jobId)).scanId)
  const job = await updateJob(config, jobId, async current => {
    const worker = activeWorker(current, workerId, token)
    for (const input of candidates) {
      const candidate = validateLlmCandidate(config, current, input)
      const fingerprint = sha256(`${candidate.ruleId}:${candidate.locations[0].path}:${candidate.locations[0].startLine}:${candidate.summary}`)
      const id = `llmcand_${sha256(fingerprint).slice(0, 24)}`
      if (current.candidates.some(item => item.id === id)) continue
      current.candidates.push({ ...candidate, id, workerId, workerKind: worker.kind, packetId: worker.packetId, fingerprint })
      worker.candidateIds.push(id)
    }
  })
  // Persist reported candidates into the scan as discovered findings with
  // receipts, reusing the deterministic candidate identity mechanism.
  await updateJob(config, jobId, async current => {
    const fresh = await loadScan(state, current.scanId)
    const added = current.candidates.filter(candidate => !fresh.findings.some(finding => finding.fingerprint === `dsh-llm:${candidate.fingerprint}`))
    if (!added.length) return
    const findings: Array<import('../contracts.js').Finding> = added.map(candidate => ({
      id: `dsf_${sha256(`${scan.targetSnapshot.targetId}:${candidate.ruleId}:${candidate.locations[0].path}:${candidate.locations[0].startLine}`).slice(0, 24)}`,
      candidateId: `cand_${sha256(`${candidate.ruleId}:${candidate.locations[0].path}:${candidate.locations[0].startLine}`).slice(0, 16)}`,
      fingerprint: `dsh-llm:${candidate.fingerprint}`,
      ruleId: candidate.ruleId,
      identity: { anchor: candidate.locations[0].path.replaceAll(/[^a-z0-9]+/gi, '-').toLowerCase() },
      title: candidate.title,
      severity: candidate.severity,
      confidence: candidate.confidence,
      cwe: candidate.cwe,
      status: 'open' as const,
      disposition: 'discovered' as const,
      locations: candidate.locations.map(location => ({ file: location.path, line: location.startLine, excerpt: '', role: (location.role ?? 'root_control') as 'root_control' })),
      rootCause: `${candidate.violatedInvariant}\n\n${candidate.sourceToSink}`,
      validation: 'Discovery candidate from an LLM review worker. Static evidence must establish attacker control, a broken control or sensitive sink, and impact before reportability.',
      attackPath: 'Not established.',
      impact: candidate.impact,
      remediation: candidate.remediation,
      counterevidence: candidate.counterevidence,
      evidence: candidate.evidence.map(item => ({ kind: 'context' as const, detail: item.explanation, location: { file: item.location.path, line: item.location.startLine, excerpt: '' } })),
      ledger: [{ at: new Date().toISOString(), phase: 'discovery' as const, disposition: 'discovered' as const, summary: `LLM ${workerId} reported ${candidate.ruleId} at ${candidate.locations[0].path}:${candidate.locations[0].startLine}.` }],
    }))
    fresh.findings.push(...findings)
    fresh.tasks.push(...findings.map(finding => ({ id: `task_${sha256(`${fresh.id}:${finding.candidateId}:validation`).slice(0, 24)}`, candidateId: finding.candidateId, phase: 'validation' as const, focus: `Validate ${finding.title}: establish attacker, entrypoint, trust boundary, root control, sink, impact, and counterevidence.`, status: 'pending' as const })))
    await saveScan(state, fresh)
  })
  return { recorded: job.candidates.length, candidateIds: job.candidates.map(candidate => candidate.id) }
}

export async function reportLlmWorker(config: Config, jobId: string, workerId: string, token: string, report: LlmWorkerReport): Promise<void> {
  await updateJob(config, jobId, async current => {
    const worker = activeWorker(current, workerId, token)
    if (!Number.isInteger(report.fullyReviewedFileCount) || report.fullyReviewedFileCount < 0) throw new Error('fullyReviewedFileCount must be a nonnegative integer.')
    worker.report = report
    worker.status = 'completed'
  })
}

/** Collect a completed worker's candidates and close coverage. */
export async function collectLlmWorkers(config: Config, jobId: string): Promise<{ candidates: number; completedWorkers: number; totalWorkers: number }> {
  const job = await loadLlmDiscoveryJob(config, jobId)
  const workers = [job.baseline, ...job.investigators]
  const completed = workers.filter(worker => worker.status === 'completed')
  if (completed.length !== workers.length) throw new Error('LLM discovery cannot close before every worker completed.')
  return { candidates: job.candidates.length, completedWorkers: completed.length, totalWorkers: workers.length }
}

function loadLlmDiscoveryJobSync(config: Config, id: string): LlmDiscoveryJob {
  // Synchronous load for tool bodies that already hold the job in memory.
  return JSON.parse(readFileSync(pathFor(getStateDir(config.stateDir), id), 'utf8')) as LlmDiscoveryJob
}

/** Freeze worker and packet artifacts, then seal the completed discovery round. */
export async function persistLlmDiscoveryArtifacts(config: Config, jobId: string): Promise<{ artifactRefs: string[] }> {
  const state = getStateDir(config.stateDir)
  const job = await loadLlmDiscoveryJob(config, jobId)
  const scan = await loadScan(state, job.scanId)
  const refs: string[] = []
  const base = 'artifacts/02_discovery/llm'
  const write = async (path: string, content: string): Promise<void> => { refs.push(await writeArtifact(scan, path, content)) }
  await write(`${base}/rank_input.jsonl`, `${job.worklist.map(item => JSON.stringify({ path: item.path, area: item.riskSignals[0] ?? 'general', preview: '' })).join('\n')}\n`)
  await write(`${base}/deep_review_input.jsonl`, `${job.worklist.map(item => JSON.stringify({ path: item.path, area: item.riskSignals[0] ?? 'general' })).join('\n')}\n`)
  await write(`${base}/packets.json`, `${JSON.stringify(job.packets, null, 2)}\n`)
  for (const worker of [job.baseline, ...job.investigators]) {
    if (!worker.report) continue
    const dir = `${base}/${worker.id}`
    await write(`${dir}/candidates.jsonl`, `${worker.candidateIds.map(id => JSON.stringify(job.candidates.find(candidate => candidate.id === id))).filter(Boolean).join('\n')}\n`)
    await write(`${dir}/report.json`, `${JSON.stringify(worker.report, null, 2)}\n`)
  }
  await write(`${base}/discovery_ledger.md`, ['# LLM Discovery Ledger', '', `- Job: \`${job.id}\``, `- Worklist digest: \`${job.worklistDigest}\``, `- Baseline worker: \`${job.baseline.id}\` (${job.baseline.status})`, `- Investigators: ${job.investigators.map(worker => `\`${worker.id}\` (${worker.lens ?? 'no-lens'}, ${worker.status})`).join(', ')}`, `- Candidates: ${job.candidates.length}`, ...job.notes.map(note => `- Note: ${note}`), ''].join('\n'))
  await persistInvestigationArtifacts(state, scan)
  await saveScan(state, scan)
  return { artifactRefs: refs }
}

/** The worker-bound tool view for LLM discovery workers. */
export const LLM_WORKER_TOOLS = ['security_llm_get_scope', 'security_llm_read_source', 'security_llm_search', 'security_llm_report_candidates', 'security_llm_report_worker'] as const

type NativeAgents = { create?: unknown }

function nativeAgents(ctx: Context): NativeAgents | undefined {
  const get = (ctx as Context & { get?: (name: string) => unknown }).get
  return (typeof get === 'function' ? get.call(ctx, 'agents') : (ctx as Context & { agents?: NativeAgents }).agents) as NativeAgents | undefined
}

/** This suite delegates only through the public DSH agent registry. */
export function llmDiscoveryCapability(ctx: Context): { available: boolean; workers: number; reason?: string } {
  const agents = nativeAgents(ctx)
  if (!agents || typeof agents.create !== 'function') return { available: false, workers: LLM_DISCOVERY_WORKERS_PER_SCAN, reason: 'The active DSH profile has no native agent-creation service.' }
  return { available: true, workers: LLM_DISCOVERY_WORKERS_PER_SCAN }
}

function transcript(agent: { session: { deriveMessages(): Array<{ role: string; content: Array<{ type: string; text?: string }> }> } }): string {
  return agent.session.deriveMessages().filter(message => message.role === 'assistant').flatMap(message => message.content.filter(block => block.type === 'text' || block.type === 'reasoning').map(block => block.text ?? '')).join('\n\n').slice(-200_000)
}

function cancelled(signal: AbortSignal | undefined): boolean { return signal?.aborted === true }

async function runLlmWorker(ctx: Context, config: Config, job: LlmDiscoveryJob, worker: LlmWorkerState, prompt: string, signal?: AbortSignal): Promise<void> {
  const { createUserMessage } = await import('@deepseek-ai/dsh-llm')
  const { SessionId } = await import('@deepseek-ai/dsh-session')
  const sessionId = SessionId(`dsh-security-llm-${randomUUID()}`)
  await updateJob(config, job.id, current => { const record = current.baseline.id === worker.id ? current.baseline : current.investigators.find(item => item.id === worker.id); if (!record) throw new Error('LLM discovery worker was not created.'); record.status = 'running' })
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
      agentCtx.tools.restrict({ allow: [...LLM_WORKER_TOOLS] })
      agentCtx.systemPrompt.section({ name: `dsh-security-suite:llm-worker:${worker.id}`, order: 162, text: prompt })
    } })
    if (cancelledByCaller) return
    handle.agent.followup(createUserMessage({ content: [{ type: 'text', text: prompt }], source: { kind: 'plugin', plugin: 'dsh-security-suite', form: 'relay' } }))
    if (signal) {
      let removeAbortWait = (): void => undefined
      const aborted = new Promise<void>(resolveAbort => { const wake = (): void => resolveAbort(); signal.addEventListener('abort', wake, { once: true }); removeAbortWait = (): void => signal.removeEventListener('abort', wake) })
      try { await Promise.race([handle.agent.whenIdle(), aborted]) } finally { removeAbortWait() }
    } else await handle.agent.whenIdle()
    if (cancelledByCaller) return
    const workerTranscript = transcript(handle.agent)
    await updateJob(config, job.id, current => { const record = current.baseline.id === worker.id ? current.baseline : current.investigators.find(item => item.id === worker.id); if (record && record.status === 'running') { record.transcript = workerTranscript; record.status = 'completed' } })
  } catch (error) {
    if (cancelledByCaller) return
    const message = error instanceof Error ? error.message : String(error)
    await updateJob(config, job.id, current => { const record = current.baseline.id === worker.id ? current.baseline : current.investigators.find(item => item.id === worker.id); if (record && record.status === 'running') { record.status = 'failed'; record.error = message } })
  } finally {
    signal?.removeEventListener('abort', onAbort)
    if (cancelledByCaller) await updateJob(config, job.id, current => { const record = current.baseline.id === worker.id ? current.baseline : current.investigators.find(item => item.id === worker.id); if (record && record.status !== 'completed') { record.status = 'cancelled'; record.error = 'Cancelled by the owning DSH tool call.' } })
    await dispose()
  }
}

/**
 * Run one standard-scan LLM discovery job: one independent baseline auditor,
 * then focused investigators per source-backed packet, then persist artifacts
 * and scan candidates. Nonterminal worker failure marks the job incomplete.
 */
export async function runLlmDiscovery(ctx: Context, config: Config, jobId: string, signal?: AbortSignal): Promise<LlmDiscoveryJob> {
  const state = getStateDir(config.stateDir)
  let job = await loadLlmDiscoveryJob(config, jobId)
  if (!['queued', 'cancelled', 'incomplete'].includes(job.lifecycle)) throw new Error('LLM discovery job has already completed or failed.')
  const capability = llmDiscoveryCapability(ctx)
  if (!capability.available) {
    await updateJob(config, jobId, current => { current.lifecycle = 'failed' })
    throw new Error(capability.reason ?? 'The active DSH profile has no native agent-creation service.')
  }
  await updateJob(config, jobId, current => { current.lifecycle = 'running' })
  job = await loadLlmDiscoveryJob(config, jobId)
  const { baselineAuditorPrompt, focusedInvestigatorPrompt } = await import('./prompts.js')
  const shared: Omit<Parameters<typeof baselineAuditorPrompt>[0], 'jobId' | 'workerId' | 'claimToken' | 'lens' | 'packet'> = {
    worklistDigest: job.worklistDigest, target: job.target, threatModel: job.threatModel, userContext: job.userContext,
    policyGuidance: job.policyGuidance, knowledgeBasePromptText: job.knowledgeBasePromptText, scanPrompt: config.scanPrompt,
  }
  const baselinePrompt = baselineAuditorPrompt({ ...shared, jobId: job.id, workerId: job.baseline.id, claimToken: job.baseline.token })
  await runLlmWorker(ctx, config, job, job.baseline, baselinePrompt, signal)
  job = await loadLlmDiscoveryJob(config, jobId)
  if (job.baseline.status !== 'completed') {
    await updateJob(config, jobId, current => { current.lifecycle = current.baseline.status === 'cancelled' ? 'cancelled' : 'incomplete' })
    return loadLlmDiscoveryJob(config, jobId)
  }
  // Build one investigator per packet, capped at the remaining worker slots.
  const slots = Math.max(1, LLM_DISCOVERY_WORKERS_PER_SCAN - 1)
  const assignments = job.packets.slice(0, slots).map((packet, index) => {
    const lens = INVESTIGATOR_LENSES[index % INVESTIGATOR_LENSES.length]
    return { packet, lens }
  })
  await updateJob(config, jobId, current => {
    current.investigators = assignments.map((assignment, index) => ({
      id: `investigator_${index + 1}`, kind: 'investigator' as const, lens: assignment.lens.id, packetId: assignment.packet.id,
      status: 'pending' as const, token: randomUUID(), candidateIds: [],
    }))
  })
  job = await loadLlmDiscoveryJob(config, jobId)
  await Promise.all(job.investigators.map(worker => {
    const assignment = assignments.find(item => item.packet.id === worker.packetId)
    const prompt = focusedInvestigatorPrompt({ ...shared, jobId: job.id, workerId: worker.id, claimToken: worker.token, lens: assignment?.lens, packet: job.packets.find(packet => packet.id === worker.packetId) ?? job.packets[0] }, job.packets.find(packet => packet.id === worker.packetId) ?? job.packets[0])
    return runLlmWorker(ctx, config, job, worker, prompt, signal)
  }))
  job = await loadLlmDiscoveryJob(config, jobId)
  const allComplete = job.baseline.status === 'completed' && job.investigators.every(worker => worker.status === 'completed')
  const anyCancelled = cancelled(signal)
  await updateJob(config, jobId, current => { current.lifecycle = anyCancelled ? 'cancelled' : allComplete ? 'completed' : 'incomplete' })
  if (allComplete) await persistLlmDiscoveryArtifacts(config, jobId)
  return loadLlmDiscoveryJob(config, jobId)
}

/** Create a scan, freeze the LLM discovery worklist, and run the full standard-scan LLM discovery. */
export async function runLlmScan(ctx: Context, config: Config, target: string, options: { threatModel?: string; scopeRequested?: boolean; userContext?: string; signal?: AbortSignal } = {}): Promise<{ scan: ScanRecord; jobId: string }> {
  const { runScan } = await import('../scanner.js')
  const scan = await runScan(target, config, 'standard', options.threatModel ?? '', options.scopeRequested ?? false, config.stateDir, false)
  await persistInvestigationArtifacts(getStateDir(config.stateDir), scan)
  await saveScan(getStateDir(config.stateDir), scan)
  const job = await createLlmDiscoveryJob(config, scan.id, options.userContext ?? '')
  await runLlmDiscovery(ctx, config, job.id, options.signal)
  return { scan: await loadScan(getStateDir(config.stateDir), scan.id), jobId: job.id }
}
