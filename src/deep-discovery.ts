import { mkdir, readFile, rename, writeFile } from 'node:fs/promises'
import { isAbsolute, join, relative, resolve } from 'node:path'
import { randomUUID } from 'node:crypto'
import type { Context } from '@deepseek-ai/cordis'
import { createUserMessage } from '@deepseek-ai/dsh-llm'
import { SessionId } from '@deepseek-ai/dsh-session'
import type {} from '@deepseek-ai/dsh-agent'
import type { Config } from './config.js'
import type { Finding, ScanRecord, Severity } from './contracts.js'
import { candidateId, findingId, getStateDir, loadScan, persistInvestigationArtifacts, saveScan, sha256 } from './state.js'

const WORKERS_PER_ROUND = 6
const jobWrites = new Map<string, Promise<void>>()
export interface DeepCandidateInput { ruleId: string; title: string; severity: Severity; cwe: string; file: string; line: number; rootCause: string }
export interface DeepCandidate extends DeepCandidateInput { id: string; workerId: string; excerpt: string; fingerprint: string; reportedAt: string }
export interface DeepWorker { id: string; round: number; status: 'pending' | 'running' | 'completed' | 'failed'; token: string; sessionId?: string; transcript?: string; error?: string; candidateIds: string[] }
export interface DeepRound { number: number; workerIds: string[]; candidateCount: number; novelty: number; status: 'running' | 'complete' | 'incomplete' }
export interface DeepDiscoveryJob { id: string; scanId: string; target: string; createdAt: string; updatedAt: string; lifecycle: 'queued' | 'running' | 'saturated' | 'capped' | 'incomplete' | 'failed'; maxRounds: number; rounds: DeepRound[]; workers: DeepWorker[]; candidates: DeepCandidate[] }

/** This suite delegates only through the public DSH agent registry. */
export function deepDiscoveryCapability(ctx: Context): { available: boolean; workersPerRound: number; reason?: string } {
  const agents = (ctx as Context & { agents?: { create?: unknown } }).agents
  if (!agents || typeof agents.create !== 'function') return { available: false, workersPerRound: WORKERS_PER_ROUND, reason: 'The active DSH profile has no native agent-creation service.' }
  return { available: true, workersPerRound: WORKERS_PER_ROUND }
}

function inside(root: string, path: string): boolean { const item = relative(root, path); return item === '' || (!item.startsWith('..') && !isAbsolute(item)) }
function slug(value: string): string { return value.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '') || 'root-control' }
function jobPath(state: string, id: string): string { if (!/^deep_[0-9a-f-]+$/.test(id)) throw new Error('Invalid deep discovery job id.'); return join(state, 'deep-discovery', `${id}.json`) }
async function atomic(path: string, content: string): Promise<void> { await mkdir(resolve(path, '..'), { recursive: true }); const temp = `${path}.${randomUUID()}.tmp`; await writeFile(temp, content, 'utf8'); await rename(temp, path) }
async function save(state: string, job: DeepDiscoveryJob): Promise<void> { job.updatedAt = new Date().toISOString(); await atomic(jobPath(state, job.id), `${JSON.stringify(job, null, 2)}\n`) }
export async function loadDeepDiscoveryJob(config: Config, id: string): Promise<DeepDiscoveryJob> { return JSON.parse(await readFile(jobPath(getStateDir(config.stateDir), id), 'utf8')) as DeepDiscoveryJob }

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

export async function createDeepDiscoveryJob(config: Config, scanId: string, maxRounds = 10): Promise<DeepDiscoveryJob> {
  const scan = await loadScan(getStateDir(config.stateDir), scanId); if (scan.mode !== 'deep') throw new Error('Delegated deep discovery requires a scan started in deep mode.'); if (scan.lifecycle === 'completed') throw new Error('Completed scans cannot accept new discovery candidates.')
  const now = new Date().toISOString(); const job: DeepDiscoveryJob = { id: `deep_${randomUUID()}`, scanId, target: scan.target, createdAt: now, updatedAt: now, lifecycle: 'queued', maxRounds: Math.max(1, Math.min(maxRounds, 10)), rounds: [], workers: [], candidates: [] }; await save(getStateDir(config.stateDir), job); return job
}

export async function reportDeepCandidate(config: Config, jobId: string, workerId: string, token: string, input: DeepCandidateInput): Promise<DeepCandidate> {
  return updateJob(config, jobId, async job => {
    if (job.lifecycle !== 'running') throw new Error('Deep discovery job is not accepting candidates.')
    const worker = job.workers.find(item => item.id === workerId); if (!worker || worker.token !== token || worker.status !== 'running') throw new Error('Deep discovery worker claim is invalid.')
    if (!/^[a-z][a-z0-9.-]{2,100}$/.test(input.ruleId) || !input.title.trim() || !input.cwe.trim() || !Number.isInteger(input.line) || input.line < 1) throw new Error('Candidate fields are invalid.')
    const source = resolve(job.target, input.file); if (!inside(job.target, source)) throw new Error('Candidate location is outside the deep-scan target.')
    const lines = (await readFile(source, 'utf8')).split(/\r?\n/); const excerpt = lines[input.line - 1]?.trim().slice(0, 240); if (!excerpt) throw new Error('Candidate location does not identify a readable source line.')
    const fingerprint = sha256(`${input.ruleId}:${input.file}:${excerpt.replace(/\s+/g, ' ')}`); const existing = job.candidates.find(item => item.fingerprint === fingerprint); if (existing) return existing
    const candidate: DeepCandidate = { ...input, id: `deepcand_${sha256(`${job.id}:${workerId}:${fingerprint}`).slice(0, 24)}`, workerId, excerpt, fingerprint, reportedAt: new Date().toISOString() }; job.candidates.push(candidate); worker.candidateIds.push(candidate.id); return candidate
  })
}

function transcript(agent: { session: { deriveMessages(): Array<{ role: string; content: Array<{ type: string; text?: string }> }> } }): string { return agent.session.deriveMessages().filter(message => message.role === 'assistant').flatMap(message => message.content.filter(block => block.type === 'text' || block.type === 'reasoning').map(block => block.text ?? '')).join('\n\n').slice(-200_000) }
function brief(job: DeepDiscoveryJob, worker: DeepWorker): string { return `You are one of six independent DSH security discovery workers. Inspect the target directory ${job.target} for plausible security vulnerabilities. Do not modify source, do not validate or fix findings, and do not use external services. For every distinct candidate with a concrete local source line, call security_deep_report_candidate with job_id ${job.id}, worker_id ${worker.id}, claim_token ${worker.token}, stable rule_id, title, severity, CWE, workspace-relative file, line, and root_cause. Report only candidates you can support with source evidence. When finished, provide a concise summary of reviewed surfaces and any proof gaps.` }

async function runWorker(ctx: Context, config: Config, job: DeepDiscoveryJob, worker: DeepWorker): Promise<void> {
  const sessionId = SessionId(`dsh-security-deep-${randomUUID()}`)
  await updateJob(config, job.id, current => { const record = current.workers.find(item => item.id === worker.id); if (!record) throw new Error('Deep discovery worker was not created.'); record.status = 'running'; record.sessionId = sessionId as unknown as string })
  let handle: Awaited<ReturnType<typeof ctx.agents.create>> | undefined
  try {
    handle = await ctx.agents.create({ sessionId, meta: { cwd: resolve(job.target), origin: 'subagent', delegationDepth: 1 } })
    handle.agent.followup(createUserMessage({ content: [{ type: 'text', text: brief(job, worker) }], source: { kind: 'plugin', plugin: 'dsh-security-suite', form: 'relay' } }))
    await handle.agent.whenIdle()
    const workerTranscript = transcript(handle.agent)
    await updateJob(config, job.id, current => { const record = current.workers.find(item => item.id === worker.id); if (record) { record.transcript = workerTranscript; record.status = 'completed' } })
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    await updateJob(config, job.id, current => { const record = current.workers.find(item => item.id === worker.id); if (record) { record.status = 'failed'; record.error = message } })
  } finally { await handle?.dispose().catch(() => undefined) }
}

function addCandidate(scan: ScanRecord, candidate: DeepCandidate): void {
  if (scan.findings.some(finding => finding.fingerprint === candidate.fingerprint)) return
  const anchor = slug(`${candidate.file}-${candidate.excerpt}`); const id = candidateId(candidate.ruleId, candidate.file, candidate.line); const finding: Finding = { id: findingId(candidate.ruleId, anchor), candidateId: id, fingerprint: candidate.fingerprint, ruleId: candidate.ruleId, identity: { anchor, instance: slug(`${candidate.file}-${candidate.line}`) }, title: candidate.title, severity: candidate.severity, confidence: 'low', cwe: candidate.cwe, status: 'open', disposition: 'discovered', locations: [{ file: candidate.file, line: candidate.line, excerpt: candidate.excerpt, role: 'root_control' }], rootCause: candidate.rootCause, validation: 'Discovery-only delegated candidate. Validate source, closest control, sink, reachability, impact, and counterevidence.', attackPath: 'Not established.', impact: 'Not established.', remediation: 'Determine the narrowest effective control after validation.', counterevidence: 'No validation has been completed.', evidence: [{ kind: 'pattern', detail: `Independent delegated discovery worker ${candidate.workerId} reported this candidate.`, location: { file: candidate.file, line: candidate.line, excerpt: candidate.excerpt, role: 'root_control' } }], ledger: [{ at: candidate.reportedAt, phase: 'discovery', disposition: 'discovered', summary: `Delegated worker ${candidate.workerId} reported ${candidate.ruleId}.` }] }
  scan.findings.push(finding); scan.tasks.push({ id: `task_${sha256(`${scan.id}:${id}:validation`).slice(0, 24)}`, candidateId: id, phase: 'validation', focus: `Validate delegated discovery candidate ${finding.title}: establish attacker, entrypoint, control, sink, impact, and counterevidence.`, status: 'pending' })
}

export async function runDeepDiscovery(ctx: Context, config: Config, jobId: string): Promise<DeepDiscoveryJob> {
  const state = getStateDir(config.stateDir); let job = await loadDeepDiscoveryJob(config, jobId); if (job.lifecycle !== 'queued') throw new Error('Deep discovery job has already started or ended.')
  const capability = deepDiscoveryCapability(ctx)
  if (!capability.available) {
    job.lifecycle = 'failed'; await save(state, job)
    throw new Error(capability.reason)
  }
  job.lifecycle = 'running'; await save(state, job)
  let known = new Set<string>()
  for (let number = 1; number <= job.maxRounds; number++) {
    const workers = Array.from({ length: WORKERS_PER_ROUND }, (_, index): DeepWorker => ({ id: `worker_${number}_${index + 1}`, round: number, status: 'pending', token: randomUUID(), candidateIds: [] })); job.workers.push(...workers); const round: DeepRound = { number, workerIds: workers.map(worker => worker.id), candidateCount: 0, novelty: 0, status: 'running' }; job.rounds.push(round); await save(state, job)
    await Promise.all(workers.map(worker => runWorker(ctx, config, job, worker)))
    job = await loadDeepDiscoveryJob(config, jobId)
    const completedRound = job.rounds.find(item => item.number === number); if (!completedRound) throw new Error('Deep discovery round state is missing.')
    const incomplete = workers.some(worker => job.workers.find(item => item.id === worker.id)?.status !== 'completed'); const candidates = job.candidates.filter(candidate => workers.some(worker => worker.id === candidate.workerId)); completedRound.candidateCount = candidates.length; completedRound.novelty = candidates.filter(candidate => !known.has(candidate.fingerprint)).length; for (const candidate of candidates) known.add(candidate.fingerprint); completedRound.status = incomplete ? 'incomplete' : 'complete'; await save(state, job)
    if (incomplete) { job.lifecycle = 'incomplete'; await save(state, job); return job }
    if (completedRound.novelty === 0) { job.lifecycle = 'saturated'; break }
    if (number === job.maxRounds) job.lifecycle = 'capped'
  }
  const scan = await loadScan(state, job.scanId); for (const candidate of job.candidates) addCandidate(scan, candidate); scan.activity.push({ at: new Date().toISOString(), phase: 'discovery', message: `Delegated deep discovery ${job.lifecycle}: ${job.rounds.length} complete rounds, ${job.candidates.length} worker candidates.` }); await persistInvestigationArtifacts(state, scan); await saveScan(state, scan); await save(state, job); return job
}
