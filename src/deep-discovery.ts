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
import { candidateId, findingId, getStateDir, loadScan, persistInvestigationArtifacts, saveScan, sha256, writeArtifact } from './state.js'

const WORKERS_PER_ROUND = 6
const jobWrites = new Map<string, Promise<void>>()
export interface DeepCandidateInput { ruleId: string; title: string; severity: Severity; cwe: string; file: string; line: number; rootCause: string }
export interface DeepCandidate extends DeepCandidateInput { id: string; workerId: string; workerIds: string[]; reportIds: string[]; excerpt: string; fingerprint: string; reportedAt: string }
export interface DeepWorkerReport { threatModel: string; reviewedPaths: string[]; deferred: Array<{ path: string; reason: string }>; coverageSummary: string; reportedAt: string }
export interface DeepWorker { id: string; round: number; status: 'pending' | 'running' | 'completed' | 'cancelled' | 'failed'; token: string; sessionId?: string; transcript?: string; error?: string; candidateIds: string[]; report?: DeepWorkerReport }
export interface DeepRound { number: number; workerIds: string[]; candidateCount: number; novelty: number; status: 'running' | 'complete' | 'incomplete'; artifactRefs?: string[] }
export interface DeepWorkItem { path: string; sha256: string; language: string }
export interface DeepDiscoveryJob { id: string; scanId: string; target: string; createdAt: string; updatedAt: string; lifecycle: 'queued' | 'running' | 'saturated' | 'capped' | 'incomplete' | 'cancelled' | 'failed'; maxRounds: number; worklist: DeepWorkItem[]; worklistDigest: string; rounds: DeepRound[]; workers: DeepWorker[]; candidates: DeepCandidate[] }

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
  const state = getStateDir(config.stateDir); const scan = await loadScan(state, scanId); if (scan.mode !== 'deep') throw new Error('Delegated deep discovery requires a scan started in deep mode.'); if (scan.lifecycle === 'completed') throw new Error('Completed scans cannot accept new discovery candidates.')
  const worklist = scan.coverage.receipts.map(item => ({ path: item.path, sha256: item.sha256, language: item.language })).sort((left, right) => left.path.localeCompare(right.path))
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
    const source = resolve(job.target, input.file); if (!inside(job.target, source)) throw new Error('Candidate location is outside the deep-scan target.')
    const lines = (await readFile(source, 'utf8')).split(/\r?\n/); const excerpt = lines[input.line - 1]?.trim().slice(0, 240); if (!excerpt) throw new Error('Candidate location does not identify a readable source line.')
    const fingerprint = sha256(`${input.ruleId}:${input.file}:${excerpt.replace(/\s+/g, ' ')}`); const reportId = `deepreport_${sha256(`${job.id}:${workerId}:${fingerprint}`).slice(0, 24)}`; const existing = job.candidates.find(item => item.fingerprint === fingerprint)
    if (existing) { if (!existing.workerIds.includes(workerId)) existing.workerIds.push(workerId); if (!existing.reportIds.includes(reportId)) existing.reportIds.push(reportId); if (!worker.candidateIds.includes(existing.id)) worker.candidateIds.push(existing.id); return existing }
    const candidate: DeepCandidate = { ...input, id: `deepcand_${sha256(`${job.id}:${workerId}:${fingerprint}`).slice(0, 24)}`, workerId, workerIds: [workerId], reportIds: [reportId], excerpt, fingerprint, reportedAt: new Date().toISOString() }; job.candidates.push(candidate); worker.candidateIds.push(candidate.id); return candidate
  })
}

export async function reportDeepWorker(config: Config, jobId: string, workerId: string, token: string, input: { threatModel: string; reviewedPaths: string[]; deferred: Array<{ path: string; reason: string }>; coverageSummary: string }): Promise<DeepWorkerReport> {
  return updateJob(config, jobId, job => {
    if (job.lifecycle !== 'running') throw new Error('Deep discovery job is not accepting worker reports.')
    const worker = job.workers.find(item => item.id === workerId); if (!worker || worker.token !== token || worker.status !== 'running') throw new Error('Deep discovery worker claim is invalid.')
    if (input.threatModel.trim().length < 40 || input.coverageSummary.trim().length < 10) throw new Error('Worker threat model and coverage summary must contain substantive evidence.')
    const required = new Set(job.worklist.map(item => item.path)); const reviewed = new Set(input.reviewedPaths)
    const deferred = new Map(input.deferred.map(item => [item.path, item.reason.trim()] as const))
    if ([...reviewed].some(path => !required.has(path)) || [...deferred.keys()].some(path => !required.has(path))) throw new Error('Worker coverage report contains a path outside the authoritative worklist.')
    for (const path of required) if (!reviewed.has(path) && !deferred.has(path)) throw new Error(`Worker coverage report leaves authoritative worklist path unclosed: ${path}`)
    if ([...deferred.values()].some(reason => reason.length < 3)) throw new Error('Deferred worklist paths require a concrete reason.')
    const report: DeepWorkerReport = { threatModel: input.threatModel.trim().slice(0, 100_000), reviewedPaths: [...reviewed].sort(), deferred: [...deferred.entries()].map(([path, reason]) => ({ path, reason })).sort((left, right) => left.path.localeCompare(right.path)), coverageSummary: input.coverageSummary.trim().slice(0, 20_000), reportedAt: new Date().toISOString() }
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

export async function readDeepSource(config: Config, jobId: string, workerId: string, token: string, path: string, startLine = 1, endLine = 400): Promise<{ path: string; startLine: number; endLine: number; content: string; sha256: string }> {
  const job = await loadDeepDiscoveryJob(config, jobId); activeWorker(job, workerId, token)
  const item = job.worklist.find(row => row.path === path); if (!item) throw new Error('Source path is not in the authoritative deep-discovery worklist.')
  const start = Math.max(1, Math.floor(startLine)); const end = Math.max(start, Math.min(start + 399, Math.floor(endLine)))
  const source = resolve(job.target, item.path); if (!inside(job.target, source)) throw new Error('Source path is outside the deep-scan target.')
  const content = await readFile(source, 'utf8'); const digest = sha256(content); if (digest !== item.sha256) throw new Error('Source file changed after the authoritative deep-discovery worklist was created.')
  const lines = content.split(/\r?\n/); return { path: item.path, startLine: start, endLine: Math.min(end, lines.length), content: lines.slice(start - 1, end).join('\n'), sha256: digest }
}

function transcript(agent: { session: { deriveMessages(): Array<{ role: string; content: Array<{ type: string; text?: string }> }> } }): string { return agent.session.deriveMessages().filter(message => message.role === 'assistant').flatMap(message => message.content.filter(block => block.type === 'text' || block.type === 'reasoning').map(block => block.text ?? '')).join('\n\n').slice(-200_000) }
function brief(job: DeepDiscoveryJob, worker: DeepWorker): string { return `You are one of six independent DSH security discovery workers. You have exactly four DSH tools: security_deep_get_worklist, security_deep_read_source, security_deep_report_candidate, and security_deep_report_worker. Do not modify source, validate or fix findings, or use external services. Call security_deep_get_worklist with job_id ${job.id}, worker_id ${worker.id}, claim_token ${worker.token}; confirm its digest is ${job.worklistDigest}; then inspect every returned path with security_deep_read_source. Independently create a source-evidenced worker threat model; do not use another worker's analysis. For every distinct candidate with a concrete local source line, call security_deep_report_candidate with job_id ${job.id}, worker_id ${worker.id}, claim_token ${worker.token}, stable rule_id, title, severity, CWE, workspace-relative file, line, and root_cause. When all worklist rows are closed, call security_deep_report_worker with job_id ${job.id}, worker_id ${worker.id}, claim_token ${worker.token}, your worker threat model, every reviewed path, explicit deferred rows with reasons, and a coverage summary. A worker run without that report is incomplete. Report only candidates you can support with source evidence.` }

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

function addCandidate(scan: ScanRecord, candidate: DeepCandidate): void {
  if (scan.findings.some(finding => finding.fingerprint === candidate.fingerprint)) return
  const anchor = slug(`${candidate.file}-${candidate.excerpt}`); const id = candidateId(candidate.ruleId, candidate.file, candidate.line); const reporters = candidate.workerIds.join(', '); const finding: Finding = { id: findingId(candidate.ruleId, anchor), candidateId: id, fingerprint: candidate.fingerprint, ruleId: candidate.ruleId, identity: { anchor, instance: slug(`${candidate.file}-${candidate.line}`) }, title: candidate.title, severity: candidate.severity, confidence: 'low', cwe: candidate.cwe, status: 'open', disposition: 'discovered', locations: [{ file: candidate.file, line: candidate.line, excerpt: candidate.excerpt, role: 'root_control' }], rootCause: candidate.rootCause, validation: 'Discovery-only delegated candidate. Validate source, closest control, sink, reachability, impact, and counterevidence.', attackPath: 'Not established.', impact: 'Not established.', remediation: 'Determine the narrowest effective control after validation.', counterevidence: 'No validation has been completed.', evidence: [{ kind: 'pattern', detail: `Independent delegated discovery workers ${reporters} reported this candidate; absorbed report ids: ${candidate.reportIds.join(', ')}.`, location: { file: candidate.file, line: candidate.line, excerpt: candidate.excerpt, role: 'root_control' } }], ledger: [{ at: candidate.reportedAt, phase: 'discovery', disposition: 'discovered', summary: `Delegated workers ${reporters} reported ${candidate.ruleId}; absorbed reports: ${candidate.reportIds.join(', ')}.` }] }
  scan.findings.push(finding); scan.tasks.push({ id: `task_${sha256(`${scan.id}:${id}:validation`).slice(0, 24)}`, candidateId: id, phase: 'validation', focus: `Validate delegated discovery candidate ${finding.title}: establish attacker, entrypoint, control, sink, impact, and counterevidence.`, status: 'pending' })
}

function completeWorkerIds(job: DeepDiscoveryJob): Set<string> {
  return new Set(job.rounds.filter(round => round.status === 'complete').flatMap(round => round.workerIds))
}

async function persistRoundArtifacts(scan: ScanRecord, job: DeepDiscoveryJob, round: DeepRound): Promise<string[]> {
  const workers = round.workerIds.map(id => job.workers.find(worker => worker.id === id)).filter((worker): worker is DeepWorker => Boolean(worker))
  const refs: string[] = []
  for (const worker of workers) {
    const base = `artifacts/02_discovery/deep/round-${String(round.number).padStart(2, '0')}/${worker.id}`; const report = worker.report
    if (!report) continue
    refs.push(await writeArtifact(scan, `${base}/threat_model.md`, `${report.threatModel}\n`))
    refs.push(await writeArtifact(scan, `${base}/coverage.json`, `${JSON.stringify({ worklistDigest: job.worklistDigest, reviewedPaths: report.reviewedPaths, deferred: report.deferred, summary: report.coverageSummary }, null, 2)}\n`))
    const candidates = job.candidates.filter(candidate => candidate.workerIds.includes(worker.id))
    refs.push(await writeArtifact(scan, `${base}/candidates.jsonl`, `${candidates.map(candidate => JSON.stringify(candidate)).join('\n')}\n`))
    refs.push(await writeArtifact(scan, `${base}/summary.md`, `# Deep Discovery Worker ${worker.id}\n\n- Status: ${worker.status}\n- Reviewed: ${report.reviewedPaths.length}\n- Deferred: ${report.deferred.length}\n- Candidates: ${candidates.length}\n\n${report.coverageSummary}\n`))
    if (worker.transcript) refs.push(await writeArtifact(scan, `${base}/transcript.md`, `${worker.transcript}\n`))
  }
  const ledger = job.workers.filter(worker => worker.round <= round.number).map(worker => JSON.stringify({ round: worker.round, workerId: worker.id, status: worker.status, hasReport: Boolean(worker.report), reviewed: worker.report?.reviewedPaths.length ?? 0, deferred: worker.report?.deferred.length ?? 0, candidateIds: worker.candidateIds })).join('\n')
  refs.push(await writeArtifact(scan, 'artifacts/02_discovery/work_ledger.jsonl', `${ledger}\n`))
  const canonical = job.candidates.map(candidate => ({ id: candidate.id, fingerprint: candidate.fingerprint, ruleId: candidate.ruleId, title: candidate.title, file: candidate.file, line: candidate.line, workerIds: candidate.workerIds, reportIds: candidate.reportIds }))
  const merge = { jobId: job.id, round: round.number, workers: workers.map(worker => ({ id: worker.id, status: worker.status, report: Boolean(worker.report), candidateIds: worker.candidateIds })), canonicalCandidates: canonical, novelty: round.novelty }
  refs.push(await writeArtifact(scan, `artifacts/04_reconciliation/deep-round-${String(round.number).padStart(2, '0')}-merge.json`, `${JSON.stringify(merge, null, 2)}\n`))
  refs.push(await writeArtifact(scan, 'artifacts/04_reconciliation/deduped_candidates.jsonl', `${canonical.map(candidate => JSON.stringify(candidate)).join('\n')}\n`))
  refs.push(await writeArtifact(scan, 'artifacts/04_reconciliation/dedupe_report.md', `# Deep Discovery Reconciliation\n\n- Job: \`${job.id}\`\n- Completed rounds: ${job.rounds.filter(item => item.status === 'complete').length}\n- Canonical candidates: ${canonical.length}\n\n${canonical.map(candidate => `- \`${candidate.id}\`: ${candidate.ruleId} at ${candidate.file}:${candidate.line}; absorbed workers ${candidate.workerIds.join(', ')}.`).join('\n')}\n`))
  const closures = job.worklist.map(item => {
    const completed = workers.filter(worker => worker.report?.reviewedPaths.includes(item.path)).map(worker => worker.id)
    const deferred = workers.flatMap(worker => worker.report?.deferred.filter(row => row.path === item.path).map(row => `${worker.id}: ${row.reason}`) ?? [])
    return `| \`${item.path}\` | ${item.language} | ${completed.length}/${workers.length} | ${deferred.length ? deferred.join('; ') : 'none'} |`
  })
  refs.push(await writeArtifact(scan, 'artifacts/03_coverage/repository_coverage_ledger.md', `# Repository Coverage Ledger\n\n- Authoritative worklist digest: \`${job.worklistDigest}\`\n- Round: ${round.number}\n\n| Surface | Language | Worker closures | Deferred |\n| --- | --- | --- | --- |\n${closures.join('\n')}\n`))
  refs.push(await writeArtifact(scan, 'artifacts/03_coverage/reviewed_surfaces.md', `# Reviewed Surfaces\n\n${job.worklist.map(item => `- \`${item.path}\` (${item.language}): reviewed by ${workers.filter(worker => worker.report?.reviewedPaths.includes(item.path)).length}/${workers.length} workers.`).join('\n')}\n`))
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
    const workers = Array.from({ length: WORKERS_PER_ROUND }, (_, index): DeepWorker => ({ id: `worker_${number}_${index + 1}`, round: number, status: 'pending', token: randomUUID(), candidateIds: [] })); job.workers.push(...workers); const round: DeepRound = { number, workerIds: workers.map(worker => worker.id), candidateCount: 0, novelty: 0, status: 'running' }; job.rounds.push(round); await save(state, job)
    await Promise.all(workers.map(worker => runWorker(ctx, config, job, worker, signal)))
    job = await loadDeepDiscoveryJob(config, jobId)
    const completedRound = job.rounds.find(item => item.number === number); if (!completedRound) throw new Error('Deep discovery round state is missing.')
    const incomplete = workers.some(worker => { const record = job.workers.find(item => item.id === worker.id); return record?.status !== 'completed' || !record.report }); const candidates = job.candidates.filter(candidate => workers.some(worker => candidate.workerIds.includes(worker.id))); completedRound.candidateCount = candidates.length; completedRound.novelty = candidates.filter(candidate => !known.has(candidate.fingerprint)).length; for (const candidate of candidates) known.add(candidate.fingerprint); completedRound.status = incomplete ? 'incomplete' : 'complete'
    const source = await loadScan(state, job.scanId); completedRound.artifactRefs = await persistRoundArtifacts(source, job, completedRound); await save(state, job)
    if (cancelled(signal)) { job.lifecycle = 'cancelled'; await save(state, job); return job }
    if (incomplete) { job.lifecycle = 'incomplete'; await save(state, job); return job }
    if (completedRound.novelty === 0) { job.lifecycle = 'saturated'; break }
    completedRounds++
    if (completedRounds === job.maxRounds) job.lifecycle = 'capped'
  }
  const eligibleWorkers = completeWorkerIds(job); const eligibleCandidates = job.candidates.filter(candidate => candidate.workerIds.some(workerId => eligibleWorkers.has(workerId))); const scan = await loadScan(state, job.scanId); for (const candidate of eligibleCandidates) addCandidate(scan, candidate); scan.activity.push({ at: new Date().toISOString(), phase: 'discovery', message: `Delegated deep discovery ${job.lifecycle}: ${job.rounds.filter(round => round.status === 'complete').length} complete rounds, ${eligibleCandidates.length} eligible worker candidates.` }); await persistInvestigationArtifacts(state, scan); await saveScan(state, scan); await save(state, job); return job
}
