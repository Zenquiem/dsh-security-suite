import { readFileSync } from 'node:fs'
import { randomUUID } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { join, relative, resolve } from 'node:path'
import type { Context } from '@deepseek-ai/cordis'
import type { Config } from '../config.js'
import type { ScanRecord } from '../contracts.js'
import { getStateDir, loadScan, persistInvestigationArtifacts, saveScan, sha256, writeArtifact } from '../state.js'
import { loadKnowledgeBase } from './knowledge-base.js'

/**
 * Diff-scan LLM file review, aligned with the codex-security compact diff
 * workflow (Apache-2.0, adapted): one restricted file-review subagent per
 * changed source file reads it in full against the frozen diff worklist and
 * reports source-backed candidates anchored to the changed code. The
 * deterministic diff engine remains the receipt baseline.
 */

export const DIFF_REVIEW_WORKERS = 6

export type DiffDiscoveryLifecycle = 'queued' | 'running' | 'completed' | 'incomplete' | 'cancelled' | 'failed'

export interface DiffReviewItem { path: string; sha256: string; language: string; mode: string }

export interface DiffCandidateInput {
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
  evidence: Array<{ location: { path: string; startLine: number; role?: string }; explanation: string }>
}

export interface DiffWorkerReport { resolvedQuestions: string[]; fullyReviewedFileCount: number }

export interface DiffWorker {
  id: string
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled'
  token: string
  assignedPaths: string[]
  candidateIds: string[]
  report?: DiffWorkerReport
  error?: string
  transcript?: string
}

export interface DiffDiscoveryJob {
  id: string
  scanId: string
  target: string
  lifecycle: DiffDiscoveryLifecycle
  createdAt: string
  updatedAt: string
  worklistDigest: string
  worklist: DiffReviewItem[]
  threatModel: string
  userContext: string
  policyGuidance: string
  knowledgeBasePromptText: string
  workers: DiffWorker[]
  candidates: Array<DiffCandidateInput & { id: string; workerId: string; fingerprint: string }>
  notes: string[]
}

function inside(workspace: string, path: string): boolean {
  const rel = relative(resolve(workspace), resolve(path))
  return rel === '' || (!rel.startsWith('..') && !resolve(rel).startsWith('..'))
}

function pathFor(state: string, id: string): string {
  if (!/^diffdiscovery_[0-9a-f-]+$/.test(id)) throw new Error('Invalid diff discovery job id.')
  return join(state, 'diff-discovery', `${id}.json`)
}

async function atomicWrite(path: string, content: string): Promise<void> {
  const { mkdir, rename, writeFile } = await import('node:fs/promises')
  await mkdir(resolve(path, '..'), { recursive: true })
  const temporary = `${path}.${randomUUID()}.tmp`
  await writeFile(temporary, content, 'utf8')
  await rename(temporary, path)
}

const jobWrites = new Map<string, Promise<unknown>>()

async function updateJob(config: Config, id: string, update: (job: DiffDiscoveryJob) => void | Promise<void>): Promise<DiffDiscoveryJob> {
  const previous = jobWrites.get(id) ?? Promise.resolve()
  const barrier = previous.then(async () => {
    const job = await loadDiffDiscoveryJob(config, id)
    await update(job)
    job.updatedAt = new Date().toISOString()
    await atomicWrite(pathFor(getStateDir(config.stateDir), id), `${JSON.stringify(job, null, 2)}\n`)
    return job
  })
  jobWrites.set(id, barrier)
  await previous
  try { return await barrier } finally { if (jobWrites.get(id) === barrier) jobWrites.delete(id) }
}

export async function loadDiffDiscoveryJob(config: Config, id: string): Promise<DiffDiscoveryJob> {
  const { readFile: read } = await import('node:fs/promises')
  return JSON.parse(await read(pathFor(getStateDir(config.stateDir), id), 'utf8')) as DiffDiscoveryJob
}

/** Freeze the changed-file worklist from a saved diff scan; bind each file to its current content digest. */
export async function createDiffDiscoveryJob(config: Config, scanId: string, userContext = ''): Promise<DiffDiscoveryJob> {
  const state = getStateDir(config.stateDir)
  const scan = await loadScan(state, scanId)
  const kb = await loadKnowledgeBase(scan.target, config.knowledgeBase ?? [])
  const worklist: DiffReviewItem[] = []
  for (const receipt of scan.coverage.receipts) {
    const source = resolve(scan.target, receipt.path)
    if (!inside(scan.target, source)) throw new Error(`Diff receipt path ${receipt.path} is outside the scan target.`)
    const content = await readFile(source, 'utf8')
    worklist.push({ path: receipt.path, sha256: sha256(content), language: receipt.language, mode: scan.coverage.mode })
  }
  const now = new Date().toISOString()
  const job: DiffDiscoveryJob = {
    id: `diffdiscovery_${randomUUID()}`, scanId, target: scan.target, lifecycle: 'queued', createdAt: now, updatedAt: now,
    worklistDigest: sha256(JSON.stringify(worklist)), worklist, threatModel: scan.threatModel, userContext, policyGuidance: scan.policyGuidance,
    knowledgeBasePromptText: kb.promptText, workers: [], candidates: [],
    notes: kb.skipped.length ? [`Knowledge base skipped ${kb.skipped.length} document(s): ${kb.skipped.map(item => `${item.path} (${item.reason})`).join('; ')}`] : [],
  }
  await atomicWrite(pathFor(state, job.id), `${JSON.stringify(job, null, 2)}\n`)
  return job
}

export function activeDiffWorker(job: DiffDiscoveryJob, workerId: string, token: string): DiffWorker {
  if (job.lifecycle !== 'running') throw new Error('Diff discovery job is not running.')
  const worker = job.workers.find(item => item.id === workerId)
  if (!worker) throw new Error('Worker is not part of this diff discovery job.')
  if (worker.status !== 'running') throw new Error('Worker is not active for this diff discovery job.')
  if (worker.token !== token) throw new Error('Worker claim token does not own this worker.')
  return worker
}

export function getDiffReviewItems(config: Config, jobId: string, workerId: string, token: string): { jobId: string; scanId: string; target: string; worklistDigest: string; mode: string; items: Array<{ path: string; language: string }>; threatModel: string; userContext: string; policyGuidance: string; knowledgeBasePromptText: string } {
  const job = loadDiffDiscoveryJobSync(config, jobId)
  const worker = activeDiffWorker(job, workerId, token)
  return {
    jobId, scanId: job.scanId, target: job.target, worklistDigest: job.worklistDigest, mode: job.worklist[0]?.mode ?? 'diff',
    items: job.worklist.filter(item => worker.assignedPaths.includes(item.path)).map(item => ({ path: item.path, language: item.language })),
    threatModel: job.threatModel, userContext: job.userContext, policyGuidance: job.policyGuidance, knowledgeBasePromptText: job.knowledgeBasePromptText,
  }
}

export async function readDiffSource(config: Config, jobId: string, workerId: string, token: string, path: string, startLine?: number, endLine?: number): Promise<{ path: string; sha256: string; startLine: number; endLine: number; content: string }> {
  const job = await loadDiffDiscoveryJob(config, jobId)
  const worker = activeDiffWorker(job, workerId, token)
  if (!worker.assignedPaths.includes(path)) throw new Error('Path is not assigned to this diff review worker.')
  const item = job.worklist.find(entry => entry.path === path)
  if (!item) throw new Error('Path is not in the diff discovery worklist.')
  const source = resolve(job.target, item.path)
  if (!inside(job.target, source)) throw new Error('Path is outside the scan target.')
  const content = await readFile(source, 'utf8')
  if (sha256(content) !== item.sha256) throw new Error('Source file changed after the diff discovery worklist was created.')
  const lines = content.split(/\r?\n/)
  const from = startLine ?? 1
  const to = endLine ?? Math.min(lines.length || 1, from + 199)
  if (from < 1 || to < from) throw new Error('Invalid source line range.')
  return { path: item.path, sha256: item.sha256, startLine: from, endLine: to, content: lines.slice(from - 1, to).join('\n') }
}

function validateDiffCandidate(job: DiffDiscoveryJob, candidate: DiffCandidateInput): DiffCandidateInput {
  if (!/^[a-z0-9][a-z0-9._/-]*$/.test(candidate.ruleId)) throw new Error('ruleId must be a stable lowercase slug.')
  if (!candidate.locations.length) throw new Error('Candidate requires at least one concrete source location.')
  for (const location of candidate.locations) {
    if (!job.worklist.some(item => item.path === location.path)) throw new Error(`Candidate location ${location.path} is outside the diff worklist.`)
    if (!Number.isInteger(location.startLine) || location.startLine < 1) throw new Error(`Candidate location ${location.path} has an invalid startLine.`)
  }
  return candidate
}

/** Persist reported candidates into the diff scan as discovered findings with receipts. */
async function addDiffFindingsToScan(config: Config, job: DiffDiscoveryJob, workerId: string, candidateIds: string[]): Promise<void> {
  const state = getStateDir(config.stateDir)
  const scan = await loadScan(state, job.scanId)
  const added = job.candidates.filter(candidate => candidateIds.includes(candidate.id) && !scan.findings.some(finding => finding.fingerprint === `dsh-diff:${candidate.fingerprint}`))
  if (!added.length) return
  const findings: Array<import('../contracts.js').Finding> = added.map(candidate => ({
    id: `dsf_${sha256(`${scan.targetSnapshot.targetId}:${candidate.ruleId}:${candidate.locations[0].path}:${candidate.locations[0].startLine}`).slice(0, 24)}`,
    candidateId: `cand_${sha256(`${candidate.ruleId}:${candidate.locations[0].path}:${candidate.locations[0].startLine}`).slice(0, 16)}`,
    fingerprint: `dsh-diff:${candidate.fingerprint}`,
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
    validation: 'Diff review candidate from an LLM file-review worker. Static evidence must establish attacker control, a broken control or sensitive sink, and impact before reportability.',
    attackPath: 'Not established.',
    impact: candidate.impact,
    remediation: candidate.remediation,
    counterevidence: candidate.counterevidence,
    evidence: candidate.evidence.map(item => ({ kind: 'context' as const, detail: item.explanation, location: { file: item.location.path, line: item.location.startLine, excerpt: '' } })),
    ledger: [{ at: new Date().toISOString(), phase: 'discovery' as const, disposition: 'discovered' as const, summary: `LLM diff file-review worker ${workerId} reported ${candidate.ruleId} at ${candidate.locations[0].path}:${candidate.locations[0].startLine}.` }],
  }))
  scan.findings.push(...findings)
  scan.tasks.push(...findings.map(finding => ({ id: `task_${sha256(`${scan.id}:${finding.candidateId}:validation`).slice(0, 24)}`, candidateId: finding.candidateId, phase: 'validation' as const, focus: `Validate ${finding.title}: establish attacker, entrypoint, trust boundary, root control, sink, impact, and counterevidence.`, status: 'pending' as const })))
  await saveScan(state, scan)
}

export async function reportDiffCandidates(config: Config, jobId: string, workerId: string, token: string, candidates: DiffCandidateInput[]): Promise<{ recorded: number; candidateIds: string[] }> {
  const job = await updateJob(config, jobId, async current => {
    const worker = activeDiffWorker(current, workerId, token)
    for (const input of candidates) {
      const candidate = validateDiffCandidate(current, input)
      const fingerprint = sha256(`${candidate.ruleId}:${candidate.locations[0].path}:${candidate.locations[0].startLine}:${candidate.summary}`)
      const id = `diffcand_${sha256(fingerprint).slice(0, 24)}`
      if (current.candidates.some(item => item.id === id)) continue
      current.candidates.push({ ...candidate, id, workerId, fingerprint })
      worker.candidateIds.push(id)
    }
  })
  await addDiffFindingsToScan(config, job, workerId, job.candidates.map(candidate => candidate.id))
  return { recorded: job.candidates.length, candidateIds: job.candidates.map(candidate => candidate.id) }
}

export async function reportDiffWorker(config: Config, jobId: string, workerId: string, token: string, report: DiffWorkerReport): Promise<void> {
  await updateJob(config, jobId, async current => {
    const worker = activeDiffWorker(current, workerId, token)
    if (!Number.isInteger(report.fullyReviewedFileCount) || report.fullyReviewedFileCount < 0) throw new Error('fullyReviewedFileCount must be a nonnegative integer.')
    worker.report = report
    worker.status = 'completed'
  })
}

export const DIFF_WORKER_TOOLS = ['security_diff_get_review_items', 'security_diff_read_source', 'security_diff_report_candidates', 'security_diff_report_worker'] as const

type NativeAgents = { create?: unknown }

function nativeAgents(ctx: Context): NativeAgents | undefined {
  const get = (ctx as Context & { get?: (name: string) => unknown }).get
  return (typeof get === 'function' ? get.call(ctx, 'agents') : (ctx as Context & { agents?: NativeAgents }).agents) as NativeAgents | undefined
}

export function diffDiscoveryCapability(ctx: Context): { available: boolean; workers: number; reason?: string } {
  const agents = nativeAgents(ctx)
  if (!agents || typeof agents.create !== 'function') return { available: false, workers: DIFF_REVIEW_WORKERS, reason: 'The active DSH profile has no native agent-creation service.' }
  return { available: true, workers: DIFF_REVIEW_WORKERS }
}

function transcript(agent: { session: { deriveMessages(): Array<{ role: string; content: Array<{ type: string; text?: string }> }> } }): string {
  return agent.session.deriveMessages().filter(message => message.role === 'assistant').flatMap(message => message.content.filter(block => block.type === 'text' || block.type === 'reasoning').map(block => block.text ?? '')).join('\n\n').slice(-200_000)
}

function cancelled(signal: AbortSignal | undefined): boolean { return signal?.aborted === true }

async function runDiffWorker(ctx: Context, config: Config, job: DiffDiscoveryJob, worker: DiffWorker, prompt: string, signal?: AbortSignal): Promise<void> {
  const { createUserMessage } = await import('@deepseek-ai/dsh-llm')
  const { SessionId } = await import('@deepseek-ai/dsh-session')
  const sessionId = SessionId(`dsh-security-diff-${randomUUID()}`)
  await updateJob(config, job.id, current => { const record = current.workers.find(item => item.id === worker.id); if (!record) throw new Error('Diff review worker was not created.'); record.status = 'running' })
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
      agentCtx.tools.restrict({ allow: [...DIFF_WORKER_TOOLS] })
      agentCtx.systemPrompt.section({ name: `dsh-security-suite:diff-worker:${worker.id}`, order: 162, text: prompt })
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
    await updateJob(config, job.id, current => { const record = current.workers.find(item => item.id === worker.id); if (record && record.status === 'running') { record.transcript = workerTranscript; record.status = 'completed' } })
  } catch (error) {
    if (cancelledByCaller) return
    const message = error instanceof Error ? error.message : String(error)
    await updateJob(config, job.id, current => { const record = current.workers.find(item => item.id === worker.id); if (record && record.status === 'running') { record.status = 'failed'; record.error = message } })
  } finally {
    signal?.removeEventListener('abort', onAbort)
    if (cancelledByCaller) await updateJob(config, job.id, current => { const record = current.workers.find(item => item.id === worker.id); if (record && record.status !== 'completed') { record.status = 'cancelled'; record.error = 'Cancelled by the owning DSH tool call.' } })
    await dispose()
  }
}

async function persistDiffArtifacts(config: Config, jobId: string): Promise<void> {
  const state = getStateDir(config.stateDir)
  const job = await loadDiffDiscoveryJob(config, jobId)
  const scan = await loadScan(state, job.scanId)
  const base = 'artifacts/02_discovery/diff'
  await writeArtifact(scan, `${base}/rank_input.jsonl`, `${job.worklist.map(item => JSON.stringify({ path: item.path, area: 'diff', preview: '' })).join('\n')}\n`)
  await writeArtifact(scan, `${base}/deep_review_input.jsonl`, `${job.worklist.map(item => JSON.stringify({ path: item.path, area: 'diff' })).join('\n')}\n`)
  for (const worker of job.workers) {
    if (!worker.report) continue
    const dir = `${base}/${worker.id}`
    await writeArtifact(scan, `${dir}/report.json`, `${JSON.stringify(worker.report, null, 2)}\n`)
    await writeArtifact(scan, `${dir}/candidates.jsonl`, `${job.candidates.filter(candidate => candidate.workerId === worker.id).map(candidate => JSON.stringify(candidate)).join('\n')}\n`)
    if (worker.transcript) await writeArtifact(scan, `${dir}/transcript.md`, `${worker.transcript}\n`)
  }
  await writeArtifact(scan, `${base}/discovery_ledger.md`, ['# Diff File-Review Ledger', '', `- Job: \`${job.id}\``, `- Worklist digest: \`${job.worklistDigest}\``, `- Changed files: ${job.worklist.length}`, `- Workers: ${job.workers.map(worker => `\`${worker.id}\` (${worker.status}, ${worker.assignedPaths.length} files)`).join(', ')}`, `- Candidates: ${job.candidates.length}`, ...job.notes.map(note => `- Note: ${note}`), ''].join('\n'))
  await persistInvestigationArtifacts(state, scan)
  await saveScan(state, scan)
}

/** Run one diff file-review job: one restricted worker per changed file, capped, then persist artifacts and scan candidates. */
export async function runDiffDiscovery(ctx: Context, config: Config, jobId: string, signal?: AbortSignal): Promise<DiffDiscoveryJob> {
  const state = getStateDir(config.stateDir)
  let job = await loadDiffDiscoveryJob(config, jobId)
  if (!['queued', 'cancelled', 'incomplete'].includes(job.lifecycle)) throw new Error('Diff discovery job has already completed or failed.')
  const capability = diffDiscoveryCapability(ctx)
  if (!capability.available) {
    await updateJob(config, jobId, current => { current.lifecycle = 'failed' })
    throw new Error(capability.reason ?? 'The active DSH profile has no native agent-creation service.')
  }
  await updateJob(config, jobId, current => { current.lifecycle = 'running' })
  job = await loadDiffDiscoveryJob(config, jobId)
  const { diffFileReviewPrompt } = await import('./prompts.js')
  const slots = Math.max(1, Math.min(DIFF_REVIEW_WORKERS, job.worklist.length))
  const assignments = job.worklist.slice(0, slots).map((item, index) => ({ path: item.path, workerId: `filereview_${index + 1}` }))
  await updateJob(config, jobId, current => {
    current.workers = assignments.map((assignment, index) => ({ id: assignment.workerId, status: 'pending' as const, token: randomUUID(), assignedPaths: [assignment.path], candidateIds: [] }))
  })
  job = await loadDiffDiscoveryJob(config, jobId)
  await Promise.all(job.workers.map(worker => {
    const assigned = job.worklist.filter(item => worker.assignedPaths.includes(item.path)).map(item => item.path)
    const prompt = diffFileReviewPrompt({ jobId: job.id, workerId: worker.id, token: worker.token, worklistDigest: job.worklistDigest, target: job.target, mode: worker.assignedPaths[0] ? (job.worklist.find(item => item.path === worker.assignedPaths[0])?.mode ?? 'diff') : 'diff', assignedPaths: assigned, threatModel: job.threatModel, userContext: job.userContext, policyGuidance: job.policyGuidance, knowledgeBasePromptText: job.knowledgeBasePromptText, scanPrompt: config.scanPrompt })
    return runDiffWorker(ctx, config, job, worker, prompt, signal)
  }))
  job = await loadDiffDiscoveryJob(config, jobId)
  const allComplete = job.workers.length > 0 && job.workers.every(worker => worker.status === 'completed')
  const anyCancelled = cancelled(signal)
  await updateJob(config, jobId, current => { current.lifecycle = anyCancelled ? 'cancelled' : allComplete ? 'completed' : 'incomplete' })
  if (allComplete) await persistDiffArtifacts(config, jobId)
  return loadDiffDiscoveryJob(config, jobId)
}

function loadDiffDiscoveryJobSync(config: Config, id: string): DiffDiscoveryJob {
  return JSON.parse(readFileSync(pathFor(getStateDir(config.stateDir), id), 'utf8')) as DiffDiscoveryJob
}

/** Run a diff scan, then LLM file review over the changed files. */
export async function runDiffLlmReview(ctx: Context, config: Config, workspace: string, base: string | undefined, userContext = '', signal?: AbortSignal, requestedMode?: 'working_tree' | 'commit' | 'branch_diff'): Promise<{ scan: ScanRecord; jobId: string }> {
  const { runDiffScan } = await import('../scanner.js')
  const scan = await runDiffScan(workspace, base, '', config.stateDir, false, requestedMode)
  await persistInvestigationArtifacts(getStateDir(config.stateDir), scan)
  await saveScan(getStateDir(config.stateDir), scan)
  if (!scan.coverage.receipts.length) return { scan, jobId: '' }
  const job = await createDiffDiscoveryJob(config, scan.id, userContext)
  await runDiffDiscovery(ctx, config, job.id, signal)
  return { scan: await loadScan(getStateDir(config.stateDir), scan.id), jobId: job.id }
}
