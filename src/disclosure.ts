import { mkdir, readFile, rename, writeFile } from 'node:fs/promises'
import { randomUUID } from 'node:crypto'
import { isAbsolute, join, relative, resolve } from 'node:path'
import type { Context } from '@deepseek-ai/cordis'
import { createUserMessage } from '@deepseek-ai/dsh-llm'
import { SessionId } from '@deepseek-ai/dsh-session'
import type {} from '@deepseek-ai/dsh-agent'
import type {} from '@deepseek-ai/dsh-system-prompt'
import type {} from '@deepseek-ai/dsh-tools'
import type { Config } from './config.js'
import { getStateDir, sha256 } from './state.js'

export interface DisclosureInput { id: string; title: string; notes: string; sourcePaths: string[]; experimentArtifactPaths?: string[] }
export interface DisclosureSource { path: string; sha256: string; content: string }
export interface DisclosureExperimentArtifact { path: string; sha256: string; bytes: number; content: string }
export interface DisclosureReportInput { summary: string; attacker: string; entryPoint: string; vulnerablePath: string; badState: string; impact: string; exploitability: string; counterevidence: string; limitations: string; remediation: string; reproductionStatus: 'not_run' | 'built_only' | 'executed_safely'; reproductionNotes: string; sourceReferences: Array<{ path: string; line: number; explanation: string }>; experimentReferences?: Array<{ path: string; explanation: string }> }
export interface DisclosureWorker { id: string; vulnerabilityId: string; token: string; status: 'pending' | 'running' | 'completed' | 'cancelled' | 'failed'; sessionId?: string; transcript?: string; error?: string; report?: DisclosureReportInput }
export interface DisclosureCampaign { id: string; createdAt: string; updatedAt: string; sourceRoot: string; sourceRevision?: string; experimentAuthorized: boolean; inputs: Array<DisclosureInput & { notesSha256: string; sources: DisclosureSource[]; experimentArtifacts: DisclosureExperimentArtifact[] }>; workers: DisclosureWorker[]; lifecycle: 'queued' | 'running' | 'completed' | 'incomplete' | 'cancelled' | 'failed'; reportsDirectory: string }

const writes = new Map<string, Promise<void>>()
function inside(root: string, path: string): boolean { const value = relative(root, path); return value === '' || (!value.startsWith('..') && !isAbsolute(value)) }
function pathFor(state: string, id: string): string { if (!/^disclosure_[0-9a-f-]+$/.test(id)) throw new Error('Invalid disclosure campaign id.'); return join(state, 'disclosures', `${id}.json`) }
async function atomic(path: string, content: string): Promise<void> { await mkdir(resolve(path, '..'), { recursive: true }); const temporary = `${path}.${randomUUID()}.tmp`; await writeFile(temporary, content, 'utf8'); await rename(temporary, path) }
async function save(state: string, campaign: DisclosureCampaign): Promise<void> { campaign.updatedAt = new Date().toISOString(); await atomic(pathFor(state, campaign.id), `${JSON.stringify(campaign, null, 2)}\n`) }
export async function loadDisclosureCampaign(config: Config, id: string): Promise<DisclosureCampaign> { return JSON.parse(await readFile(pathFor(getStateDir(config.stateDir), id), 'utf8')) as DisclosureCampaign }
async function update<T>(config: Config, id: string, fn: (campaign: DisclosureCampaign) => Promise<T> | T): Promise<T> {
  const previous = writes.get(id) ?? Promise.resolve(); let release!: () => void; const barrier = new Promise<void>(resolveBarrier => { release = resolveBarrier }); const chained = previous.then(() => barrier); writes.set(id, chained); await previous
  try { const campaign = await loadDisclosureCampaign(config, id); const value = await fn(campaign); await save(getStateDir(config.stateDir), campaign); return value } finally { release(); if (writes.get(id) === chained) writes.delete(id) }
}

function validInput(input: DisclosureInput): void {
  if (!/^[a-z][a-z0-9._-]{1,80}$/.test(input.id)) throw new Error('Each disclosure vulnerability id must be a stable lowercase identifier.')
  if (input.title.trim().length < 5 || input.notes.trim().length < 20) throw new Error('Each disclosure requires a substantive title and notes.')
  if (!input.sourcePaths.length) throw new Error(`Disclosure ${input.id} requires at least one source path.`)
}

async function freezeExperimentArtifacts(root: string, paths: string[], authorized: boolean): Promise<DisclosureExperimentArtifact[]> {
  if (paths.length && !authorized) throw new Error('Disclosure experiment artifacts require explicit campaign experiment authorization.')
  return Promise.all([...new Set(paths)].map(async path => {
    const file = resolve(root, path); if (!inside(root, file)) throw new Error(`Disclosure experiment artifact escapes its source root: ${path}`)
    const content = await readFile(file, 'utf8'); if (Buffer.byteLength(content, 'utf8') > 512_000) throw new Error(`Disclosure experiment artifact exceeds the 512 KB evidence limit: ${path}`)
    return { path, sha256: sha256(content), bytes: Buffer.byteLength(content, 'utf8'), content }
  }))
}

/** Freeze supplied notes and source files before one DSH writer is assigned per vulnerability. */
export async function createDisclosureCampaign(workspace: string, config: Config, sourceRoot: string | undefined, inputs: DisclosureInput[], experimentAuthorized: boolean, sourceRevision?: string): Promise<DisclosureCampaign> {
  if (!inputs.length || inputs.length > 25) throw new Error('A disclosure campaign requires from 1 to 25 distinct vulnerabilities.')
  const ids = new Set<string>(); const root = resolve(workspace, sourceRoot ?? '.')
  if (!inside(resolve(workspace), root)) throw new Error('Disclosure source root must remain inside the active workspace.')
  const frozen = await Promise.all(inputs.map(async input => {
    validInput(input); if (ids.has(input.id)) throw new Error(`Duplicate disclosure vulnerability id: ${input.id}`); ids.add(input.id)
    const sources = await Promise.all(input.sourcePaths.map(async path => { const file = resolve(root, path); if (!inside(root, file)) throw new Error(`Disclosure source path escapes its source root: ${path}`); const content = await readFile(file, 'utf8'); return { path, sha256: sha256(content), content } }))
    const experimentArtifactPaths = [...new Set(input.experimentArtifactPaths ?? [])]; const experimentArtifacts = await freezeExperimentArtifacts(root, experimentArtifactPaths, experimentAuthorized)
    return { ...input, title: input.title.trim(), notes: input.notes.trim(), sourcePaths: [...new Set(input.sourcePaths)], experimentArtifactPaths, notesSha256: sha256(input.notes.trim()), sources, experimentArtifacts }
  }))
  const now = new Date().toISOString(); const id = `disclosure_${randomUUID()}`; const directory = join(getStateDir(config.stateDir), 'disclosure-reports', id)
  const campaign: DisclosureCampaign = { id, createdAt: now, updatedAt: now, sourceRoot: root, sourceRevision: sourceRevision?.trim() || undefined, experimentAuthorized, inputs: frozen, workers: frozen.map(input => ({ id: `writer_${input.id}`, vulnerabilityId: input.id, token: randomUUID(), status: 'pending' })), lifecycle: 'queued', reportsDirectory: directory }
  await mkdir(directory, { recursive: true }); await save(getStateDir(config.stateDir), campaign); return campaign
}

function worker(campaign: DisclosureCampaign, workerId: string, token: string): DisclosureWorker {
  const value = campaign.workers.find(item => item.id === workerId); if (!value || value.token !== token || value.status !== 'running') throw new Error('Disclosure writer assignment is invalid.'); return value
}
function inputFor(campaign: DisclosureCampaign, workerValue: DisclosureWorker): DisclosureCampaign['inputs'][number] { const input = campaign.inputs.find(item => item.id === workerValue.vulnerabilityId); if (!input) throw new Error('Disclosure writer input is missing.'); return input }

/** Return only the frozen notes and immutable source receipt list assigned to one active writer. */
export async function getDisclosureAssignment(config: Config, campaignId: string, workerId: string, token: string): Promise<{ vulnerability: { id: string; title: string; notes: string; notesSha256: string }; sources: Array<{ path: string; sha256: string }>; experimentArtifacts: Array<{ path: string; sha256: string; bytes: number }>; experimentAuthorized: boolean; sourceRevision?: string }> {
  const campaign = await loadDisclosureCampaign(config, campaignId); const assigned = inputFor(campaign, worker(campaign, workerId, token)); return { vulnerability: { id: assigned.id, title: assigned.title, notes: assigned.notes, notesSha256: assigned.notesSha256 }, sources: assigned.sources.map(source => ({ path: source.path, sha256: source.sha256 })), experimentArtifacts: assigned.experimentArtifacts.map(artifact => ({ path: artifact.path, sha256: artifact.sha256, bytes: artifact.bytes })), experimentAuthorized: campaign.experimentAuthorized, sourceRevision: campaign.sourceRevision }
}

/** Read a bounded frozen source range for the active writer; changed source fails closed. */
export async function readDisclosureSource(config: Config, campaignId: string, workerId: string, token: string, path: string, startLine = 1, endLine = 400): Promise<{ path: string; sha256: string; startLine: number; endLine: number; content: string }> {
  const campaign = await loadDisclosureCampaign(config, campaignId); const assigned = inputFor(campaign, worker(campaign, workerId, token)); const source = assigned.sources.find(item => item.path === path); if (!source) throw new Error('Source path is not assigned to this disclosure writer.')
  const file = resolve(campaign.sourceRoot, source.path); if (!inside(campaign.sourceRoot, file)) throw new Error('Assigned disclosure source path is outside its source root.'); const current = await readFile(file, 'utf8'); if (sha256(current) !== source.sha256) throw new Error('Disclosure source changed after campaign creation. Create a new campaign from the current source.')
  const start = Math.max(1, Math.floor(startLine)); const end = Math.max(start, Math.min(start + 399, Math.floor(endLine))); const lines = current.split(/\r?\n/); return { path: source.path, sha256: source.sha256, startLine: start, endLine: Math.min(end, lines.length), content: lines.slice(start - 1, end).join('\n') }
}

/** Read a bounded range from a user-supplied frozen experiment artifact; it is never executed by this plugin. */
export async function readDisclosureExperimentArtifact(config: Config, campaignId: string, workerId: string, token: string, path: string, startLine = 1, endLine = 400): Promise<{ path: string; sha256: string; startLine: number; endLine: number; content: string }> {
  const campaign = await loadDisclosureCampaign(config, campaignId); const assigned = inputFor(campaign, worker(campaign, workerId, token)); if (!campaign.experimentAuthorized) throw new Error('Disclosure experiment artifacts are unavailable without campaign experiment authorization.')
  const artifact = assigned.experimentArtifacts.find(item => item.path === path); if (!artifact) throw new Error('Experiment artifact is not assigned to this disclosure writer.')
  const file = resolve(campaign.sourceRoot, artifact.path); if (!inside(campaign.sourceRoot, file)) throw new Error('Assigned experiment artifact is outside its source root.'); const current = await readFile(file, 'utf8'); if (sha256(current) !== artifact.sha256) throw new Error('Disclosure experiment artifact changed after campaign creation. Create a new campaign from current evidence.')
  const start = Math.max(1, Math.floor(startLine)); const end = Math.max(start, Math.min(start + 399, Math.floor(endLine))); const lines = current.split(/\r?\n/); return { path: artifact.path, sha256: artifact.sha256, startLine: start, endLine: Math.min(end, lines.length), content: lines.slice(start - 1, end).join('\n') }
}

function reportMarkdown(campaign: DisclosureCampaign, input: DisclosureCampaign['inputs'][number], report: DisclosureReportInput): string {
  const citations = report.sourceReferences.map(reference => `- \`${reference.path}:${reference.line}\`: ${reference.explanation}`).join('\n')
  const experiments = report.experimentReferences?.length ? report.experimentReferences.map(reference => `- \`${reference.path}\`: ${reference.explanation}`).join('\n') : '- No user-supplied experiment artifact was cited.'
  return `# ${input.title}\n\n## Scope and Evidence\n\n- Campaign: \`${campaign.id}\`\n- Vulnerability: \`${input.id}\`\n- Source revision: ${campaign.sourceRevision ? `\`${campaign.sourceRevision}\`` : 'not supplied'}\n- Notes digest: \`${input.notesSha256}\`\n- Source receipts: ${input.sources.map(source => `\`${source.path}\` (${source.sha256})`).join(', ')}\n\n## Summary\n\n${report.summary}\n\n## Vulnerable Path\n\n- Attacker: ${report.attacker}\n- Entry point: ${report.entryPoint}\n- Path: ${report.vulnerablePath}\n- Bad state: ${report.badState}\n\n## Source References\n\n${citations}\n\n## Impact\n\n${report.impact}\n\n## Exploitability Analysis\n\n${report.exploitability}\n\n## Counterevidence\n\n${report.counterevidence}\n\n## Reproduction Status\n\n- Status: ${report.reproductionStatus}\n- Authorization for experiments: ${campaign.experimentAuthorized ? 'granted for this campaign' : 'not granted'}\n\n${report.reproductionNotes}\n\n## Frozen Experiment Evidence\n\n${experiments}\n\n## Limitations\n\n${report.limitations}\n\n## Remediation\n\n${report.remediation}\n\n## Evidence Boundary\n\nThis report is based only on the frozen notes, source receipts, and explicitly cited user-supplied experiment artifacts listed above. This plugin does not generate or execute experiment artifacts. It does not claim a runtime result unless the retained reproduction status and notes establish one.\n`
}

function substantive(value: string, label: string): string { const text = value.trim(); if (text.length < 12) throw new Error(`${label} must contain substantive evidence.`); return text.slice(0, 100_000) }

/** Persist one source-cited report for the writer's sole assigned vulnerability. */
export async function submitDisclosureReport(config: Config, campaignId: string, workerId: string, token: string, report: DisclosureReportInput): Promise<{ reportPath: string; sha256: string }> {
  return update(config, campaignId, async campaign => {
    const assignedWorker = worker(campaign, workerId, token); const input = inputFor(campaign, assignedWorker)
    if (!['not_run', 'built_only', 'executed_safely'].includes(report.reproductionStatus)) throw new Error('Disclosure reproduction status is invalid.')
    if (!campaign.experimentAuthorized && report.reproductionStatus === 'executed_safely') throw new Error('An executed reproduction cannot be claimed without campaign experiment authorization.')
    if (!report.sourceReferences.length) throw new Error('Disclosure reports require at least one assigned source reference.')
    for (const reference of report.sourceReferences) { const source = input.sources.find(item => item.path === reference.path); if (!source || !Number.isInteger(reference.line) || reference.line < 1 || reference.line > source.content.split(/\r?\n/).length || reference.explanation.trim().length < 8) throw new Error('Disclosure source references must cite an assigned path, existing line, and explanation.') }
    const experimentReferences = report.experimentReferences ?? []; if (report.reproductionStatus === 'executed_safely' && !experimentReferences.length) throw new Error('An executed reproduction claim requires a cited user-supplied experiment artifact.')
    for (const reference of experimentReferences) if (!campaign.experimentAuthorized || !input.experimentArtifacts.some(item => item.path === reference.path) || reference.explanation.trim().length < 8) throw new Error('Experiment references require an assigned authorized artifact and substantive explanation.')
    const normalized: DisclosureReportInput = { ...report, summary: substantive(report.summary, 'summary'), attacker: substantive(report.attacker, 'attacker'), entryPoint: substantive(report.entryPoint, 'entryPoint'), vulnerablePath: substantive(report.vulnerablePath, 'vulnerablePath'), badState: substantive(report.badState, 'badState'), impact: substantive(report.impact, 'impact'), exploitability: substantive(report.exploitability, 'exploitability'), counterevidence: substantive(report.counterevidence, 'counterevidence'), limitations: substantive(report.limitations, 'limitations'), remediation: substantive(report.remediation, 'remediation'), reproductionNotes: substantive(report.reproductionNotes, 'reproductionNotes'), sourceReferences: report.sourceReferences.map(reference => ({ path: reference.path, line: reference.line, explanation: reference.explanation.trim().slice(0, 10_000) })), experimentReferences: experimentReferences.map(reference => ({ path: reference.path, explanation: reference.explanation.trim().slice(0, 10_000) })) }
    const content = reportMarkdown(campaign, input, normalized); const reportPath = join(campaign.reportsDirectory, `${input.id}.md`); await atomic(reportPath, content); assignedWorker.report = normalized; return { reportPath, sha256: sha256(content) }
  })
}

function nativeAgents(ctx: Context): { create?: unknown } | undefined { const get = (ctx as Context & { get?: (name: string) => unknown }).get; return (typeof get === 'function' ? get.call(ctx, 'agents') : (ctx as Context & { agents?: { create?: unknown } }).agents) as { create?: unknown } | undefined }
function transcript(agent: { session: { deriveMessages(): Array<{ role: string; content: Array<{ type: string; text?: string }> }> } }): string { return agent.session.deriveMessages().filter(message => message.role === 'assistant').flatMap(message => message.content.filter(block => block.type === 'text' || block.type === 'reasoning').map(block => block.text ?? '')).join('\n\n').slice(-200_000) }
function brief(campaign: DisclosureCampaign, writer: DisclosureWorker): string { return `You are the sole DSH disclosure writer for one vulnerability. You may use only security_disclosure_get_assignment, security_disclosure_read_source, security_disclosure_read_experiment_artifact, and security_disclosure_submit_report. Do not modify source, run commands, call external services, access other vulnerabilities, or create an executable PoC. First call security_disclosure_get_assignment with campaign_id ${campaign.id}, worker_id ${writer.id}, claim_token ${writer.token}. Reopen assigned source with security_disclosure_read_source. Only if the campaign provides user-supplied experiment artifacts and explicit authorization may you read them with security_disclosure_read_experiment_artifact; this plugin never runs them. Then submit exactly one structured report. Cite only assigned source paths and, when used, assigned experiment artifacts. The campaign experiment authorization is ${campaign.experimentAuthorized ? 'granted, but only report what the user-supplied retained evidence actually establishes' : 'not granted, so use not_run or built_only and state the proof gap'}.` }
async function runWriter(ctx: Context, config: Config, campaign: DisclosureCampaign, writer: DisclosureWorker, signal?: AbortSignal): Promise<void> {
  const sessionId = SessionId(`dsh-security-disclosure-${randomUUID()}`); await update(config, campaign.id, current => { const row = current.workers.find(item => item.id === writer.id); if (!row) throw new Error('Disclosure writer is missing.'); row.status = 'running'; row.sessionId = sessionId as unknown as string })
  let handle: Awaited<ReturnType<typeof ctx.agents.create>> | undefined; let disposed: Promise<void> | undefined; let cancelled = signal?.aborted === true; const dispose = (): Promise<void> => handle ? (disposed ??= handle.dispose().catch(() => undefined)) : Promise.resolve(); const abort = (): void => { cancelled = true; void dispose() }; signal?.addEventListener('abort', abort, { once: true })
  try { if (cancelled) return; const agents = nativeAgents(ctx) as typeof ctx.agents | undefined; if (!agents || typeof agents.create !== 'function') throw new Error('The active DSH profile has no native agent-creation service.'); handle = await agents.create({ sessionId, meta: { cwd: campaign.sourceRoot, origin: 'subagent', delegationDepth: 1 }, setup(agentCtx) { agentCtx.tools.restrict({ allow: ['security_disclosure_get_assignment', 'security_disclosure_read_source', 'security_disclosure_read_experiment_artifact', 'security_disclosure_submit_report'] }); agentCtx.systemPrompt.section({ name: `dsh-security-suite:disclosure:${campaign.id}:${writer.id}`, order: 164, text: brief(campaign, writer) }) } }); if (cancelled) return; handle.agent.followup(createUserMessage({ content: [{ type: 'text', text: brief(campaign, writer) }], source: { kind: 'plugin', plugin: 'dsh-security-suite', form: 'relay' } })); if (signal) { let remove = (): void => undefined; const aborted = new Promise<void>(wake => { const listener = (): void => wake(); signal.addEventListener('abort', listener, { once: true }); remove = (): void => signal.removeEventListener('abort', listener) }); try { await Promise.race([handle.agent.whenIdle(), aborted]) } finally { remove() } } else await handle.agent.whenIdle(); if (cancelled) return; const value = transcript(handle.agent); await update(config, campaign.id, current => { const row = current.workers.find(item => item.id === writer.id); if (row) { row.status = 'completed'; row.transcript = value } }) } catch (error) { if (!cancelled) await update(config, campaign.id, current => { const row = current.workers.find(item => item.id === writer.id); if (row) { row.status = 'failed'; row.error = error instanceof Error ? error.message : String(error) } }) } finally { signal?.removeEventListener('abort', abort); if (cancelled) await update(config, campaign.id, current => { const row = current.workers.find(item => item.id === writer.id); if (row && row.status !== 'completed') { row.status = 'cancelled'; row.error = 'Cancelled by the owning DSH tool call.' } }); await dispose() }
}

/** Run exactly one restricted DSH writer per frozen disclosure input. */
export async function runDisclosureCampaign(ctx: Context, config: Config, campaignId: string, signal?: AbortSignal): Promise<DisclosureCampaign> {
  let campaign = await loadDisclosureCampaign(config, campaignId); if (!['queued', 'cancelled', 'incomplete'].includes(campaign.lifecycle)) throw new Error('Disclosure campaign has already completed or failed.'); if (campaign.workers.some(worker => worker.status !== 'pending')) throw new Error('Disclosure campaign cannot be resumed after a partial writer run; create a fresh campaign to preserve one-writer-per-vulnerability isolation.')
  const agents = nativeAgents(ctx); if (!agents || typeof agents.create !== 'function') { campaign.lifecycle = 'failed'; await save(getStateDir(config.stateDir), campaign); throw new Error('The active DSH profile has no native agent-creation service.') }
  if (signal?.aborted) { campaign.lifecycle = 'cancelled'; await save(getStateDir(config.stateDir), campaign); return campaign }
  campaign.lifecycle = 'running'; await save(getStateDir(config.stateDir), campaign); await Promise.all(campaign.workers.map(writer => runWriter(ctx, config, campaign, writer, signal))); campaign = await loadDisclosureCampaign(config, campaignId)
  if (signal?.aborted) { campaign.lifecycle = 'cancelled'; await save(getStateDir(config.stateDir), campaign); return campaign }
  campaign.lifecycle = campaign.workers.every(writer => writer.status === 'completed' && writer.report) ? 'completed' : 'incomplete'; await save(getStateDir(config.stateDir), campaign); return campaign
}
