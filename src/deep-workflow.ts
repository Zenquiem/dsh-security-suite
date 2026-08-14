import { mkdir, readFile, rename, writeFile } from 'node:fs/promises'
import { randomUUID } from 'node:crypto'
import { join, resolve } from 'node:path'
import type { Context } from '@deepseek-ai/cordis'
import type { Config } from './config.js'
import { createDeepClosureJob, createDeepDiscoveryJob, runDeepClosure, runDeepDiscovery } from './deep-discovery.js'
import { runScan } from './scanner.js'
import { getStateDir, loadScan, persistInvestigationArtifacts, saveScan } from './state.js'
import { completeScan } from './workbench.js'

export type DeepInvestigationPhase = 'discovery' | 'validation' | 'attack_path' | 'finalization'
export type DeepInvestigationLifecycle = 'queued' | 'running' | 'completed' | 'incomplete' | 'cancelled' | 'failed'

/** Durable state for the complete DSH-native deep security workflow. */
export interface DeepInvestigationJob {
  id: string
  scanId: string
  target: string
  phase: DeepInvestigationPhase
  lifecycle: DeepInvestigationLifecycle
  createdAt: string
  updatedAt: string
  completedAt?: string
  discoveryJobId: string
  validationClosureJobId?: string
  attackPathClosureJobId?: string
}

function pathFor(state: string, id: string): string {
  if (!/^deepflow_[0-9a-f-]+$/.test(id)) throw new Error('Invalid deep investigation job id.')
  return join(state, 'deep-investigations', `${id}.json`)
}

async function atomic(path: string, content: string): Promise<void> {
  await mkdir(resolve(path, '..'), { recursive: true })
  const temporary = `${path}.${randomUUID()}.tmp`
  await writeFile(temporary, content, 'utf8')
  await rename(temporary, path)
}

async function save(config: Config, job: DeepInvestigationJob): Promise<void> {
  job.updatedAt = new Date().toISOString()
  await atomic(pathFor(getStateDir(config.stateDir), job.id), `${JSON.stringify(job, null, 2)}\n`)
}

export async function loadDeepInvestigationJob(config: Config, id: string): Promise<DeepInvestigationJob> {
  return JSON.parse(await readFile(pathFor(getStateDir(config.stateDir), id), 'utf8')) as DeepInvestigationJob
}

export async function createDeepInvestigationJob(target: string, config: Config, threatModel = '', scopeRequested = false, maxRounds = 10): Promise<DeepInvestigationJob> {
  const state = getStateDir(config.stateDir)
  const scan = await runScan(target, config, 'deep', threatModel, scopeRequested, config.stateDir, false)
  await persistInvestigationArtifacts(state, scan)
  await saveScan(state, scan)
  const discovery = await createDeepDiscoveryJob(config, scan.id, maxRounds)
  const now = new Date().toISOString()
  const job: DeepInvestigationJob = {
    id: `deepflow_${randomUUID()}`,
    scanId: scan.id,
    target: scan.target,
    phase: 'discovery',
    lifecycle: 'queued',
    createdAt: now,
    updatedAt: now,
    discoveryJobId: discovery.id,
  }
  await save(config, job)
  return job
}

function cancelled(signal: AbortSignal | undefined): boolean { return signal?.aborted === true }

function pausedLifecycle(lifecycle: string): Extract<DeepInvestigationLifecycle, 'incomplete' | 'cancelled' | 'failed'> {
  if (lifecycle === 'cancelled' || lifecycle === 'failed') return lifecycle
  return 'incomplete'
}

function hasOpenTasks(scan: Awaited<ReturnType<typeof loadScan>>, phase: 'validation' | 'attack_path'): boolean {
  return scan.tasks.some(task => task.phase === phase && (task.status === 'pending' || task.status === 'claimed'))
}

/**
 * Advance one complete deep investigation using only native DSH child agents.
 * A nonterminal subordinate job is retained for an explicit resume; it is never
 * silently replaced with a local heuristic or another assistant runtime.
 */
export async function runDeepInvestigation(ctx: Context, config: Config, jobId: string, signal?: AbortSignal): Promise<DeepInvestigationJob> {
  let job = await loadDeepInvestigationJob(config, jobId)
  if (!['queued', 'incomplete', 'cancelled'].includes(job.lifecycle)) throw new Error('Deep investigation job has already completed or failed.')
  if (cancelled(signal)) { job.lifecycle = 'cancelled'; await save(config, job); return job }
  job.lifecycle = 'running'
  await save(config, job)
  try {
    while (true) {
      if (cancelled(signal)) { job.lifecycle = 'cancelled'; await save(config, job); return job }
      if (job.phase === 'discovery') {
        const discovery = await runDeepDiscovery(ctx, config, job.discoveryJobId, signal)
        if (!['saturated', 'capped'].includes(discovery.lifecycle)) {
          job.lifecycle = pausedLifecycle(discovery.lifecycle)
          await save(config, job)
          return job
        }
        job.phase = 'validation'
        await save(config, job)
        continue
      }

      const scan = await loadScan(getStateDir(config.stateDir), job.scanId)
      if (job.phase === 'validation') {
        if (!hasOpenTasks(scan, 'validation')) {
          job.phase = 'attack_path'
          await save(config, job)
          continue
        }
        if (!job.validationClosureJobId) {
          const closure = await createDeepClosureJob(config, job.scanId, 'validation')
          job.validationClosureJobId = closure.id
          await save(config, job)
        }
        const closure = await runDeepClosure(ctx, config, job.validationClosureJobId, signal)
        if (closure.lifecycle !== 'completed') {
          job.lifecycle = pausedLifecycle(closure.lifecycle)
          await save(config, job)
          return job
        }
        job.phase = 'attack_path'
        await save(config, job)
        continue
      }

      if (job.phase === 'attack_path') {
        if (!hasOpenTasks(scan, 'attack_path')) {
          job.phase = 'finalization'
          await save(config, job)
          continue
        }
        if (!job.attackPathClosureJobId) {
          const closure = await createDeepClosureJob(config, job.scanId, 'attack_path')
          job.attackPathClosureJobId = closure.id
          await save(config, job)
        }
        const closure = await runDeepClosure(ctx, config, job.attackPathClosureJobId, signal)
        if (closure.lifecycle !== 'completed') {
          job.lifecycle = pausedLifecycle(closure.lifecycle)
          await save(config, job)
          return job
        }
        job.phase = 'finalization'
        await save(config, job)
        continue
      }

      const completed = await completeScan(config, job.scanId)
      job.lifecycle = completed.lifecycle === 'completed' ? 'completed' : 'incomplete'
      if (job.lifecycle === 'completed') job.completedAt = new Date().toISOString()
      await save(config, job)
      return job
    }
  } catch (error) {
    job.lifecycle = 'failed'
    await save(config, job)
    throw error
  }
}
