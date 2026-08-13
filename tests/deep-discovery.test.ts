import assert from 'node:assert/strict'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { createDeepDiscoveryJob, loadDeepDiscoveryJob, reportDeepCandidate, runDeepDiscovery } from '../src/deep-discovery.ts'
import { runScan } from '../src/scanner.ts'
import { loadScan, saveScan } from '../src/state.ts'

test('deep candidate reports require the exact active worker token and readable source location', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  const state = await mkdtemp(join(tmpdir(), 'dsh-security-suite-state-'))
  const config = { enabled: true, maxFiles: 10, maxFileBytes: 4096, stateDir: state }
  try {
    await writeFile(join(root, 'app.ts'), 'function h(req) { return eval(req.query.code) }\n')
    const scan = await runScan(root, config, 'deep', '', false, state, false)
    await saveScan(state, scan)
    const job = await createDeepDiscoveryJob(config, scan.id)
    job.lifecycle = 'running'; job.workers.push({ id: 'worker_1_1', round: 1, status: 'running', token: 'claim', candidateIds: [] })
    await writeFile(join(state, 'deep-discovery', `${job.id}.json`), `${JSON.stringify(job)}\n`)
    await assert.rejects(() => reportDeepCandidate(config, job.id, 'worker_1_1', 'wrong', { ruleId: 'dynamic-code.eval', title: 'eval', severity: 'high', cwe: 'CWE-95', file: 'app.ts', line: 1, rootCause: 'request input reaches eval' }), /claim/)
    const candidate = await reportDeepCandidate(config, job.id, 'worker_1_1', 'claim', { ruleId: 'dynamic-code.eval', title: 'eval', severity: 'high', cwe: 'CWE-95', file: 'app.ts', line: 1, rootCause: 'request input reaches eval' })
    assert.equal(candidate.workerId, 'worker_1_1')
    assert.equal((await loadScan(state, scan.id)).findings.length > 0, true)
  } finally { await rm(root, { recursive: true, force: true }); await rm(state, { recursive: true, force: true }) }
})

function deepWorkerContext(config: { stateDir: string }, reports: boolean, failAt?: number) {
  let created = 0
  const ctx = {
    agents: {
      async create() {
        const index = ++created
        let prompt = ''
        return {
          agent: {
            followup(message: { content: Array<{ type: string; text?: string }> }) { prompt = message.content[0]?.text ?? '' },
            async whenIdle() {
              if (index === failAt) throw new Error('worker driver failed')
              if (!reports) return
              const jobId = /job_id (deep_[0-9a-f-]+)/.exec(prompt)?.[1]
              const workerId = /worker_id (worker_\d+_\d+)/.exec(prompt)?.[1]
              const token = /claim_token ([0-9a-f-]+)/.exec(prompt)?.[1]
              if (!jobId || !workerId || !token) throw new Error('worker brief was incomplete')
              await reportDeepCandidate(config, jobId, workerId, token, { ruleId: 'custom.delegated-sink', title: 'Delegated sink', severity: 'high', cwe: 'CWE-78', file: 'app.ts', line: 1, rootCause: 'The worker found a source-backed sink.' })
            },
            session: { deriveMessages: () => [{ role: 'assistant', content: [{ type: 'text', text: 'review complete' }] }] },
          },
          async dispose() {},
        }
      },
    },
  }
  return { ctx, count: () => created }
}

test('deep discovery creates six native DSH workers per round and only saturates after a complete zero-novelty round', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  const state = await mkdtemp(join(tmpdir(), 'dsh-security-suite-state-'))
  const config = { enabled: true, maxFiles: 10, maxFileBytes: 4096, stateDir: state }
  try {
    await writeFile(join(root, 'app.ts'), 'runUntrustedCommand(input)\n')
    const scan = await runScan(root, config, 'deep', '', false, state, false)
    await saveScan(state, scan)
    const job = await createDeepDiscoveryJob(config, scan.id, 2)
    const fake = deepWorkerContext(config, true)
    const result = await runDeepDiscovery(fake.ctx as never, config, job.id)
    assert.equal(fake.count(), 12)
    assert.equal(result.lifecycle, 'saturated')
    assert.deepEqual(result.rounds.map(round => round.status), ['complete', 'complete'])
    assert.deepEqual(result.rounds.map(round => round.novelty), [1, 0])
    const persisted = await loadScan(state, scan.id)
    assert.equal(persisted.findings.some(finding => finding.ruleId === 'custom.delegated-sink'), true)
    assert.equal(persisted.tasks.some(task => task.focus.includes('Delegated sink')), true)
  } finally { await rm(root, { recursive: true, force: true }); await rm(state, { recursive: true, force: true }) }
})

test('failed worker produces incomplete discovery and does not merge candidates into the scan', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  const state = await mkdtemp(join(tmpdir(), 'dsh-security-suite-state-'))
  const config = { enabled: true, maxFiles: 10, maxFileBytes: 4096, stateDir: state }
  try {
    await writeFile(join(root, 'app.ts'), 'runUntrustedCommand(input)\n')
    const scan = await runScan(root, config, 'deep', '', false, state, false)
    await saveScan(state, scan)
    const before = (await loadScan(state, scan.id)).findings.length
    const job = await createDeepDiscoveryJob(config, scan.id, 1)
    const fake = deepWorkerContext(config, true, 3)
    const result = await runDeepDiscovery(fake.ctx as never, config, job.id)
    assert.equal(result.lifecycle, 'incomplete')
    assert.equal(result.rounds[0]?.status, 'incomplete')
    assert.equal((await loadScan(state, scan.id)).findings.length, before)
  } finally { await rm(root, { recursive: true, force: true }); await rm(state, { recursive: true, force: true }) }
})

test('missing DSH agent runtime marks the queued job failed without a fallback engine', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  const state = await mkdtemp(join(tmpdir(), 'dsh-security-suite-state-'))
  const config = { enabled: true, maxFiles: 10, maxFileBytes: 4096, stateDir: state }
  try {
    await writeFile(join(root, 'app.ts'), 'const x = 1\n')
    const scan = await runScan(root, config, 'deep', '', false, state, false)
    await saveScan(state, scan)
    const job = await createDeepDiscoveryJob(config, scan.id, 1)
    await assert.rejects(() => runDeepDiscovery({} as never, config, job.id), /native agent-creation service/)
    assert.equal((await loadDeepDiscoveryJob(config, job.id)).lifecycle, 'failed')
  } finally { await rm(root, { recursive: true, force: true }); await rm(state, { recursive: true, force: true }) }
})
