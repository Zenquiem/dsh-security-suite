import assert from 'node:assert/strict'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { createDeepDiscoveryJob, getDeepWorklist, loadDeepDiscoveryJob, readDeepSource, reportDeepCandidate, reportDeepWorker, runDeepDiscovery } from '../src/deep-discovery.ts'
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

function deepWorkerContext(config: { stateDir: string }, reports: boolean, failAt?: number, closesCoverage = true) {
  let created = 0; const restrictions: string[][] = []
  const ctx = {
    agents: {
      async create(options: { setup?: (ctx: { tools: { restrict(filter: { allow: string[] }): void }; systemPrompt: { section(section: { name: string }): void } }) => void }) {
        const index = ++created
        let prompt = ''
        options.setup?.({ tools: { restrict(filter) { restrictions.push(filter.allow) } }, systemPrompt: { section() {} } })
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
              if (closesCoverage) await reportDeepWorker(config, jobId, workerId, token, { threatModel: 'The worker independently models remote request input crossing command execution and filesystem trust boundaries.', reviewedPaths: ['app.ts'], deferred: [], coverageSummary: 'Reviewed the complete authoritative source worklist and found one source-backed candidate.' })
            },
            session: { deriveMessages: () => [{ role: 'assistant', content: [{ type: 'text', text: 'review complete' }] }] },
          },
          async dispose() {},
        }
      },
    },
  }
  return { ctx, count: () => created, restrictions }
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
    assert.deepEqual(fake.restrictions[0], ['security_deep_get_worklist', 'security_deep_read_source', 'security_deep_report_candidate', 'security_deep_report_worker'])
    assert.equal(result.lifecycle, 'saturated')
    assert.deepEqual(result.rounds.map(round => round.status), ['complete', 'complete'])
    assert.deepEqual(result.rounds.map(round => round.novelty), [1, 0])
    const persisted = await loadScan(state, scan.id)
    assert.equal(persisted.findings.some(finding => finding.ruleId === 'custom.delegated-sink'), true)
    assert.equal(persisted.tasks.some(task => task.focus.includes('Delegated sink')), true)
    const coverage = JSON.parse(await readFile(join(persisted.artifacts.directory, 'artifacts', '02_discovery', 'deep', 'round-01', 'worker_1_1', 'coverage.json'), 'utf8')) as { reviewedPaths: string[] }
    assert.deepEqual(coverage.reviewedPaths, ['app.ts'])
    assert.equal(result.rounds[0]?.artifactRefs?.some(path => path.endsWith('merge.json')), true)
    assert.match(await readFile(join(persisted.artifacts.directory, 'artifacts', '03_coverage', 'repository_coverage_ledger.md'), 'utf8'), /app\.ts/)
    assert.match(await readFile(join(persisted.artifacts.directory, 'artifacts', '04_reconciliation', 'dedupe_report.md'), 'utf8'), /absorbed workers/)
  } finally { await rm(root, { recursive: true, force: true }); await rm(state, { recursive: true, force: true }) }
})

test('worker closure rejects an incomplete authoritative worklist', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  const state = await mkdtemp(join(tmpdir(), 'dsh-security-suite-state-'))
  const config = { enabled: true, maxFiles: 10, maxFileBytes: 4096, stateDir: state }
  try {
    await writeFile(join(root, 'app.ts'), 'runUntrustedCommand(input)\n')
    await writeFile(join(root, 'other.ts'), 'const x = 1\n')
    const scan = await runScan(root, config, 'deep', '', false, state, false)
    await saveScan(state, scan)
    const job = await createDeepDiscoveryJob(config, scan.id)
    job.lifecycle = 'running'; job.workers.push({ id: 'worker_1_1', round: 1, status: 'running', token: 'claim', candidateIds: [] })
    await writeFile(join(state, 'deep-discovery', `${job.id}.json`), `${JSON.stringify(job)}\n`)
    await assert.rejects(() => reportDeepWorker(config, job.id, 'worker_1_1', 'claim', { threatModel: 'The independent model identifies untrusted inputs crossing route, command, and storage trust boundaries.', reviewedPaths: ['app.ts'], deferred: [], coverageSummary: 'Only one file was reviewed.' }), /unclosed: other\.ts/)
  } finally { await rm(root, { recursive: true, force: true }); await rm(state, { recursive: true, force: true }) }
})

test('claimed workers can read only the immutable authoritative worklist and source snapshot', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  const state = await mkdtemp(join(tmpdir(), 'dsh-security-suite-state-'))
  const config = { enabled: true, maxFiles: 10, maxFileBytes: 4096, stateDir: state }
  try {
    await writeFile(join(root, 'app.ts'), 'const value = 1\n')
    const scan = await runScan(root, config, 'deep', '', false, state, false)
    await saveScan(state, scan)
    const job = await createDeepDiscoveryJob(config, scan.id)
    job.lifecycle = 'running'; job.workers.push({ id: 'worker_1_1', round: 1, status: 'running', token: 'claim', candidateIds: [] })
    await writeFile(join(state, 'deep-discovery', `${job.id}.json`), `${JSON.stringify(job)}\n`)
    const worklist = await getDeepWorklist(config, job.id, 'worker_1_1', 'claim')
    assert.equal(worklist.items[0]?.path, 'app.ts')
    const source = await readDeepSource(config, job.id, 'worker_1_1', 'claim', 'app.ts')
    assert.match(source.content, /value = 1/)
    await assert.rejects(() => readDeepSource(config, job.id, 'worker_1_1', 'claim', '../outside.ts'), /authoritative/)
    await writeFile(join(root, 'app.ts'), 'const changed = 2\n')
    await assert.rejects(() => readDeepSource(config, job.id, 'worker_1_1', 'claim', 'app.ts'), /changed after/)
  } finally { await rm(root, { recursive: true, force: true }); await rm(state, { recursive: true, force: true }) }
})

test('workers that omit their threat-model and coverage closure make the deep round incomplete', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  const state = await mkdtemp(join(tmpdir(), 'dsh-security-suite-state-'))
  const config = { enabled: true, maxFiles: 10, maxFileBytes: 4096, stateDir: state }
  try {
    await writeFile(join(root, 'app.ts'), 'runUntrustedCommand(input)\n')
    const scan = await runScan(root, config, 'deep', '', false, state, false)
    await saveScan(state, scan)
    const job = await createDeepDiscoveryJob(config, scan.id, 1)
    const result = await runDeepDiscovery(deepWorkerContext(config, true, undefined, false).ctx as never, config, job.id)
    assert.equal(result.lifecycle, 'incomplete')
    assert.equal(result.rounds[0]?.status, 'incomplete')
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

test('cancelling deep discovery disposes active DSH workers and preserves the incomplete round without merging it', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  const state = await mkdtemp(join(tmpdir(), 'dsh-security-suite-state-'))
  const config = { enabled: true, maxFiles: 10, maxFileBytes: 4096, stateDir: state }
  try {
    await writeFile(join(root, 'app.ts'), 'runUntrustedCommand(input)\n')
    const scan = await runScan(root, config, 'deep', '', false, state, false)
    await saveScan(state, scan)
    const job = await createDeepDiscoveryJob(config, scan.id, 1)
    const controller = new AbortController(); let created = 0; let disposed = 0; let releaseCreated!: () => void
    const allCreated = new Promise<void>(resolve => { releaseCreated = resolve })
    const ctx = {
      agents: {
        async create(options: { setup?: (ctx: { tools: { restrict(): void }; systemPrompt: { section(): void } }) => void }) {
          options.setup?.({ tools: { restrict() {} }, systemPrompt: { section() {} } })
          created++; if (created === 6) releaseCreated()
          return {
            agent: {
              followup() {},
              async whenIdle() { await new Promise<void>(() => undefined) },
              session: { deriveMessages: () => [] },
            },
            async dispose() { disposed++ },
          }
        },
      },
    }
    const running = runDeepDiscovery(ctx as never, config, job.id, controller.signal)
    await allCreated
    controller.abort('user cancelled')
    const result = await running
    assert.equal(result.lifecycle, 'cancelled')
    assert.equal(disposed, 6)
    assert.equal(result.workers.filter(worker => worker.status === 'cancelled').length, 6)
    assert.equal(result.rounds[0]?.status, 'incomplete')
    assert.equal((await loadScan(state, scan.id)).findings.length, scan.findings.length)
  } finally { await rm(root, { recursive: true, force: true }); await rm(state, { recursive: true, force: true }) }
})

test('a cancelled deep discovery resumes with fresh workers and merges only its completed round', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  const state = await mkdtemp(join(tmpdir(), 'dsh-security-suite-state-'))
  const config = { enabled: true, maxFiles: 10, maxFileBytes: 4096, stateDir: state }
  try {
    await writeFile(join(root, 'app.ts'), 'runUntrustedCommand(input)\n')
    const scan = await runScan(root, config, 'deep', '', false, state, false)
    await saveScan(state, scan)
    const job = await createDeepDiscoveryJob(config, scan.id, 1)
    const controller = new AbortController(); let releaseCreated!: () => void
    const allCreated = new Promise<void>(resolve => { releaseCreated = resolve }); let created = 0
    const cancelledContext = { agents: { async create(options: { setup?: (ctx: { tools: { restrict(): void }; systemPrompt: { section(): void } }) => void }) { options.setup?.({ tools: { restrict() {} }, systemPrompt: { section() {} } }); if (++created === 6) releaseCreated(); return { agent: { followup() {}, async whenIdle() { await new Promise<void>(() => undefined) }, session: { deriveMessages: () => [] } }, async dispose() {} } } } }
    const interrupted = runDeepDiscovery(cancelledContext as never, config, job.id, controller.signal)
    await allCreated; controller.abort()
    assert.equal((await interrupted).lifecycle, 'cancelled')
    const resumed = await runDeepDiscovery(deepWorkerContext(config, true).ctx as never, config, job.id)
    assert.equal(resumed.lifecycle, 'capped')
    assert.equal(resumed.rounds.length, 2)
    assert.deepEqual(resumed.rounds.map(round => round.status), ['incomplete', 'complete'])
    assert.equal((await loadScan(state, scan.id)).findings.some(finding => finding.ruleId === 'custom.delegated-sink'), true)
  } finally { await rm(root, { recursive: true, force: true }); await rm(state, { recursive: true, force: true }) }
})
