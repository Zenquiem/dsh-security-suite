import assert from 'node:assert/strict'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { createDeepClosureJob, createDeepDiscoveryJob, getDeepWorklist, loadDeepDiscoveryJob, readDeepSource, readScanSource, reportDeepCandidate, reportDeepReducer, reportDeepWorker, runDeepClosure, runDeepDiscovery } from '../src/deep-discovery.ts'
import { runScan } from '../src/scanner.ts'
import { finalizeAndSaveScan, loadScan, saveScan, verifyScanBundle } from '../src/state.ts'
import { claimAuditTask, recordAttackPath, recordValidation } from '../src/workbench.ts'

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

test('deep reconciliation merges only reports with one shared remediation identity', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  const state = await mkdtemp(join(tmpdir(), 'dsh-security-suite-state-'))
  const config = { enabled: true, maxFiles: 10, maxFileBytes: 4096, stateDir: state }
  try {
    await writeFile(join(root, 'app.ts'), 'function h(req) { return eval(req.query.code) }\n')
    const scan = await runScan(root, config, 'deep', '', false, state, false); await saveScan(state, scan)
    const job = await createDeepDiscoveryJob(config, scan.id)
    job.lifecycle = 'running'; job.workers.push({ id: 'worker_1_1', round: 1, status: 'running', token: 'first', candidateIds: [] }, { id: 'worker_1_2', round: 1, status: 'running', token: 'second', candidateIds: [] })
    await writeFile(join(state, 'deep-discovery', `${job.id}.json`), `${JSON.stringify(job)}\n`)
    const shared = { ruleId: 'dynamic-code.eval', title: 'eval', severity: 'high' as const, cwe: 'CWE-95', file: 'app.ts', line: 1, rootCause: 'Request input reaches dynamic code execution.', remediationIdentity: 'Reject untrusted request data before dynamic evaluation.' }
    const first = await reportDeepCandidate(config, job.id, 'worker_1_1', 'first', shared)
    const duplicate = await reportDeepCandidate(config, job.id, 'worker_1_2', 'second', shared)
    const independent = await reportDeepCandidate(config, job.id, 'worker_1_2', 'second', { ...shared, remediationIdentity: 'Remove dynamic evaluation and dispatch only an allowlisted operation.' })
    assert.equal(duplicate.id, first.id)
    assert.equal(first.remediationSubsumption.decision, 'not_merged')
    assert.equal((await loadDeepDiscoveryJob(config, job.id)).candidates.find(candidate => candidate.id === first.id)?.remediationSubsumption.decision, 'merged_equivalent_reports')
    assert.notEqual(independent.id, first.id)
    assert.equal((await loadDeepDiscoveryJob(config, job.id)).candidates.length, 2)
  } finally { await rm(root, { recursive: true, force: true }); await rm(state, { recursive: true, force: true }) }
})

test('deep candidate reports fail closed when the frozen source receipt drifts', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  const state = await mkdtemp(join(tmpdir(), 'dsh-security-suite-state-'))
  const config = { enabled: true, maxFiles: 10, maxFileBytes: 4096, stateDir: state }
  try {
    await writeFile(join(root, 'app.ts'), 'function h(req) { return eval(req.query.code) }\n')
    const scan = await runScan(root, config, 'deep', '', false, state, false); await saveScan(state, scan)
    const job = await createDeepDiscoveryJob(config, scan.id)
    job.lifecycle = 'running'; job.workers.push({ id: 'worker_1_1', round: 1, status: 'running', token: 'claim', candidateIds: [] })
    await writeFile(join(state, 'deep-discovery', `${job.id}.json`), `${JSON.stringify(job)}\n`)
    await writeFile(join(root, 'app.ts'), 'function h(req) { return eval(req.query.changed) }\n')
    await assert.rejects(() => reportDeepCandidate(config, job.id, 'worker_1_1', 'claim', { ruleId: 'dynamic-code.eval', title: 'eval', severity: 'high', cwe: 'CWE-95', file: 'app.ts', line: 1, rootCause: 'request input reaches eval' }), /changed after/)
  } finally { await rm(root, { recursive: true, force: true }); await rm(state, { recursive: true, force: true }) }
})

function deepWorkerContext(config: { stateDir: string }, reports: boolean, failAt?: number, closesCoverage = true) {
  let created = 0; const restrictions: string[][] = []; const prompts: string[] = []
  const ctx = {
    agents: {
      async create(options: { setup?: (ctx: { tools: { restrict(filter: { allow: string[] }): void }; systemPrompt: { section(section: { name: string }): void } }) => void }) {
        const index = ++created
        let prompt = ''
        options.setup?.({ tools: { restrict(filter) { restrictions.push(filter.allow) } }, systemPrompt: { section() {} } })
        return {
          agent: {
            followup(message: { content: Array<{ type: string; text?: string }> }) { prompt = message.content[0]?.text ?? ''; prompts.push(prompt) },
            async whenIdle() {
              if (index === failAt) throw new Error('worker driver failed')
              if (!reports) return
              // Semantic reducer agent: parse reducer ids and close without merges.
              if (prompt.includes('Deep Discovery Semantic Reducer')) {
                const reducerId = /reducer_id ([a-z0-9_]+)/.exec(prompt)?.[1]
                const reducerToken = /claim_token ([0-9a-f-]+)/.exec(prompt)?.[1]
                if (!reducerId || !reducerToken) throw new Error('reducer brief was incomplete')
                await reportDeepReducer(config, /job_id (deep_[0-9a-f-]+)/.exec(prompt)?.[1] ?? '', reducerId, reducerToken, [])
                return
              }
              const jobId = /job_id (deep_[0-9a-f-]+)/.exec(prompt)?.[1]
              const workerId = /worker_id (worker_\d+_\d+)/.exec(prompt)?.[1]
              const token = /claim_token ([0-9a-f-]+)/.exec(prompt)?.[1]
              if (!jobId || !workerId || !token) throw new Error('worker brief was incomplete')
              await reportDeepCandidate(config, jobId, workerId, token, { ruleId: 'custom.delegated-sink', title: 'Delegated sink', severity: 'high', cwe: 'CWE-78', file: 'app.ts', line: 1, rootCause: 'The worker found a source-backed sink.' })
              if (closesCoverage) { const worklist = await getDeepWorklist(config, jobId, workerId, token); await reportDeepWorker(config, jobId, workerId, token, { threatModel: 'The worker independently models remote request input crossing command execution and filesystem trust boundaries.', reviewedWorkItemIds: worklist.items.map(item => item.id), deferred: [], coverageSummary: 'Reviewed every authoritative source region and found one source-backed candidate.' }) }
            },
            session: { deriveMessages: () => [{ role: 'assistant', content: [{ type: 'text', text: 'review complete' }] }] },
          },
          async dispose() {},
        }
      },
    },
  }
  return { ctx, count: () => created, restrictions, prompts }
}

test('deep discovery creates six native DSH workers per round and only saturates after a complete zero-novelty round', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  const state = await mkdtemp(join(tmpdir(), 'dsh-security-suite-state-'))
  const config = { enabled: true, maxFiles: 10, maxFileBytes: 4096, stateDir: state, deepScan: { workers: 'auto' as const, subagents: 0, stopAfterNoNew: 1, stopAfterConsecutiveErrors: 3, maxDiscoveryRuns: 60, maxTimeHours: 96 } }
  try {
    await writeFile(join(root, 'app.ts'), 'runUntrustedCommand(input)\n')
    const scan = await runScan(root, config, 'deep', '', false, state, false)
    await saveScan(state, scan)
    const job = await createDeepDiscoveryJob(config, scan.id, 2)
    const fake = deepWorkerContext(config, true)
    const result = await runDeepDiscovery(fake.ctx as never, config, job.id)
    assert.equal(fake.count(), 14) // 12 discovery workers + 2 semantic reducers
    assert.deepEqual(fake.restrictions[0], ['security_deep_get_worklist', 'security_deep_read_source', 'security_deep_report_candidate', 'security_deep_report_worker'])
    assert.equal(result.lifecycle, 'saturated')
    assert.deepEqual(result.rounds.map(round => round.status), ['complete', 'complete'])
    assert.deepEqual(result.rounds.map(round => round.novelty), [1, 0])
    assert.deepEqual(result.workers.slice(0, 6).map(worker => worker.lens), ['forward', 'backward', 'authorization', 'open-ended', 'parsers', 'secrets'])
    const canonicalBriefs = fake.prompts.slice(0, 6).map(prompt => prompt.replace(/worker_id worker_1_\d+/g, 'worker_id <worker>').replace(/claim_token [0-9a-f-]+/g, 'claim_token <token>'))
    assert.equal(new Set(canonicalBriefs).size, 6)
    assert.equal(canonicalBriefs[0]?.includes('distinct review lens is Forward dataflow'), true)
    assert.equal(canonicalBriefs[1]?.includes('distinct review lens is Backward from sinks'), true)
    assert.equal(result.canonicalThreatModel?.workerIds.length, 12)
    const persisted = await loadScan(state, scan.id)
    assert.equal(persisted.findings.some(finding => finding.ruleId === 'custom.delegated-sink'), true)
    assert.equal(persisted.tasks.some(task => task.focus.includes('Delegated sink')), true)
    const coverage = JSON.parse(await readFile(join(persisted.artifacts.directory, 'artifacts', '02_discovery', 'deep', 'round-01', 'worker_1_1', 'coverage.json'), 'utf8')) as { reviewedWorkItemIds: string[] }
    assert.equal(coverage.reviewedWorkItemIds.length, 1)
    assert.equal(result.rounds[0]?.artifactRefs?.some(path => path.endsWith('merge.json')), true)
    assert.match(await readFile(join(persisted.artifacts.directory, 'artifacts', '03_coverage', 'repository_coverage_ledger.md'), 'utf8'), /app\.ts/)
    assert.match(await readFile(join(persisted.artifacts.directory, 'artifacts', '04_reconciliation', 'dedupe_report.md'), 'utf8'), /absorbed workers/)
    assert.match(await readFile(join(persisted.artifacts.directory, 'artifacts', '01_context', 'deep_canonical_threat_model.md'), 'utf8'), /Canonical Deep Validation Threat Model/)
  } finally { await rm(root, { recursive: true, force: true }); await rm(state, { recursive: true, force: true }) }
})

test('an incomplete deep round retains process evidence but cannot merge or saturate provisional candidates', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  const state = await mkdtemp(join(tmpdir(), 'dsh-security-suite-state-'))
  const config = { enabled: true, maxFiles: 10, maxFileBytes: 4096, stateDir: state, deepScan: { workers: 'auto' as const, subagents: 0, stopAfterNoNew: 1, stopAfterConsecutiveErrors: 3, maxDiscoveryRuns: 60, maxTimeHours: 96 } }
  try {
    await writeFile(join(root, 'app.ts'), 'runUntrustedCommand(input)\n')
    const scan = await runScan(root, config, 'deep', '', false, state, false); await saveScan(state, scan)
    const job = await createDeepDiscoveryJob(config, scan.id, 2)
    const result = await runDeepDiscovery(deepWorkerContext(config, true, 6).ctx as never, config, job.id)
    assert.equal(result.lifecycle, 'incomplete')
    assert.deepEqual(result.rounds.map(round => [round.status, round.novelty]), [['incomplete', 0]])
    const persisted = await loadScan(state, scan.id)
    assert.equal(persisted.findings.some(finding => finding.ruleId === 'custom.delegated-sink'), false)
    const reconciliation = join(persisted.artifacts.directory, 'artifacts', '04_reconciliation')
    assert.match(await readFile(join(reconciliation, 'deep-round-01-incomplete.json'), 'utf8'), /excluded from canonical reconciliation/)
    await assert.rejects(() => readFile(join(reconciliation, 'deep-round-01-merge.json'), 'utf8'))
  } finally { await rm(root, { recursive: true, force: true }); await rm(state, { recursive: true, force: true }) }
})

test('deep worklists freeze risk-prioritized source evidence and fail closed if a receipt changes before job creation', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  const state = await mkdtemp(join(tmpdir(), 'dsh-security-suite-state-'))
  const config = { enabled: true, maxFiles: 10, maxFileBytes: 4096, stateDir: state }
  try {
    await writeFile(join(root, 'plain.ts'), 'export const value = 1\n')
    await writeFile(join(root, 'api.ts'), 'export function h(req) { return eval(req.query.code) }\n')
    const scan = await runScan(root, config, 'deep', '', false, state, false); await saveScan(state, scan)
    const job = await createDeepDiscoveryJob(config, scan.id)
    assert.equal(job.worklist[0]?.path, 'api.ts')
    assert.equal(job.worklist[0]?.startLine, 1)
    assert.equal(job.worklist[0]?.endLine, 1)
    assert.equal(job.worklist[0]?.priority > job.worklist[1]!.priority, true)
    assert.equal(job.worklist[0]?.riskSignals.includes('execution or query sink'), true)
    await writeFile(join(root, 'api.ts'), 'export const changed = true\n')
    await assert.rejects(() => createDeepDiscoveryJob(config, scan.id), /changed after scan receipt/)
  } finally { await rm(root, { recursive: true, force: true }); await rm(state, { recursive: true, force: true }) }
})

test('deep worklists split large files into immutable source regions and bind candidates to a region', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  const state = await mkdtemp(join(tmpdir(), 'dsh-security-suite-state-'))
  const config = { enabled: true, maxFiles: 10, maxFileBytes: 100_000, stateDir: state }
  try {
    const lines = Array.from({ length: 401 }, (_, index) => index === 250 ? 'function h(req) { return eval(req.query.code) }' : `const line${index + 1} = ${index + 1}`)
    await writeFile(join(root, 'app.ts'), `${lines.join('\n')}\n`)
    const scan = await runScan(root, config, 'deep', '', false, state, false); await saveScan(state, scan)
    const job = await createDeepDiscoveryJob(config, scan.id)
    assert.deepEqual(job.worklist.filter(item => item.path === 'app.ts').map(item => [item.startLine, item.endLine]), [[201, 400], [1, 200], [401, 401]])
    job.lifecycle = 'running'; job.workers.push({ id: 'worker_1_1', round: 1, status: 'running', token: 'claim', candidateIds: [] })
    await writeFile(join(state, 'deep-discovery', `${job.id}.json`), `${JSON.stringify(job)}\n`)
    const region = job.worklist.find(item => item.path === 'app.ts' && item.startLine === 201)!
    const source = await readDeepSource(config, job.id, 'worker_1_1', 'claim', region.id)
    assert.equal(source.startLine, 201)
    assert.equal(source.endLine, 400)
    assert.match(source.content, /eval/)
    await assert.rejects(() => reportDeepCandidate(config, job.id, 'worker_1_1', 'claim', { ruleId: 'custom.outside-region', title: 'Outside receipt', severity: 'high', cwe: 'CWE-78', file: 'app.ts', line: 999, rootCause: 'This line does not exist in the immutable region list.' }), /region/)
  } finally { await rm(root, { recursive: true, force: true }); await rm(state, { recursive: true, force: true }) }
})

test('worker closure rejects an incomplete authoritative worklist', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  const state = await mkdtemp(join(tmpdir(), 'dsh-security-suite-state-'))
  const config = { enabled: true, maxFiles: 10, maxFileBytes: 4096, stateDir: state, deepScan: { workers: 'auto' as const, subagents: 0, stopAfterNoNew: 1, stopAfterConsecutiveErrors: 3, maxDiscoveryRuns: 60, maxTimeHours: 96 } }
  try {
    await writeFile(join(root, 'app.ts'), 'runUntrustedCommand(input)\n')
    await writeFile(join(root, 'other.ts'), 'const x = 1\n')
    const scan = await runScan(root, config, 'deep', '', false, state, false)
    await saveScan(state, scan)
    const job = await createDeepDiscoveryJob(config, scan.id)
    job.lifecycle = 'running'; job.workers.push({ id: 'worker_1_1', round: 1, status: 'running', token: 'claim', candidateIds: [] })
    await writeFile(join(state, 'deep-discovery', `${job.id}.json`), `${JSON.stringify(job)}\n`)
    const worklist = await getDeepWorklist(config, job.id, 'worker_1_1', 'claim')
    await assert.rejects(() => reportDeepWorker(config, job.id, 'worker_1_1', 'claim', { threatModel: 'The independent model identifies untrusted inputs crossing route, command, and storage trust boundaries.', reviewedWorkItemIds: [worklist.items.find(item => item.path === 'app.ts')!.id], deferred: [], coverageSummary: 'Only one source region was reviewed.' }), /region unclosed/)
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
    const source = await readDeepSource(config, job.id, 'worker_1_1', 'claim', worklist.items[0]!.id)
    assert.match(source.content, /value = 1/)
    await assert.rejects(() => readDeepSource(config, job.id, 'worker_1_1', 'claim', '../outside.ts'), /authoritative/)
    await writeFile(join(root, 'app.ts'), 'const changed = 2\n')
    await assert.rejects(() => readDeepSource(config, job.id, 'worker_1_1', 'claim', worklist.items[0]!.id), /changed after/)
  } finally { await rm(root, { recursive: true, force: true }); await rm(state, { recursive: true, force: true }) }
})

function deepClosureContext(config: { stateDir: string }, phase: 'validation' | 'attack_path') {
  let created = 0; const restrictions: string[][] = []
  const ctx = { agents: { async create(options: { setup?: (ctx: { tools: { restrict(filter: { allow: string[] }): void }; systemPrompt: { section(section: { name: string }): void } }) => void }) {
    const index = ++created; let prompt = ''
    options.setup?.({ tools: { restrict(filter) { restrictions.push(filter.allow) } }, systemPrompt: { section() {} } })
    return { agent: { followup(message: { content: Array<{ text?: string }> }) { prompt = message.content[0]?.text ?? '' }, async whenIdle() {
      if (index !== 1) return
      const scanId = /scan_id (scan_[0-9a-f-]+)/.exec(prompt)?.[1]; const owner = /owner (closure_[a-z_]+_\d+_\d+)/.exec(prompt)?.[1]
      if (!scanId || !owner) throw new Error('closure worker brief was incomplete')
      while (true) {
        const task = await claimAuditTask(config as never, scanId, owner, phase)
        if (!task) return
        const current = await loadScan(config.stateDir, scanId)
        const finding = current.findings.find(item => item.candidateId === task.candidateId); if (!finding) throw new Error('Test candidate was not found.')
        const sourceReferences = finding.locations.map(location => ({ file: location.file, line: location.line, role: location.role ?? 'root_control' })) as never
        if (phase === 'validation') await recordValidation(config as never, scanId, task.candidateId, { conclusion: 'reportable', method: 'static', attacker: 'Remote caller able to provide a request parameter.', entryPoint: 'Request handler input.', trustBoundary: 'Untrusted request to application execution.', rootControl: 'Dynamic execution control.', sink: 'Dynamic code execution.', impact: 'Remote caller-controlled code execution.', directEvidence: 'Request-derived input reaches the reported execution operation.', counterevidence: 'No sanitizing or authorization control was found in the reviewed path.', limitations: 'Runtime reproduction was not performed in this isolated closure phase.', confidence: 'medium', sourceReferences }, task.claimToken)
        else await recordAttackPath(config as never, scanId, task.candidateId, { attacker: 'Remote caller.', entryPoint: 'HTTP request parameter.', preconditions: 'The handler is reachable in the supported runtime.', dataflow: 'Request parameter -> dynamic execution control.', outcome: 'Attacker-controlled execution.', severityRationale: 'Remote input reaches a sensitive execution sink.', changeConditions: 'Lower severity if a complete upstream authorization boundary is established.', sourceReferences }, task.claimToken)
      }
    }, session: { deriveMessages: () => [{ role: 'assistant', content: [{ type: 'text', text: 'closure complete' }] }] } }, async dispose() {} }
  } } }
  return { ctx, count: () => created, restrictions }
}

test('centralized deep closure uses six restricted DSH workers and closes persistent validation then attack-path tasks', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  const state = await mkdtemp(join(tmpdir(), 'dsh-security-suite-state-'))
  const config = { enabled: true, maxFiles: 10, maxFileBytes: 4096, stateDir: state }
  try {
    await writeFile(join(root, 'app.ts'), 'function h(req) { return eval(req.query.code) }\n')
    const scan = await runScan(root, config, 'deep', '', false, state, false); await saveScan(state, scan)
    assert.equal(scan.tasks.filter(task => task.phase === 'validation').length > 0, true)
    const validationJob = await createDeepClosureJob(config, scan.id, 'validation'); const validation = deepClosureContext(config, 'validation'); const validationResult = await runDeepClosure(validation.ctx as never, config, validationJob.id)
    assert.equal(validation.count(), 6)
    assert.equal(validationResult.lifecycle, 'completed')
    assert.equal(validationResult.threatModel.source, 'scan_preflight')
    assert.deepEqual(validation.restrictions[0], ['security_claim_audit_task', 'security_get_scan', 'security_read_scan_source', 'security_record_validation'])
    const attackJob = await createDeepClosureJob(config, scan.id, 'attack_path'); const attack = deepClosureContext(config, 'attack_path'); const attackResult = await runDeepClosure(attack.ctx as never, config, attackJob.id)
    assert.equal(attack.count(), 6)
    assert.equal(attackResult.lifecycle, 'completed')
    assert.deepEqual(attack.restrictions[0], ['security_claim_audit_task', 'security_get_scan', 'security_read_scan_source', 'security_record_attack_path'])
    const closed = await loadScan(state, scan.id)
    assert.equal(closed.findings.every(finding => finding.ledger.some(row => row.phase === 'validation') && (finding.disposition !== 'reportable' || finding.ledger.some(row => row.phase === 'attack_path'))), true)
    assert.match(await readFile(join(closed.artifacts.directory, 'artifacts', '04_reconciliation', `deep-validation-closure-${validationJob.id}.json`), 'utf8'), /completed/)
  } finally { await rm(root, { recursive: true, force: true }); await rm(state, { recursive: true, force: true }) }
})

test('deep closure binds the canonical model synthesized from complete delegated discovery', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  const state = await mkdtemp(join(tmpdir(), 'dsh-security-suite-state-'))
  const config = { enabled: true, maxFiles: 10, maxFileBytes: 4096, stateDir: state }
  try {
    await writeFile(join(root, 'app.ts'), 'function h(req) { return eval(req.query.code) }\n')
    const scan = await runScan(root, config, 'deep', '', false, state, false); await saveScan(state, scan)
    const discovery = await createDeepDiscoveryJob(config, scan.id, 1)
    const result = await runDeepDiscovery(deepWorkerContext(config, true).ctx as never, config, discovery.id)
    assert.equal(result.canonicalThreatModel?.artifactRef, 'artifacts/01_context/deep_canonical_threat_model.md')
    const closure = await createDeepClosureJob(config, scan.id, 'validation')
    assert.equal(closure.threatModel.source, 'canonical_deep_discovery')
    assert.equal(closure.threatModel.digest, result.canonicalThreatModel?.digest)
  } finally { await rm(root, { recursive: true, force: true }); await rm(state, { recursive: true, force: true }) }
})

test('final deep bundles seal every retained worker, coverage, model, and closure artifact', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  const state = await mkdtemp(join(tmpdir(), 'dsh-security-suite-state-'))
  const config = { enabled: true, maxFiles: 10, maxFileBytes: 4096, stateDir: state }
  try {
    await writeFile(join(root, 'app.ts'), 'function h(req) { return eval(req.query.code) }\n')
    const scan = await runScan(root, config, 'deep', '', false, state, false); await saveScan(state, scan)
    const discovery = await createDeepDiscoveryJob(config, scan.id, 1)
    await runDeepDiscovery(deepWorkerContext(config, true).ctx as never, config, discovery.id)
    const validation = await createDeepClosureJob(config, scan.id, 'validation')
    await runDeepClosure(deepClosureContext(config, 'validation').ctx as never, config, validation.id)
    const attack = await createDeepClosureJob(config, scan.id, 'attack_path')
    await runDeepClosure(deepClosureContext(config, 'attack_path').ctx as never, config, attack.id)
    const completed = await loadScan(state, scan.id)
    completed.lifecycle = 'completed'; completed.completedAt = new Date().toISOString()
    await finalizeAndSaveScan(state, completed)
    const sealed = await loadScan(state, scan.id)
    const verified = await verifyScanBundle(sealed)
    assert.equal(verified.valid, true, verified.errors.join('\n'))
    const manifest = JSON.parse(await readFile(join(sealed.artifacts.directory, sealed.artifacts.manifest!), 'utf8')) as { scan: { artifacts: Array<{ path: string }> } }
    const paths = new Set(manifest.scan.artifacts.map(item => item.path))
    assert.equal(paths.has('artifacts/01_context/deep_canonical_threat_model.md'), true)
    assert.equal([...paths].some(path => path.includes('artifacts/02_discovery/deep/round-01/worker_1_1/coverage.json')), true)
    assert.equal([...paths].some(path => path.includes(`deep-validation-closure-${validation.id}.json`)), true)
    assert.equal([...paths].some(path => path.includes(`deep-attack_path-closure-${attack.id}.json`)), true)
    await writeFile(join(sealed.artifacts.directory, 'artifacts', '04_reconciliation', 'late-evidence.json'), '{}\n')
    const afterAddition = await verifyScanBundle(sealed)
    assert.equal(afterAddition.valid, false)
    assert.equal(afterAddition.errors.some(error => error.includes('late-evidence.json')), true)
  } finally { await rm(root, { recursive: true, force: true }); await rm(state, { recursive: true, force: true }) }
})

test('deep closure fails closed when its bound threat model drifts', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  const state = await mkdtemp(join(tmpdir(), 'dsh-security-suite-state-'))
  const config = { enabled: true, maxFiles: 10, maxFileBytes: 4096, stateDir: state }
  try {
    await writeFile(join(root, 'app.ts'), 'function h(req) { return eval(req.query.code) }\n')
    const scan = await runScan(root, config, 'deep', '', false, state, false); await saveScan(state, scan)
    const job = await createDeepClosureJob(config, scan.id, 'validation')
    const changed = await loadScan(state, scan.id); changed.threatModel = 'changed after closure creation'; await saveScan(state, changed)
    await assert.rejects(() => runDeepClosure(deepClosureContext(config, 'validation').ctx as never, config, job.id), /threat model changed/)
  } finally { await rm(root, { recursive: true, force: true }); await rm(state, { recursive: true, force: true }) }
})

test('centralized source reads fail closed when a scan-receipted file changes', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  const state = await mkdtemp(join(tmpdir(), 'dsh-security-suite-state-'))
  const config = { enabled: true, maxFiles: 10, maxFileBytes: 4096, stateDir: state }
  try {
    await writeFile(join(root, 'app.ts'), 'const original = 1\n')
    const scan = await runScan(root, config, 'deep', '', false, state, false); await saveScan(state, scan)
    assert.match((await readScanSource(config, scan.id, 'app.ts')).content, /original/)
    await writeFile(join(root, 'app.ts'), 'const changed = 2\n')
    await assert.rejects(() => readScanSource(config, scan.id, 'app.ts'), /changed after/)
  } finally { await rm(root, { recursive: true, force: true }); await rm(state, { recursive: true, force: true }) }
})

test('cancelled centralized deep closure preserves completed receipts and resumes with a fresh worker round', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  const state = await mkdtemp(join(tmpdir(), 'dsh-security-suite-state-'))
  const config = { enabled: true, maxFiles: 10, maxFileBytes: 4096, stateDir: state }
  try {
    await writeFile(join(root, 'app.ts'), 'function h(req) { return eval(req.query.code) }\n')
    const scan = await runScan(root, config, 'deep', '', false, state, false); await saveScan(state, scan)
    const job = await createDeepClosureJob(config, scan.id, 'validation'); const controller = new AbortController(); let created = 0; let releaseCreated!: () => void; const allCreated = new Promise<void>(resolve => { releaseCreated = resolve })
    const stalled = { agents: { async create(options: { setup?: (ctx: { tools: { restrict(): void }; systemPrompt: { section(): void } }) => void }) { options.setup?.({ tools: { restrict() {} }, systemPrompt: { section() {} } }); if (++created === 6) releaseCreated(); return { agent: { followup() {}, async whenIdle() { await new Promise<void>(() => undefined) }, session: { deriveMessages: () => [] } }, async dispose() {} } } } }
    const interrupted = runDeepClosure(stalled as never, config, job.id, controller.signal); await allCreated; controller.abort(); const cancelled = await interrupted
    assert.equal(cancelled.lifecycle, 'cancelled')
    const resumed = await runDeepClosure(deepClosureContext(config, 'validation').ctx as never, config, job.id)
    assert.equal(resumed.lifecycle, 'completed')
    assert.equal(resumed.workers.length, 12)
    assert.equal(new Set(resumed.workers.map(worker => worker.id)).size, 12)
  } finally { await rm(root, { recursive: true, force: true }); await rm(state, { recursive: true, force: true }) }
})

test('workers that omit their threat-model and coverage closure make the deep round incomplete', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  const state = await mkdtemp(join(tmpdir(), 'dsh-security-suite-state-'))
  const config = { enabled: true, maxFiles: 10, maxFileBytes: 4096, stateDir: state, deepScan: { workers: 'auto' as const, subagents: 0, stopAfterNoNew: 1, stopAfterConsecutiveErrors: 3, maxDiscoveryRuns: 60, maxTimeHours: 96 } }
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
  const config = { enabled: true, maxFiles: 10, maxFileBytes: 4096, stateDir: state, deepScan: { workers: 'auto' as const, subagents: 0, stopAfterNoNew: 1, stopAfterConsecutiveErrors: 3, maxDiscoveryRuns: 60, maxTimeHours: 96 } }
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
  const config = { enabled: true, maxFiles: 10, maxFileBytes: 4096, stateDir: state, deepScan: { workers: 'auto' as const, subagents: 0, stopAfterNoNew: 1, stopAfterConsecutiveErrors: 3, maxDiscoveryRuns: 60, maxTimeHours: 96 } }
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
  const config = { enabled: true, maxFiles: 10, maxFileBytes: 4096, stateDir: state, deepScan: { workers: 'auto' as const, subagents: 0, stopAfterNoNew: 1, stopAfterConsecutiveErrors: 3, maxDiscoveryRuns: 60, maxTimeHours: 96 } }
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

test('the semantic reducer merges equivalent candidates across workers and preserves provenance', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-reducer-'))
  const state = await mkdtemp(join(tmpdir(), 'dsh-security-suite-reducer-state-'))
  const config = { enabled: true, maxFiles: 10, maxFileBytes: 4096, stateDir: state }
  try {
    await writeFile(join(root, 'app.ts'), 'function route(req) { return eval(req.query.code) }\n')
    const scan = await runScan(root, config, 'deep', '', false, state, false)
    await saveScan(state, scan)
    const job = await createDeepDiscoveryJob(config, scan.id, 1)
    job.lifecycle = 'running'
    job.workers.push({ id: 'worker_1_1', round: 1, status: 'completed', token: 'a', candidateIds: ['one'] }, { id: 'worker_1_2', round: 1, status: 'completed', token: 'b', candidateIds: ['two'] })
    job.rounds.push({ number: 1, workerIds: ['worker_1_1', 'worker_1_2'], candidateCount: 2, novelty: 2, status: 'complete' })
    job.reducers = [{ id: 'reducer_1', round: 1, status: 'running', token: 'red', merges: [] }]
    job.candidates.push(
      { ruleId: 'dynamic-code.eval', title: 'eval sink', severity: 'high', cwe: 'CWE-95', file: 'app.ts', line: 1, rootCause: 'Request input reaches eval.', remediationIdentity: 'Reject untrusted input before eval.', id: 'one', workerId: 'worker_1_1', workerIds: ['worker_1_1'], reportIds: ['r1'], excerpt: 'eval(req.query.code)', fingerprint: 'f1', remediationSubsumption: { remediationIdentity: 'Reject untrusted input before eval.', decision: 'not_merged', rationale: '', absorbedReportIds: [] }, reportedAt: new Date().toISOString() },
      { ruleId: 'dynamic-code.eval', title: 'eval sink (same control)', severity: 'high', cwe: 'CWE-95', file: 'app.ts', line: 1, rootCause: 'Attacker input flows into dynamic evaluation.', remediationIdentity: 'Reject untrusted input before eval.', id: 'two', workerId: 'worker_1_2', workerIds: ['worker_1_2'], reportIds: ['r2'], excerpt: 'eval(req.query.code)', fingerprint: 'f2', remediationSubsumption: { remediationIdentity: 'Reject untrusted input before eval.', decision: 'not_merged', rationale: '', absorbedReportIds: [] }, reportedAt: new Date().toISOString() },
    )
    await writeFile(join(state, 'deep-discovery', `${job.id}.json`), `${JSON.stringify(job)}\n`)
    const merged = await reportDeepReducer(config, job.id, 'reducer_1', 'red', [{ targetId: 'one', absorbedIds: ['two'], rationale: 'Both candidates reach the same eval sink through the same missing control.' }])
    assert.equal(merged.merged, 1)
    assert.equal(merged.absorbed, 1)
    const persisted = await loadDeepDiscoveryJob(config, job.id)
    assert.equal(persisted.candidates.find(candidate => candidate.id === 'one')?.workerIds.includes('worker_1_2'), true)
    assert.equal(persisted.candidates.find(candidate => candidate.id === 'two')?.absorbedBy, 'one')
    assert.deepEqual(persisted.candidates.find(candidate => candidate.id === 'one')?.remediationSubsumption.absorbedReportIds, ['r2'])
    assert.equal(persisted.reducers?.[0].status, 'running')
  } finally { await rm(root, { recursive: true, force: true }); await rm(state, { recursive: true, force: true }) }
})
