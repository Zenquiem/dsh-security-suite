import assert from 'node:assert/strict'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { createLlmDiscoveryJob, getLlmScope, readLlmSource, reportLlmCandidates, reportLlmWorker, runLlmDiscovery, runLlmScan, searchLlmSource } from '../src/llm/discovery.ts'
import { runScan } from '../src/scanner.ts'
import { loadScan, saveScan } from '../src/state.ts'

function llmWorkerContext(config: { stateDir: string }, mode: 'report' | 'silent' | 'fail-baseline' = 'report') {
  let created = 0
  const restrictions: string[][] = []
  const prompts: string[] = []
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
              const jobId = /Job: `([^`]+)`; worker: `([^`]+)`; claim token: `([^`]+)`/.exec(prompt)?.[1]
              const workerId = /Job: `([^`]+)`; worker: `([^`]+)`; claim token: `([^`]+)`/.exec(prompt)?.[2]
              const token = /Job: `([^`]+)`; worker: `([^`]+)`; claim token: `([^`]+)`/.exec(prompt)?.[3]
              if (!jobId || !workerId || !token) throw new Error('worker prompt was incomplete')
              if (mode === 'fail-baseline' && workerId.startsWith('baseline_')) throw new Error('baseline worker driver failed')
              if (mode === 'silent') { await reportLlmWorker(config, jobId, workerId, token, { findings: [], resolvedQuestions: [], fullyReviewedFileCount: 0 }); return }
              const scope = await getLlmScope(config, jobId, workerId, token)
              const first = scope.worklist[0]
              if (first) {
                const source = await readLlmSource(config, jobId, workerId, token, first.path, 1, 5)
                assert.ok(source.content.length > 0)
                await searchLlmSource(config, jobId, workerId, token, 'req', 5)
              }
              await reportLlmCandidates(config, jobId, workerId, token, [{
                ruleId: 'dynamic-code.eval', title: 'Request input reaches eval', summary: 'req.query.code reaches eval without validation',
                cwe: 'CWE-95', severity: 'high', confidence: 'medium', attacker: 'remote caller', violatedInvariant: 'Untrusted request data must not reach dynamic evaluation.',
                sourceToSink: 'req.query.code -> eval()', impact: 'Code execution', remediation: 'Reject untrusted input before dynamic evaluation.', counterevidence: 'No control analysis performed.',
                locations: [{ path: first.path, startLine: 1, role: 'root_control' }], evidence: [],
              }])
              await reportLlmWorker(config, jobId, workerId, token, { findings: [], resolvedQuestions: ['none'], fullyReviewedFileCount: scope.worklist.length })
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

test('LLM discovery creates one baseline auditor plus focused investigators with distinct lenses and restricted tools', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-llm-'))
  const state = await mkdtemp(join(tmpdir(), 'dsh-security-suite-llm-state-'))
  const config = { enabled: true, maxFiles: 10, maxFileBytes: 4096, stateDir: state }
  try {
    await writeFile(join(root, 'app.ts'), 'function route(req) { return eval(req.query.code) }\n')
    const scan = await runScan(root, config, 'standard', '', false, state, false)
    await saveScan(state, scan)
    const job = await createLlmDiscoveryJob(config, scan.id)
    const { ctx, count, restrictions, prompts } = llmWorkerContext(config)
    const completed = await runLlmDiscovery(ctx as never, config, job.id)
    assert.equal(count(), 1 + job.packets.length)
    assert.equal(completed.lifecycle, 'completed')
    assert.ok(prompts[0].includes('Security Code Auditor'), 'baseline prompt must be the codex-security baseline auditor')
    assert.ok(prompts.some(prompt => prompt.includes('Investigate the assigned source-backed security questions')), 'investigator prompt must be the codex-security investigator')
    for (const allow of restrictions) assert.deepEqual(allow, ['security_llm_get_scope', 'security_llm_read_source', 'security_llm_search', 'security_llm_report_candidates', 'security_llm_report_worker'])
    assert.ok(completed.candidates.length >= 1)
    const persisted = await loadScan(state, scan.id)
    assert.ok(persisted.findings.some(finding => finding.fingerprint.startsWith('dsh-llm:')))
  } finally { await rm(root, { recursive: true, force: true }); await rm(state, { recursive: true, force: true }) }
})

test('LLM discovery fails closed when the baseline worker does not complete', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-llm-fail-'))
  const state = await mkdtemp(join(tmpdir(), 'dsh-security-suite-llm-fail-state-'))
  const config = { enabled: true, maxFiles: 10, maxFileBytes: 4096, stateDir: state }
  try {
    await writeFile(join(root, 'app.ts'), 'function route(req) { return eval(req.query.code) }\n')
    const scan = await runScan(root, config, 'standard', '', false, state, false)
    await saveScan(state, scan)
    const job = await createLlmDiscoveryJob(config, scan.id)
    const { ctx } = llmWorkerContext(config, 'fail-baseline')
    const completed = await runLlmDiscovery(ctx as never, config, job.id)
    assert.equal(completed.lifecycle, 'incomplete')
    assert.equal(completed.investigators.length, 0, 'investigators must not start when the baseline fails')
  } finally { await rm(root, { recursive: true, force: true }); await rm(state, { recursive: true, force: true }) }
})

test('LLM candidates must cite receipted in-scope locations', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-llm-reject-'))
  const state = await mkdtemp(join(tmpdir(), 'dsh-security-suite-llm-reject-state-'))
  const config = { enabled: true, maxFiles: 10, maxFileBytes: 4096, stateDir: state }
  try {
    await writeFile(join(root, 'app.ts'), 'function route(req) { return eval(req.query.code) }\n')
    const scan = await runScan(root, config, 'standard', '', false, state, false)
    await saveScan(state, scan)
    const job = await createLlmDiscoveryJob(config, scan.id)
    job.lifecycle = 'running'
    job.baseline.status = 'running'
    await writeFile(join(state, 'llm-discovery', `${job.id}.json`), `${JSON.stringify(job)}\n`)
    await assert.rejects(() => reportLlmCandidates(config, job.id, job.baseline.id, job.baseline.token, [{ ruleId: 'sql-injection.query-builder', title: 'Outside scope', summary: 's', cwe: 'CWE-89', severity: 'high', confidence: 'low', attacker: 'a', violatedInvariant: 'v', sourceToSink: 's', impact: 'i', remediation: 'r', counterevidence: 'c', locations: [{ path: 'missing.ts', startLine: 1 }], evidence: [] }]), /outside the in-scope worklist/)
  } finally { await rm(root, { recursive: true, force: true }); await rm(state, { recursive: true, force: true }) }
})

test('runLlmScan composes a scan, LLM discovery, and persisted candidate receipts', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-llm-scan-'))
  const state = await mkdtemp(join(tmpdir(), 'dsh-security-suite-llm-scan-state-'))
  const config = { enabled: true, maxFiles: 10, maxFileBytes: 4096, stateDir: state }
  try {
    await writeFile(join(root, 'app.ts'), 'function route(req) { return eval(req.query.code) }\n')
    const { ctx } = llmWorkerContext(config)
    const result = await runLlmScan(ctx as never, config, root, { scopeRequested: false })
    assert.equal(result.scan.lifecycle, 'validation')
    assert.equal(result.scan.coverage.complete, true)
    const artifacts = await readFile(join(result.scan.artifacts.directory, 'artifacts', '02_discovery', 'llm', 'discovery_ledger.md'), 'utf8')
    assert.match(artifacts, /LLM Discovery Ledger/)
  } finally { await rm(root, { recursive: true, force: true }); await rm(state, { recursive: true, force: true }) }
})
