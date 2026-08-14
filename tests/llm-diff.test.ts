import assert from 'node:assert/strict'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import test from 'node:test'
import { createDiffDiscoveryJob, getDiffReviewItems, readDiffSource, reportDiffCandidates, reportDiffWorker, runDiffDiscovery } from '../src/llm/diff.ts'
import { runDiffScan } from '../src/scanner.ts'
import { loadScan, saveScan } from '../src/state.ts'

const execFileAsync = promisify(execFile)

function diffWorkerContext(config: { stateDir: string }) {
  let created = 0
  const restrictions: string[][] = []
  const prompts: string[] = []
  const ctx = {
    agents: {
      async create(options: { setup?: (ctx: { tools: { restrict(filter: { allow: string[] }): void }; systemPrompt: { section(section: { name: string }): void } }) => void }) {
        created++
        let prompt = ''
        options.setup?.({ tools: { restrict(filter) { restrictions.push(filter.allow) } }, systemPrompt: { section() {} } })
        return {
          agent: {
            followup(message: { content: Array<{ type: string; text?: string }> }) { prompt = message.content[0]?.text ?? ''; prompts.push(prompt) },
            async whenIdle() {
              const jobId = /Job: `([^`]+)`; worker: `([^`]+)`; claim token: `([^`]+)`/.exec(prompt)?.[1]
              const workerId = /Job: `([^`]+)`; worker: `([^`]+)`; claim token: `([^`]+)`/.exec(prompt)?.[2]
              const token = /Job: `([^`]+)`; worker: `([^`]+)`; claim token: `([^`]+)`/.exec(prompt)?.[3]
              if (!jobId || !workerId || !token) throw new Error('diff worker prompt was incomplete')
              const scope = await getDiffReviewItems(config, jobId, workerId, token)
              const first = scope.items[0]
              if (first) {
                const source = await readDiffSource(config, jobId, workerId, token, first.path, 1, 5)
                assert.ok(source.content.length > 0)
              }
              await reportDiffCandidates(config, jobId, workerId, token, scope.items.map(item => ({
                ruleId: 'path-traversal.archive-extraction', title: 'Changed file review candidate', summary: 'Changed code exposes a source-backed path issue',
                cwe: 'CWE-22', severity: 'high', confidence: 'medium', attacker: 'remote caller', violatedInvariant: 'Untrusted input must not control filesystem paths.',
                sourceToSink: 'changed input -> filesystem path', impact: 'Unauthorized file access', remediation: 'Contain and validate the path.',
                counterevidence: 'No control analysis performed.', locations: [{ path: item.path, startLine: 1, role: 'root_control' }], evidence: [],
              })))
              await reportDiffWorker(config, jobId, workerId, token, { resolvedQuestions: [], fullyReviewedFileCount: scope.items.length })
            },
            session: { deriveMessages: () => [{ role: 'assistant', content: [{ type: 'text', text: 'diff review complete' }] }] },
          },
          async dispose() {},
        }
      },
    },
  }
  return { ctx, count: () => created, restrictions, prompts }
}

test('diff LLM discovery spawns one file-review worker per changed file with restricted tools', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-diff-'))
  const state = await mkdtemp(join(tmpdir(), 'dsh-security-suite-diff-state-'))
  const config = { enabled: true, maxFiles: 10, maxFileBytes: 4096, stateDir: state }
  try {
    await execFileAsync('git', ['init'], { cwd: root })
    await execFileAsync('git', ['config', 'user.email', 'test@example.invalid'], { cwd: root })
    await execFileAsync('git', ['config', 'user.name', 'DSH Security Suite Test'], { cwd: root })
    await writeFile(join(root, 'app.ts'), 'function route(req) { return safe(req.query.code) }\n')
    await execFileAsync('git', ['add', 'app.ts'], { cwd: root })
    await execFileAsync('git', ['commit', '-m', 'baseline'], { cwd: root })
    await writeFile(join(root, 'app.ts'), 'function route(req) { return eval(req.query.code) }\n')
    const scan = await runDiffScan(root, undefined, '', state, false, 'working_tree')
    await saveScan(state, scan)
    const job = await createDiffDiscoveryJob(config, scan.id)
    assert.equal(job.worklist.length, 1)
    assert.equal(job.worklist[0]?.path, 'app.ts')
    const { ctx, count, restrictions, prompts } = diffWorkerContext(config)
    const completed = await runDiffDiscovery(ctx as never, config, job.id)
    assert.equal(count(), 1)
    assert.equal(completed.lifecycle, 'completed')
    assert.deepEqual(restrictions[0], ['security_diff_get_review_items', 'security_diff_read_source', 'security_diff_report_candidates', 'security_diff_report_worker'])
    assert.match(prompts[0], /Diff File-Review Worker/)
    assert.match(prompts[0], /app\.ts/)
    const persisted = await loadScan(state, scan.id)
    assert.ok(persisted.findings.some(finding => finding.fingerprint.startsWith('dsh-diff:')))
  } finally { await rm(root, { recursive: true, force: true }); await rm(state, { recursive: true, force: true }) }
})

test('diff LLM candidates must cite assigned changed files', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-diff-reject-'))
  const state = await mkdtemp(join(tmpdir(), 'dsh-security-suite-diff-reject-state-'))
  const config = { enabled: true, maxFiles: 10, maxFileBytes: 4096, stateDir: state }
  try {
    await execFileAsync('git', ['init'], { cwd: root })
    await execFileAsync('git', ['config', 'user.email', 'test@example.invalid'], { cwd: root })
    await execFileAsync('git', ['config', 'user.name', 'DSH Security Suite Test'], { cwd: root })
    await writeFile(join(root, 'app.ts'), 'function route(req) { return safe(req.query.code) }\n')
    await execFileAsync('git', ['add', 'app.ts'], { cwd: root })
    await execFileAsync('git', ['commit', '-m', 'baseline'], { cwd: root })
    await writeFile(join(root, 'app.ts'), 'function route(req) { return eval(req.query.code) }\n')
    const scan = await runDiffScan(root, undefined, '', state, false, 'working_tree')
    await saveScan(state, scan)
    const job = await createDiffDiscoveryJob(config, scan.id)
    job.lifecycle = 'running'
    job.workers.push({ id: 'filereview_1', status: 'running', token: 'tok', assignedPaths: ['app.ts'], candidateIds: [] })
    await writeFile(join(state, 'diff-discovery', `${job.id}.json`), `${JSON.stringify(job)}\n`)
    await assert.rejects(() => reportDiffCandidates(config, job.id, 'filereview_1', 'tok', [{ ruleId: 'sql-injection.query-builder', title: 'Out of scope', summary: 's', cwe: 'CWE-89', severity: 'high', confidence: 'low', attacker: 'a', violatedInvariant: 'v', sourceToSink: 's', impact: 'i', remediation: 'r', counterevidence: 'c', locations: [{ path: 'unchanged.ts', startLine: 1 }], evidence: [] }]), /outside the diff worklist/)
  } finally { await rm(root, { recursive: true, force: true }); await rm(state, { recursive: true, force: true }) }
})
