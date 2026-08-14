import assert from 'node:assert/strict'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { createDeepInvestigationJob, loadDeepInvestigationJob, runDeepInvestigation } from '../src/deep-workflow.ts'
import { getDeepWorklist, reportDeepCandidate, reportDeepWorker } from '../src/deep-discovery.ts'
import { loadScan, verifyScanBundle } from '../src/state.ts'
import { claimAuditTask, recordAttackPath, recordValidation } from '../src/workbench.ts'

function nativeWorkflowContext(config: { stateDir: string }) {
  let created = 0
  const restrictions: string[][] = []
  const ctx = { agents: { async create(options: { setup?: (agent: { tools: { restrict(filter: { allow: string[] }): void }; systemPrompt: { section(section: { name: string }): void } }) => void }) {
    const index = ++created
    let prompt = ''
    let allowed: string[] = []
    options.setup?.({ tools: { restrict(filter) { allowed = filter.allow; restrictions.push(filter.allow) } }, systemPrompt: { section() {} } })
    return {
      agent: {
        followup(message: { content: Array<{ text?: string }> }) { prompt = message.content[0]?.text ?? '' },
        async whenIdle() {
          if (allowed.includes('security_deep_report_candidate')) {
            const jobId = /job_id (deep_[0-9a-f-]+)/.exec(prompt)?.[1]
            const workerId = /worker_id (worker_\d+_\d+)/.exec(prompt)?.[1]
            const token = /claim_token ([0-9a-f-]+)/.exec(prompt)?.[1]
            if (!jobId || !workerId || !token) throw new Error('Discovery worker assignment was incomplete.')
            await reportDeepCandidate(config as never, jobId, workerId, token, { ruleId: 'custom.native-deep-flow', title: 'Native deep workflow candidate', severity: 'high', cwe: 'CWE-95', file: 'app.ts', line: 1, rootCause: 'The restricted worker found a source-backed dynamic execution control.' })
            const worklist = await getDeepWorklist(config as never, jobId, workerId, token)
            await reportDeepWorker(config as never, jobId, workerId, token, { threatModel: 'The independent worker models externally supplied request data crossing a trust boundary into dynamic execution.', reviewedWorkItemIds: worklist.items.map(item => item.id), deferred: [], coverageSummary: 'Reviewed every immutable worklist region and retained one source-backed candidate.' })
            return
          }
          const scanId = /scan_id (scan_[0-9a-f-]+)/.exec(prompt)?.[1]
          const owner = /owner (closure_[a-z_]+_\d+_\d+)/.exec(prompt)?.[1]
          if (!scanId || !owner) throw new Error('Closure worker assignment was incomplete.')
          const phase = allowed.includes('security_record_validation') ? 'validation' : 'attack_path'
          while (true) {
            const task = await claimAuditTask(config as never, scanId, owner, phase)
            if (!task) return
            const scan = await loadScan(config.stateDir, scanId)
            const finding = scan.findings.find(item => item.candidateId === task.candidateId)
            if (!finding) throw new Error('Claimed finding was not retained.')
            const sourceReferences = finding.locations.map(location => ({ file: location.file, line: location.line, role: location.role ?? 'root_control' })) as never
            if (phase === 'validation') {
              await recordValidation(config as never, scanId, task.candidateId, { conclusion: 'reportable', method: 'static', attacker: 'Remote request sender.', entryPoint: 'Request parameter.', trustBoundary: 'Untrusted request crosses into the application.', rootControl: 'Dynamic execution control.', sink: 'Dynamic execution operation.', impact: 'Attacker-controlled execution.', directEvidence: 'The frozen source receipt preserves the request-to-sink control path.', counterevidence: 'No effective local guard was retained in the scanned path.', limitations: 'This closure used source evidence and did not execute a runtime reproduction.', confidence: 'medium', sourceReferences }, task.claimToken)
            } else {
              await recordAttackPath(config as never, scanId, task.candidateId, { attacker: 'Remote request sender.', entryPoint: 'HTTP request parameter.', preconditions: 'The reviewed request handler is reachable.', dataflow: 'Request input crosses the application boundary into dynamic execution.', outcome: 'Attacker-controlled execution.', severityRationale: 'A remote input reaches a sensitive execution sink.', changeConditions: 'A proven enforced guard would reduce impact or suppress the candidate.', sourceReferences }, task.claimToken)
            }
          }
        },
        session: { deriveMessages: () => [{ role: 'assistant', content: [{ type: 'text', text: `native worker ${index} complete` }] }] },
      },
      async dispose() {},
    }
  } } }
  return { ctx, count: () => created, restrictions }
}

test('a durable DSH deep investigation runs discovery, validation, attack-path closure, and finalization end to end', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  const state = await mkdtemp(join(tmpdir(), 'dsh-security-suite-state-'))
  const config = { enabled: true, maxFiles: 20, maxFileBytes: 4096, stateDir: state }
  try {
    await writeFile(join(root, 'app.ts'), 'function route(req) { return eval(req.query.code) }\n')
    const created = await createDeepInvestigationJob(root, config, '', false, 1)
    const native = nativeWorkflowContext(config)
    const result = await runDeepInvestigation(native.ctx as never, config, created.id)
    assert.equal(result.lifecycle, 'completed')
    assert.equal(result.phase, 'finalization')
    assert.ok(result.validationClosureJobId)
    assert.ok(result.attackPathClosureJobId)
    assert.equal(native.count(), 18)
    assert.deepEqual(native.restrictions[0], ['security_deep_get_worklist', 'security_deep_read_source', 'security_deep_report_candidate', 'security_deep_report_worker'])
    const persistedJob = await loadDeepInvestigationJob(config, result.id)
    assert.equal(persistedJob.lifecycle, 'completed')
    const scan = await loadScan(state, result.scanId)
    assert.equal(scan.lifecycle, 'completed')
    assert.equal(scan.tasks.every(task => task.status === 'completed'), true)
    assert.equal(scan.findings.every(finding => finding.validationRecord && (!['reportable'].includes(finding.disposition) || finding.attackPathRecord)), true)
    const bundle = await verifyScanBundle(scan)
    assert.equal(bundle.valid, true, bundle.errors.join('\n'))
  } finally { await rm(root, { recursive: true, force: true }); await rm(state, { recursive: true, force: true }) }
})
