import assert from 'node:assert/strict'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { runScan } from '../src/scanner.ts'
import { getStateDir, loadScan, saveScan, verifyScanBundle } from '../src/state.ts'
import { claimAuditTask, completeScan, recordAttackPath, recordValidation } from '../src/workbench.ts'

test('workbench requires validation and attack-path receipts before finalization', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  const state = await mkdtemp(join(tmpdir(), 'dsh-security-suite-state-'))
  const config = { enabled: true, maxFiles: 20, maxFileBytes: 4096, stateDir: state }
  try {
    await writeFile(join(root, 'app.ts'), 'function h(req) { const value = req.query.code; eval(value) }\n')
    const scan = await runScan(root, config, 'standard', '', false, state, false)
    await saveScan(getStateDir(state), scan)
    const candidate = scan.findings.find(finding => finding.ruleId === 'dangerous.dynamic.code')
    assert.ok(candidate)
    const taskPath = join(scan.artifacts.directory, 'artifacts', '04_reconciliation', 'tasks', scan.tasks[0].id + '.md')
    await assert.rejects(() => readFile(taskPath, 'utf8'), /ENOENT/)
    await assert.rejects(() => completeScan(config, scan.id), /incomplete/)
    const validationTask = await claimAuditTask(config, scan.id, 'worker-a', 'validation')
    assert.ok(validationTask)
    assert.match(await readFile(join(scan.artifacts.directory, validationTask.artifactRef), 'utf8'), /Security Audit Task/)
    assert.equal(await claimAuditTask(config, scan.id, 'worker-b', 'validation'), null)
    await assert.rejects(() => recordValidation(config, scan.id, candidate.candidateId, { conclusion: 'reportable', method: 'static', attacker: 'remote caller', entryPoint: 'req.query.code', trustBoundary: 'HTTP request to evaluator', rootControl: 'eval(value)', sink: 'eval', impact: 'code execution', directEvidence: 'AST data-flow reaches eval', counterevidence: 'no allowlist', limitations: 'not executed', confidence: 'medium' }, 'wrong-token'), /claim token/)
    await recordValidation(config, scan.id, candidate.candidateId, { conclusion: 'reportable', method: 'static', attacker: 'remote caller', entryPoint: 'req.query.code', trustBoundary: 'HTTP request to evaluator', rootControl: 'eval(value)', sink: 'eval', impact: 'code execution', directEvidence: 'AST data-flow reaches eval', counterevidence: 'no allowlist', limitations: 'not executed', confidence: 'medium' }, validationTask.claimToken)
    await assert.rejects(() => completeScan(config, scan.id), /incomplete/)
    const attackTask = await claimAuditTask(config, scan.id, 'worker-c', 'attack_path')
    assert.ok(attackTask)
    await recordAttackPath(config, scan.id, candidate.candidateId, { attacker: 'remote caller', entryPoint: 'HTTP query', preconditions: 'route reachable', dataflow: 'req.query.code -> value -> eval(value)', outcome: 'arbitrary script execution', severityRationale: 'high impact with reachable source', changeConditions: 'runtime test can raise confidence' }, attackTask.claimToken)
    const completed = await completeScan(config, scan.id)
    assert.equal(completed.lifecycle, 'completed')
    const verified = await verifyScanBundle(await loadScan(state, scan.id))
    assert.equal(verified.valid, true, verified.errors.join('\n'))
  } finally { await rm(root, { recursive: true, force: true }); await rm(state, { recursive: true, force: true }) }
})

test('workbench rejects attack-path evidence for a suppressed candidate', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  const state = await mkdtemp(join(tmpdir(), 'dsh-security-suite-state-'))
  const config = { enabled: true, maxFiles: 20, maxFileBytes: 4096, stateDir: state }
  try {
    await writeFile(join(root, 'app.ts'), 'const token = "static-token-value"\n')
    const scan = await runScan(root, config, 'standard', '', false, state, false)
    await saveScan(state, scan)
    const candidate = scan.findings[0]
    const validationTask = await claimAuditTask(config, scan.id, 'worker-a', 'validation')
    assert.ok(validationTask)
    await recordValidation(config, scan.id, candidate.candidateId, { conclusion: 'suppressed', method: 'static', attacker: 'none', entryPoint: 'none', trustBoundary: 'none', rootControl: 'static source', sink: 'none', impact: 'none', directEvidence: 'value is a test fixture', counterevidence: 'not reachable', limitations: 'none', confidence: 'high' }, validationTask.claimToken)
    await assert.rejects(() => recordAttackPath(config, scan.id, candidate.candidateId, { attacker: 'none', entryPoint: 'none', preconditions: 'none', dataflow: 'none', outcome: 'none', severityRationale: 'none', changeConditions: 'none' }), /only allowed for a reportable/)
  } finally { await rm(root, { recursive: true, force: true }); await rm(state, { recursive: true, force: true }) }
})
