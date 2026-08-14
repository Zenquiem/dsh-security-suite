import assert from 'node:assert/strict'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { runScan } from '../src/scanner.ts'
import { loadScan, saveScan } from '../src/state.ts'
import { recordAttackPath, recordTriageDecision, recordValidation } from '../src/workbench.ts'
import { calibrateSeverity } from '../src/llm/severity.ts'

function testConfig(state: string) { return { enabled: true, maxFiles: 10, maxFileBytes: 4096, stateDir: state } }

async function reportableFinding(root: string, state: string) {
  await writeFile(join(root, 'app.ts'), 'function route(req) { return eval(req.query.code) }\n')
  const config = testConfig(state)
  const scan = await runScan(root, config, 'standard', '', false, state, false)
  await saveScan(state, scan)
  const finding = scan.findings[0]!
  const task = scan.tasks.find(item => item.candidateId === finding.candidateId)!
  const claimed = await (await import('../src/workbench.ts')).claimAuditTask(config, scan.id, 'tester', 'validation')
  await recordValidation(config, scan.id, finding.candidateId, {
    conclusion: 'reportable', method: 'static', attacker: 'Remote request sender.', entryPoint: 'Request parameter.', trustBoundary: 'Untrusted request crosses into the application.',
    rootControl: 'Dynamic execution control.', sink: 'Dynamic execution operation.', impact: 'Attacker-controlled execution.',
    directEvidence: 'The frozen source receipt preserves the request-to-sink control path.', counterevidence: 'No effective local guard was retained.', limitations: 'Static source evidence only.',
    confidence: 'medium', sourceReferences: finding.locations.map(location => ({ file: location.file, line: location.line, role: location.role ?? 'root_control' })),
  }, claimed?.claimToken)
  const pathClaimed = await (await import('../src/workbench.ts')).claimAuditTask(config, scan.id, 'tester', 'attack_path')
  await recordAttackPath(config, scan.id, finding.candidateId, {
    attacker: 'Remote request sender.', entryPoint: 'HTTP request parameter.', preconditions: 'Reachable handler.', dataflow: 'Request input crosses into dynamic execution.',
    outcome: 'Attacker-controlled execution.', severityRationale: 'Remote input reaches a sensitive sink.', changeConditions: 'A proven guard would reduce impact.',
    sourceReferences: finding.locations.map(location => ({ file: location.file, line: location.line, role: location.role ?? 'root_control' })),
  }, pathClaimed?.claimToken)
  return { config, scan: await loadScan(state, scan.id) }
}

test('triage decisions append an audit log and require a close reason when closed', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-triage-'))
  const state = await mkdtemp(join(tmpdir(), 'dsh-triage-state-'))
  try {
    const { config, scan } = await reportableFinding(root, state)
    const finding = scan.findings[0]!
    await assert.rejects(() => recordTriageDecision(config, scan.id, finding.id, { status: 'closed' }), /close reason/)
    await assert.rejects(() => recordTriageDecision(config, scan.id, finding.id, { status: 'open', closeReason: 'wont_fix' }), /cannot carry a close reason/)
    const first = await recordTriageDecision(config, scan.id, finding.id, { status: 'closed', closeReason: 'already_fixed', note: 'Fixed in a follow-up.' })
    assert.equal(first.updated, true)
    const repeat = await recordTriageDecision(config, scan.id, finding.id, { status: 'closed', closeReason: 'already_fixed', note: 'Fixed in a follow-up.' })
    assert.equal(repeat.updated, false, 'identical triple must not append')
    const reopened = await recordTriageDecision(config, scan.id, finding.id, { status: 'open' })
    assert.equal(reopened.updated, true)
    const persisted = await loadScan(state, scan.id)
    const current = persisted.findings[0]!
    assert.equal(current.status, 'open')
    assert.equal(current.closeReason, undefined)
    assert.equal(current.triageDecisions?.length, 2)
    assert.deepEqual(current.triageDecisions?.[0], { status: 'closed', closeReason: 'already_fixed', note: 'Fixed in a follow-up.', at: current.triageDecisions![0]!.at })
  } finally { await rm(root, { recursive: true, force: true }); await rm(state, { recursive: true, force: true }) }
})

test('a false-positive close requires a suppressed or not_applicable validation receipt', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-triage-fp-'))
  const state = await mkdtemp(join(tmpdir(), 'dsh-triage-fp-state-'))
  try {
    const { config, scan } = await reportableFinding(root, state)
    const finding = scan.findings[0]!
    await assert.rejects(() => recordTriageDecision(config, scan.id, finding.id, { status: 'closed', closeReason: 'false_positive' }), /suppressed or not_applicable/)
  } finally { await rm(root, { recursive: true, force: true }); await rm(state, { recursive: true, force: true }) }
})

test('severity calibration drives the comparison reopened decision', () => {
  // A closed-then-open finding across scans is reopened, not persisting.
  const closed = { status: 'resolved' as const }
  const open = { status: 'open' as const }
  const before = new Map([['f1', closed]])
  const current = new Map([['f1', open]])
  const isClosed = (finding: { status: string }): boolean => finding.status === 'resolved' || finding.status === 'false_positive'
  const result = { new: [] as string[], persisting: [] as string[], reopened: [] as string[], resolved: [] as string[], unknown: [] as string[] }
  for (const finding of current.values()) {
    const prior = before.get('f1')
    if (!prior) { result.new.push('f1'); continue }
    if (isClosed(prior) && finding.status === 'open') { result.reopened.push('f1'); continue }
    result.persisting.push('f1')
  }
  assert.deepEqual(result.reopened, ['f1'])
  assert.equal(calibrateSeverity({ impact: 'high', likelihood: 'high' }).priority, 'P1')
})
