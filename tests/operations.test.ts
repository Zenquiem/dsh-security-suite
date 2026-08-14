import assert from 'node:assert/strict'
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { applyRemediationProposal, installPreCommitHook, loadRemediationRollback, planCandidateValidation, proposeReviewedRemediation, remediationPlan, resumeBulkJob, rollbackRemediationProposal, runCandidateRuntimeValidation, runCandidateValidation, runCandidateValidationPlan, runIsolatedValidation, runRemediationVerification, startBulkCsvJob } from '../src/operations.ts'
import { runScan } from '../src/scanner.ts'
import { finalizeAndSaveScan, loadScan, saveScan, verifyScanBundle } from '../src/state.ts'
import { claimAuditTask, recordValidation } from '../src/workbench.ts'

const config = { enabled: true, maxFiles: 20, maxFileBytes: 4096, stateDir: '' }
function references(finding: { locations: Array<{ file: string; line: number; role?: string }> }) { return finding.locations.map(location => ({ file: location.file, line: location.line, role: location.role ?? 'root_control' })) as Array<{ file: string; line: number; role: 'entrypoint' | 'wrapper' | 'propagation' | 'root_control' | 'sink' | 'outcome' | 'expected_control' }> }

test('remediationPlan proposes but does not apply a TLS fix', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  const state = await mkdtemp(join(tmpdir(), 'dsh-security-suite-state-'))
  try {
    await writeFile(join(root, 'client.ts'), 'request({ rejectUnauthorized: false })\n')
    const scan = await runScan(root, { ...config, stateDir: state }, 'standard', '', false, state)
    await saveScan(state, scan)
    const plan = await remediationPlan(root, { ...config, stateDir: state }, scan.id, scan.findings[0].id)
    assert.match(plan.patch, /rejectUnauthorized: true/)
    assert.match(await readFile(join(root, 'client.ts'), 'utf8'), /false/)
  } finally { await rm(root, { recursive: true, force: true }) }
})

test('pre-commit hook requires approval and preserves an existing hook', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  try {
    await mkdir(join(root, '.git', 'hooks'), { recursive: true })
    await assert.rejects(() => installPreCommitHook(root, false), /approved to true/)
    await writeFile(join(root, '.git', 'hooks', 'pre-commit'), '#!/bin/sh\necho existing\n')
    const result = await installPreCommitHook(root, true)
    assert.equal(result.installed, false)
    assert.match(await readFile(join(root, '.git', 'hooks', 'pre-commit'), 'utf8'), /existing/)
  } finally { await rm(root, { recursive: true, force: true }) }
})

test('isolated validation records a command receipt without modifying the source target', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  const state = await mkdtemp(join(tmpdir(), 'dsh-security-suite-state-'))
  try {
    await writeFile(join(root, 'app.ts'), 'eval(input)\n')
    const scan = await runScan(root, { ...config, stateDir: state }, 'standard', '', false, state)
    for (const finding of scan.findings) { finding.disposition = 'suppressed'; finding.ledger.push({ at: new Date().toISOString(), phase: 'validation', disposition: 'suppressed', summary: 'Static control review.' }) }
    scan.lifecycle = 'completed'; scan.completedAt = new Date().toISOString(); await finalizeAndSaveScan(state, scan)
    const receipt = await runIsolatedValidation(root, { ...config, stateDir: state }, scan.id, 'node --version')
    assert.equal(receipt.exitCode, 0)
    assert.equal(receipt.timedOut, false)
    assert.ok(receipt.artifactRef)
    assert.equal(await readFile(join(root, 'app.ts'), 'utf8'), 'eval(input)\n')
    assert.equal((await verifyScanBundle(await loadScan(state, scan.id))).valid, true)
  } finally { await rm(root, { recursive: true, force: true }); await rm(state, { recursive: true, force: true }) }
})

test('isolated validation propagates DSH cancellation to the child process without recording a failed receipt', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  const state = await mkdtemp(join(tmpdir(), 'dsh-security-suite-state-'))
  try {
    await writeFile(join(root, 'app.ts'), 'eval(input)\n')
    await writeFile(join(root, 'wait.js'), 'setTimeout(() => {}, 5000)\n')
    const scan = await runScan(root, { ...config, stateDir: state }, 'standard', '', false, state)
    for (const finding of scan.findings) { finding.disposition = 'suppressed'; finding.ledger.push({ at: new Date().toISOString(), phase: 'validation', disposition: 'suppressed', summary: 'Static control review.' }) }
    scan.lifecycle = 'completed'; scan.completedAt = new Date().toISOString(); await finalizeAndSaveScan(state, scan)
    const controller = new AbortController(); const started = Date.now()
    const pending = runIsolatedValidation(root, { ...config, stateDir: state }, scan.id, 'node wait.js', 10_000, controller.signal)
    setTimeout(() => controller.abort('cancel validation'), 100)
    await assert.rejects(pending, error => (error as { name?: string }).name === 'AbortError')
    assert.ok(Date.now() - started < 2_000)
    assert.equal((await verifyScanBundle(await loadScan(state, scan.id))).valid, true)
  } finally { await rm(root, { recursive: true, force: true }); await rm(state, { recursive: true, force: true }) }
})

test('candidate validation attaches an isolated receipt to the claimed candidate ledger without deciding the finding', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  const state = await mkdtemp(join(tmpdir(), 'dsh-security-suite-state-'))
  const local = { ...config, stateDir: state }
  try {
    await writeFile(join(root, 'app.ts'), 'function h(req) { return eval(req.query.code) }\n')
    const scan = await runScan(root, local, 'standard', '', false, state, false)
    await saveScan(state, scan)
    const candidate = scan.findings[0]; const claim = await claimAuditTask(local, scan.id, 'validator', 'validation')
    assert.ok(claim)
    await assert.rejects(() => runCandidateValidation(root, local, scan.id, candidate.candidateId, 'wrong', 'node --version'), /Claim token/)
    const receipt = await runCandidateValidation(root, local, scan.id, candidate.candidateId, claim.claimToken, 'node --version')
    assert.match(receipt.artifactRef ?? '', new RegExp(`${candidate.candidateId}/validation_artifacts`))
    const attached = await loadScan(state, scan.id); const finding = attached.findings.find(item => item.candidateId === candidate.candidateId)
    assert.ok(finding); assert.equal(finding.disposition, 'discovered')
    assert.equal(finding.evidence.some(item => item.kind === 'test' && item.artifactRef === receipt.artifactRef), true)
    assert.equal(finding.ledger.some(item => item.artifactRef === receipt.artifactRef), true)
    assert.match(await readFile(join(attached.artifacts.directory, receipt.artifactRef ?? ''), 'utf8'), /node --version/)
    await recordValidation(local, scan.id, candidate.candidateId, { conclusion: 'suppressed', method: 'test', attacker: 'none', entryPoint: 'test fixture', trustBoundary: 'isolated copy', rootControl: 'eval call', sink: 'eval', impact: 'none', directEvidence: 'The isolated command is attached as supporting evidence.', counterevidence: 'No reachable route was established.', limitations: 'The command does not exercise an HTTP route.', confidence: 'medium', sourceReferences: references(candidate) }, claim.claimToken)
  } finally { await rm(root, { recursive: true, force: true }); await rm(state, { recursive: true, force: true }) }
})

test('runtime validation binds a reviewed local interface reproduction to snapshot-receipted fixtures without deciding the candidate', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  const state = await mkdtemp(join(tmpdir(), 'dsh-security-suite-state-'))
  const local = { ...config, stateDir: state }
  try {
    await writeFile(join(root, 'app.ts'), 'function route(req) { return eval(req.query.code) }\n')
    await writeFile(join(root, 'repro.js'), 'console.log("controlled interface reproduction")\n')
    const scan = await runScan(root, local, 'standard', '', false, state, false); await saveScan(state, scan)
    const candidate = scan.findings[0]; const claim = await claimAuditTask(local, scan.id, 'runtime-validator', 'validation'); assert.ok(claim)
    await assert.rejects(() => runCandidateRuntimeValidation(root, local, scan.id, candidate.candidateId, claim.claimToken, 'realistic_interface_reproduction', 'node repro.js', ['repro.js'], 'A disposable local harness records the route-boundary reproduction output.', false), /approved/)
    await assert.rejects(() => runCandidateRuntimeValidation(root, local, scan.id, candidate.candidateId, claim.claimToken, 'realistic_interface_reproduction', 'node repro.js', ['missing.js'], 'A disposable local harness records the route-boundary reproduction output.', true), /scan-receipted/)
    const receipt = await runCandidateRuntimeValidation(root, local, scan.id, candidate.candidateId, claim.claimToken, 'realistic_interface_reproduction', 'node repro.js', ['repro.js'], 'A disposable local harness records the route-boundary reproduction output.', true)
    assert.equal(receipt.method, 'realistic_interface_reproduction')
    assert.equal(receipt.exitCode, 0)
    assert.deepEqual(receipt.fixturePaths, ['repro.js'])
    assert.match(receipt.limitation, /does not establish production reachability/i)
    const attached = await loadScan(state, scan.id); const finding = attached.findings.find(item => item.candidateId === candidate.candidateId)
    assert.ok(finding); assert.equal(finding.disposition, 'discovered')
    assert.equal(finding.evidence.some(item => item.kind === 'runtime' && item.artifactRef === receipt.artifactRef), true)
    const artifact = await readFile(join(attached.artifacts.directory, receipt.artifactRef!), 'utf8')
    assert.match(artifact, /node repro\.js/)
    assert.match(artifact, /route-boundary reproduction output/)
  } finally { await rm(root, { recursive: true, force: true }); await rm(state, { recursive: true, force: true }) }
})

test('runtime validation rejects unsafe remote, interactive-debugger, and non-sanitizer commands before execution', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  const state = await mkdtemp(join(tmpdir(), 'dsh-security-suite-state-'))
  const local = { ...config, stateDir: state }
  try {
    await writeFile(join(root, 'app.ts'), 'function route(req) { return eval(req.query.code) }\n')
    await writeFile(join(root, 'repro.js'), 'console.log("ok")\n')
    const scan = await runScan(root, local, 'standard', '', false, state, false); await saveScan(state, scan)
    const claim = await claimAuditTask(local, scan.id, 'runtime-validator', 'validation'); assert.ok(claim)
    const run = (method: 'realistic_interface_reproduction' | 'debugger_trace' | 'sanitizer_or_memory_checker', command: string) => runCandidateRuntimeValidation(root, local, scan.id, scan.findings[0].candidateId, claim.claimToken, method, command, ['repro.js'], 'A bounded disposable local check.', true)
    await assert.rejects(() => run('realistic_interface_reproduction', 'node http://example.com'), /loopback URLs/)
    await assert.rejects(() => run('debugger_trace', 'gdb app'), /non-interactive/)
    await assert.rejects(() => run('sanitizer_or_memory_checker', 'node repro.js'), /sanitizer or memory checker/)
  } finally { await rm(root, { recursive: true, force: true }); await rm(state, { recursive: true, force: true }) }
})

test('candidate validation plan is preflight-derived, approval-gated, and retains every command outcome', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  const state = await mkdtemp(join(tmpdir(), 'dsh-security-suite-state-'))
  const local = { ...config, stateDir: state }
  try {
    await writeFile(join(root, 'package.json'), '{"scripts":{"test":"node --version","build":"node --invalid-option"}}\n')
    await writeFile(join(root, 'app.ts'), 'function h(req) { return eval(req.query.code) }\n')
    const scan = await runScan(root, local, 'standard', '', false, state, false); await saveScan(state, scan)
    const candidate = scan.findings[0]; const plan = await planCandidateValidation(local, scan.id, candidate.candidateId)
    assert.deepEqual(plan.commands.map(item => item.command), ['npm test', 'npm run build'])
    assert.equal(plan.strategies.find(strategy => strategy.method === 'isolated_project_checks')?.status, 'runnable_with_approval')
    assert.equal(plan.strategies.find(strategy => strategy.method === 'source_trace')?.status, 'available_without_execution')
    assert.equal(plan.strategies.some(strategy => strategy.method === 'debugger_trace' && strategy.status === 'runnable_with_approval'), false)
    const claim = await claimAuditTask(local, scan.id, 'validator', 'validation'); assert.ok(claim)
    await assert.rejects(() => runCandidateValidationPlan(root, local, scan.id, candidate.candidateId, claim.claimToken, false), /approved/)
    const run = await runCandidateValidationPlan(root, local, scan.id, candidate.candidateId, claim.claimToken, true)
    assert.equal(run.receipts.length, 2)
    assert.equal(run.receipts[0].exitCode, 0)
    assert.notEqual(run.receipts[1].exitCode, 0)
    const attached = await loadScan(state, scan.id); const finding = attached.findings.find(item => item.candidateId === candidate.candidateId)
    assert.ok(finding); assert.equal(finding.disposition, 'discovered')
    assert.equal(finding.evidence.filter(item => item.kind === 'test').length, 2)
    assert.equal(finding.ledger.some(item => item.artifactRef === run.artifactRef), true)
    assert.match(await readFile(join(attached.artifacts.directory, run.artifactRef), 'utf8'), /npm run build/)
    assert.equal(await readFile(join(root, 'app.ts'), 'utf8'), 'function h(req) { return eval(req.query.code) }\n')
  } finally { await rm(root, { recursive: true, force: true }); await rm(state, { recursive: true, force: true }) }
})

test('candidate validation plan reports an explicit skip when no manifest maps to a command', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  const state = await mkdtemp(join(tmpdir(), 'dsh-security-suite-state-'))
  const local = { ...config, stateDir: state }
  try {
    await writeFile(join(root, 'app.ts'), 'function h(req) { return eval(req.query.code) }\n')
    const scan = await runScan(root, local, 'standard', '', false, state, false); await saveScan(state, scan)
    const plan = await planCandidateValidation(local, scan.id, scan.findings[0].candidateId)
    assert.deepEqual(plan.commands, [])
    assert.equal(plan.strategies.find(strategy => strategy.method === 'isolated_project_checks')?.status, 'not_applicable')
    assert.match(plan.skipped[0]?.reason ?? '', /No recognized project manifest/)
  } finally { await rm(root, { recursive: true, force: true }); await rm(state, { recursive: true, force: true }) }
})

test('remediation application requires approval, rejects a stale proposal, and verifies applied changes', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  const state = await mkdtemp(join(tmpdir(), 'dsh-security-suite-state-'))
  try {
    await writeFile(join(root, 'client.ts'), 'request({ rejectUnauthorized: false })\n')
    const scan = await runScan(root, { ...config, stateDir: state }, 'standard', '', false, state)
    await saveScan(state, scan)
    const proposal = await remediationPlan(root, { ...config, stateDir: state }, scan.id, scan.findings[0].id)
    await assert.rejects(() => applyRemediationProposal(root, { ...config, stateDir: state }, scan.id, proposal.id, false), /approved/)
    await writeFile(join(root, 'client.ts'), 'request({ rejectUnauthorized: false })\n// changed\n')
    await assert.rejects(() => applyRemediationProposal(root, { ...config, stateDir: state }, scan.id, proposal.id, true), /stale/)

    const second = await runScan(root, { ...config, stateDir: state }, 'standard', '', false, state)
    await saveScan(state, second)
    const fresh = await remediationPlan(root, { ...config, stateDir: state }, second.id, second.findings[0].id)
    const applied = await applyRemediationProposal(root, { ...config, stateDir: state }, second.id, fresh.id, true)
    assert.equal(applied.status, 'applied')
    assert.ok(applied.verificationScanId)
    assert.match(await readFile(join(root, 'client.ts'), 'utf8'), /rejectUnauthorized: true/)
  } finally { await rm(root, { recursive: true, force: true }); await rm(state, { recursive: true, force: true }) }
})

test('safe TLS remediation saves a snapshot-bound rollback record and verifies a restore', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  const state = await mkdtemp(join(tmpdir(), 'dsh-security-suite-state-'))
  const local = { ...config, stateDir: state }
  const original = 'request({ rejectUnauthorized: false })\n'
  try {
    await writeFile(join(root, 'client.ts'), original)
    const scan = await runScan(root, local, 'standard', '', false, state); await saveScan(state, scan)
    const proposal = await remediationPlan(root, local, scan.id, scan.findings[0].id)
    assert.equal(proposal.safeToApply, true)
    const applied = await applyRemediationProposal(root, local, scan.id, proposal.id, true)
    assert.ok(applied.rollbackId); assert.match(await readFile(join(root, 'client.ts'), 'utf8'), /rejectUnauthorized: true/)
    const rollback = await loadRemediationRollback(state, applied.rollbackId!)
    assert.equal(rollback.status, 'available'); assert.equal(rollback.beforeContent, original)
    await assert.rejects(() => rollbackRemediationProposal(root, local, scan.id, proposal.id, false), /approved/)
    const restored = await rollbackRemediationProposal(root, local, scan.id, proposal.id, true)
    assert.equal(restored.status, 'rolled_back'); assert.ok(restored.verificationScanId)
    assert.equal(await readFile(join(root, 'client.ts'), 'utf8'), original)
  } finally { await rm(root, { recursive: true, force: true }); await rm(state, { recursive: true, force: true }) }
})

test('remediation verification runs only source-preflight commands after an exact applied patch without closing the original finding', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  const state = await mkdtemp(join(tmpdir(), 'dsh-security-suite-state-'))
  const local = { ...config, stateDir: state }
  try {
    await writeFile(join(root, 'package.json'), '{"scripts":{"test":"node verify.js","build":"node --version"}}\n')
    await writeFile(join(root, 'verify.js'), 'import { readFileSync } from "node:fs"\nif (!readFileSync("client.ts", "utf8").includes("rejectUnauthorized: true")) process.exit(1)\n')
    await writeFile(join(root, 'client.ts'), 'request({ rejectUnauthorized: false })\n')
    const scan = await runScan(root, local, 'standard', '', false, state); await saveScan(state, scan)
    const proposal = await remediationPlan(root, local, scan.id, scan.findings[0].id)
    const applied = await applyRemediationProposal(root, local, scan.id, proposal.id, true)
    await assert.rejects(() => runRemediationVerification(root, local, scan.id, proposal.id, false), /approved/)
    const run = await runRemediationVerification(root, local, scan.id, proposal.id, true)
    assert.deepEqual(run.commands.map(item => item.command), ['npm test', 'npm run build'])
    assert.equal(run.outcome, 'passed')
    assert.equal(run.receipts.every(receipt => receipt.exitCode === 0), true)
    assert.match(await readFile(run.artifactRef, 'utf8'), /not prove/i)
    assert.match(run.limitation, /not prove/i)
    assert.equal((await loadRemediationRollback(state, applied.rollbackId!)).status, 'available')
    assert.equal((await loadScan(state, scan.id)).findings[0]?.status, 'open')
  } finally { await rm(root, { recursive: true, force: true }); await rm(state, { recursive: true, force: true }) }
})

test('remediation verification retains failing project checks and rejects an altered applied target', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  const state = await mkdtemp(join(tmpdir(), 'dsh-security-suite-state-'))
  const local = { ...config, stateDir: state }
  try {
    await writeFile(join(root, 'package.json'), '{"scripts":{"test":"node --invalid-option"}}\n')
    await writeFile(join(root, 'client.ts'), 'request({ rejectUnauthorized: false })\n')
    const scan = await runScan(root, local, 'standard', '', false, state); await saveScan(state, scan)
    const proposal = await remediationPlan(root, local, scan.id, scan.findings[0].id)
    await applyRemediationProposal(root, local, scan.id, proposal.id, true)
    const failed = await runRemediationVerification(root, local, scan.id, proposal.id, true)
    assert.equal(failed.outcome, 'failed')
    assert.notEqual(failed.receipts[0]?.exitCode, 0)
    await writeFile(join(root, 'client.ts'), 'request({ rejectUnauthorized: true })\n// drift\n')
    await assert.rejects(() => runRemediationVerification(root, local, scan.id, proposal.id, true), /changed since application/)
  } finally { await rm(root, { recursive: true, force: true }); await rm(state, { recursive: true, force: true }) }
})

test('safe JWT remediation is reversible and rollback refuses an altered applied state', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  const state = await mkdtemp(join(tmpdir(), 'dsh-security-suite-state-'))
  const local = { ...config, stateDir: state }
  try {
    await writeFile(join(root, 'jwt.py'), 'options = {"verify_signature": False}\nclaims = jwt.decode(token, key, options=options)\n')
    const scan = await runScan(root, local, 'standard', '', false, state); await saveScan(state, scan)
    const finding = scan.findings.find(item => item.ruleId === 'jwt.verification.disabled'); assert.ok(finding)
    const proposal = await remediationPlan(root, local, scan.id, finding.id); assert.equal(proposal.safeToApply, true)
    const applied = await applyRemediationProposal(root, local, scan.id, proposal.id, true)
    assert.match(await readFile(join(root, 'jwt.py'), 'utf8'), /["']verify_signature["']:\s*True/)
    await writeFile(join(root, 'jwt.py'), 'options = {"verify_signature": True}\n# reviewed manually\n')
    await assert.rejects(() => rollbackRemediationProposal(root, local, scan.id, applied.id, true), /stale/)
    assert.equal((await loadRemediationRollback(state, applied.rollbackId!)).status, 'stale')
  } finally { await rm(root, { recursive: true, force: true }); await rm(state, { recursive: true, force: true }) }
})

test('semantic findings retain a review-only remediation proposal instead of a behavior-changing automatic patch', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  const state = await mkdtemp(join(tmpdir(), 'dsh-security-suite-state-'))
  try {
    await writeFile(join(root, 'app.ts'), 'function route(req) { eval(req.query.code) }\n')
    const scan = await runScan(root, { ...config, stateDir: state }, 'standard', '', false, state); await saveScan(state, scan)
    const proposal = await remediationPlan(root, { ...config, stateDir: state }, scan.id, scan.findings[0].id)
    assert.equal(proposal.safeToApply, false)
    await assert.rejects(() => applyRemediationProposal(root, { ...config, stateDir: state }, scan.id, proposal.id, true), /No mechanically safe replacement/)
  } finally { await rm(root, { recursive: true, force: true }); await rm(state, { recursive: true, force: true }) }
})

test('reviewed remediation binds an exact validated source range, applies reversibly, and rejects drift', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  const state = await mkdtemp(join(tmpdir(), 'dsh-security-suite-state-'))
  const local = { ...config, stateDir: state }
  try {
    const original = 'function route(req) { return eval(req.query.code) }\n'
    await writeFile(join(root, 'app.ts'), original)
    const scan = await runScan(root, local, 'standard', '', false, state, false); await saveScan(state, scan)
    const finding = scan.findings[0]
    await assert.rejects(() => proposeReviewedRemediation(root, local, scan.id, finding.id, { file: 'app.ts', startLine: 1, endLine: 1, expectedText: original.trim(), replacementText: 'function route(req) { return safeEvaluate(req.query.code) }', rationale: 'Replace the dynamic execution primitive with the application-owned constrained evaluator.', testPlan: 'Run focused route regression tests.' }), /structured reportable validation/)
    const claim = await claimAuditTask(local, scan.id, 'validator', 'validation'); assert.ok(claim)
    await recordValidation(local, scan.id, finding.candidateId, { conclusion: 'reportable', method: 'static', attacker: 'Remote request sender.', entryPoint: 'route request parameter.', trustBoundary: 'Untrusted request crosses into application execution.', rootControl: 'Dynamic evaluation statement.', sink: 'eval invocation.', impact: 'Attacker-controlled execution.', directEvidence: 'Request data reaches eval without a parser or authorization guard.', counterevidence: 'No local containment was identified.', limitations: 'Runtime route execution was not performed.', confidence: 'medium', sourceReferences: references(finding) }, claim.claimToken)
    const validated = await loadScan(state, scan.id); const reportable = validated.findings.find(item => item.id === finding.id)!; assert.equal(reportable.disposition, 'reportable')
    const proposal = await proposeReviewedRemediation(root, local, scan.id, finding.id, { file: 'app.ts', startLine: 1, endLine: 1, expectedText: original.trim(), replacementText: 'function route(req) { return safeEvaluate(req.query.code) }', rationale: 'Replace the dynamic execution primitive with the application-owned constrained evaluator.', testPlan: 'Run focused route regression tests.' })
    assert.equal(proposal.safeToApply, true)
    assert.match(proposal.patch, /safeEvaluate/)
    await writeFile(join(root, 'app.ts'), `${original}// concurrent edit\n`)
    await assert.rejects(() => applyRemediationProposal(root, local, scan.id, proposal.id, true), /stale/)
    await writeFile(join(root, 'app.ts'), original)
    const fresh = await runScan(root, local, 'standard', '', false, state, false); await saveScan(state, fresh)
    const freshClaim = await claimAuditTask(local, fresh.id, 'validator', 'validation'); assert.ok(freshClaim)
    await recordValidation(local, fresh.id, fresh.findings[0].candidateId, { conclusion: 'reportable', method: 'static', attacker: 'Remote request sender.', entryPoint: 'route request parameter.', trustBoundary: 'Untrusted request crosses into application execution.', rootControl: 'Dynamic evaluation statement.', sink: 'eval invocation.', impact: 'Attacker-controlled execution.', directEvidence: 'Request data reaches eval without a parser or authorization guard.', counterevidence: 'No local containment was identified.', limitations: 'Runtime route execution was not performed.', confidence: 'medium', sourceReferences: references(fresh.findings[0]) }, freshClaim.claimToken)
    const freshProposal = await proposeReviewedRemediation(root, local, fresh.id, fresh.findings[0].id, { file: 'app.ts', startLine: 1, endLine: 1, expectedText: original.trim(), replacementText: 'function route(req) { return safeEvaluate(req.query.code) }', rationale: 'Replace the dynamic execution primitive with the application-owned constrained evaluator.', testPlan: 'Run focused route regression tests.' })
    const applied = await applyRemediationProposal(root, local, fresh.id, freshProposal.id, true)
    assert.match(await readFile(join(root, 'app.ts'), 'utf8'), /safeEvaluate/)
    assert.ok(applied.rollbackId); assert.ok(applied.verificationScanId)
    assert.equal(applied.verification?.status, 'not_detected')
    assert.match(applied.verification?.limitation ?? '', /not proof/i)
    await rollbackRemediationProposal(root, local, fresh.id, freshProposal.id, true)
    assert.equal(await readFile(join(root, 'app.ts'), 'utf8'), original)
  } finally { await rm(root, { recursive: true, force: true }); await rm(state, { recursive: true, force: true }) }
})

test('reviewed remediation atomically applies and rolls back a source fix with its regression test', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  const state = await mkdtemp(join(tmpdir(), 'dsh-security-suite-state-'))
  const local = { ...config, stateDir: state }
  try {
    const source = 'function route(req) { return eval(req.query.code) }\n'
    const testSource = 'assert.equal(route({ query: { code: "1 + 1" } }), 2)\n'
    await writeFile(join(root, 'app.ts'), source); await writeFile(join(root, 'route.test.ts'), testSource)
    const scan = await runScan(root, local, 'standard', '', false, state); await saveScan(state, scan)
    const finding = scan.findings[0]; const claim = await claimAuditTask(local, scan.id, 'validator', 'validation'); assert.ok(claim)
    await recordValidation(local, scan.id, finding.candidateId, { conclusion: 'reportable', method: 'static', attacker: 'Remote request sender.', entryPoint: 'route request parameter.', trustBoundary: 'Untrusted request crosses into application execution.', rootControl: 'Dynamic evaluation statement.', sink: 'eval invocation.', impact: 'Attacker-controlled execution.', directEvidence: 'Request data reaches eval without a parser or authorization guard.', counterevidence: 'No local containment was identified.', limitations: 'Runtime route execution was not performed.', confidence: 'medium', sourceReferences: references(finding) }, claim.claimToken)
    const proposal = await proposeReviewedRemediation(root, local, scan.id, finding.id, { changes: [
      { file: 'app.ts', startLine: 1, endLine: 1, expectedText: source.trim(), replacementText: 'function route(req) { return safeEvaluate(req.query.code) }' },
      { file: 'route.test.ts', startLine: 1, endLine: 1, expectedText: testSource.trim(), replacementText: 'assert.throws(() => route({ query: { code: "process.exit()" } }))' },
    ], rationale: 'Replace the execution primitive and encode the malicious-input regression through the same route boundary.', testPlan: 'Run the focused route regression suite.' })
    assert.equal(proposal.replacements?.length, 2)
    assert.match(proposal.patch, /route\.test\.ts/)
    const applied = await applyRemediationProposal(root, local, scan.id, proposal.id, true)
    assert.match(await readFile(join(root, 'app.ts'), 'utf8'), /safeEvaluate/)
    assert.match(await readFile(join(root, 'route.test.ts'), 'utf8'), /assert\.throws/)
    const rollback = await loadRemediationRollback(state, applied.rollbackId!)
    assert.equal(rollback.files?.length, 2)
    await rollbackRemediationProposal(root, local, scan.id, proposal.id, true)
    assert.equal(await readFile(join(root, 'app.ts'), 'utf8'), source)
    assert.equal(await readFile(join(root, 'route.test.ts'), 'utf8'), testSource)
  } finally { await rm(root, { recursive: true, force: true }); await rm(state, { recursive: true, force: true }) }
})

test('reviewed multi-file remediation rejects drift in a regression test before changing any file', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  const state = await mkdtemp(join(tmpdir(), 'dsh-security-suite-state-'))
  const local = { ...config, stateDir: state }
  try {
    const source = 'function route(req) { return eval(req.query.code) }\n'
    const testSource = 'assert.equal(route({ query: { code: "1 + 1" } }), 2)\n'
    await writeFile(join(root, 'app.ts'), source); await writeFile(join(root, 'route.test.ts'), testSource)
    const scan = await runScan(root, local, 'standard', '', false, state); await saveScan(state, scan)
    const finding = scan.findings[0]; const claim = await claimAuditTask(local, scan.id, 'validator', 'validation'); assert.ok(claim)
    await recordValidation(local, scan.id, finding.candidateId, { conclusion: 'reportable', method: 'static', attacker: 'Remote request sender.', entryPoint: 'route request parameter.', trustBoundary: 'Untrusted request crosses into application execution.', rootControl: 'Dynamic evaluation statement.', sink: 'eval invocation.', impact: 'Attacker-controlled execution.', directEvidence: 'Request data reaches eval without a parser or authorization guard.', counterevidence: 'No local containment was identified.', limitations: 'Runtime route execution was not performed.', confidence: 'medium', sourceReferences: references(finding) }, claim.claimToken)
    const proposal = await proposeReviewedRemediation(root, local, scan.id, finding.id, { changes: [
      { file: 'app.ts', startLine: 1, endLine: 1, expectedText: source.trim(), replacementText: 'function route(req) { return safeEvaluate(req.query.code) }' },
      { file: 'route.test.ts', startLine: 1, endLine: 1, expectedText: testSource.trim(), replacementText: 'assert.throws(() => route({ query: { code: "process.exit()" } }))' },
    ], rationale: 'Replace the execution primitive and encode the malicious-input regression through the same route boundary.', testPlan: 'Run the focused route regression suite.' })
    await writeFile(join(root, 'route.test.ts'), `${testSource}// concurrent test edit\n`)
    await assert.rejects(() => applyRemediationProposal(root, local, scan.id, proposal.id, true), /stale/)
    assert.equal(await readFile(join(root, 'app.ts'), 'utf8'), source)
  } finally { await rm(root, { recursive: true, force: true }); await rm(state, { recursive: true, force: true }) }
})

test('remediation verification reports a still-detected family without claiming resolution', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  const state = await mkdtemp(join(tmpdir(), 'dsh-security-suite-state-'))
  const local = { ...config, stateDir: state }
  try {
    await writeFile(join(root, 'client.ts'), 'request({ rejectUnauthorized: false })\nrequest({ rejectUnauthorized: false })\n')
    const scan = await runScan(root, local, 'standard', '', false, state, false); await saveScan(state, scan)
    const claim = await claimAuditTask(local, scan.id, 'validator', 'validation'); assert.ok(claim)
    await recordValidation(local, scan.id, scan.findings[0].candidateId, { conclusion: 'reportable', method: 'static', attacker: 'Network attacker.', entryPoint: 'Outbound client configuration.', trustBoundary: 'TLS connection to remote service.', rootControl: 'Certificate verification setting.', sink: 'TLS client request.', impact: 'A network attacker can intercept traffic.', directEvidence: 'The first client disables certificate verification.', counterevidence: 'No explicit compensating verification is present.', limitations: 'No live network test was performed.', confidence: 'high', sourceReferences: references(scan.findings[0]) }, claim.claimToken)
    const proposal = await proposeReviewedRemediation(root, local, scan.id, scan.findings[0].id, { file: 'client.ts', startLine: 1, endLine: 1, expectedText: 'request({ rejectUnauthorized: false })', replacementText: 'request({ rejectUnauthorized: true })', rationale: 'Re-enable certificate verification for the first outbound client path.', testPlan: 'Run the client regression suite.' })
    const applied = await applyRemediationProposal(root, local, scan.id, proposal.id, true)
    assert.equal(applied.verification?.status, 'still_detected')
    assert.equal(applied.verification?.matchingFindingIds.length, 1)
    assert.match(applied.verification?.limitation ?? '', /not proof/i)
  } finally { await rm(root, { recursive: true, force: true }); await rm(state, { recursive: true, force: true }) }
})

test('bulk CSV jobs persist outcomes and retry only failed targets on resume', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  const state = await mkdtemp(join(tmpdir(), 'dsh-security-suite-state-'))
  try {
    await mkdir(join(root, 'good'))
    await writeFile(join(root, 'good', 'app.ts'), 'eval(input)\n')
    await writeFile(join(root, 'targets.csv'), 'path\ngood\nmissing\n')
    const job = await startBulkCsvJob(root, { ...config, stateDir: state }, 'targets.csv', 'standard', '', 2)
    assert.equal(job.entries.find(entry => entry.path === 'good')?.status, 'completed')
    assert.equal(job.entries.find(entry => entry.path === 'missing')?.status, 'failed')
    await mkdir(join(root, 'missing'))
    await writeFile(join(root, 'missing', 'app.ts'), 'eval(input)\n')
    const resumed = await resumeBulkJob(root, { ...config, stateDir: state }, job.id, 2)
    assert.equal(resumed.entries.find(entry => entry.path === 'good')?.attempts, 1)
    assert.equal(resumed.entries.find(entry => entry.path === 'missing')?.status, 'completed')
    assert.equal(resumed.entries.find(entry => entry.path === 'missing')?.attempts, 2)
  } finally { await rm(root, { recursive: true, force: true }); await rm(state, { recursive: true, force: true }) }
})
