import assert from 'node:assert/strict'
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { applyRemediationProposal, installPreCommitHook, planCandidateValidation, remediationPlan, resumeBulkJob, runCandidateValidation, runCandidateValidationPlan, runIsolatedValidation, startBulkCsvJob } from '../src/operations.ts'
import { runScan } from '../src/scanner.ts'
import { finalizeAndSaveScan, loadScan, saveScan, verifyScanBundle } from '../src/state.ts'
import { claimAuditTask, recordValidation } from '../src/workbench.ts'

const config = { enabled: true, maxFiles: 20, maxFileBytes: 4096, stateDir: '' }

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
  } finally { await rm(root, { recursive: true, force: true }); await rm(state, { recursive: true, force: true }) }
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
    await recordValidation(local, scan.id, candidate.candidateId, { conclusion: 'suppressed', method: 'test', attacker: 'none', entryPoint: 'test fixture', trustBoundary: 'isolated copy', rootControl: 'eval call', sink: 'eval', impact: 'none', directEvidence: 'The isolated command is attached as supporting evidence.', counterevidence: 'No reachable route was established.', limitations: 'The command does not exercise an HTTP route.', confidence: 'medium' }, claim.claimToken)
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
