import assert from 'node:assert/strict'
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { applyRemediationProposal, installPreCommitHook, remediationPlan, runIsolatedValidation } from '../src/operations.ts'
import { runScan } from '../src/scanner.ts'
import { saveScan } from '../src/state.ts'

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
    await saveScan(state, scan)
    const receipt = await runIsolatedValidation(root, { ...config, stateDir: state }, scan.id, 'node --version')
    assert.equal(receipt.exitCode, 0)
    assert.equal(receipt.timedOut, false)
    assert.ok(receipt.artifactRef)
    assert.equal(await readFile(join(root, 'app.ts'), 'utf8'), 'eval(input)\n')
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
