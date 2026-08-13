import assert from 'node:assert/strict'
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { installPreCommitHook, remediationPlan } from '../src/operations.ts'
import { runScan } from '../src/scanner.ts'
import { saveScan } from '../src/state.ts'

const config = { enabled: true, maxFiles: 20, maxFileBytes: 4096, stateDir: '' }

test('remediationPlan proposes but does not apply a TLS fix', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  const state = await mkdtemp(join(tmpdir(), 'dsh-security-suite-state-'))
  try {
    await writeFile(join(root, 'client.ts'), 'request({ rejectUnauthorized: false })\n')
    const scan = await runScan(root, { ...config }, 'standard', '')
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
