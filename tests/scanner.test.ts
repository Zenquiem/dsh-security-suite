import assert from 'node:assert/strict'
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { assessDirectory, resolveSafeTarget, runScan } from '../src/scanner.ts'
import { finalizeAndSaveScan, loadScan, renderCsv, saveScan, toSarif, verifyScanBundle, verifySeal } from '../src/state.ts'

test('assessDirectory reports source candidates and skips dependencies', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  try {
    await writeFile(join(root, 'app.ts'), "const apiKey = 'not-a-real-secret-value'\neval(input)\n")
    await mkdir(join(root, 'node_modules'))
    await writeFile(join(root, 'node_modules', 'ignored.js'), 'eval(input)')

    const result = await assessDirectory(root, { maxFiles: 10, maxFileBytes: 4096 })
    assert.equal(result.filesScanned, 1)
    assert.equal(result.filesSkipped, 1)
    assert.deepEqual(result.candidates.map(candidate => candidate.rule).sort(), ['dangerous-dynamic-code', 'hardcoded-secret-marker'])
  } finally {
    await rm(root, { recursive: true, force: true })
  }
})

test('resolveSafeTarget rejects paths outside the workspace', () => {
  assert.throws(() => resolveSafeTarget('/workspace', '../outside'), /inside the current workspace/)
})

test('scan records persist canonical findings and export SARIF', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  const state = await mkdtemp(join(tmpdir(), 'dsh-security-suite-state-'))
  try {
    await writeFile(join(root, 'app.ts'), 'eval(input)\n')
    const scan = await runScan(root, { maxFiles: 10, maxFileBytes: 4096 }, 'deep', '')
    await saveScan(state, scan)
    const loaded = await loadScan(state, scan.id)
    assert.equal(loaded.findings[0].cwe, 'CWE-95')
    assert.equal(loaded.recipe.passes.length, 3)
    assert.equal(loaded.coverage.receipts[0].sha256.length, 64)
    assert.equal(verifySeal(loaded), true)
    const sarif = toSarif(loaded)
    assert.equal(sarif.version, '2.1.0')
    assert.match(renderCsv(loaded), /fingerprint/)
  } finally {
    await rm(root, { recursive: true, force: true })
    await rm(state, { recursive: true, force: true })
  }
})

test('integrity seal detects an in-memory scan mutation', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  try {
    await writeFile(join(root, 'app.ts'), 'eval(input)\n')
    const scan = await runScan(root, { maxFiles: 10, maxFileBytes: 4096 }, 'standard', '')
    scan.findings[0].severity = 'low'
    assert.equal(verifySeal(scan), false)
  } finally { await rm(root, { recursive: true, force: true }) }
})

test('completed scan persists canonical artifacts and candidate-ledger phase receipts', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  const state = await mkdtemp(join(tmpdir(), 'dsh-security-suite-state-'))
  try {
    await writeFile(join(root, 'SECURITY.md'), 'Use explicit authorization checks.\n')
    await writeFile(join(root, 'app.ts'), 'app.get("/x", (req) => eval(req.query.code))\n')
    const scan = await runScan(root, { maxFiles: 10, maxFileBytes: 4096 }, 'deep', '', false, state)
    await finalizeAndSaveScan(state, scan)
    const loaded = await loadScan(state, scan.id)
    const verified = await verifyScanBundle(loaded)
    assert.equal(verified.valid, true, verified.errors.join('\n'))
    assert.equal(loaded.coverage.policyFiles.includes('SECURITY.md'), true)
    assert.equal(loaded.artifacts.report, 'report.md')
    assert.equal(loaded.findings[0].ledger.some(row => row.phase === 'discovery'), true)
    assert.equal(loaded.findings[0].ledger.some(row => row.phase === 'validation'), true)
    assert.equal(loaded.findings[0].ledger.some(row => row.phase === 'attack_path'), true)
  } finally { await rm(root, { recursive: true, force: true }); await rm(state, { recursive: true, force: true }) }
})

test('native preflight and source-evidenced threat model are durable scan context', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  const state = await mkdtemp(join(tmpdir(), 'dsh-security-suite-state-'))
  try {
    await writeFile(join(root, 'package.json'), '{"scripts":{"test":"node --test"}}\n')
    await writeFile(join(root, 'app.ts'), 'app.post("/export", (req) => fetch(req.body.callback))\n')
    const scan = await runScan(root, { maxFiles: 10, maxFileBytes: 4096, stateDir: state }, 'standard', '', false, state)
    assert.equal(scan.preflight.projectFiles.includes('package.json'), true)
    assert.equal(scan.preflight.languages.includes('typescript'), true)
    assert.deepEqual(scan.preflight.suggestedCommands, ['npm test', 'npm run build'])
    assert.match(scan.threatModel, /Source-Evidenced Threat Model/)
    assert.match(scan.threatModel, /app\.ts/)
  } finally { await rm(root, { recursive: true, force: true }); await rm(state, { recursive: true, force: true }) }
})
