import assert from 'node:assert/strict'
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { assessDirectory, resolveSafeTarget, runScan } from '../src/scanner.ts'
import { loadScan, saveScan, toSarif } from '../src/state.ts'

test('assessDirectory reports source candidates and skips dependencies', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  try {
    await writeFile(join(root, 'app.ts'), "const apiKey = 'not-a-real-secret-value'\neval(input)\n")
    await mkdir(join(root, 'node_modules'))
    await writeFile(join(root, 'node_modules', 'ignored.js'), 'eval(input)')

    const result = await assessDirectory(root, { maxFiles: 10, maxFileBytes: 4096 })
    assert.equal(result.filesScanned, 1)
    assert.equal(result.filesSkipped, 1)
    assert.deepEqual(result.candidates.map(candidate => candidate.rule), [
      'hardcoded-secret-marker',
      'dangerous-dynamic-code',
    ])
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
    const scan = await runScan(root, { maxFiles: 10, maxFileBytes: 4096 }, 'standard', '')
    await saveScan(state, scan)
    const loaded = await loadScan(state, scan.id)
    assert.equal(loaded.findings[0].cwe, 'CWE-95')
    const sarif = toSarif(loaded)
    assert.equal(sarif.version, '2.1.0')
  } finally {
    await rm(root, { recursive: true, force: true })
    await rm(state, { recursive: true, force: true })
  }
})
