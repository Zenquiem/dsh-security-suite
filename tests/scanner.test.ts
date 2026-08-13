import assert from 'node:assert/strict'
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { assessDirectory, resolveSafeTarget } from '../src/scanner.ts'

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
