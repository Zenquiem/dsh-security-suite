import assert from 'node:assert/strict'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { candidateIdFromIdentity, candidateIdentity, combineCandidates, EXCLUDED_DIRS, EXCLUDED_FILENAMES, isBinarySample, pathIsExcluded, previewForBytes, previewForPath, qualifiesForRanking, structuralOutline, TEXT_CODE_EXTENSIONS } from '../src/llm/rank.ts'

test('exclusion sets match the codex-security constants', () => {
  assert.ok(EXCLUDED_DIRS.has('.git'))
  assert.ok(EXCLUDED_DIRS.has('node_modules'))
  assert.ok(EXCLUDED_DIRS.has('tests'))
  assert.ok(EXCLUDED_DIRS.size >= 40)
  assert.ok(EXCLUDED_FILENAMES.has('package-lock.json'))
  assert.ok(EXCLUDED_FILENAMES.has('README.md'))
  assert.ok(TEXT_CODE_EXTENSIONS.has('.ts'))
  assert.ok(TEXT_CODE_EXTENSIONS.has('.py'))
  assert.ok(TEXT_CODE_EXTENSIONS.has('.go'))
  assert.ok(TEXT_CODE_EXTENSIONS.has('.rs'))
  assert.ok(!TEXT_CODE_EXTENSIONS.has('.md'))
  assert.ok(TEXT_CODE_EXTENSIONS.size >= 40)
})

test('pathIsExcluded applies directory parts and file names', () => {
  assert.equal(pathIsExcluded('src/app.ts'), false)
  assert.equal(pathIsExcluded('node_modules/x/index.js'), true)
  assert.equal(pathIsExcluded('tests/app.test.ts'), true)
  assert.equal(pathIsExcluded('package-lock.json'), true)
  assert.equal(pathIsExcluded('src/README.md'), true)
})

test('candidate identity hashes with the codex byte discipline', () => {
  const identity = candidateIdentity({ cweIds: ['CWE-89'], locations: [{ path: 'a.ts', startLine: 1, role: 'root_control' }], instance: undefined })
  // sort_keys=True -> cwe_ids, instance, locations; compact separators; null instance preserved.
  assert.equal(identity, '{"cwe_ids":["CWE-89"],"instance":null,"locations":[{"path":"a.ts","startLine":1,"role":"root_control"}]}')
  const id = candidateIdFromIdentity(identity)
  assert.match(id, /^candidate-[0-9a-f]{16}$/)
  assert.equal(candidateIdFromIdentity(identity), id, 'deterministic')
  // instance changes the identity
  assert.notEqual(candidateIdentity({ cweIds: ['CWE-89'], locations: [{ path: 'a.ts', startLine: 1, role: 'root_control' }], instance: 'param-a' }), identity)
})

test('combineCandidates merges by identity and preserves sorted merged text', () => {
  const base = { cweIds: ['CWE-89'], locations: [{ path: 'a.ts', startLine: 1, role: 'root_control' }], summary: 's1', evidence: 'e1' }
  const combined = combineCandidates([
    { ...base, summary: 'second', evidence: 'b' },
    { ...base, summary: 'first', evidence: 'a' },
  ])
  assert.equal(combined.length, 1)
  assert.equal(combined[0]?.summary, 'first\nsecond')
  assert.equal(combined[0]?.evidence, 'a\nb')
  assert.match(combined[0]?.candidateId ?? '', /^candidate-[0-9a-f]{16}$/)
})

test('preview and outline work on source bytes', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-rank-'))
  try {
    await writeFile(join(root, 'app.ts'), 'export function handler(req) {\n  const q = req.query.q\n  return eval(q)\n}\n')
    assert.equal(isBinarySample(Buffer.from('hello')), false)
    assert.equal(isBinarySample(Buffer.from([0, 1, 2])), true)
    const preview = await previewForPath(join(root, 'app.ts'))
    assert.match(preview, /function handler/)
    assert.ok(structuralOutline('def foo():\n  pass\n').includes('def foo'))
    assert.ok(structuralOutline('func bar(x int) {}').includes('func bar'))
    assert.equal(qualifiesForRanking(root, join(root, 'app.ts')), true)
    assert.equal(qualifiesForRanking(root, join(root, 'node_modules', 'x.js')), false)
  } finally { await rm(root, { recursive: true, force: true }) }
})

test('previewForBytes respects the byte budget', () => {
  const long = Array.from({ length: 500 }, (_, index) => `line ${index} content`).join('\n')
  const preview = previewForBytes(long, 1024)
  assert.ok(Buffer.byteLength(preview, 'utf8') <= 1024)
})
