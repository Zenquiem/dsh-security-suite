import assert from 'node:assert/strict'
import test from 'node:test'
import { analyzeJavaScriptAst } from '../src/ast-analysis.ts'

test('AST analysis follows request-derived values through local assignments into sensitive sinks', () => {
  const result = analyzeJavaScriptAst(`
    function handler(req) {
      const cmd = ` + '`cat ${req.query.file}`' + `
      const path = req.params.path + '.json'
      const endpoint = req.body.url
      const script = req.query.code
      exec(cmd)
      readFile(path)
      fetch(endpoint)
      eval(script)
    }
  `, 'handler.ts')
  assert.deepEqual(result.candidates.map(candidate => candidate.rule).sort(), [
    'dangerous-dynamic-code',
    'path-traversal-sink',
    'shell-command-construction',
    'ssrf-request-sink',
  ])
  assert.equal(result.candidates.every(candidate => candidate.evidence.some(evidence => evidence.detail.startsWith('AST resolved'))), true)
})

test('AST analysis does not treat static sensitive calls as request-derived findings', () => {
  const result = analyzeJavaScriptAst(`
    const command = 'git --version'
    exec(command)
    fetch('https://status.example.test')
  `, 'static.ts')
  assert.equal(result.candidates.length, 0)
})
