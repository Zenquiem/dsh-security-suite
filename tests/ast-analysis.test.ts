import assert from 'node:assert/strict'
import test from 'node:test'
import { analyzeJavaScriptAst, analyzeJavaScriptModuleGraph } from '../src/ast-analysis.ts'

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

test('AST analysis treats only outbound destinations, not request payloads, as SSRF-sensitive', () => {
  const result = analyzeJavaScriptAst(`
    function route(req) {
      fetch('https://api.example.test/events', { method: 'POST', body: req.body.payload })
      axios.request({ url: req.query.target, data: req.body.payload })
      request({ url: req.query.secondary, headers: { authorization: req.headers.authorization } })
    }
  `, 'outbound.ts')
  assert.deepEqual(result.candidates.map(candidate => candidate.rule), ['ssrf-request-sink', 'ssrf-request-sink'])
  assert.deepEqual(result.candidates.map(candidate => candidate.line), [4, 5])
})

test('AST analysis follows request input through named local helper calls to a sensitive sink', () => {
  const result = analyzeJavaScriptAst(`
    function executeTemplate(command) { exec(command) }
    function route(req) {
      const command = req.query.command
      executeTemplate(command)
    }
  `, 'helpers.ts')
  assert.equal(result.candidates.length, 1)
  assert.equal(result.candidates[0]?.rule, 'shell-command-construction')
  assert.equal(result.candidates[0]?.line, 2)
  assert.equal(result.candidates[0]?.evidence.some(item => item.detail.includes('call-chain analysis')), true)
})

test('AST analysis follows destructured request aliases into sensitive calls', () => {
  const result = analyzeJavaScriptAst(`
    function route(req) {
      const { body, query: q } = req
      eval(body.code)
      exec(q.command)
    }
  `, 'destructured.ts')
  assert.deepEqual(result.candidates.map(candidate => candidate.rule).sort(), ['dangerous-dynamic-code', 'shell-command-construction'])
})

test('AST analysis does not treat destructuring from a non-request object as a source', () => {
  const result = analyzeJavaScriptAst(`
    const trusted = { body: { code: '1 + 1' } }
    const { body } = trusted
    eval(body.code)
  `, 'destructured-negative.ts')
  assert.equal(result.candidates.some(candidate => candidate.rule === 'dangerous-dynamic-code'), false)
})

test('AST analysis does not treat a static argument to a helper parameter named req as request data', () => {
  const result = analyzeJavaScriptAst(`
    function execute(req) { eval(req) }
    execute('1 + 1')
  `, 'parameter-name-negative.ts')
  assert.equal(result.candidates.some(candidate => candidate.rule === 'dangerous-dynamic-code'), false)
})

test('AST analysis follows named local wrapper chains without treating static helper calls as tainted', () => {
  const result = analyzeJavaScriptAst(`
    const executeTemplate = (command) => exec(command)
    function wrapper(value) { executeTemplate(value) }
    function route(req) { wrapper(req.query.command) }
    wrapper('git --version')
  `, 'wrappers.ts')
  assert.equal(result.candidates.length, 1)
  assert.equal(result.candidates[0]?.rule, 'shell-command-construction')
})

test('AST module analysis follows request input through relative named imports into a sink module', () => {
  const result = analyzeJavaScriptModuleGraph([
    { file: 'server/route.ts', source: "import { executeTemplate } from '../lib/runner'\nexport function route(req) { executeTemplate(req.query.command) }\n" },
    { file: 'lib/runner.ts', source: 'export function executeTemplate(command) { exec(command) }\n' },
  ])
  assert.deepEqual(result.parseErrors, [])
  assert.equal(result.candidates.length, 1)
  assert.equal(result.candidates[0]?.rule, 'shell-command-construction')
  assert.equal(result.candidates[0]?.file, 'lib/runner.ts')
  assert.equal(result.candidates[0]?.evidence.some(item => item.detail.includes('cross-module call-chain')), true)
})

test('AST module analysis preserves destructured request aliases through local imports', () => {
  const result = analyzeJavaScriptModuleGraph([
    { file: 'route.ts', source: "import { execute } from './runner'\nexport function route(request) { const { query: q } = request; execute(q.command) }\n" },
    { file: 'runner.ts', source: 'export function execute(command) { exec(command) }\n' },
  ])
  assert.equal(result.candidates.length, 1)
  assert.equal(result.candidates[0]?.rule, 'shell-command-construction')
  assert.equal(result.candidates[0]?.evidence.some(item => item.detail.includes('cross-module call-chain')), true)
})

test('AST module analysis supports namespace imports but does not infer external package internals', () => {
  const result = analyzeJavaScriptModuleGraph([
    { file: 'route.ts', source: "import * as runner from './runner'\nimport { execute as external } from 'external-runner'\nexport function route(req) { runner.execute(req.query.command); external(req.query.command); runner.execute('git --version') }\n" },
    { file: 'runner.ts', source: 'export const execute = command => exec(command)\n' },
  ])
  assert.equal(result.candidates.length, 1)
  assert.equal(result.candidates[0]?.file, 'runner.ts')
})

test('AST module analysis follows static CommonJS destructured and namespace imports into local exports', () => {
  const result = analyzeJavaScriptModuleGraph([
    { file: 'route.cjs', source: "const { execute: run } = require('./runner')\nconst helpers = require('./helpers')\nfunction route(req) { run(req.query.command); helpers.launch(req.query.secondary) }\n" },
    { file: 'runner.cjs', source: 'function execute(command) { exec(command) }\nmodule.exports.execute = execute\n' },
    { file: 'helpers.js', source: 'function launch(command) { exec(command) }\nexports.launch = launch\n' },
  ])
  assert.deepEqual(result.parseErrors, [])
  assert.equal(result.candidates.length, 2)
  assert.deepEqual(result.candidates.map(item => item.file).sort(), ['helpers.js', 'runner.cjs'])
  assert.equal(result.candidates.every(item => item.evidence.some(evidence => evidence.detail.includes('cross-module call-chain'))), true)
})

test('AST module analysis resolves static CommonJS object and default exports without resolving external or dynamic requires', () => {
  const result = analyzeJavaScriptModuleGraph([
    { file: 'route.js', source: "const runner = require('./runner')\nconst external = require('external-runner')\nconst dynamic = require(name)\nfunction route(req) { runner.execute(req.query.command); external.execute(req.query.command); dynamic.execute(req.query.command) }\n" },
    { file: 'runner.js', source: 'function execute(command) { exec(command) }\nmodule.exports = { execute }\n' },
  ])
  assert.equal(result.candidates.length, 1)
  assert.equal(result.candidates[0]?.file, 'runner.js')
})

test('AST module analysis follows a static CommonJS default function export', () => {
  const result = analyzeJavaScriptModuleGraph([
    { file: 'route.cjs', source: "const execute = require('./runner')\nfunction route(req) { execute(req.query.command) }\n" },
    { file: 'runner.cjs', source: 'function execute(command) { exec(command) }\nmodule.exports = execute\n' },
  ])
  assert.deepEqual(result.parseErrors, [])
  assert.equal(result.candidates.length, 1)
  assert.equal(result.candidates[0]?.file, 'runner.cjs')
  assert.equal(result.candidates[0]?.evidence.some(item => item.detail.includes('cross-module call-chain')), true)
})

test('AST module analysis traces request-derived SQL text to a local database wrapper but not parameter bindings', () => {
  const result = analyzeJavaScriptModuleGraph([
    { file: 'route.ts', source: "import { search, byId } from './queries'\nexport function route(req) { search(req.query.where); byId(req.query.id) }\n" },
    { file: 'queries.ts', source: 'export function search(sql) { db.query(sql) }\nexport function byId(id) { db.query("SELECT * FROM users WHERE id = ?", [id]) }\n' },
  ])
  assert.equal(result.candidates.length, 1)
  assert.equal(result.candidates[0]?.rule, 'sql-injection-query-construction')
  assert.equal(result.candidates[0]?.file, 'queries.ts')
  assert.equal(result.candidates[0]?.evidence.some(item => item.detail.includes('cross-module call-chain')), true)
})

test('AST analysis traces request-derived source objects into supported prototype-polluting merge APIs', () => {
  const result = analyzeJavaScriptAst(`
    function route(req) {
      const payload = req.body
      Object.assign({}, payload)
      _.merge({}, req.body)
      lodash.merge({}, req.body)
    }
  `, 'merge.ts')
  assert.deepEqual(result.candidates.map(candidate => candidate.rule), [
    'prototype-pollution-merge',
    'prototype-pollution-merge',
    'prototype-pollution-merge',
  ])
  assert.equal(result.candidates.every(candidate => candidate.evidence.some(item => item.location?.role === 'sink')), true)
})

test('AST prototype merge analysis excludes request targets, static sources, and unrelated merge-named calls', () => {
  const result = analyzeJavaScriptAst(`
    function merge(target, source) { return source }
    function route(req) {
      Object.assign(req.body, { role: 'user' })
      _.merge({}, { role: 'user' })
      merge({}, req.body)
    }
  `, 'merge-negative.ts')
  assert.equal(result.candidates.some(candidate => candidate.rule === 'prototype-pollution-merge'), false)
})

test('AST module analysis follows request-derived objects through local wrappers to a supported merge source', () => {
  const result = analyzeJavaScriptModuleGraph([
    { file: 'route.ts', source: "import { apply } from './merge'\nexport function route(req) { apply(req.body) }\n" },
    { file: 'merge.ts', source: 'export function apply(payload) { return Object.assign({}, payload) }\n' },
  ])
  assert.equal(result.candidates.length, 1)
  assert.equal(result.candidates[0]?.rule, 'prototype-pollution-merge')
  assert.equal(result.candidates[0]?.file, 'merge.ts')
  assert.equal(result.candidates[0]?.evidence.some(item => item.detail.includes('cross-module call-chain')), true)
})

test('AST analysis traces Math.random through local transformations into named security fields only', () => {
  const result = analyzeJavaScriptAst(`
    const resetToken = Math.random().toString(36)
    session.nonce = Math.random()
    const response = { verificationCode: 'v-' + Math.random() }
    const color = Math.random()
    const layout = { shade: Math.random() }
  `, 'randomness.ts')
  const candidates = result.candidates.filter(candidate => candidate.rule === 'weak-randomness-security')
  assert.deepEqual(candidates.map(candidate => candidate.line), [2, 3, 4])
  assert.equal(candidates.every(candidate => candidate.evidence.some(item => item.location?.role === 'entrypoint') && candidate.evidence.some(item => item.location?.role === 'sink')), true)
})
