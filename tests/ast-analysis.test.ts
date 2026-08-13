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
