import assert from 'node:assert/strict'
import test from 'node:test'
import { analyzeGoFlow, analyzeGoPackageGraph, analyzePythonFlow, analyzePythonModuleGraph } from '../src/flow-analysis.ts'

test('Python local flow resolves request-derived values at command and SSRF sinks', () => {
  const source = 'value = request.args.get("cmd")\ncommand = "echo " + value\nsubprocess.run(command, shell=True)\nurl = request.args.get("url")\nrequests.get(url)\n'
  assert.deepEqual(analyzePythonFlow(source, 'app.py').map(item => item.rule).sort(), ['shell-command-construction', 'ssrf-request-sink'])
})

test('Go local flow resolves request-derived values at filesystem and command sinks', () => {
  const source = 'name := r.URL.Query().Get("name")\npath := "/tmp/" + name\nos.ReadFile(path)\nexec.Command("sh", "-c", name)\n'
  assert.deepEqual(analyzeGoFlow(source, 'main.go').map(item => item.rule).sort(), ['path-traversal-sink', 'shell-command-construction'])
})

test('Python module analysis follows request input through imported function wrappers to a sink', () => {
  const result = analyzePythonModuleGraph([
    { file: 'routes.py', source: 'from runner import execute\ndef route():\n    execute(request.args.get("cmd"))\n' },
    { file: 'runner.py', source: 'import subprocess\ndef execute(command):\n    subprocess.run(command, shell=True)\n' },
  ])
  assert.equal(result.candidates.length, 1)
  assert.equal(result.candidates[0]?.rule, 'shell-command-construction')
  assert.equal(result.candidates[0]?.file, 'runner.py')
  assert.equal(result.candidates[0]?.evidence.some(item => item.detail.includes('cross-function')), true)
})

test('Python module analysis does not infer an external import implementation', () => {
  const result = analyzePythonModuleGraph([{ file: 'routes.py', source: 'from external_runner import execute\ndef route():\n    execute(request.args.get("cmd"))\n' }])
  assert.equal(result.candidates.length, 0)
})

test('Python module analysis resolves an unambiguous package import without conflating external modules', () => {
  const result = analyzePythonModuleGraph([
    { file: 'app/routes.py', source: 'from app.runner import execute\ndef route():\n    execute(request.args.get("cmd"))\n' },
    { file: 'app/runner.py', source: 'import subprocess\ndef execute(command):\n    subprocess.run(command, shell=True)\n' },
  ])
  assert.equal(result.candidates.length, 1)
  assert.equal(result.candidates[0]?.file, 'app/runner.py')
})

test('Go package analysis follows request input across same-package files to a command sink', () => {
  const result = analyzeGoPackageGraph([
    { file: 'route.go', source: 'package app\nfunc Route(r Request) { Execute(r.FormValue("cmd")) }\n' },
    { file: 'runner.go', source: 'package app\nfunc Execute(command string) { exec.Command("sh", "-c", command) }\n' },
  ])
  assert.equal(result.candidates.length, 1)
  assert.equal(result.candidates[0]?.rule, 'shell-command-construction')
  assert.equal(result.candidates[0]?.file, 'runner.go')
})

test('Go package analysis does not report static calls to a sensitive wrapper', () => {
  const result = analyzeGoPackageGraph([
    { file: 'route.go', source: 'package app\nfunc Route() { Execute("git --version") }\n' },
    { file: 'runner.go', source: 'package app\nfunc Execute(command string) { exec.Command("sh", "-c", command) }\n' },
  ])
  assert.equal(result.candidates.length, 0)
})

test('Go package analysis does not join matching package names across directories', () => {
  const result = analyzeGoPackageGraph([
    { file: 'api/route.go', source: 'package app\nfunc Route(r Request) { Execute(r.FormValue("cmd")) }\n' },
    { file: 'internal/runner.go', source: 'package app\nfunc Execute(command string) { exec.Command("sh", "-c", command) }\n' },
  ])
  assert.equal(result.candidates.length, 0)
})
