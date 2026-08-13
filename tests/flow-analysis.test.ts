import assert from 'node:assert/strict'
import test from 'node:test'
import { analyzeGoFlow, analyzeGoPackageGraph, analyzePythonFlow, analyzePythonModuleGraph } from '../src/flow-analysis.ts'
import { analyzeStructuredFlow, type StructuredLanguage } from '../src/structured-flow-analysis.ts'

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

const structuredCases: Array<{ language: StructuredLanguage; file: string; source: string }> = [
  { language: 'java', file: 'Handler.java', source: 'class Handler {\n void execute(String command) {\n  Runtime.getRuntime().exec(command);\n }\n void route(Request request) {\n  execute(request.getParameter("cmd"));\n }\n}' },
  { language: 'csharp', file: 'Handler.cs', source: 'class Handler {\n void Execute(string command) {\n  Process.Start(command);\n }\n void Route(HttpRequest Request) {\n  Execute(Request.Query["cmd"]);\n }\n}' },
  { language: 'php', file: 'handler.php', source: 'function execute($command) { system($command); }\nfunction route() { execute($_GET["cmd"]); }' },
  { language: 'ruby', file: 'handler.rb', source: 'def execute(command)\n  system(command)\nend\ndef route\n  execute(params[:cmd])\nend' },
  { language: 'c', file: 'handler.c', source: 'void execute(char *command) { system(command); }\nvoid route(char **argv) { execute(argv[1]); }' },
  { language: 'cpp', file: 'handler.cpp', source: 'void execute(char *command) { system(command); }\nvoid route(char **argv) { execute(argv[1]); }' },
]

for (const item of structuredCases) test(`${item.language} structured analysis traces request input through a local wrapper`, () => {
  const result = analyzeStructuredFlow([{ file: item.file, source: item.source }], item.language)
  assert.equal(result.candidates.length, 1)
  assert.equal(result.candidates[0]?.rule, 'shell-command-construction')
  assert.equal(result.candidates[0]?.evidence.some(evidence => evidence.detail.includes('structured function data-flow')), true)
})

test('structured analysis does not report a static call to a sensitive Java wrapper', () => {
  const result = analyzeStructuredFlow([{ file: 'Handler.java', source: 'class Handler {\n void execute(String command) {\n  Runtime.getRuntime().exec(command);\n }\n void route() {\n  execute("git --version");\n }\n}' }], 'java')
  assert.equal(result.candidates.length, 0)
})

test('structured analysis follows a C# caller into a same-directory helper file only', () => {
  const result = analyzeStructuredFlow([
    { file: 'api/Route.cs', source: 'class Route {\n void RouteRequest(HttpRequest Request) {\n  Execute(Request.Query["cmd"]);\n }\n}' },
    { file: 'api/Runner.cs', source: 'class Runner {\n void Execute(string command) {\n  Process.Start(command);\n }\n}' },
    { file: 'other/Runner.cs', source: 'class Runner {\n void Execute(string command) {\n  Process.Start(command);\n }\n}' },
  ], 'csharp')
  assert.equal(result.candidates.length, 1)
  assert.equal(result.candidates[0]?.file, 'api/Runner.cs')
})
