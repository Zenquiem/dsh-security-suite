import assert from 'node:assert/strict'
import test from 'node:test'
import { analyzeGoFlow, analyzePythonFlow } from '../src/flow-analysis.ts'

test('Python local flow resolves request-derived values at command and SSRF sinks', () => {
  const source = 'value = request.args.get("cmd")\ncommand = "echo " + value\nsubprocess.run(command, shell=True)\nurl = request.args.get("url")\nrequests.get(url)\n'
  assert.deepEqual(analyzePythonFlow(source, 'app.py').map(item => item.rule).sort(), ['shell-command-construction', 'ssrf-request-sink'])
})

test('Go local flow resolves request-derived values at filesystem and command sinks', () => {
  const source = 'name := r.URL.Query().Get("name")\npath := "/tmp/" + name\nos.ReadFile(path)\nexec.Command("sh", "-c", name)\n'
  assert.deepEqual(analyzeGoFlow(source, 'main.go').map(item => item.rule).sort(), ['path-traversal-sink', 'shell-command-construction'])
})
