import assert from 'node:assert/strict'
import test from 'node:test'
import { analyzeGoFlow, analyzeGoPackageGraph, analyzePythonFlow, analyzePythonModuleGraph } from '../src/flow-analysis.ts'
import { analyzeStructuredFlow, type StructuredLanguage } from '../src/structured-flow-analysis.ts'

test('Python local flow resolves request-derived values at command and SSRF sinks', () => {
  const source = 'value = request.args.get("cmd")\ncommand = "echo " + value\nsubprocess.run(command, shell=True)\nurl = request.args.get("url")\nrequests.get(url)\n'
  assert.deepEqual(analyzePythonFlow(source, 'app.py').map(item => item.rule).sort(), ['shell-command-construction', 'ssrf-request-sink'])
})

test('Python SSRF analysis distinguishes destination arguments from request payloads', () => {
  const source = 'payload = request.json\nrequests.post("https://api.example.test/events", json=payload)\ntarget = request.args.get("target")\nrequests.request("GET", target, json=payload)\n'
  const result = analyzePythonFlow(source, 'outbound.py')
  assert.deepEqual(result.map(item => item.rule), ['ssrf-request-sink'])
  assert.equal(result[0]?.line, 4)
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

test('Python and Go module analysis trace request-derived SQL text but exclude bound values', () => {
  const python = analyzePythonModuleGraph([
    { file: 'routes.py', source: 'from queries import search, by_id\ndef route():\n    search(request.args.get("where"))\n    by_id(request.args.get("id"))\n' },
    { file: 'queries.py', source: 'def search(sql):\n    cursor.execute(sql)\ndef by_id(value):\n    cursor.execute("SELECT * FROM users WHERE id = %s", [value])\n' },
  ])
  const go = analyzeGoPackageGraph([
    { file: 'route.go', source: 'package app\nfunc Route(r Request) { Search(r.FormValue("where")); ByID(r.FormValue("id")) }\n' },
    { file: 'queries.go', source: 'package app\nfunc Search(sql string) { db.QueryContext(ctx, sql) }\nfunc ByID(id string) { db.QueryContext(ctx, "SELECT * FROM users WHERE id = $1", id) }\n' },
  ])
  assert.deepEqual(python.candidates.map(item => item.rule), ['sql-injection-query-construction'])
  assert.deepEqual(go.candidates.map(item => item.rule), ['sql-injection-query-construction'])
  assert.equal(python.candidates[0]?.file, 'queries.py')
  assert.equal(go.candidates[0]?.file, 'queries.go')
})

test('Python module analysis traces request bytes into unsafe deserializers and excludes SafeLoader', () => {
  const result = analyzePythonModuleGraph([
    { file: 'routes.py', source: 'from parsers import load_pickle, load_yaml, load_safe\ndef route():\n    load_pickle(request.get_data())\n    load_yaml(request.get_data())\n    load_safe(request.get_data())\n' },
    { file: 'parsers.py', source: 'import pickle\nimport yaml\ndef load_pickle(payload):\n    return pickle.loads(payload)\ndef load_yaml(payload):\n    return yaml.load(payload, Loader=yaml.FullLoader)\ndef load_safe(payload):\n    return yaml.load(payload, Loader=yaml.SafeLoader)\n' },
  ])
  assert.deepEqual(result.candidates.map(item => item.rule), ['unsafe-deserialization', 'unsafe-deserialization'])
  assert.deepEqual(result.candidates.map(item => item.file), ['parsers.py', 'parsers.py'])
  assert.equal(result.candidates.every(item => item.evidence.some(evidence => evidence.detail.includes('cross-function'))), true)
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

test('Go package analysis follows a static local-module import across package directories', () => {
  const result = analyzeGoPackageGraph([
    { file: 'api/route.go', modulePath: 'example.test/service', source: 'package api\nimport runner "example.test/service/internal/runner"\nfunc Route(r Request) { runner.Execute(r.FormValue("cmd")) }\n' },
    { file: 'internal/runner/runner.go', modulePath: 'example.test/service', source: 'package runner\nfunc Execute(command string) { exec.Command("sh", "-c", command) }\n' },
  ])
  assert.equal(result.candidates.length, 1)
  assert.equal(result.candidates[0]?.file, 'internal/runner/runner.go')
  assert.equal(result.candidates[0]?.evidence.some(item => item.location?.file === 'api/route.go'), true)
})

test('Go package analysis does not resolve external imports to a scanned package with the same name', () => {
  const result = analyzeGoPackageGraph([
    { file: 'api/route.go', modulePath: 'example.test/service', source: 'package api\nimport runner "github.com/external/runner"\nfunc Route(r Request) { runner.Execute(r.FormValue("cmd")) }\n' },
    { file: 'internal/runner/runner.go', modulePath: 'example.test/service', source: 'package runner\nfunc Execute(command string) { exec.Command("sh", "-c", command) }\n' },
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
  { language: 'rust', file: 'handler.rs', source: 'fn execute(command: String) {\n Command::new(command);\n}\nasync fn route(req: Request) {\n execute(req.query("cmd"));\n}' },
]

for (const item of structuredCases) test(`${item.language} structured analysis traces request input through a local wrapper`, () => {
  const result = analyzeStructuredFlow([{ file: item.file, source: item.source }], item.language)
  assert.equal(result.candidates.length, 1)
  assert.equal(result.candidates[0]?.rule, 'shell-command-construction')
  assert.equal(result.candidates[0]?.evidence.some(evidence => evidence.detail.includes('structured function data-flow')), true)
})

test('Java structured SSRF analysis follows a request-derived URL destination', () => {
  const result = analyzeStructuredFlow([{ file: 'Handler.java', source: 'class Handler {\n void outbound(String url) { new URL(url); }\n void route(Request request) { outbound(request.getParameter("url")); }\n}' }], 'java')
  assert.deepEqual(result.candidates.map(item => item.rule), ['ssrf-request-sink'])
})

test('structured analysis traces request-derived SQL text and excludes parameterized Java queries', () => {
  const result = analyzeStructuredFlow([{ file: 'Handler.java', source: 'class Handler {\n void search(String sql) { statement.executeQuery(sql); }\n void byId(String id) { statement.executeQuery("SELECT * FROM users WHERE id = ?", id); }\n void route(Request request) { search(request.getParameter("where")); byId(request.getParameter("id")); }\n}' }], 'java')
  assert.deepEqual(result.candidates.map(item => item.rule), ['sql-injection-query-construction'])
  assert.equal(result.candidates[0]?.line, 2)
})

test('Java structured analysis traces request streams into ObjectInputStream readObject directly and through local wrappers', () => {
  const direct = analyzeStructuredFlow([{ file: 'Direct.java', source: 'class Direct {\n Object route(Request request) throws Exception {\n  ObjectInputStream input = new ObjectInputStream(request.getInputStream());\n  return input.readObject();\n }\n}' }], 'java')
  const wrapped = analyzeStructuredFlow([{ file: 'Wrapped.java', source: 'class Wrapped {\n Object load(InputStream payload) throws Exception {\n  ObjectInputStream input = new ObjectInputStream(payload);\n  return input.readObject();\n }\n Object route(Request request) throws Exception {\n  return load(request.getInputStream());\n }\n}' }], 'java')
  assert.deepEqual(direct.candidates.map(item => item.rule), ['unsafe-deserialization'])
  assert.equal(direct.candidates[0]?.evidence.some(item => item.location?.role === 'entrypoint' && item.location.line === 3), true)
  assert.deepEqual(wrapped.candidates.map(item => item.rule), ['unsafe-deserialization'])
  assert.equal(wrapped.candidates[0]?.evidence.some(item => item.detail.includes('structured function data-flow') && item.location?.role === 'propagation'), true)
})

test('Java structured deserialization analysis excludes trusted streams and readObject on non-ObjectInputStream variables', () => {
  const result = analyzeStructuredFlow([{ file: 'Trusted.java', source: 'class Trusted {\n Object load() throws Exception {\n  ObjectInputStream input = new ObjectInputStream(new ByteArrayInputStream(FIXTURE));\n  return input.readObject();\n }\n Object unrelated() throws Exception {\n  Reader input = source;\n  return input.readObject();\n }\n}' }], 'java')
  assert.equal(result.candidates.some(item => item.rule === 'unsafe-deserialization'), false)
})

test('C# structured SSRF analysis does not treat a request body sent to a fixed destination as SSRF', () => {
  const result = analyzeStructuredFlow([{ file: 'Handler.cs', source: 'class Handler {\n void outbound(string body) { client.PostAsync("https://api.example.test/events", body); }\n void route(HttpRequest Request) { outbound(Request.Body); }\n}' }], 'csharp')
  assert.equal(result.candidates.some(item => item.rule === 'ssrf-request-sink'), false)
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

test('Rust structured analysis follows async request data into a same-directory helper only', () => {
  const result = analyzeStructuredFlow([
    { file: 'api/route.rs', source: 'async fn route(req: Request) {\n execute(req.query("cmd"));\n}' },
    { file: 'api/runner.rs', source: 'pub fn execute(command: String) {\n Command::new(command);\n}' },
    { file: 'other/runner.rs', source: 'pub fn execute(command: String) {\n Command::new(command);\n}' },
  ], 'rust')
  assert.equal(result.candidates.length, 1)
  assert.equal(result.candidates[0]?.rule, 'shell-command-construction')
  assert.equal(result.candidates[0]?.file, 'api/runner.rs')
})

test('Rust structured analysis does not report a static sensitive wrapper call', () => {
  const result = analyzeStructuredFlow([{ file: 'handler.rs', source: 'fn execute(command: String) {\n Command::new(command);\n}\nfn route() {\n execute("git --version".to_string());\n}' }], 'rust')
  assert.equal(result.candidates.length, 0)
})
