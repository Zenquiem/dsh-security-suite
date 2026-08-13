import assert from 'node:assert/strict'
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { assessDirectory, resolveSafeTarget, runScan } from '../src/scanner.ts'
import { finalizeAndSaveScan, loadScan, renderCsv, saveScan, saveTriageAnnotation, toSarif, verifyScanBundle, verifySeal } from '../src/state.ts'

test('assessDirectory reports source candidates and skips dependencies', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  try {
    await writeFile(join(root, 'app.ts'), "const apiKey = 'not-a-real-secret-value'\neval(input)\n")
    await mkdir(join(root, 'node_modules'))
    await writeFile(join(root, 'node_modules', 'ignored.js'), 'eval(input)')

    const result = await assessDirectory(root, { maxFiles: 10, maxFileBytes: 4096 })
    assert.equal(result.filesScanned, 1)
    assert.equal(result.filesSkipped, 1)
    assert.deepEqual(result.candidates.map(candidate => candidate.rule).sort(), ['dangerous-dynamic-code', 'hardcoded-secret-marker'])
  } finally {
    await rm(root, { recursive: true, force: true })
  }
})

test('directory assessment records cross-module JavaScript data-flow evidence', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  try {
    await mkdir(join(root, 'lib'))
    await writeFile(join(root, 'route.ts'), "import { execute } from './lib/runner'\nexport function route(req) { execute(req.query.command) }\n")
    await writeFile(join(root, 'lib', 'runner.ts'), 'export function execute(command) { exec(command) }\n')
    const result = await assessDirectory(root, { maxFiles: 10, maxFileBytes: 4096 })
    const candidate = result.candidates.find(item => item.rule === 'shell-command-construction' && item.file === 'lib/runner.ts')
    assert.ok(candidate)
    assert.equal(candidate.evidence.some(item => item.detail.includes('cross-module call-chain')), true)
    assert.equal(result.ruleReceipts.some(item => item.ruleId === 'ast.cross-module-taint' && item.matches === 1), true)
  } finally { await rm(root, { recursive: true, force: true }) }
})

test('directory assessment records Python and Go cross-file data-flow evidence', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  try {
    await writeFile(join(root, 'route.py'), 'from runner import execute\ndef route():\n    execute(request.args.get("cmd"))\n')
    await writeFile(join(root, 'runner.py'), 'import subprocess\ndef execute(command):\n    subprocess.run(command, shell=True)\n')
    await writeFile(join(root, 'route.go'), 'package app\nfunc Route(r Request) { Execute(r.FormValue("cmd")) }\n')
    await writeFile(join(root, 'runner.go'), 'package app\nfunc Execute(command string) { exec.Command("sh", "-c", command) }\n')
    const result = await assessDirectory(root, { maxFiles: 10, maxFileBytes: 4096 })
    assert.equal(result.candidates.some(item => item.rule === 'shell-command-construction' && item.file === 'runner.py' && item.evidence.some(evidence => evidence.detail.includes('cross-function'))), true)
    assert.equal(result.candidates.some(item => item.rule === 'shell-command-construction' && item.file === 'runner.go' && item.evidence.some(evidence => evidence.detail.includes('cross-function'))), true)
    assert.equal(result.ruleReceipts.some(item => item.ruleId === 'python.cross-module-taint' && item.matches === 1), true)
    assert.equal(result.ruleReceipts.some(item => item.ruleId === 'go.cross-file-taint' && item.matches === 1), true)
  } finally { await rm(root, { recursive: true, force: true }) }
})

test('directory assessment records structured flow evidence for Java, C#, PHP, Ruby, C and C++', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  try {
    await writeFile(join(root, 'Handler.java'), 'class Handler {\n void execute(String command) {\n  Runtime.getRuntime().exec(command);\n }\n void route(Request request) {\n  execute(request.getParameter("cmd"));\n }\n}')
    await writeFile(join(root, 'Handler.cs'), 'class Handler {\n void Execute(string command) {\n  Process.Start(command);\n }\n void Route(HttpRequest Request) {\n  Execute(Request.Query["cmd"]);\n }\n}')
    await writeFile(join(root, 'handler.php'), 'function execute($command) { system($command); }\nfunction route() { execute($_GET["cmd"]); }')
    await writeFile(join(root, 'handler.rb'), 'def execute(command)\n system(command)\nend\ndef route\n execute(params[:cmd])\nend')
    await writeFile(join(root, 'handler.c'), 'void execute(char *command) { system(command); }\nvoid route(char **argv) { execute(argv[1]); }')
    await writeFile(join(root, 'handler.cpp'), 'void execute(char *command) { system(command); }\nvoid route(char **argv) { execute(argv[1]); }')
    const result = await assessDirectory(root, { maxFiles: 10, maxFileBytes: 4096 })
    for (const file of ['Handler.java', 'Handler.cs', 'handler.php', 'handler.rb', 'handler.c', 'handler.cpp']) assert.equal(result.candidates.some(item => item.rule === 'shell-command-construction' && item.file === file && item.evidence.some(evidence => evidence.detail.includes('structured function data-flow'))), true)
    for (const rule of ['java.structured-taint', 'csharp.structured-taint', 'php.structured-taint', 'ruby.structured-taint', 'c.structured-taint', 'cpp.structured-taint']) assert.equal(result.ruleReceipts.some(item => item.ruleId === rule && item.matches === 1), true)
  } finally { await rm(root, { recursive: true, force: true }) }
})

test('directory assessment keeps structured local-call resolution within one directory', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  try {
    await mkdir(join(root, 'api')); await mkdir(join(root, 'other'))
    await writeFile(join(root, 'api', 'Route.cs'), 'class Route {\n void RouteRequest(HttpRequest Request) {\n  Execute(Request.Query["cmd"]);\n }\n}')
    await writeFile(join(root, 'api', 'Runner.cs'), 'class Runner {\n void Execute(string command) {\n  Process.Start(command);\n }\n}')
    await writeFile(join(root, 'other', 'Runner.cs'), 'class Runner {\n void Execute(string command) {\n  Process.Start(command);\n }\n}')
    const result = await assessDirectory(root, { maxFiles: 10, maxFileBytes: 4096 })
    assert.equal(result.candidates.filter(item => item.rule === 'shell-command-construction' && item.evidence.some(evidence => evidence.detail.includes('structured function data-flow'))).length, 1)
    assert.equal(result.candidates.some(item => item.file === 'api/Runner.cs'), true)
  } finally { await rm(root, { recursive: true, force: true }) }
})

test('resolveSafeTarget rejects paths outside the workspace', () => {
  assert.throws(() => resolveSafeTarget('/workspace', '../outside'), /inside the current workspace/)
})

test('scan records persist canonical findings and export SARIF', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  const state = await mkdtemp(join(tmpdir(), 'dsh-security-suite-state-'))
  try {
    await writeFile(join(root, 'app.ts'), 'eval(input)\n')
    const scan = await runScan(root, { maxFiles: 10, maxFileBytes: 4096 }, 'deep', '')
    await saveScan(state, scan)
    const loaded = await loadScan(state, scan.id)
    assert.equal(loaded.findings[0].cwe, 'CWE-95')
    assert.equal(loaded.recipe.passes.length, 3)
    assert.equal(loaded.coverage.receipts[0].sha256.length, 64)
    assert.equal(verifySeal(loaded), true)
    const sarif = toSarif(loaded)
    assert.equal(sarif.version, '2.1.0')
    assert.match(renderCsv(loaded), /fingerprint/)
  } finally {
    await rm(root, { recursive: true, force: true })
    await rm(state, { recursive: true, force: true })
  }
})

test('integrity seal detects an in-memory scan mutation', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  try {
    await writeFile(join(root, 'app.ts'), 'eval(input)\n')
    const scan = await runScan(root, { maxFiles: 10, maxFileBytes: 4096 }, 'standard', '')
    scan.findings[0].severity = 'low'
    assert.equal(verifySeal(scan), false)
  } finally { await rm(root, { recursive: true, force: true }) }
})

test('completed scan persists canonical artifacts and candidate-ledger phase receipts', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  const state = await mkdtemp(join(tmpdir(), 'dsh-security-suite-state-'))
  try {
    await writeFile(join(root, 'SECURITY.md'), 'Use explicit authorization checks.\n')
    await writeFile(join(root, 'app.ts'), 'app.get("/x", (req) => eval(req.query.code))\n')
    const scan = await runScan(root, { maxFiles: 10, maxFileBytes: 4096 }, 'deep', '', false, state)
    await finalizeAndSaveScan(state, scan)
    const loaded = await loadScan(state, scan.id)
    const verified = await verifyScanBundle(loaded)
    assert.equal(verified.valid, true, verified.errors.join('\n'))
    assert.equal(loaded.coverage.policyFiles.includes('SECURITY.md'), true)
    assert.equal(loaded.artifacts.report, 'report.md')
    assert.equal(loaded.findings[0].ledger.some(row => row.phase === 'discovery'), true)
    assert.equal(loaded.findings[0].ledger.some(row => row.phase === 'validation'), true)
    assert.equal(loaded.findings[0].ledger.some(row => row.phase === 'attack_path'), true)
  } finally { await rm(root, { recursive: true, force: true }); await rm(state, { recursive: true, force: true }) }
})

test('native preflight and source-evidenced threat model are durable scan context', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  const state = await mkdtemp(join(tmpdir(), 'dsh-security-suite-state-'))
  try {
    await writeFile(join(root, 'package.json'), '{"scripts":{"test":"node --test"}}\n')
    await writeFile(join(root, 'app.ts'), 'app.post("/export", (req) => fetch(req.body.callback))\n')
    const scan = await runScan(root, { maxFiles: 10, maxFileBytes: 4096, stateDir: state }, 'standard', '', false, state)
    assert.equal(scan.preflight.projectFiles.includes('package.json'), true)
    assert.equal(scan.preflight.languages.includes('typescript'), true)
    assert.deepEqual(scan.preflight.suggestedCommands, ['npm test', 'npm run build'])
    assert.match(scan.threatModel, /Source-Evidenced Threat Model/)
    assert.match(scan.threatModel, /app\.ts/)
  } finally { await rm(root, { recursive: true, force: true }); await rm(state, { recursive: true, force: true }) }
})

test('post-completion annotations do not mutate a sealed scan bundle', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  const state = await mkdtemp(join(tmpdir(), 'dsh-security-suite-state-'))
  try {
    await writeFile(join(root, 'client.ts'), 'request({ rejectUnauthorized: false })\n')
    const scan = await runScan(root, { maxFiles: 10, maxFileBytes: 4096, stateDir: state }, 'standard', '', false, state)
    const finding = scan.findings[0]
    finding.disposition = 'reportable'
    finding.ledger.push({ at: new Date().toISOString(), phase: 'validation', disposition: 'reportable', summary: 'Validated.' })
    finding.ledger.push({ at: new Date().toISOString(), phase: 'attack_path', disposition: 'reportable', summary: 'Path.' })
    scan.lifecycle = 'completed'; scan.completedAt = new Date().toISOString()
    await finalizeAndSaveScan(state, scan)
    const sealed = await loadScan(state, scan.id)
    const annotated = structuredClone(sealed.findings[0]); annotated.status = 'resolved'
    await saveTriageAnnotation(state, sealed, annotated)
    assert.equal((await verifyScanBundle(await loadScan(state, scan.id))).valid, true)
  } finally { await rm(root, { recursive: true, force: true }); await rm(state, { recursive: true, force: true }) }
})
