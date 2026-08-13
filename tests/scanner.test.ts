import assert from 'node:assert/strict'
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises'
import { execFile } from 'node:child_process'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'
import test from 'node:test'
import { assessDirectory, resolveSafeTarget, runDiffScan, runScan } from '../src/scanner.ts'
import { finalizeAndSaveScan, loadScan, renderCsv, saveScan, saveTriageAnnotation, toSarif, verifyScanBundle, verifySeal } from '../src/state.ts'

const execFileAsync = promisify(execFile)

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

test('directory assessment records structured flow evidence for Java, C#, PHP, Ruby, C, C++, and Rust', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  try {
    await writeFile(join(root, 'Handler.java'), 'class Handler {\n void execute(String command) {\n  Runtime.getRuntime().exec(command);\n }\n void route(Request request) {\n  execute(request.getParameter("cmd"));\n }\n}')
    await writeFile(join(root, 'Handler.cs'), 'class Handler {\n void Execute(string command) {\n  Process.Start(command);\n }\n void Route(HttpRequest Request) {\n  Execute(Request.Query["cmd"]);\n }\n}')
    await writeFile(join(root, 'handler.php'), 'function execute($command) { system($command); }\nfunction route() { execute($_GET["cmd"]); }')
    await writeFile(join(root, 'handler.rb'), 'def execute(command)\n system(command)\nend\ndef route\n execute(params[:cmd])\nend')
    await writeFile(join(root, 'handler.c'), 'void execute(char *command) { system(command); }\nvoid route(char **argv) { execute(argv[1]); }')
    await writeFile(join(root, 'handler.cpp'), 'void execute(char *command) { system(command); }\nvoid route(char **argv) { execute(argv[1]); }')
    await writeFile(join(root, 'handler.rs'), 'fn execute(command: String) {\n Command::new(command);\n}\nasync fn route(req: Request) {\n execute(req.query("cmd"));\n}')
    const result = await assessDirectory(root, { maxFiles: 10, maxFileBytes: 4096 })
    for (const file of ['Handler.java', 'Handler.cs', 'handler.php', 'handler.rb', 'handler.c', 'handler.cpp', 'handler.rs']) assert.equal(result.candidates.some(item => item.rule === 'shell-command-construction' && item.file === file && item.evidence.some(evidence => evidence.detail.includes('structured function data-flow'))), true)
    for (const rule of ['java.structured-taint', 'csharp.structured-taint', 'php.structured-taint', 'ruby.structured-taint', 'c.structured-taint', 'cpp.structured-taint', 'rust.structured-taint']) assert.equal(result.ruleReceipts.some(item => item.ruleId === rule && item.matches === 1), true)
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

test('diff scan distinguishes added risks from deleted authorization and input controls', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-diff-'))
  const state = await mkdtemp(join(tmpdir(), 'dsh-security-suite-state-'))
  try {
    await execFileAsync('git', ['init'], { cwd: root })
    await execFileAsync('git', ['config', 'user.email', 'test@example.invalid'], { cwd: root })
    await execFileAsync('git', ['config', 'user.name', 'DSH Security Suite Test'], { cwd: root })
    await writeFile(join(root, 'route.ts'), 'app.post("/admin", requireAuthorization, handler)\nvalidateRequest(req.body)\nconst response = "ok"\n')
    await execFileAsync('git', ['add', 'route.ts'], { cwd: root })
    await execFileAsync('git', ['commit', '-m', 'baseline'], { cwd: root })
    await writeFile(join(root, 'route.ts'), 'app.post("/admin", handler)\nconst script = req.query.code\neval(script)\n')
    const scan = await runDiffScan(root, undefined, '', state)
    const rules = scan.findings.map(finding => finding.ruleId).sort()
    assert.deepEqual(rules, ['dangerous.dynamic.code', 'removed.authorization.control', 'removed.input.validation.control'])
    assert.equal(scan.findings.filter(finding => finding.disposition === 'reportable').length, 3)
    const authorization = scan.findings.find(finding => finding.ruleId === 'removed.authorization.control')
    assert.ok(authorization)
    assert.equal(authorization.locations[0]?.line, 1)
    assert.equal(authorization.evidence.some(item => item.kind === 'counterevidence' && item.location?.role === 'expected_control'), true)
    assert.equal(scan.coverage.receipts.length, 1)
    assert.equal(scan.coverage.receipts[0]?.path, 'route.ts')
    assert.equal(scan.coverage.ruleReceipts.find(receipt => receipt.ruleId === 'removed-authorization-control')?.matches, 1)
    assert.deepEqual(scan.recipe.passes, ['diff-added-lines', 'diff-semantic-multilanguage', 'diff-ci-workflows', 'diff-removed-controls'])
  } finally { await rm(root, { recursive: true, force: true }); await rm(state, { recursive: true, force: true }) }
})

test('diff scan does not classify ordinary deleted code as a removed security control', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-diff-'))
  try {
    await execFileAsync('git', ['init'], { cwd: root })
    await execFileAsync('git', ['config', 'user.email', 'test@example.invalid'], { cwd: root })
    await execFileAsync('git', ['config', 'user.name', 'DSH Security Suite Test'], { cwd: root })
    await writeFile(join(root, 'app.ts'), 'const message = "hello"\n')
    await execFileAsync('git', ['add', 'app.ts'], { cwd: root })
    await execFileAsync('git', ['commit', '-m', 'baseline'], { cwd: root })
    await writeFile(join(root, 'app.ts'), '')
    const scan = await runDiffScan(root, undefined, '')
    assert.equal(scan.findings.length, 0)
    assert.equal(scan.coverage.receipts.length, 1)
  } finally { await rm(root, { recursive: true, force: true }) }
})

test('diff scan traces an added request path into an unchanged local JavaScript sink wrapper', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-diff-'))
  try {
    await execFileAsync('git', ['init'], { cwd: root })
    await execFileAsync('git', ['config', 'user.email', 'test@example.invalid'], { cwd: root })
    await execFileAsync('git', ['config', 'user.name', 'DSH Security Suite Test'], { cwd: root })
    await mkdir(join(root, 'lib'))
    await writeFile(join(root, 'lib', 'runner.ts'), 'export function execute(command: string) { exec(command) }\n')
    await writeFile(join(root, 'route.ts'), "import { execute } from './lib/runner'\nexport function route(req: Request) { return 'ok' }\n")
    await execFileAsync('git', ['add', 'lib/runner.ts', 'route.ts'], { cwd: root })
    await execFileAsync('git', ['commit', '-m', 'baseline'], { cwd: root })
    await writeFile(join(root, 'route.ts'), "import { execute } from './lib/runner'\nexport function route(req: Request) { execute(req.query.command) }\n")
    const scan = await runDiffScan(root, undefined, '')
    const finding = scan.findings.find(item => item.ruleId === 'shell.command.construction')
    assert.ok(finding)
    assert.equal(finding.locations[0]?.file, 'lib/runner.ts')
    assert.equal(finding.evidence.some(item => item.detail.includes('cross-module call-chain') && item.location?.file === 'route.ts' && item.location.line === 2), true)
    assert.equal(scan.coverage.ruleReceipts.find(receipt => receipt.ruleId === 'ast.diff-semantic-taint')?.matches, 1)
    assert.deepEqual(scan.recipe.passes, ['diff-added-lines', 'diff-semantic-multilanguage', 'diff-ci-workflows', 'diff-removed-controls'])
  } finally { await rm(root, { recursive: true, force: true }) }
})

test('diff scan does not restate an unchanged JavaScript source-to-sink path', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-diff-'))
  try {
    await execFileAsync('git', ['init'], { cwd: root })
    await execFileAsync('git', ['config', 'user.email', 'test@example.invalid'], { cwd: root })
    await execFileAsync('git', ['config', 'user.name', 'DSH Security Suite Test'], { cwd: root })
    await writeFile(join(root, 'app.ts'), 'function run(value: string) { exec(value) }\nfunction route(req: Request) { run(req.query.command) }\n')
    await execFileAsync('git', ['add', 'app.ts'], { cwd: root })
    await execFileAsync('git', ['commit', '-m', 'baseline'], { cwd: root })
    await writeFile(join(root, 'notes.ts'), 'export const releaseNote = "update docs"\n')
    const scan = await runDiffScan(root, undefined, '')
    assert.equal(scan.findings.length, 0)
    assert.equal(scan.coverage.ruleReceipts.find(receipt => receipt.ruleId === 'ast.diff-semantic-taint')?.matches, 0)
  } finally { await rm(root, { recursive: true, force: true }) }
})

test('diff scan traces added Python and Go request paths into unchanged local wrappers', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-diff-'))
  try {
    await execFileAsync('git', ['init'], { cwd: root })
    await execFileAsync('git', ['config', 'user.email', 'test@example.invalid'], { cwd: root })
    await execFileAsync('git', ['config', 'user.name', 'DSH Security Suite Test'], { cwd: root })
    await writeFile(join(root, 'py_runner.py'), 'import subprocess\ndef execute(command):\n    subprocess.run(command, shell=True)\n')
    await writeFile(join(root, 'py_route.py'), 'def route():\n    return "ok"\n')
    await writeFile(join(root, 'go_runner.go'), 'package app\nfunc Execute(command string) { exec.Command("sh", "-c", command) }\n')
    await writeFile(join(root, 'go_route.go'), 'package app\nfunc Route() string { return "ok" }\n')
    await execFileAsync('git', ['add', '.'], { cwd: root })
    await execFileAsync('git', ['commit', '-m', 'baseline'], { cwd: root })
    await writeFile(join(root, 'py_route.py'), 'from py_runner import execute\ndef route():\n    execute(request.args.get("cmd"))\n')
    await writeFile(join(root, 'go_route.go'), 'package app\nfunc Route(r Request) { Execute(r.FormValue("cmd")) }\n')
    const scan = await runDiffScan(root, undefined, '')
    const shells = scan.findings.filter(item => item.ruleId === 'shell.command.construction')
    assert.equal(shells.some(item => item.locations[0]?.file === 'py_runner.py' && item.evidence.some(evidence => evidence.location?.file === 'py_route.py' && evidence.location.line === 3)), true)
    assert.equal(shells.some(item => item.locations[0]?.file === 'go_runner.go' && item.evidence.some(evidence => evidence.location?.file === 'go_route.go' && evidence.location.line === 2)), true)
    assert.equal(scan.coverage.ruleReceipts.find(receipt => receipt.ruleId === 'python.diff-semantic-taint')?.matches, 1)
    assert.equal(scan.coverage.ruleReceipts.find(receipt => receipt.ruleId === 'go.diff-semantic-taint')?.matches, 1)
  } finally { await rm(root, { recursive: true, force: true }) }
})

test('diff scan traces an added Rust request path into an unchanged same-directory wrapper', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-diff-'))
  try {
    await execFileAsync('git', ['init'], { cwd: root })
    await execFileAsync('git', ['config', 'user.email', 'test@example.invalid'], { cwd: root })
    await execFileAsync('git', ['config', 'user.name', 'DSH Security Suite Test'], { cwd: root })
    await writeFile(join(root, 'runner.rs'), 'pub fn execute(command: String) {\n Command::new(command);\n}\n')
    await writeFile(join(root, 'route.rs'), 'async fn route() {}\n')
    await execFileAsync('git', ['add', '.'], { cwd: root })
    await execFileAsync('git', ['commit', '-m', 'baseline'], { cwd: root })
    await writeFile(join(root, 'route.rs'), 'async fn route(req: Request) {\n execute(req.query("cmd"));\n}\n')
    const scan = await runDiffScan(root, undefined, '')
    const finding = scan.findings.find(item => item.ruleId === 'shell.command.construction')
    assert.ok(finding)
    assert.equal(finding.locations[0]?.file, 'runner.rs')
    assert.equal(finding.evidence.some(item => item.location?.file === 'route.rs' && item.location.line === 2), true)
    assert.equal(scan.coverage.ruleReceipts.find(receipt => receipt.ruleId === 'rust.diff-semantic-taint')?.matches, 1)
  } finally { await rm(root, { recursive: true, force: true }) }
})

test('diff scan reports new GitHub Actions trust-boundary regressions', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-diff-'))
  try {
    await execFileAsync('git', ['init'], { cwd: root })
    await execFileAsync('git', ['config', 'user.email', 'test@example.invalid'], { cwd: root })
    await execFileAsync('git', ['config', 'user.name', 'DSH Security Suite Test'], { cwd: root })
    await mkdir(join(root, '.github', 'workflows'), { recursive: true })
    await writeFile(join(root, '.github', 'workflows', 'review.yml'), 'name: review\non: [pull_request]\njobs:\n  check:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29\n')
    await execFileAsync('git', ['add', '.'], { cwd: root })
    await execFileAsync('git', ['commit', '-m', 'baseline'], { cwd: root })
    await writeFile(join(root, '.github', 'workflows', 'review.yml'), 'name: review\non:\n  pull_request_target:\npermissions:\n  contents: write\njobs:\n  check:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@main\n      - run: echo "${{ github.event.pull_request.title }}"\n')
    const scan = await runDiffScan(root, undefined, '')
    const rules = scan.findings.map(item => item.ruleId).sort()
    assert.deepEqual(rules, ['ci.mutable.action.ref', 'ci.pull.request.target.write.permissions', 'ci.untrusted.event.shell'])
    assert.equal(scan.findings.every(item => item.disposition === 'reportable'), true)
    assert.equal(scan.findings.every(item => item.locations[0]?.file === '.github/workflows/review.yml'), true)
    assert.equal(scan.coverage.ruleReceipts.find(receipt => receipt.ruleId === 'ci-untrusted-event-shell')?.matches, 1)
    assert.equal(scan.coverage.ruleReceipts.find(receipt => receipt.ruleId === 'ci-pull-request-target-write-permissions')?.matches, 1)
    assert.equal(scan.coverage.ruleReceipts.find(receipt => receipt.ruleId === 'ci-mutable-action-ref')?.matches, 1)
    assert.deepEqual(scan.recipe.passes, ['diff-added-lines', 'diff-semantic-multilanguage', 'diff-ci-workflows', 'diff-removed-controls'])
  } finally { await rm(root, { recursive: true, force: true }) }
})

test('diff scan does not restate an unchanged GitHub Actions workflow risk', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-diff-'))
  try {
    await execFileAsync('git', ['init'], { cwd: root })
    await execFileAsync('git', ['config', 'user.email', 'test@example.invalid'], { cwd: root })
    await execFileAsync('git', ['config', 'user.name', 'DSH Security Suite Test'], { cwd: root })
    await mkdir(join(root, '.github', 'workflows'), { recursive: true })
    await writeFile(join(root, '.github', 'workflows', 'review.yml'), 'on:\n  pull_request_target:\npermissions:\n  contents: write\njobs:\n  check:\n    steps:\n      - run: echo "${{ github.event.pull_request.title }}"\n')
    await execFileAsync('git', ['add', '.'], { cwd: root })
    await execFileAsync('git', ['commit', '-m', 'baseline'], { cwd: root })
    await writeFile(join(root, 'notes.txt'), 'Documentation only\n')
    const scan = await runDiffScan(root, undefined, '')
    assert.equal(scan.findings.length, 0)
    assert.equal(scan.coverage.ruleReceipts.find(receipt => receipt.ruleId === 'ci-untrusted-event-shell')?.matches, 0)
  } finally { await rm(root, { recursive: true, force: true }) }
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
