import assert from 'node:assert/strict'
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises'
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

test('directory assessment structurally detects unsafe multi-line JWT, CORS, and XML configurations', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  try {
    await writeFile(join(root, 'auth.py'), 'claims = jwt.decode(\n  token,\n  key,\n  verify=False,\n)\n')
    await writeFile(join(root, 'server.ts'), 'app.use(cors({\n  origin: true,\n  credentials: true,\n}))\n')
    await writeFile(join(root, 'Xml.java'), 'class Xml {\n void parse() throws Exception {\n  DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\n  factory.newDocumentBuilder();\n }\n}\n')
    const result = await assessDirectory(root, { maxFiles: 10, maxFileBytes: 4096 })
    assert.deepEqual(result.candidates.filter(item => ['jwt-verification-disabled', 'cors-wildcard-credentials', 'xml-external-entity-risk'].includes(item.rule)).map(item => item.rule).sort(), ['cors-wildcard-credentials', 'jwt-verification-disabled', 'xml-external-entity-risk'])
    const cors = result.candidates.find(item => item.rule === 'cors-wildcard-credentials')
    assert.equal(cors?.evidence.some(item => item.kind === 'context' && item.location?.role === 'expected_control' && item.location.line === 3), true)
    assert.equal(result.ruleReceipts.some(item => item.ruleId === 'jwt-verification-disabled' && item.matches === 1), true)
    assert.equal(result.ruleReceipts.some(item => item.ruleId === 'cors-wildcard-credentials' && item.matches === 1), true)
    assert.equal(result.ruleReceipts.some(item => item.ruleId === 'xml-external-entity-risk' && item.matches === 1), true)
  } finally { await rm(root, { recursive: true, force: true }) }
})

test('directory assessment does not flag paired configuration controls that remain explicit', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  try {
    await writeFile(join(root, 'auth.py'), 'claims = jwt.decode(token, key, algorithms=["RS256"])\n')
    await writeFile(join(root, 'server.ts'), 'app.use(cors({\n  origin: ["https://console.example.test"],\n  credentials: true,\n}))\n')
    await writeFile(join(root, 'Xml.java'), 'class Xml {\n void parse() throws Exception {\n  DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\n  factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\n  factory.newDocumentBuilder();\n }\n}\n')
    const result = await assessDirectory(root, { maxFiles: 10, maxFileBytes: 4096 })
    assert.equal(result.candidates.some(item => ['jwt-verification-disabled', 'cors-wildcard-credentials', 'xml-external-entity-risk'].includes(item.rule)), false)
  } finally { await rm(root, { recursive: true, force: true }) }
})

test('directory assessment relates Express state-changing routes to local and preceding global authorization middleware', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  try {
    await writeFile(join(root, 'routes.ts'), `
      app.post('/open', (req, res) => res.json({ ok: true }))
      app.post('/local', requireAuthorization, (req, res) => res.json({ ok: true }))
      api.use(requireAuthentication)
      api.delete('/global', (req, res) => res.sendStatus(204))
      late.patch('/before', (req, res) => res.json({ ok: true }))
      late.use(requireRole)
      late.patch('/after', (req, res) => res.json({ ok: true }))
    `)
    const result = await assessDirectory(root, { maxFiles: 10, maxFileBytes: 4096 })
    const routes = result.candidates.filter(item => item.rule === 'missing-authorization-route')
    assert.deepEqual(routes.map(item => item.line), [2, 6])
    assert.equal(result.ruleReceipts.some(item => item.ruleId === 'missing-authorization-route' && item.matches === 2), true)
  } finally { await rm(root, { recursive: true, force: true }) }
})

test('directory assessment propagates explicit parent-router authorization mounts without masking unprotected routers', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  try {
    await writeFile(join(root, 'routes.ts'), `
      const admin = Router()
      const sessions = Router()
      const publicApi = Router()
      const late = Router()
      app.use('/admin', requireAuthorization, admin)
      app.use('/public', publicApi)
      app.use(requireSession, sessions)
      admin.post('/users', createUser)
      sessions.delete('/current', sessionController.destroy)
      publicApi.post('/signup', signup)
      late.post('/early', removeDraft)
      late.use(requireRole)
      late.post('/late', removeDraft)
    `)
    const result = await assessDirectory(root, { maxFiles: 10, maxFileBytes: 4096 })
    const routes = result.candidates.filter(item => item.rule === 'missing-authorization-route')
    assert.deepEqual(routes.map(item => item.line), [11, 12])
    assert.equal(routes.every(item => item.evidence[0]?.detail.includes('protected parent-mount')), true)
  } finally { await rm(root, { recursive: true, force: true }) }
})

test('directory assessment relates FastAPI and Spring write routes to explicit authorization declarations', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  try {
    await writeFile(join(root, 'api.py'), `
@app.post('/public')
def publish(payload: Payload):
    return payload

@app.delete('/private', dependencies=[Depends(require_authorization)])
def remove(payload: Payload):
    return payload

@router.patch('/account')
async def update(current_user: User = Depends(require_session)):
    return current_user
`)
    await writeFile(join(root, 'Controller.java'), `
class Controller {
  @PostMapping("/public")
  public void create() {}

  @PreAuthorize("hasRole('ADMIN')")
  @DeleteMapping("/private")
  public void remove() {}

  @PreAuthorize("hasRole('ADMIN')")
  public void unrelated() {}

  @PostMapping("/still-public")
  public void stillPublic() {}

  @RequestMapping(value = "/account", method = RequestMethod.PATCH)
  @RolesAllowed("USER")
  public void update() {}
}
`)
    const result = await assessDirectory(root, { maxFiles: 10, maxFileBytes: 4096 })
    const routes = result.candidates.filter(item => item.rule === 'missing-authorization-route')
    assert.deepEqual(routes.map(item => `${item.file}:${item.line}`).sort(), ['Controller.java:13', 'Controller.java:3', 'api.py:2'])
    assert.equal(routes.some(item => item.evidence[0]?.detail.includes('FastAPI-style')), true)
    assert.equal(routes.some(item => item.evidence[0]?.detail.includes('Spring-style')), true)
  } finally { await rm(root, { recursive: true, force: true }) }
})

test('directory assessment recognizes explicit FastAPI router mounts and Spring class-level authorization without leaking controls', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  try {
    await writeFile(join(root, 'mounted.py'), `
admin = APIRouter()
sessions = APIRouter(dependencies=[Depends(require_session)])
public = APIRouter()
app.include_router(admin, dependencies=[Depends(require_authorization)])
app.include_router(public)

@admin.post('/users')
def create_user():
    return None

@sessions.delete('/current')
def destroy_session():
    return None

@public.patch('/profile')
def update_profile():
    return None
`)
    await writeFile(join(root, 'ClassController.java'), `
@RestController
@PreAuthorize("hasRole('ADMIN')")
class AdminController {
  @PostMapping("/users")
  public void create() {}
}

class PublicController {
  @PostMapping("/signup")
  public void signup() {}
}
`)
    const result = await assessDirectory(root, { maxFiles: 10, maxFileBytes: 4096 })
    const routes = result.candidates.filter(item => item.rule === 'missing-authorization-route')
    assert.deepEqual(routes.map(item => `${item.file}:${item.line}`).sort(), ['ClassController.java:10', 'mounted.py:16'])
    assert.equal(routes.some(item => item.excerpt.includes('create_user')), false)
    assert.equal(routes.some(item => item.excerpt.includes('destroy_session')), false)
  } finally { await rm(root, { recursive: true, force: true }) }
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

test('directory assessment records cross-module CommonJS data-flow evidence', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  try {
    await mkdir(join(root, 'lib'))
    await writeFile(join(root, 'route.cjs'), "const { execute: run } = require('./lib/runner')\nfunction route(req) { run(req.query.command) }\n")
    await writeFile(join(root, 'lib', 'runner.cjs'), 'function execute(command) { exec(command) }\nmodule.exports = { execute }\n')
    const result = await assessDirectory(root, { maxFiles: 10, maxFileBytes: 4096 })
    const candidate = result.candidates.find(item => item.rule === 'shell-command-construction' && item.file === 'lib/runner.cjs')
    assert.ok(candidate)
    assert.equal(candidate.evidence.some(item => item.detail.includes('cross-module call-chain')), true)
    assert.equal(result.ruleReceipts.some(item => item.ruleId === 'ast.cross-module-taint' && item.matches === 1), true)
  } finally { await rm(root, { recursive: true, force: true }) }
})

test('directory assessment follows a CommonJS default function export', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  try {
    await mkdir(join(root, 'lib'))
    await writeFile(join(root, 'route.cjs'), "const execute = require('./lib/runner')\nfunction route(req) { execute(req.query.command) }\n")
    await writeFile(join(root, 'lib', 'runner.cjs'), 'function execute(command) { exec(command) }\nmodule.exports = execute\n')
    const result = await assessDirectory(root, { maxFiles: 10, maxFileBytes: 4096 })
    const candidate = result.candidates.find(item => item.rule === 'shell-command-construction' && item.file === 'lib/runner.cjs')
    assert.ok(candidate)
    assert.equal(candidate.evidence.some(item => item.detail.includes('cross-module call-chain')), true)
  } finally { await rm(root, { recursive: true, force: true }) }
})

test('scan findings preserve structured entrypoint, propagation, and sink locations from native flow evidence', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  const state = await mkdtemp(join(tmpdir(), 'dsh-security-suite-state-'))
  try {
    await mkdir(join(root, 'lib'))
    await writeFile(join(root, 'route.ts'), "import { execute } from './lib/runner'\nexport function route(req) { execute(req.query.command) }\n")
    await writeFile(join(root, 'lib', 'runner.ts'), 'export function execute(command) { exec(command) }\n')
    const scan = await runScan(root, { maxFiles: 10, maxFileBytes: 4096, stateDir: state }, 'standard', '', false, state)
    const finding = scan.findings.find(item => item.ruleId === 'shell.command.construction')
    assert.ok(finding)
    assert.equal(finding.locations.some(location => location.file === 'lib/runner.ts' && location.role === 'sink'), true)
    assert.equal(finding.locations.some(location => location.file === 'route.ts' && location.role === 'propagation'), true)
    finding.disposition = 'reportable'; finding.ledger.push({ at: new Date().toISOString(), phase: 'validation', disposition: 'reportable', summary: 'Validated source flow.' }); finding.ledger.push({ at: new Date().toISOString(), phase: 'attack_path', disposition: 'reportable', summary: 'Validated path.' }); scan.lifecycle = 'completed'; scan.completedAt = new Date().toISOString()
    await finalizeAndSaveScan(state, scan)
    const saved = await loadScan(state, scan.id); const reportable = saved.findings.find(item => item.id === finding.id)!
    const report = await readFile(join(saved.artifacts.directory, reportable.writeup!.reportPath), 'utf8')
    assert.match(report, /route\.ts:2/)
    assert.match(report, /lib\/runner\.ts:1/)
  } finally { await rm(root, { recursive: true, force: true }); await rm(state, { recursive: true, force: true }) }
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

test('directory assessment traces Go data flow through a static local-module import', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  try {
    await mkdir(join(root, 'api')); await mkdir(join(root, 'internal', 'runner'), { recursive: true })
    await writeFile(join(root, 'go.mod'), 'module example.test/service\n\ngo 1.24\n')
    await writeFile(join(root, 'api', 'route.go'), 'package api\nimport runner "example.test/service/internal/runner"\nfunc Route(r Request) { runner.Execute(r.FormValue("cmd")) }\n')
    await writeFile(join(root, 'internal', 'runner', 'runner.go'), 'package runner\nfunc Execute(command string) { exec.Command("sh", "-c", command) }\n')
    const result = await assessDirectory(root, { maxFiles: 10, maxFileBytes: 4096 })
    const candidate = result.candidates.find(item => item.rule === 'shell-command-construction' && item.file === 'internal/runner/runner.go')
    assert.ok(candidate)
    assert.equal(candidate.evidence.some(item => item.location?.file === 'api/route.go'), true)
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

test('a clean GitHub worktree scan records an immutable advisory-eligible source revision', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-git-source-'))
  const state = await mkdtemp(join(tmpdir(), 'dsh-security-suite-state-'))
  try {
    await execFileAsync('git', ['init'], { cwd: root })
    await execFileAsync('git', ['config', 'user.email', 'test@example.invalid'], { cwd: root })
    await execFileAsync('git', ['config', 'user.name', 'DSH Security Suite Test'], { cwd: root })
    await execFileAsync('git', ['remote', 'add', 'origin', 'git@github.com:owner/repo.git'], { cwd: root })
    await writeFile(join(root, 'client.ts'), 'request({ rejectUnauthorized: false })\n')
    await execFileAsync('git', ['add', 'client.ts'], { cwd: root })
    await execFileAsync('git', ['commit', '-m', 'baseline'], { cwd: root })
    const clean = await runScan(root, { maxFiles: 10, maxFileBytes: 4096 }, 'standard', '', false, state)
    assert.equal(clean.targetSnapshot.kind, 'git_revision')
    assert.equal(clean.targetSnapshot.sourceRepository, 'owner/repo')
    assert.match(clean.targetSnapshot.revision ?? '', /^[0-9a-f]{40}$/)
    await writeFile(join(root, 'client.ts'), 'request({ rejectUnauthorized: false })\n// dirty\n')
    const dirty = await runScan(root, { maxFiles: 10, maxFileBytes: 4096 }, 'standard', '', false, state)
    assert.equal(dirty.targetSnapshot.kind, 'git_worktree')
    assert.equal(dirty.targetSnapshot.sourceRepository, undefined)
  } finally { await rm(root, { recursive: true, force: true }); await rm(state, { recursive: true, force: true }) }
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
    assert.deepEqual(rules, ['dangerous.dynamic.code', 'missing.authorization.route', 'removed.authorization.control', 'removed.input.validation.control'])
    assert.equal(scan.findings.filter(finding => finding.disposition === 'reportable').length, 3)
    const route = scan.findings.find(finding => finding.ruleId === 'missing.authorization.route')
    assert.ok(route)
    assert.equal(route.locations[0]?.line, 1)
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

test('open diff investigations retain candidates but require independent validation before reportability', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-diff-open-'))
  const state = await mkdtemp(join(tmpdir(), 'dsh-security-suite-state-'))
  try {
    await execFileAsync('git', ['init'], { cwd: root })
    await execFileAsync('git', ['config', 'user.email', 'test@example.invalid'], { cwd: root })
    await execFileAsync('git', ['config', 'user.name', 'DSH Security Suite Test'], { cwd: root })
    await writeFile(join(root, 'route.ts'), 'const result = "safe"\n')
    await execFileAsync('git', ['add', 'route.ts'], { cwd: root }); await execFileAsync('git', ['commit', '-m', 'baseline'], { cwd: root })
    await writeFile(join(root, 'route.ts'), 'const script = req.query.code\neval(script)\n')
    const scan = await runDiffScan(root, undefined, '', state, false)
    assert.equal(scan.lifecycle, 'validation')
    assert.equal(scan.findings.length, 1)
    assert.equal(scan.findings[0]?.disposition, 'discovered')
    assert.equal(scan.findings[0]?.ledger.some(row => row.phase === 'validation'), false)
    assert.equal(scan.tasks.length, 1)
    assert.equal(scan.coverage.surfaces[0]?.disposition, 'needs_follow_up')
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

test('diff scan traces an added request path into an unchanged local SQL query wrapper without treating bound values as SQL text', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-diff-'))
  try {
    await execFileAsync('git', ['init'], { cwd: root })
    await execFileAsync('git', ['config', 'user.email', 'test@example.invalid'], { cwd: root })
    await execFileAsync('git', ['config', 'user.name', 'DSH Security Suite Test'], { cwd: root })
    await mkdir(join(root, 'lib'))
    await writeFile(join(root, 'route.ts'), 'export function route() {}\n')
    await writeFile(join(root, 'lib', 'queries.ts'), 'export function search(sql: string) { db.query(sql) }\nexport function byId(id: string) { db.query("SELECT * FROM users WHERE id = ?", [id]) }\n')
    await execFileAsync('git', ['add', '.'], { cwd: root }); await execFileAsync('git', ['commit', '-m', 'baseline'], { cwd: root })
    await writeFile(join(root, 'route.ts'), "import { search, byId } from './lib/queries'\nexport function route(req: Request) { search(req.query.where); byId(req.query.id) }\n")
    const scan = await runDiffScan(root, undefined, '')
    const finding = scan.findings.find(item => item.ruleId === 'sql.injection.query.construction')
    assert.ok(finding)
    assert.equal(finding.locations[0]?.file, 'lib/queries.ts')
    assert.equal(scan.findings.filter(item => item.ruleId === 'sql.injection.query.construction').length, 1)
    assert.equal(finding.evidence.some(item => item.location?.file === 'route.ts' && item.location.line === 2), true)
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

test('diff scan traces an added Go caller into an unchanged local-module package', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-diff-'))
  try {
    await execFileAsync('git', ['init'], { cwd: root })
    await execFileAsync('git', ['config', 'user.email', 'test@example.invalid'], { cwd: root })
    await execFileAsync('git', ['config', 'user.name', 'DSH Security Suite Test'], { cwd: root })
    await mkdir(join(root, 'api')); await mkdir(join(root, 'internal', 'runner'), { recursive: true })
    await writeFile(join(root, 'go.mod'), 'module example.test/service\n\ngo 1.24\n')
    await writeFile(join(root, 'api', 'route.go'), 'package api\nimport runner "example.test/service/internal/runner"\nfunc Route() string { return "ok" }\n')
    await writeFile(join(root, 'internal', 'runner', 'runner.go'), 'package runner\nfunc Execute(command string) { exec.Command("sh", "-c", command) }\n')
    await execFileAsync('git', ['add', '.'], { cwd: root }); await execFileAsync('git', ['commit', '-m', 'baseline'], { cwd: root })
    await writeFile(join(root, 'api', 'route.go'), 'package api\nimport runner "example.test/service/internal/runner"\nfunc Route(r Request) { runner.Execute(r.FormValue("cmd")) }\n')
    const scan = await runDiffScan(root, undefined, '')
    const finding = scan.findings.find(item => item.ruleId === 'shell.command.construction')
    assert.ok(finding)
    assert.equal(finding.locations[0]?.file, 'internal/runner/runner.go')
    assert.equal(finding.evidence.some(item => item.location?.file === 'api/route.go' && item.location.line === 3), true)
    assert.equal(scan.coverage.ruleReceipts.find(receipt => receipt.ruleId === 'go.diff-semantic-taint')?.matches, 1)
  } finally { await rm(root, { recursive: true, force: true }) }
})

test('diff scan retains a complete CORS policy when an added paired control creates the risk', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-diff-'))
  try {
    await execFileAsync('git', ['init'], { cwd: root })
    await execFileAsync('git', ['config', 'user.email', 'test@example.invalid'], { cwd: root })
    await execFileAsync('git', ['config', 'user.name', 'DSH Security Suite Test'], { cwd: root })
    await writeFile(join(root, 'server.ts'), 'app.use(cors({\n  origin: true,\n  credentials: false,\n}))\n')
    await execFileAsync('git', ['add', 'server.ts'], { cwd: root }); await execFileAsync('git', ['commit', '-m', 'baseline'], { cwd: root })
    await writeFile(join(root, 'server.ts'), 'app.use(cors({\n  origin: true,\n  credentials: true,\n}))\n')
    const scan = await runDiffScan(root, undefined, '')
    const finding = scan.findings.find(item => item.ruleId === 'cors.wildcard.credentials')
    assert.ok(finding)
    assert.equal(finding.locations[0]?.line, 2)
    assert.equal(finding.evidence.some(item => item.location?.file === 'server.ts' && item.location.line === 3), true)
  } finally { await rm(root, { recursive: true, force: true }) }
})

test('diff scan reports a newly unprotected route but not a route with newly added authorization middleware', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-diff-'))
  try {
    await execFileAsync('git', ['init'], { cwd: root })
    await execFileAsync('git', ['config', 'user.email', 'test@example.invalid'], { cwd: root })
    await execFileAsync('git', ['config', 'user.name', 'DSH Security Suite Test'], { cwd: root })
    await writeFile(join(root, 'routes.ts'), 'app.post("/admin", requireAuthorization, (req, res) => res.json({ ok: true }))\n')
    await execFileAsync('git', ['add', 'routes.ts'], { cwd: root }); await execFileAsync('git', ['commit', '-m', 'baseline'], { cwd: root })
    await writeFile(join(root, 'routes.ts'), 'app.post("/admin", (req, res) => res.json({ ok: true }))\napp.delete("/operators", requireRole, (req, res) => res.sendStatus(204))\n')
    const scan = await runDiffScan(root, undefined, '')
    const routes = scan.findings.filter(item => item.ruleId === 'missing.authorization.route')
    assert.equal(routes.length, 1)
    assert.equal(routes[0]?.locations[0]?.line, 1)
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

test('diff scan traces same-step untrusted GitHub event environment variables into shell execution', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-diff-'))
  try {
    await execFileAsync('git', ['init'], { cwd: root })
    await execFileAsync('git', ['config', 'user.email', 'test@example.invalid'], { cwd: root })
    await execFileAsync('git', ['config', 'user.name', 'DSH Security Suite Test'], { cwd: root })
    await mkdir(join(root, '.github', 'workflows'), { recursive: true })
    await writeFile(join(root, '.github', 'workflows', 'review.yml'), 'on:\n  pull_request_target:\njobs:\n  review:\n    steps:\n      - name: title\n        env:\n          TITLE: ${{ github.event.pull_request.title }}\n        run: echo "verified"\n')
    await execFileAsync('git', ['add', '.'], { cwd: root }); await execFileAsync('git', ['commit', '-m', 'baseline'], { cwd: root })
    await writeFile(join(root, '.github', 'workflows', 'review.yml'), 'on:\n  pull_request_target:\njobs:\n  review:\n    steps:\n      - name: title\n        env:\n          TITLE: ${{ github.event.pull_request.title }}\n        run: |\n          printf "%s\\n" "$TITLE"\n')
    const scan = await runDiffScan(root, undefined, '')
    assert.deepEqual(scan.findings.map(item => item.ruleId), ['ci.untrusted.event.shell'])
    const finding = scan.findings[0]
    assert.equal(finding?.locations[0]?.line, 10)
    assert.equal(finding?.evidence.some(item => item.location?.line === 8 && item.location.role === 'entrypoint'), true)
    assert.equal(finding?.evidence.some(item => item.location?.line === 10 && item.location.role === 'sink'), true)
  } finally { await rm(root, { recursive: true, force: true }) }
})

test('diff scan traces a job-scoped untrusted GitHub event environment variable into a newly added shell sink', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-diff-'))
  try {
    await execFileAsync('git', ['init'], { cwd: root })
    await execFileAsync('git', ['config', 'user.email', 'test@example.invalid'], { cwd: root })
    await execFileAsync('git', ['config', 'user.name', 'DSH Security Suite Test'], { cwd: root })
    await mkdir(join(root, '.github', 'workflows'), { recursive: true })
    await writeFile(join(root, '.github', 'workflows', 'review.yml'), 'on:\n  pull_request_target:\njobs:\n  review:\n    env:\n      TITLE: ${{ github.event.pull_request.title }}\n    steps:\n      - run: echo "verified"\n')
    await execFileAsync('git', ['add', '.'], { cwd: root }); await execFileAsync('git', ['commit', '-m', 'baseline'], { cwd: root })
    await writeFile(join(root, '.github', 'workflows', 'review.yml'), 'on:\n  pull_request_target:\njobs:\n  review:\n    env:\n      TITLE: ${{ github.event.pull_request.title }}\n    steps:\n      - run: |\n          printf "%s\\n" "$TITLE"\n')
    const scan = await runDiffScan(root, undefined, '')
    assert.deepEqual(scan.findings.map(item => item.ruleId), ['ci.untrusted.event.shell'])
    const finding = scan.findings[0]
    assert.equal(finding?.locations[0]?.line, 9)
    assert.equal(finding?.evidence.some(item => item.location?.line === 6 && item.location.role === 'entrypoint'), true)
    assert.equal(finding?.evidence.some(item => item.location?.line === 9 && item.location.role === 'sink'), true)
  } finally { await rm(root, { recursive: true, force: true }) }
})

test('diff scan traces a direct GITHUB_ENV event assignment into a later step shell sink', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-diff-'))
  try {
    await execFileAsync('git', ['init'], { cwd: root })
    await execFileAsync('git', ['config', 'user.email', 'test@example.invalid'], { cwd: root })
    await execFileAsync('git', ['config', 'user.name', 'DSH Security Suite Test'], { cwd: root })
    await mkdir(join(root, '.github', 'workflows'), { recursive: true })
    await writeFile(join(root, '.github', 'workflows', 'review.yml'), 'on:\n  pull_request_target:\njobs:\n  review:\n    steps:\n      - run: |\n          echo "TITLE=${{ github.event.pull_request.title }}" >> "$GITHUB_ENV"\n      - run: echo "verified"\n')
    await execFileAsync('git', ['add', '.'], { cwd: root }); await execFileAsync('git', ['commit', '-m', 'baseline'], { cwd: root })
    await writeFile(join(root, '.github', 'workflows', 'review.yml'), 'on:\n  pull_request_target:\njobs:\n  review:\n    steps:\n      - run: |\n          echo "TITLE=${{ github.event.pull_request.title }}" >> "$GITHUB_ENV"\n      - run: |\n          printf "%s\\n" "$TITLE"\n')
    const scan = await runDiffScan(root, undefined, '')
    assert.deepEqual(scan.findings.map(item => item.ruleId), ['ci.untrusted.event.shell'])
    const finding = scan.findings[0]
    assert.equal(finding?.locations[0]?.line, 9)
    assert.equal(finding?.evidence.some(item => item.location?.line === 7 && item.location.role === 'entrypoint'), true)
    assert.equal(finding?.evidence.some(item => item.location?.line === 9 && item.location.role === 'sink'), true)
  } finally { await rm(root, { recursive: true, force: true }) }
})

test('diff scan does not infer GITHUB_ENV flows within one step, across jobs, or through transformed/output writes', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-diff-'))
  try {
    await execFileAsync('git', ['init'], { cwd: root })
    await execFileAsync('git', ['config', 'user.email', 'test@example.invalid'], { cwd: root })
    await execFileAsync('git', ['config', 'user.name', 'DSH Security Suite Test'], { cwd: root })
    await mkdir(join(root, '.github', 'workflows'), { recursive: true })
    await writeFile(join(root, '.github', 'workflows', 'safe.yml'), 'on: [pull_request]\n')
    await execFileAsync('git', ['add', '.'], { cwd: root }); await execFileAsync('git', ['commit', '-m', 'baseline'], { cwd: root })
    await writeFile(join(root, '.github', 'workflows', 'safe.yml'), 'on:\n  pull_request_target:\njobs:\n  same_step:\n    steps:\n      - run: |\n          echo "TITLE=${{ github.event.pull_request.title }}" >> "$GITHUB_ENV"\n          echo "$TITLE"\n  transformed:\n    steps:\n      - run: |\n          echo "TITLE=${{ github.event.pull_request.title }}-review" >> "$GITHUB_ENV"\n      - run: echo "$TITLE"\n  output:\n    steps:\n      - run: |\n          echo "TITLE=${{ github.event.pull_request.title }}" >> "$GITHUB_OUTPUT"\n      - run: echo "$TITLE"\n  other_job:\n    steps:\n      - run: echo "$TITLE"\n')
    const scan = await runDiffScan(root, undefined, '')
    assert.equal(scan.findings.length, 0)
  } finally { await rm(root, { recursive: true, force: true }) }
})

test('diff scan keeps trusted, overridden, and other-job environment values out of job-scoped shell findings', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-diff-'))
  try {
    await execFileAsync('git', ['init'], { cwd: root })
    await execFileAsync('git', ['config', 'user.email', 'test@example.invalid'], { cwd: root })
    await execFileAsync('git', ['config', 'user.name', 'DSH Security Suite Test'], { cwd: root })
    await mkdir(join(root, '.github', 'workflows'), { recursive: true })
    await writeFile(join(root, '.github', 'workflows', 'safe.yml'), 'on: [pull_request]\n')
    await execFileAsync('git', ['add', '.'], { cwd: root }); await execFileAsync('git', ['commit', '-m', 'baseline'], { cwd: root })
    await writeFile(join(root, '.github', 'workflows', 'safe.yml'), 'on:\n  pull_request_target:\njobs:\n  source:\n    env:\n      TITLE: ${{ github.event.pull_request.title }}\n    steps:\n      - run: echo "not used in this job"\n  trusted:\n    env:\n      RELEASE: stable\n    steps:\n      - run: echo "$RELEASE"\n  overridden:\n    env:\n      TITLE: ${{ github.event.pull_request.title }}\n    steps:\n      - env:\n          TITLE: release verification\n        run: echo "$TITLE"\n')
    const scan = await runDiffScan(root, undefined, '')
    assert.deepEqual(scan.findings.map(item => ({ ruleId: item.ruleId, locations: item.locations.map(location => location.line) })), [])
  } finally { await rm(root, { recursive: true, force: true }) }
})

test('diff scan does not infer a shell injection path from a trusted step environment variable', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-diff-'))
  try {
    await execFileAsync('git', ['init'], { cwd: root })
    await execFileAsync('git', ['config', 'user.email', 'test@example.invalid'], { cwd: root })
    await execFileAsync('git', ['config', 'user.name', 'DSH Security Suite Test'], { cwd: root })
    await mkdir(join(root, '.github', 'workflows'), { recursive: true })
    await writeFile(join(root, '.github', 'workflows', 'safe.yml'), 'on: [pull_request]\n')
    await execFileAsync('git', ['add', '.'], { cwd: root }); await execFileAsync('git', ['commit', '-m', 'baseline'], { cwd: root })
    await writeFile(join(root, '.github', 'workflows', 'safe.yml'), 'on:\n  pull_request_target:\njobs:\n  review:\n    steps:\n      - env:\n          TITLE: release verification\n        run: echo "$TITLE"\n')
    const scan = await runDiffScan(root, undefined, '')
    assert.equal(scan.findings.length, 0)
  } finally { await rm(root, { recursive: true, force: true }) }
})

test('diff scan traces added pull-request head checkout into a later command without reporting safe checkout forms', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-diff-'))
  try {
    await execFileAsync('git', ['init'], { cwd: root })
    await execFileAsync('git', ['config', 'user.email', 'test@example.invalid'], { cwd: root })
    await execFileAsync('git', ['config', 'user.name', 'DSH Security Suite Test'], { cwd: root })
    await mkdir(join(root, '.github', 'workflows'), { recursive: true })
    await writeFile(join(root, '.github', 'workflows', 'review.yml'), 'on:\n  pull_request_target:\npermissions:\n  contents: read\njobs:\n  review:\n    steps:\n      - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29\n      - run: npm test\n')
    await execFileAsync('git', ['add', '.'], { cwd: root })
    await execFileAsync('git', ['commit', '-m', 'baseline'], { cwd: root })
    await writeFile(join(root, '.github', 'workflows', 'review.yml'), 'on:\n  pull_request_target:\npermissions:\n  contents: read\njobs:\n  review:\n    steps:\n      - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n      - run: npm test\n')
    const scan = await runDiffScan(root, undefined, '')
    assert.deepEqual(scan.findings.map(item => item.ruleId), ['ci.pull.request.target.untrusted.checkout'])
    const finding = scan.findings[0]
    assert.equal(finding?.locations[0]?.line, 10)
    assert.equal(finding?.disposition, 'reportable')
    assert.equal(scan.coverage.ruleReceipts.find(receipt => receipt.ruleId === 'ci-pull-request-target-untrusted-checkout')?.matches, 1)
  } finally { await rm(root, { recursive: true, force: true }) }
})

test('diff scan keeps read-only permissions and trusted shell values out of CI findings', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-diff-'))
  try {
    await execFileAsync('git', ['init'], { cwd: root })
    await execFileAsync('git', ['config', 'user.email', 'test@example.invalid'], { cwd: root })
    await execFileAsync('git', ['config', 'user.name', 'DSH Security Suite Test'], { cwd: root })
    await mkdir(join(root, '.github', 'workflows'), { recursive: true })
    await writeFile(join(root, '.github', 'workflows', 'safe.yml'), 'on:\n  pull_request_target:\njobs:\n  review:\n    steps:\n      - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29\n')
    await execFileAsync('git', ['add', '.'], { cwd: root })
    await execFileAsync('git', ['commit', '-m', 'baseline'], { cwd: root })
    await writeFile(join(root, '.github', 'workflows', 'safe.yml'), 'on:\n  pull_request_target:\npermissions:\n  contents: read\njobs:\n  review:\n    steps:\n      - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29\n      - run: echo "release verification"\n')
    const scan = await runDiffScan(root, undefined, '')
    assert.equal(scan.findings.length, 0)
  } finally { await rm(root, { recursive: true, force: true }) }
})

test('diff scan anchors an existing untrusted checkout risk to a newly added execution step', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-diff-'))
  try {
    await execFileAsync('git', ['init'], { cwd: root })
    await execFileAsync('git', ['config', 'user.email', 'test@example.invalid'], { cwd: root })
    await execFileAsync('git', ['config', 'user.name', 'DSH Security Suite Test'], { cwd: root })
    await mkdir(join(root, '.github', 'workflows'), { recursive: true })
    await writeFile(join(root, '.github', 'workflows', 'review.yml'), 'on:\n  pull_request_target:\njobs:\n  review:\n    steps:\n      - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29\n        with:\n          ref: ${{ github.event.pull_request.head.ref }}\n')
    await execFileAsync('git', ['add', '.'], { cwd: root })
    await execFileAsync('git', ['commit', '-m', 'baseline'], { cwd: root })
    await writeFile(join(root, '.github', 'workflows', 'review.yml'), 'on:\n  pull_request_target:\njobs:\n  review:\n    steps:\n      - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29\n        with:\n          ref: ${{ github.event.pull_request.head.ref }}\n      - run: npm test\n')
    const scan = await runDiffScan(root, undefined, '')
    assert.deepEqual(scan.findings.map(item => item.ruleId), ['ci.pull.request.target.untrusted.checkout'])
    assert.equal(scan.findings[0]?.locations[0]?.line, 9)
    assert.equal(scan.findings[0]?.evidence.some(item => item.location?.line === 9 && item.location.role === 'sink'), true)
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
    const reportable = loaded.findings.find(finding => finding.disposition === 'reportable')
    assert.ok(reportable?.writeup)
    assert.ok(loaded.hardening)
    assert.match(await readFile(join(loaded.artifacts.directory, loaded.hardening.portfolioPath), 'utf8'), /Security Hardening Portfolio/)
    assert.match(await readFile(join(loaded.artifacts.directory, loaded.artifacts.report!), 'utf8'), new RegExp(loaded.hardening.portfolioPath.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')))
    assert.match(await readFile(join(loaded.artifacts.directory, reportable.writeup.reportPath), 'utf8'), /No executable PoC is generated/)
    assert.match(await readFile(join(loaded.artifacts.directory, loaded.artifacts.report!), 'utf8'), new RegExp(reportable.writeup.reportPath.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')))
    await rm(join(loaded.artifacts.directory, loaded.hardening.portfolioPath))
    const missingHardening = await verifyScanBundle(loaded)
    assert.equal(missingHardening.valid, false)
    assert.equal(missingHardening.errors.some(error => error.includes(loaded.hardening!.portfolioPath)), true)
    await rm(join(loaded.artifacts.directory, reportable.writeup.reportPath))
    const afterDeletion = await verifyScanBundle(loaded)
    assert.equal(afterDeletion.valid, false)
    assert.equal(afterDeletion.errors.some(error => error.includes(reportable.writeup!.reportPath)), true)
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
