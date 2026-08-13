import { createHash } from 'node:crypto'
import { access, mkdir, readdir, readFile, stat } from 'node:fs/promises'
import { execFile } from 'node:child_process'
import { basename, extname, join, relative, resolve, sep } from 'node:path'
import { promisify } from 'node:util'
import type { CandidateDisposition, Confidence, Evidence, FileReceipt, Finding, Preflight, RuleReceipt, ScanActivity, ScanRecord, Severity, TargetSnapshot } from './contracts.js'
import { candidateId, createScanId, findingId, getStateDir, scanArtifactDir, sealScan, sha256 } from './state.js'
import { analyzeJavaScriptAst, analyzeJavaScriptModuleGraph, type JavaScriptModule } from './ast-analysis.js'
import { analyzeGoFlow, analyzeGoPackageGraph, analyzePythonFlow, analyzePythonModuleGraph } from './flow-analysis.js'
import { analyzeStructuredFlow, type StructuredLanguage } from './structured-flow-analysis.js'

export interface ScanLimits { maxFiles: number; maxFileBytes: number }
export interface Candidate { rule: string; severity: Severity; file: string; line: number; excerpt: string; rationale: string; cwe: string; evidence: Evidence[] }
export interface ScanResult { root: string; filesScanned: number; filesSkipped: number; candidates: Candidate[]; receipts: FileReceipt[]; ruleReceipts: RuleReceipt[]; policyFiles: string[]; complete: boolean }

const IGNORED_DIRECTORIES = new Set(['.git', '.hg', '.svn', 'node_modules', 'dist', 'build', 'coverage', '.next', '.cache', 'vendor'])
const TEXT_EXTENSIONS = new Set(['.c', '.cc', '.cpp', '.cs', '.go', '.java', '.js', '.jsx', '.mjs', '.cjs', '.php', '.py', '.rb', '.rs', '.sh', '.bash', '.ts', '.tsx', '.vue', '.yaml', '.yml', '.json', '.toml', '.xml'])
const MAX_DIFF_BYTES = 1_000_000
const execFileAsync = promisify(execFile)

interface Rule { id: string; title: string; cwe: string; severity: Severity; rationale: string; pattern: RegExp; languages?: string[]; context?: RegExp }

const RULES: Rule[] = [
  { id: 'dangerous-dynamic-code', title: 'Dynamic code execution', cwe: 'CWE-95', severity: 'high', rationale: 'Dynamic evaluation can turn attacker-controlled data into code execution.', pattern: /\beval\s*\(|\bnew\s+Function\s*\(/, languages: ['javascript', 'typescript'], context: /(?:req\.|params\.|query\.|body\.|input|user)/i },
  { id: 'shell-command-construction', title: 'Constructed shell command', cwe: 'CWE-78', severity: 'high', rationale: 'A constructed process command needs an attacker-to-shell data-flow review.', pattern: /(?:exec|execSync|spawn|spawnSync|system|popen|subprocess\.(?:run|call|Popen))\s*\([^\n]*(?:\+|`|\$\{|f["'])/i, context: /(?:req\.|params\.|query\.|argv|input|user)/i },
  { id: 'path-traversal-sink', title: 'Request-derived filesystem path', cwe: 'CWE-22', severity: 'medium', rationale: 'A filesystem sink receives request-derived data and needs canonical containment validation.', pattern: /(?:readFile|writeFile|createReadStream|createWriteStream|sendFile|open)\s*\([^\n]*(?:req\.|params\.|query\.|body\.|input)/i },
  { id: 'tls-verification-disabled', title: 'TLS verification disabled', cwe: 'CWE-295', severity: 'high', rationale: 'TLS certificate verification is explicitly disabled.', pattern: /(?:rejectUnauthorized\s*:\s*false|verify\s*=\s*False|CURLOPT_SSL_VERIFYPEER\s*,\s*(?:false|0)|InsecureSkipVerify\s*:\s*true)/ },
  { id: 'hardcoded-secret-marker', title: 'Likely hardcoded credential', cwe: 'CWE-798', severity: 'medium', rationale: 'A likely credential literal appears in source and should be moved to managed secret storage.', pattern: /(?:api[_-]?key|secret|password|token|private[_-]?key)\s*[:=]\s*["'][^"']{8,}["']/i },
  { id: 'unsafe-deserialization', title: 'Unsafe deserialization', cwe: 'CWE-502', severity: 'high', rationale: 'Deserialization of untrusted data can create code execution or object-injection paths.', pattern: /(?:pickle\.loads|yaml\.load\s*\([^\n]*(?!SafeLoader)|ObjectInputStream\s*\(|unserialize\s*\()/i, context: /(?:request|req\.|body|input|message|payload)/i },
  { id: 'ssrf-request-sink', title: 'Request-derived outbound request', cwe: 'CWE-918', severity: 'medium', rationale: 'An outbound request appears to use request-derived input and needs destination allowlisting.', pattern: /(?:fetch|axios\.(?:get|post|request)|requests\.(?:get|post|request)|http\.request)\s*\([^\n]*(?:req\.|params\.|query\.|body\.|input)/i },
  { id: 'weak-randomness-security', title: 'Predictable randomness in security context', cwe: 'CWE-330', severity: 'medium', rationale: 'A non-cryptographic random source appears near a security-sensitive token or secret.', pattern: /(?:Math\.random\s*\(|random\.random\s*\()/, context: /(?:token|secret|session|password|reset|nonce)/i },
  { id: 'sql-injection-query-construction', title: 'Constructed SQL query', cwe: 'CWE-89', severity: 'high', rationale: 'A database query appears to construct SQL syntax from request-derived input.', pattern: /(?:query|execute|raw)\s*\([^\n]*(?:req\.|params\.|query\.|body\.|input|\+|\$\{)/i, context: /(?:select|insert|update|delete|from|where)/i },
  { id: 'xml-external-entity-risk', title: 'Potential unsafe XML parser', cwe: 'CWE-611', severity: 'high', rationale: 'An XML parser factory or parser call needs explicit external-entity hardening.', pattern: /(?:DocumentBuilderFactory\.newInstance|SAXParserFactory\.newInstance|XMLInputFactory\.newFactory|lxml\.etree\.parse|xml\.etree\.ElementTree\.parse)/ },
  { id: 'insecure-deserialization-java', title: 'Java native deserialization', cwe: 'CWE-502', severity: 'high', rationale: 'ObjectInputStream deserializes a potentially attacker-controlled object graph.', pattern: /\.readObject\s*\(\)|new\s+ObjectInputStream\s*\(/ },
  { id: 'jwt-verification-disabled', title: 'JWT verification disabled', cwe: 'CWE-347', severity: 'high', rationale: 'JWT signature or algorithm verification is disabled or accepts an unsafe configuration.', pattern: /(?:verify_signature\s*[:=]\s*False|algorithms\s*=\s*\[?['"]none|jwt\.decode\s*\([^\n]*(?:verify\s*[:=]\s*false))/i },
  { id: 'cors-wildcard-credentials', title: 'Credentialed wildcard CORS', cwe: 'CWE-942', severity: 'medium', rationale: 'Credentialed CORS with a wildcard or reflected origin can expose authenticated data cross-origin.', pattern: /(?:Access-Control-Allow-Origin\s*['":=]+\s*['"]\*|origin\s*:\s*true)[^\n]*(?:credentials\s*:\s*true|Access-Control-Allow-Credentials)/i },
  { id: 'missing-authorization-route', title: 'Potential unprotected state-changing route', cwe: 'CWE-862', severity: 'medium', rationale: 'A state-changing route is declared without an apparent authorization middleware in its local declaration.', pattern: /\.(?:post|put|patch|delete)\s*\(\s*['"][^'"]+['"]\s*,\s*(?:async\s*)?\(?\s*(?:req|request|ctx)/i },
  { id: 'prototype-pollution-merge', title: 'Unsafe object merge from request data', cwe: 'CWE-1321', severity: 'medium', rationale: 'Request-derived object data reaches a generic merge/assignment primitive and needs prototype-key filtering.', pattern: /(?:Object\.assign|lodash\.merge|merge)\s*\([^\n]*(?:req\.|params\.|query\.|body\.|input)/i },
]

function languageFor(file: string): string {
  return ({ '.js': 'javascript', '.jsx': 'javascript', '.mjs': 'javascript', '.cjs': 'javascript', '.ts': 'typescript', '.tsx': 'typescript', '.py': 'python', '.go': 'go', '.java': 'java', '.php': 'php', '.rb': 'ruby', '.rs': 'rust', '.sh': 'shell', '.bash': 'shell', '.c': 'c', '.cc': 'cpp', '.cpp': 'cpp', '.cs': 'csharp' } as Record<string, string>)[extname(file)] ?? 'text'
}

function hash(value: string): string { return createHash('sha256').update(value).digest('hex') }
function isContained(root: string, candidate: string): boolean { return candidate === root || candidate.startsWith(root + sep) }
function location(file: string, line: number, excerpt: string, role: 'root_control' = 'root_control'): { file: string; line: number; excerpt: string; role: 'root_control' } { return { file, line, excerpt: excerpt.trim().slice(0, 240), role } }

async function collectFiles(root: string, limits: ScanLimits): Promise<{ files: string[]; skipped: number; complete: boolean }> {
  const files: string[] = []; let skipped = 0; let complete = true
  const visit = async (directory: string): Promise<void> => {
    let entries
    try { entries = await readdir(directory, { withFileTypes: true }) } catch { skipped++; complete = false; return }
    for (const entry of entries.sort((a, b) => a.name.localeCompare(b.name))) {
      if (files.length >= limits.maxFiles) { complete = false; return }
      const target = join(directory, entry.name)
      if (entry.isSymbolicLink()) { skipped++; continue }
      if (entry.isDirectory()) { if (IGNORED_DIRECTORIES.has(entry.name)) skipped++; else await visit(target); continue }
      if (!entry.isFile() || !TEXT_EXTENSIONS.has(extname(entry.name))) continue
      const details = await stat(target)
      if (details.size <= limits.maxFileBytes) files.push(target); else skipped++
    }
  }
  await visit(root)
  return { files, skipped, complete }
}

function analyzeText(root: string, file: string, content: string, pass: string, onlyRules?: Set<string>): { candidates: Candidate[]; receipts: RuleReceipt[] } {
  const rel = relative(root, file); const language = languageFor(file); const lines = content.split(/\r?\n/); const candidates: Candidate[] = []; const receipts: RuleReceipt[] = []
  for (const rule of RULES) {
    if (onlyRules && !onlyRules.has(rule.id)) continue
    if (rule.languages && !rule.languages.includes(language)) continue
    let matches = 0
    for (const [index, text] of lines.entries()) {
      rule.pattern.lastIndex = 0
      if (!rule.pattern.test(text)) continue
      matches++
      const nearby = lines.slice(Math.max(0, index - 3), Math.min(lines.length, index + 4)).join('\n')
      const contextMatch = rule.context?.test(nearby) ?? false
      const excerpt = text.trim().slice(0, 240)
      candidates.push({ rule: rule.id, severity: rule.severity, file: rel, line: index + 1, excerpt, rationale: rule.rationale, cwe: rule.cwe, evidence: [{ kind: 'pattern', detail: `${pass} matched ${rule.id}.`, location: location(rel, index + 1, excerpt) }, ...(contextMatch ? [{ kind: 'context' as const, detail: 'Nearby source contains a request/input marker; reachability still requires review.' }] : [])] })
    }
    receipts.push({ ruleId: rule.id, pass, matches })
  }
  return { candidates, receipts }
}

export async function assessDirectory(directory: string, limits: ScanLimits, deep = false): Promise<ScanResult> {
  const root = resolve(directory); const { files, skipped, complete } = await collectFiles(root, limits); const candidates: Candidate[] = []; const ruleReceipts: RuleReceipt[] = []; const fileReceipts: FileReceipt[] = []; const policyFiles: string[] = []; const modules: JavaScriptModule[] = []; const pythonModules: Array<{ file: string; source: string }> = []; const goModules: Array<{ file: string; source: string }> = []; const structuredModules: Record<StructuredLanguage, Array<{ file: string; source: string }>> = { java: [], csharp: [], php: [], ruby: [], c: [], cpp: [] }; const passes = deep ? [['baseline', undefined], ['injection', new Set(['dangerous-dynamic-code', 'shell-command-construction', 'unsafe-deserialization'])], ['boundaries', new Set(['path-traversal-sink', 'ssrf-request-sink', 'tls-verification-disabled', 'weak-randomness-security', 'hardcoded-secret-marker'])]] as const : [['baseline', undefined]] as const
  for (const file of files) {
    const content = await readFile(file, 'utf8'); const rel = relative(root, file)
    fileReceipts.push({ path: rel, bytes: Buffer.byteLength(content, 'utf8'), sha256: hash(content), language: languageFor(file) })
    if (/(?:^|\/)SECURITY\.md$/i.test(rel)) policyFiles.push(rel)
    for (const [pass, ruleSet] of passes) { const analyzed = analyzeText(root, file, content, pass, ruleSet); candidates.push(...analyzed.candidates); ruleReceipts.push(...analyzed.receipts) }
    if (['.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx'].includes(extname(file))) {
      const ast = analyzeJavaScriptAst(content, rel)
      candidates.push(...ast.candidates)
      modules.push({ file: rel, source: content })
      ruleReceipts.push({ ruleId: 'ast.local-taint', pass: 'semantic', matches: ast.candidates.length })
      if (ast.parseError) ruleReceipts.push({ ruleId: 'ast.parse-error', pass: 'semantic', matches: 1 })
    }
    if (extname(file) === '.py') { const semantic = analyzePythonFlow(content, rel); candidates.push(...semantic); pythonModules.push({ file: rel, source: content }); ruleReceipts.push({ ruleId: 'python.local-taint', pass: 'semantic', matches: semantic.length }) }
    if (extname(file) === '.go') { const semantic = analyzeGoFlow(content, rel); candidates.push(...semantic); goModules.push({ file: rel, source: content }); ruleReceipts.push({ ruleId: 'go.local-taint', pass: 'semantic', matches: semantic.length }) }
    const structured = ({ '.java': 'java', '.cs': 'csharp', '.php': 'php', '.rb': 'ruby', '.c': 'c', '.cc': 'cpp', '.cpp': 'cpp' } as Record<string, StructuredLanguage>)[extname(file)]
    if (structured) structuredModules[structured].push({ file: rel, source: content })
  }
  const moduleGraph = analyzeJavaScriptModuleGraph(modules)
  candidates.push(...moduleGraph.candidates)
  ruleReceipts.push({ ruleId: 'ast.cross-module-taint', pass: 'semantic', matches: moduleGraph.candidates.length })
  const pythonGraph = analyzePythonModuleGraph(pythonModules)
  candidates.push(...pythonGraph.candidates)
  ruleReceipts.push({ ruleId: 'python.cross-module-taint', pass: 'semantic', matches: pythonGraph.candidates.length })
  const goGraph = analyzeGoPackageGraph(goModules)
  candidates.push(...goGraph.candidates)
  ruleReceipts.push({ ruleId: 'go.cross-file-taint', pass: 'semantic', matches: goGraph.candidates.length })
  for (const language of Object.keys(structuredModules) as StructuredLanguage[]) { const graph = analyzeStructuredFlow(structuredModules[language], language); candidates.push(...graph.candidates); ruleReceipts.push({ ruleId: `${language}.structured-taint`, pass: 'semantic', matches: graph.candidates.length }) }
  return { root, filesScanned: files.length, filesSkipped: skipped, candidates, receipts: fileReceipts, ruleReceipts, policyFiles, complete }
}

export async function snapshotDigestForDirectory(directory: string, limits: ScanLimits): Promise<string> {
  const result = await assessDirectory(directory, limits)
  const inventory = result.receipts.slice().sort((a, b) => a.path.localeCompare(b.path)).map(receipt => `${receipt.path}\0${receipt.sha256}`).join('\n')
  return `dsh-security-suite-snapshot/v1:sha256:${sha256(inventory)}`
}

function slug(value: string): string { return value.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '') || 'root-control' }

function candidateToFinding(candidate: Candidate): Finding {
  const fingerprint = hash(`${candidate.rule}:${candidate.file}:${candidate.excerpt.replace(/\s+/g, ' ')}`)
  const hasContext = candidate.evidence.some(item => item.kind === 'context')
  const confidence: Confidence = hasContext && candidate.rule === 'tls-verification-disabled' ? 'medium' : 'low'
  const anchor = slug(`${candidate.file}-${candidate.excerpt}`)
  const candidateIdentifier = candidateId(candidate.rule, candidate.file, candidate.line)
  return { id: findingId(candidate.rule, anchor), candidateId: candidateIdentifier, fingerprint, ruleId: candidate.rule.replaceAll('-', '.'), identity: { anchor, instance: slug(`${candidate.file}-${candidate.line}`) }, title: candidate.rule.replaceAll('-', ' '), severity: candidate.severity, confidence, cwe: candidate.cwe, status: 'open', disposition: 'discovered', locations: [location(candidate.file, candidate.line, candidate.excerpt)], rootCause: candidate.rationale, validation: 'Discovery-only candidate. Static evidence must establish attacker control, a broken control or sensitive sink, and impact before reportability.', attackPath: 'Not established.', impact: 'Not established.', remediation: 'Review the data flow and apply a context-appropriate safe API, validation, authorization, or containment control.', counterevidence: 'No control analysis has been completed.', evidence: candidate.evidence, ledger: [{ at: new Date().toISOString(), phase: 'discovery', disposition: 'discovered', summary: `Native rule ${candidate.rule} matched ${candidate.file}:${candidate.line}.` }] }
}

function reduceCandidates(candidates: Candidate[]): Finding[] {
  const byFingerprint = new Map<string, Finding>()
  for (const candidate of candidates) {
    const finding = candidateToFinding(candidate)
    const mergeKey = `${finding.ruleId}:${finding.locations[0].file}:${finding.locations[0].line}`
    const existing = [...byFingerprint.values()].find(item => `${item.ruleId}:${item.locations[0].file}:${item.locations[0].line}` === mergeKey)
    if (existing) { existing.evidence.push(...finding.evidence); if (finding.evidence.some(item => item.detail.startsWith('AST resolved'))) existing.rootCause = finding.rootCause }
    else byFingerprint.set(finding.fingerprint, finding)
  }
  return [...byFingerprint.values()].sort((a, b) => a.locations[0].file.localeCompare(b.locations[0].file) || a.locations[0].line - b.locations[0].line)
}

function activity(phase: ScanActivity['phase'], message: string): ScanActivity { return { at: new Date().toISOString(), phase, message } }

async function exists(path: string): Promise<boolean> { try { await access(path); return true } catch { return false } }

async function resolvePolicyGuidance(root: string): Promise<{ files: string[]; text: string }> {
  const files: string[] = []; const values: string[] = []; const chain: string[] = []; let current = resolve(root)
  while (true) { chain.push(current); const parent = resolve(current, '..'); if (parent === current) break; current = parent }
  for (const directory of chain.reverse()) {
    const policy = join(directory, 'SECURITY.md')
    if (await exists(policy)) { files.push(relative(root, policy) || 'SECURITY.md'); values.push(`# ${relative(root, policy) || 'SECURITY.md'}\n\n${await readFile(policy, 'utf8')}`) }
  }
  return { files, text: values.length ? values.join('\n\n---\n\n') : 'No SECURITY.md policy guidance was found. Apply least privilege, explicit trust boundaries, and fail-closed security controls.' }
}

const PROJECT_FILES = new Set(['package.json', 'package-lock.json', 'pnpm-lock.yaml', 'yarn.lock', 'pyproject.toml', 'requirements.txt', 'pipfile', 'go.mod', 'cargo.toml', 'pom.xml', 'build.gradle', 'build.gradle.kts', 'composer.json', 'gemfile', 'makefile', 'dockerfile'])

function suggestedCommands(projectFiles: string[]): string[] {
  const names = new Set(projectFiles.map(path => basename(path).toLowerCase()))
  if (names.has('package.json')) return ['npm test', 'npm run build']
  if (names.has('pyproject.toml') || names.has('requirements.txt')) return ['python -m pytest']
  if (names.has('go.mod')) return ['go test ./...']
  if (names.has('cargo.toml')) return ['cargo test']
  if (names.has('pom.xml')) return ['./mvnw test']
  if (names.has('build.gradle') || names.has('build.gradle.kts')) return ['./gradlew test']
  return []
}

async function nativePreflight(root: string, receipts: FileReceipt[], inventoryComplete: boolean, stateDirectory: string): Promise<Preflight> {
  const checks: Preflight['checks'] = []
  try { const details = await stat(root); checks.push({ id: 'target-directory', status: details.isDirectory() ? 'pass' : 'blocked', detail: details.isDirectory() ? 'Target is a readable directory.' : 'Target is not a directory.' }) } catch { checks.push({ id: 'target-directory', status: 'blocked', detail: 'Target directory cannot be read.' }) }
  const projectFiles = receipts.map(item => item.path).filter(path => PROJECT_FILES.has(basename(path).toLowerCase())).sort()
  const languages = [...new Set(receipts.map(item => item.language).filter(language => language !== 'text'))].sort()
  checks.push({ id: 'source-inventory', status: receipts.length === 0 ? 'warn' : inventoryComplete ? 'pass' : 'warn', detail: receipts.length === 0 ? 'No eligible source files were found.' : `${receipts.length} eligible source files were inventoried${inventoryComplete ? '.' : '; configured limits or unreadable paths reduced coverage.'}` })
  checks.push({ id: 'project-manifest', status: projectFiles.length ? 'pass' : 'warn', detail: projectFiles.length ? `Detected ${projectFiles.join(', ')}.` : 'No recognized project manifest was found; test commands cannot be inferred.' })
  const stateDir = getStateDir(stateDirectory)
  try { await mkdir(stateDir, { recursive: true }); await access(stateDir); checks.push({ id: 'state-directory', status: 'pass', detail: 'External state directory is writable for receipts and reports.' }) } catch { checks.push({ id: 'state-directory', status: 'blocked', detail: 'External state directory is not writable; choose stateDir or DSH_SECURITY_SUITE_STATE_DIR.' }) }
  checks.push({ id: 'worker-orchestration', status: 'warn', detail: 'Investigation tasks are durable and claimable by DSH reviewers. This plugin does not assume a private subagent API.' })
  const status = checks.some(check => check.status === 'blocked') ? 'blocked' : checks.some(check => check.status === 'warn') ? 'warn' : 'ready'
  return { status, checks, projectFiles, languages, suggestedCommands: suggestedCommands(projectFiles) }
}

export async function generateSourceThreatModel(directory: string, limits: ScanLimits, context = ''): Promise<string> {
  const result = await assessDirectory(directory, limits)
  const cited: Array<{ path: string; signal: string }> = []
  const signals = { routes: 0, requestInputs: 0, auth: 0, outbound: 0, storage: 0, secrets: 0, parsers: 0 }
  for (const receipt of result.receipts) {
    const source = await readFile(join(result.root, receipt.path), 'utf8')
    const note = (signal: keyof typeof signals, pattern: RegExp, label: string): void => { if (pattern.test(source)) { signals[signal]++; cited.push({ path: receipt.path, signal: label }) } }
    note('routes', /\b(?:app|router)\.(?:get|post|put|patch|delete)\s*\(|@(?:app|router)\.(?:get|post|put|patch|delete)|\b(?:Flask|FastAPI)\s*\(/i, 'request-handling or route declaration')
    note('requestInputs', /\b(?:req|request|ctx\.request)\.(?:body|query|params|headers|cookies)|\binput\s*\(/i, 'caller-controlled input access')
    note('auth', /\b(?:auth(?:enticate|orize|entication|orization)?|requireAuth|isAdmin|passport|permission|rbac)\b/i, 'authentication or authorization control')
    note('outbound', /\b(?:fetch|axios|requests\.(?:get|post|request)|http\.request|https\.request)\s*\(/i, 'outbound network operation')
    note('storage', /\b(?:readFile|writeFile|createReadStream|createWriteStream|open|query|execute|save|delete)\s*\(/i, 'filesystem or data-store operation')
    note('secrets', /\b(?:secret|password|api[_-]?key|token|private[_-]?key)\b/i, 'credential or secret handling')
    note('parsers', /\b(?:JSON\.parse|yaml\.load|pickle\.loads|unserialize|XML|DocumentBuilderFactory)\b/i, 'structured-data parser or deserialization')
  }
  const evidence = cited.length ? cited.slice(0, 30).map(item => `- \`${item.path}\`: ${item.signal}.`).join('\n') : '- No high-confidence architecture signal was detected in eligible source; verify deployment and entrypoints manually.'
  const lines = ['# Source-Evidenced Threat Model', '', '## Scope', `- Target: \`${basename(result.root) || result.root}\`.`, `- Reviewed source files: ${result.filesScanned}${result.complete ? '.' : ' (coverage is partial).'}`, context.trim() ? `- Supplied context: ${context.trim()}` : '- Supplied context: none.', '', '## Evidence', evidence, '', '## Assets and Security Objectives', `- Protect credentials and tokens${signals.secrets ? ' observed in source.' : '; source evidence did not identify their storage location.'}`, `- Preserve integrity of filesystem and data-store operations${signals.storage ? ' observed in source.' : '.'}`, signals.auth ? '- Enforce authorization decisions consistently at every protected operation.' : '- Verify where authorization decisions are enforced; no clear local control signal was found.', '', '## Actors and Trust Boundaries', signals.routes || signals.requestInputs ? '- Remote callers can cross the request boundary into application handlers; validate identity, tenant, and input ownership at that boundary.' : '- Confirm external callers and entrypoints; no route or request-input marker was detected.', signals.outbound ? '- Outbound network operations form a second boundary; constrain destination, protocol, and credentials.' : '', signals.parsers ? '- Structured input parsing is a trust boundary; use safe parser modes and bounded resource handling.' : '', '', '## Attack Surfaces', `- Request/route signals: ${signals.routes}; caller-input signals: ${signals.requestInputs}; outbound-operation signals: ${signals.outbound}; parser signals: ${signals.parsers}.`, '- Review sensitive sinks found by the native discovery passes and retain deployment-specific assumptions as open questions.', '', '## Assumptions and Open Questions', '- Deployment topology, authentication provider, tenant model, and production reachability require confirmation from project owners or runtime configuration.', '- This model is generated from local source evidence and does not infer unobserved services.']
  return lines.filter((line, index, all) => line || index === 0 || all[index - 1] !== '').join('\n') + '\n'
}

async function targetSnapshot(root: string, receipts: FileReceipt[]): Promise<TargetSnapshot> {
  const inventory = receipts.slice().sort((a, b) => a.path.localeCompare(b.path)).map(receipt => `${receipt.path}\0${receipt.sha256}`).join('\n')
  const digest = `dsh-security-suite-snapshot/v1:sha256:${sha256(inventory)}`
  try {
    const [{ stdout: gitRoot }, { stdout: revision }, remote] = await Promise.all([
      execFileAsync('git', ['rev-parse', '--show-toplevel'], { cwd: root, encoding: 'utf8' }),
      execFileAsync('git', ['rev-parse', '--verify', 'HEAD'], { cwd: root, encoding: 'utf8' }),
      execFileAsync('git', ['config', '--get', 'remote.origin.url'], { cwd: root, encoding: 'utf8' }).catch(() => ({ stdout: '' })),
    ])
    const repository = resolve(gitRoot.trim()); const cleanRemote = remote.stdout.trim().replace(/^[^@]+@/, '').replace(/[?#].*$/, '')
    return { kind: 'git_worktree', targetId: `dsh-security-suite-target/v1:sha256:${sha256(cleanRemote || repository)}`, displayName: basename(repository) || repository, revision: revision.trim(), snapshotDigest: digest }
  } catch {
    return { kind: 'directory_snapshot', targetId: `dsh-security-suite-target/v1:sha256:${sha256(resolve(root))}`, displayName: basename(root) || root, snapshotDigest: digest }
  }
}

function validateCandidate(finding: Finding): CandidateDisposition {
  const hasInputContext = finding.evidence.some(item => item.kind === 'context')
  const direct = finding.ruleId === 'tls.verification.disabled' || (hasInputContext && ['dangerous.dynamic.code', 'shell.command.construction', 'path.traversal.sink', 'unsafe.deserialization', 'ssrf.request.sink'].includes(finding.ruleId))
  const disposition: CandidateDisposition = direct ? 'reportable' : 'suppressed'
  const conclusion = direct ? 'reportable' : 'suppressed'
  const entry = hasInputContext ? 'Nearby source contains an input/request marker.' : 'No attacker-controlled entry point was established by the local static pass.'
  const root = `${finding.locations[0].file}:${finding.locations[0].line} (${finding.ruleId})`
  finding.disposition = disposition
  finding.validation = direct ? `Static validation established a plausible path from request-derived input or an explicitly unsafe control to ${root}. Runtime reachability remains unexecuted.` : `Suppressed after static validation: ${entry}`
  finding.impact = direct ? 'The vulnerable control could expose the security boundary described by the rule family if the observed input path is reachable.' : 'No concrete attacker-controlled path was established.'
  finding.counterevidence = direct ? 'No equivalent local control was detected in the reviewed context. Runtime behavior was not executed.' : entry
  finding.confidence = direct && finding.ruleId === 'tls.verification.disabled' ? 'high' : direct ? 'medium' : 'low'
  finding.validationRecord = { method: 'static', conclusion, attacker: direct ? 'An unauthenticated or low-privilege caller able to influence the request-derived value.' : 'Not established.', entryPoint: entry, trustBoundary: 'Application request/input boundary to a sensitive operation.', rootControl: root, sink: finding.locations[0].excerpt, impact: finding.impact, directEvidence: finding.evidence.map(item => item.detail).join(' '), counterevidence: finding.counterevidence, limitations: 'No runtime execution or package build was performed by the native scanner.', confidence: finding.confidence, recordedAt: new Date().toISOString() }
  finding.ledger.push({ at: new Date().toISOString(), phase: 'validation', disposition, summary: finding.validation })
  return disposition
}

function analyzeAttackPath(finding: Finding): void {
  if (finding.disposition !== 'reportable') return
  const location = finding.locations[0]
  finding.attackPath = `An attacker influences the observed input path, reaches ${location.file}:${location.line}, and triggers ${finding.ruleId}; the concrete outcome depends on the deployment path and missing control.`
  finding.attackPathRecord = { attacker: 'Caller able to control the identified input or invoke the affected feature.', entryPoint: finding.validationRecord?.entryPoint ?? 'Static source context.', preconditions: 'The affected code path must be reachable in deployment.', dataflow: `${finding.validationRecord?.entryPoint ?? 'Input'} -> ${finding.validationRecord?.rootControl ?? location.file} -> ${finding.validationRecord?.sink ?? location.excerpt}`, outcome: finding.impact, severityRationale: `${finding.severity} severity is provisional and reflects the sensitive operation with static reachability evidence.`, changeConditions: 'Increase confidence after a targeted test or runtime proof; lower severity if a complete upstream control prevents attacker influence.', recordedAt: new Date().toISOString() }
  finding.evidence.push({ kind: 'attack_path', detail: finding.attackPath, location })
  finding.ledger.push({ at: new Date().toISOString(), phase: 'attack_path', disposition: 'reportable', summary: finding.attackPath })
}

export async function runScan(directory: string, limits: ScanLimits, mode: 'standard' | 'deep', threatModel: string, scopeRequested = false, stateDirectory = '', automaticValidation = true): Promise<ScanRecord> {
  const deep = mode === 'deep'; const now = new Date().toISOString(); const result = await assessDirectory(directory, limits, deep); const [policy, preflight, generatedThreatModel] = await Promise.all([resolvePolicyGuidance(result.root), nativePreflight(result.root, result.receipts, result.complete, stateDirectory), threatModel.trim() ? Promise.resolve('') : generateSourceThreatModel(result.root, limits)])
  const findings = reduceCandidates(result.candidates); if (automaticValidation) { for (const finding of findings) validateCandidate(finding); for (const finding of findings) analyzeAttackPath(finding) }
  const snapshot = await targetSnapshot(result.root, result.receipts); const id = createScanId(); const closed = findings.every(finding => finding.ledger.some(row => row.phase === 'validation') && (finding.disposition !== 'reportable' || finding.ledger.some(row => row.phase === 'attack_path'))); const complete = result.complete && closed
  const record: ScanRecord = { schemaVersion: 3, id, mode, lifecycle: automaticValidation ? complete ? 'completed' : 'incomplete' : 'validation', target: result.root, targetSnapshot: snapshot, createdAt: now, completedAt: automaticValidation ? new Date().toISOString() : undefined, threatModel: threatModel.trim() || generatedThreatModel, policyGuidance: policy.text, preflight, findings, coverage: { mode: deep && !scopeRequested ? 'deep_repository' : scopeRequested ? 'scoped_path' : 'repository', reviewedFiles: result.filesScanned, skippedFiles: result.filesSkipped, exclusions: [...IGNORED_DIRECTORIES], complete: result.complete, receipts: result.receipts, ruleReceipts: result.ruleReceipts, policyFiles: [...new Set([...result.policyFiles, ...policy.files])], surfaces: result.ruleReceipts.filter(receipt => receipt.pass === 'baseline').map(receipt => ({ id: receipt.ruleId, label: receipt.ruleId, disposition: automaticValidation && findings.some(finding => finding.ruleId === receipt.ruleId && finding.disposition === 'reportable') ? 'reported' : automaticValidation && findings.some(finding => finding.ruleId === receipt.ruleId) ? 'rejected' : 'needs_follow_up', receiptRefs: ['artifacts/02_discovery/finding_discovery_report.md'], riskArea: receipt.ruleId })), deferred: result.complete ? [] : [{ id: 'coverage-limits', reason: 'File limit, unreadable path, or file-size limit prevented complete review.' }] }, activity: [activity('preflight', `Native preflight ${preflight.status}.`), activity('inventory', `Inventoried ${result.filesScanned} eligible source files.`), activity('policy', policy.files.length ? `Resolved policy files: ${policy.files.join(', ')}.` : 'No SECURITY.md policy file found in the scan scope.'), activity('threat_model', threatModel.trim() ? 'Recorded user-supplied threat model.' : 'Generated source-evidenced threat model.'), activity('discovery', `Ran ${deep ? 3 : 1} native discovery pass(es) and collected ${result.candidates.length} observations.`), activity('reduction', `Reduced observations to ${findings.length} unique candidates.`), ...(automaticValidation ? [activity('validation', `Recorded static validation receipts for ${findings.length} candidates.`), activity('attack_path', `Recorded attack-path receipts for ${findings.filter(finding => finding.disposition === 'reportable').length} reportable candidates.`), activity('complete', complete ? 'Scan completed with closed candidate ledgers.' : 'Scan incomplete because coverage or candidate closure is incomplete.')] : [activity('validation', 'Scan is awaiting structured validation receipts for each candidate.')])], tasks: automaticValidation ? [] : findings.map(finding => ({ id: `task_${sha256(`${id}:${finding.candidateId}:validation`).slice(0, 24)}`, candidateId: finding.candidateId, phase: 'validation' as const, focus: `Validate ${finding.title}: establish attacker, entrypoint, trust boundary, root control, sink, impact, and counterevidence.`, status: 'pending' as const })), recipe: { mode, scopeRequested, passes: deep ? ['baseline', 'injection', 'boundaries'] : ['baseline'] }, artifacts: { directory: scanArtifactDir(getStateDir(stateDirectory), result.root, id) }, seal: '' }
  record.seal = sealScan(record); return record
}

export function resolveSafeTarget(workspace: string, requested: string | undefined): string { const root = resolve(workspace); const target = resolve(root, requested ?? '.'); if (!isContained(root, target)) throw new Error('Scan target must remain inside the current workspace.'); return target }

export async function reviewGitDiff(workspace: string, base: string | undefined): Promise<{ mode: string; diff: string; truncated: boolean }> {
  if (base !== undefined && (!/^[A-Za-z0-9][A-Za-z0-9._/-]*$/.test(base) || base.startsWith('-'))) throw new Error('Git base ref contains unsupported characters.')
  const args = ['diff', '--no-ext-diff', '--unified=20']; const mode = base === undefined ? 'working-tree' : `base:${base}`; if (base !== undefined) args.push(`${base}...HEAD`)
  const { stdout } = await execFileAsync('git', args, { cwd: resolve(workspace), encoding: 'utf8', maxBuffer: MAX_DIFF_BYTES + 1 }); return { mode, diff: stdout.slice(0, MAX_DIFF_BYTES), truncated: Buffer.byteLength(stdout, 'utf8') > MAX_DIFF_BYTES }
}

export async function runDiffScan(workspace: string, base: string | undefined, threatModel: string, stateDirectory = ''): Promise<ScanRecord> {
  const review = await reviewGitDiff(workspace, base); const candidates: Candidate[] = []; let currentFile = ''; let newLine = 0
  for (const diffLine of review.diff.split(/\r?\n/)) {
    if (diffLine.startsWith('+++ b/')) { currentFile = diffLine.slice(6); newLine = 0; continue }
    const hunk = /^@@ -\d+(?:,\d+)? \+(\d+)/.exec(diffLine); if (hunk) { newLine = Number(hunk[1]); continue }
    if (diffLine.startsWith('+') && !diffLine.startsWith('+++')) { const analyzed = analyzeText(resolve(workspace), join(resolve(workspace), currentFile || 'unknown'), diffLine.slice(1), 'diff'); for (const candidate of analyzed.candidates) { candidate.file = currentFile || 'unknown'; candidate.line = newLine; candidate.evidence[0].location = location(candidate.file, newLine, candidate.excerpt); candidates.push(candidate) }; newLine++; continue }
    if (!diffLine.startsWith('-')) newLine++
  }
  const root = resolve(workspace); const now = new Date().toISOString(); const findings = reduceCandidates(candidates); for (const finding of findings) validateCandidate(finding); for (const finding of findings) analyzeAttackPath(finding); const policy = await resolvePolicyGuidance(root); const id = createScanId(); const complete = !review.truncated && findings.every(finding => finding.ledger.some(row => row.phase === 'validation') && (finding.disposition !== 'reportable' || finding.ledger.some(row => row.phase === 'attack_path'))); const [head, baseRevision, remote] = await Promise.all([execFileAsync('git', ['rev-parse', '--verify', 'HEAD'], { cwd: root, encoding: 'utf8' }).catch(() => ({ stdout: '' })), base ? execFileAsync('git', ['rev-parse', '--verify', base], { cwd: root, encoding: 'utf8' }).catch(() => ({ stdout: '' })) : Promise.resolve({ stdout: '' }), execFileAsync('git', ['config', '--get', 'remote.origin.url'], { cwd: root, encoding: 'utf8' }).catch(() => ({ stdout: '' }))]); const remoteValue = remote.stdout.trim().replace(/^[^@]+@/, '').replace(/[?#].*$/, ''); const record: ScanRecord = { schemaVersion: 3, id, mode: 'diff', lifecycle: complete ? 'completed' : 'incomplete', target: root, targetSnapshot: { kind: 'git_diff', targetId: `dsh-security-suite-target/v1:sha256:${sha256(remoteValue || root)}`, displayName: basename(root) || root, baseRevision: baseRevision.stdout.trim() || undefined, headRevision: head.stdout.trim() || undefined, snapshotDigest: `dsh-security-suite-snapshot/v1:sha256:${sha256(review.diff)}` }, createdAt: now, completedAt: new Date().toISOString(), threatModel: threatModel || 'Review changed behavior for attacker-controlled inputs, authorization boundaries, and sensitive sinks.', policyGuidance: policy.text, preflight: { status: review.truncated ? 'warn' : 'ready', checks: [{ id: 'git-diff', status: review.truncated ? 'warn' : 'pass', detail: `Reviewed ${review.mode}.` }, { id: 'worker-orchestration', status: 'warn', detail: 'Investigation tasks are durable and claimable by DSH reviewers. This plugin does not assume a private subagent API.' }], projectFiles: [], languages: [], suggestedCommands: [] }, findings, coverage: { mode: 'diff', reviewedFiles: review.diff.split('\ndiff --git ').length - 1, skippedFiles: review.truncated ? 1 : 0, exclusions: review.truncated ? ['diff truncated at 1 MB'] : [], complete, receipts: [], ruleReceipts: [], policyFiles: policy.files, surfaces: [{ id: 'git-diff', label: review.mode, disposition: findings.some(finding => finding.disposition === 'reportable') ? 'reported' : 'no_issue_found', receiptRefs: ['artifacts/02_discovery/finding_discovery_report.md'], riskArea: 'changed-code' }], deferred: review.truncated ? [{ id: 'diff-truncated', reason: 'Diff exceeded the 1 MB safe processing limit.' }] : [] }, activity: [activity('preflight', 'Git diff preflight completed.'), activity('policy', policy.files.length ? `Resolved policy files: ${policy.files.join(', ')}.` : 'No SECURITY.md policy file found in the scan scope.'), activity('discovery', `Analyzed changed lines in ${review.mode}.`), activity('reduction', `Reduced observations to ${findings.length} unique candidates.`), activity('validation', `Recorded static validation receipts for ${findings.length} candidates.`), activity('attack_path', `Recorded attack-path receipts for ${findings.filter(finding => finding.disposition === 'reportable').length} reportable candidates.`), activity('complete', complete ? 'Diff scan completed with closed candidate ledgers.' : 'Diff scan incomplete because the diff was truncated.')], tasks: [], recipe: { mode: 'diff', scopeRequested: true, passes: ['diff'] }, artifacts: { directory: scanArtifactDir(getStateDir(stateDirectory), root, id) }, seal: '' }; record.seal = sealScan(record); return record
}
