import { createHash } from 'node:crypto'
import { access, mkdir, readdir, readFile, stat } from 'node:fs/promises'
import { execFile } from 'node:child_process'
import { basename, dirname, extname, join, relative, resolve, sep } from 'node:path'
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

interface RemovedControlRule { id: string; severity: Severity; cwe: string; rationale: string; pattern: RegExp }

const REMOVED_CONTROL_RULES: RemovedControlRule[] = [
  { id: 'removed-authorization-control', severity: 'high', cwe: 'CWE-862', rationale: 'The patch removes an explicit authentication, authorization, permission, token, or CSRF control. An equivalent replacement was not established in the changed hunk.', pattern: /(?:\b(?:require|ensure|check|enforce)(?:Auth(?:entication|orization)?|Permission|Access)|\b(?:authorize|isAuthorized|hasPermission|verify(?:Token|Jwt|JWT)|authenticate|authMiddleware|csrf(?:Protect|Middleware)|validateCsrf)\b|\.use\s*\(\s*(?:auth|authenticate|authorize))/i },
  { id: 'removed-input-validation-control', severity: 'medium', cwe: 'CWE-20', rationale: 'The patch removes an explicit input validation, parsing, allowlist, or sanitization control. An equivalent replacement was not established in the changed hunk.', pattern: /(?:\b(?:validate(?:Input|Request|Schema)?|sanitize(?:Input)?|parse(?:Async)?|safeParse|allowlist|whitelist|escape(?:Html)?|check(?:Input|Schema)|isValid)\b|schema\.(?:parse|validate)|z\.[A-Za-z_]\w*\s*\()/i },
]

interface CiWorkflowRule { id: string; severity: Severity; cwe: string; rationale: string }

const CI_WORKFLOW_RULES: Record<'untrusted-shell' | 'write-permissions' | 'mutable-action-ref' | 'untrusted-checkout-execution', CiWorkflowRule> = {
  'untrusted-shell': { id: 'ci-untrusted-event-shell', severity: 'high', cwe: 'CWE-78', rationale: 'A GitHub Actions workflow reachable from pull_request_target interpolates pull-request or issue event data into a shell command. A contributor-controlled value can alter the trusted runner command.' },
  'write-permissions': { id: 'ci-pull-request-target-write-permissions', severity: 'high', cwe: 'CWE-269', rationale: 'A pull_request_target workflow receives broad write permissions. Its trusted token must not be exposed to untrusted pull-request data or code.' },
  'mutable-action-ref': { id: 'ci-mutable-action-ref', severity: 'medium', cwe: 'CWE-829', rationale: 'A GitHub Actions workflow uses a mutable action branch reference. The action revision is not immutable and can change after review.' },
  'untrusted-checkout-execution': { id: 'ci-pull-request-target-untrusted-checkout', severity: 'high', cwe: 'CWE-829', rationale: 'A pull_request_target workflow checks out contributor-controlled pull-request code and subsequently runs a command in the same job. The trusted workflow context can execute unreviewed code.' },
}

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
  { id: 'jwt-verification-disabled', title: 'JWT verification disabled', cwe: 'CWE-347', severity: 'high', rationale: 'JWT signature or algorithm verification is disabled or accepts an unsafe configuration.', pattern: /(?:["']?verify_signature["']?\s*[:=]\s*False|algorithms\s*=\s*\[?['"]none|jwt\.decode\s*\([^\n]*(?:verify\s*[:=]\s*false))/i },
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

async function localGoModulePath(root: string, file: string, cache: Map<string, string | undefined>): Promise<string | undefined> {
  let directory = dirname(file); const visited: string[] = []
  while (isContained(root, directory)) {
    if (cache.has(directory)) {
      const value = cache.get(directory)
      for (const path of visited) cache.set(path, value)
      return value
    }
    visited.push(directory)
    try {
      const source = await readFile(join(directory, 'go.mod'), 'utf8')
      const value = /^\s*module\s+([^\s/][^\s]*)\s*$/m.exec(source)?.[1]
      for (const path of visited) cache.set(path, value)
      return value
    } catch { /* Keep searching parent directories inside this scan root. */ }
    if (directory === root) break
    directory = dirname(directory)
  }
  for (const path of visited) cache.set(path, undefined)
  return undefined
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
  const root = resolve(directory); const { files, skipped, complete } = await collectFiles(root, limits); const candidates: Candidate[] = []; const ruleReceipts: RuleReceipt[] = []; const fileReceipts: FileReceipt[] = []; const policyFiles: string[] = []; const modules: JavaScriptModule[] = []; const pythonModules: Array<{ file: string; source: string }> = []; const goModules: Array<{ file: string; source: string; modulePath?: string }> = []; const goModuleCache = new Map<string, string | undefined>(); const structuredModules: Record<StructuredLanguage, Array<{ file: string; source: string }>> = { java: [], csharp: [], php: [], ruby: [], c: [], cpp: [], rust: [] }; const passes = deep ? [['baseline', undefined], ['injection', new Set(['dangerous-dynamic-code', 'shell-command-construction', 'unsafe-deserialization'])], ['boundaries', new Set(['path-traversal-sink', 'ssrf-request-sink', 'tls-verification-disabled', 'weak-randomness-security', 'hardcoded-secret-marker'])]] as const : [['baseline', undefined]] as const
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
    if (extname(file) === '.go') { const semantic = analyzeGoFlow(content, rel); candidates.push(...semantic); goModules.push({ file: rel, source: content, modulePath: await localGoModulePath(root, file, goModuleCache) }); ruleReceipts.push({ ruleId: 'go.local-taint', pass: 'semantic', matches: semantic.length }) }
    const structured = ({ '.java': 'java', '.cs': 'csharp', '.php': 'php', '.rb': 'ruby', '.c': 'c', '.cc': 'cpp', '.cpp': 'cpp', '.rs': 'rust' } as Record<string, StructuredLanguage>)[extname(file)]
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
  const locations = [location(candidate.file, candidate.line, candidate.excerpt), ...candidate.evidence.flatMap(item => item.location ? [item.location] : [])]
  return { id: findingId(candidate.rule, anchor), candidateId: candidateIdentifier, fingerprint, ruleId: candidate.rule.replaceAll('-', '.'), identity: { anchor, instance: slug(`${candidate.file}-${candidate.line}`) }, title: candidate.rule.replaceAll('-', ' '), severity: candidate.severity, confidence, cwe: candidate.cwe, status: 'open', disposition: 'discovered', locations: dedupeLocations(locations), rootCause: candidate.rationale, validation: 'Discovery-only candidate. Static evidence must establish attacker control, a broken control or sensitive sink, and impact before reportability.', attackPath: 'Not established.', impact: 'Not established.', remediation: 'Review the data flow and apply a context-appropriate safe API, validation, authorization, or containment control.', counterevidence: 'No control analysis has been completed.', evidence: candidate.evidence, ledger: [{ at: new Date().toISOString(), phase: 'discovery', disposition: 'discovered', summary: `Native rule ${candidate.rule} matched ${candidate.file}:${candidate.line}.` }] }
}

function dedupeLocations(locations: Finding['locations']): Finding['locations'] {
  const unique = new Map<string, Finding['locations'][number]>()
  for (const item of locations) unique.set(`${item.file}:${item.line}:${item.role ?? 'root_control'}`, item)
  // The first location is the candidate's primary sink/root-control anchor.
  // Preserve it for diff semantics while retaining every later flow location.
  return [...unique.values()]
}

function reduceCandidates(candidates: Candidate[]): Finding[] {
  const byFingerprint = new Map<string, Finding>()
  for (const candidate of candidates) {
    const finding = candidateToFinding(candidate)
    const mergeKey = `${finding.ruleId}:${finding.locations[0].file}:${finding.locations[0].line}`
    const existing = [...byFingerprint.values()].find(item => `${item.ruleId}:${item.locations[0].file}:${item.locations[0].line}` === mergeKey)
    if (existing) { existing.evidence.push(...finding.evidence); existing.locations = dedupeLocations([...existing.locations, ...finding.locations]); if (finding.evidence.some(item => item.detail.startsWith('AST resolved'))) existing.rootCause = finding.rootCause }
    else byFingerprint.set(finding.fingerprint, finding)
  }
  return [...byFingerprint.values()].sort((a, b) => a.locations[0].file.localeCompare(b.locations[0].file) || a.locations[0].line - b.locations[0].line)
}

function activity(phase: ScanActivity['phase'], message: string): ScanActivity { return { at: new Date().toISOString(), phase, message } }

function validationTasks(scanId: string, findings: Finding[]): ScanRecord['tasks'] {
  return findings.map(finding => ({ id: `task_${sha256(`${scanId}:${finding.candidateId}:validation`).slice(0, 24)}`, candidateId: finding.candidateId, phase: 'validation' as const, focus: `Validate ${finding.title}: establish attacker, entrypoint, trust boundary, root control, sink, impact, and counterevidence.`, status: 'pending' as const }))
}

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
    const [{ stdout: gitRoot }, { stdout: revision }, remote, status] = await Promise.all([
      execFileAsync('git', ['rev-parse', '--show-toplevel'], { cwd: root, encoding: 'utf8' }),
      execFileAsync('git', ['rev-parse', '--verify', 'HEAD'], { cwd: root, encoding: 'utf8' }),
      execFileAsync('git', ['config', '--get', 'remote.origin.url'], { cwd: root, encoding: 'utf8' }).catch(() => ({ stdout: '' })),
      execFileAsync('git', ['status', '--porcelain'], { cwd: root, encoding: 'utf8' }),
    ])
    const repository = resolve(gitRoot.trim()); const cleanRemote = remote.stdout.trim().replace(/[?#].*$/, '')
    const github = /^(?:git@github\.com:|ssh:\/\/git@github\.com\/|https:\/\/github\.com\/)([^/\s]+)\/([^/\s]+?)(?:\.git)?\/?$/i.exec(cleanRemote)
    if (!status.stdout.trim() && github) {
      const sourceRepository = `${github[1]}/${github[2]}`
      return { kind: 'git_revision', targetId: `dsh-security-suite-target/v1:sha256:${sha256(sourceRepository)}`, displayName: basename(repository) || repository, revision: revision.trim(), sourceRepository, snapshotDigest: digest }
    }
    return { kind: 'git_worktree', targetId: `dsh-security-suite-target/v1:sha256:${sha256(cleanRemote || repository)}`, displayName: basename(repository) || repository, revision: revision.trim(), snapshotDigest: digest }
  } catch {
    return { kind: 'directory_snapshot', targetId: `dsh-security-suite-target/v1:sha256:${sha256(resolve(root))}`, displayName: basename(root) || root, snapshotDigest: digest }
  }
}

function validateCandidate(finding: Finding): CandidateDisposition {
  const hasInputContext = finding.evidence.some(item => item.kind === 'context')
  const removedControl = ['removed.authorization.control', 'removed.input.validation.control'].includes(finding.ruleId)
  const direct = removedControl || ['tls.verification.disabled', 'ci.untrusted.event.shell', 'ci.pull.request.target.write.permissions', 'ci.mutable.action.ref', 'ci.pull.request.target.untrusted.checkout'].includes(finding.ruleId) || (hasInputContext && ['dangerous.dynamic.code', 'shell.command.construction', 'path.traversal.sink', 'unsafe.deserialization', 'ssrf.request.sink'].includes(finding.ruleId))
  const disposition: CandidateDisposition = direct ? 'reportable' : 'suppressed'
  const conclusion = direct ? 'reportable' : 'suppressed'
  const entry = removedControl ? 'The changed hunk deletes an explicit security control; equivalent replacement remains unproven.' : hasInputContext ? 'Nearby source contains an input/request marker.' : 'No attacker-controlled entry point was established by the local static pass.'
  const root = `${finding.locations[0].file}:${finding.locations[0].line} (${finding.ruleId})`
  finding.disposition = disposition
  finding.validation = direct ? `Static validation established a plausible path from request-derived input or an explicitly unsafe control to ${root}. Runtime reachability remains unexecuted.` : `Suppressed after static validation: ${entry}`
  finding.impact = direct ? 'The vulnerable control could expose the security boundary described by the rule family if the observed input path is reachable.' : 'No concrete attacker-controlled path was established.'
  finding.counterevidence = direct ? 'No equivalent local control was detected in the reviewed context. Runtime behavior was not executed.' : entry
  finding.confidence = direct && finding.ruleId === 'tls.verification.disabled' ? 'high' : direct ? 'medium' : 'low'
  finding.validationRecord = { method: 'static', conclusion, attacker: direct ? removedControl ? 'A caller who can reach the affected route or operation after the removed control.' : 'An unauthenticated or low-privilege caller able to influence the request-derived value.' : 'Not established.', entryPoint: entry, trustBoundary: 'Application request/input boundary to a sensitive operation.', rootControl: root, sink: finding.locations[0].excerpt, impact: finding.impact, directEvidence: finding.evidence.map(item => item.detail).join(' '), counterevidence: finding.counterevidence, limitations: 'No runtime execution or package build was performed by the native scanner.', confidence: finding.confidence, sourceReferences: finding.locations.map(location => ({ file: location.file, line: location.line, role: location.role ?? 'root_control' })), recordedAt: new Date().toISOString() }
  finding.ledger.push({ at: new Date().toISOString(), phase: 'validation', disposition, summary: finding.validation })
  return disposition
}

function analyzeAttackPath(finding: Finding): void {
  if (finding.disposition !== 'reportable') return
  const location = finding.locations[0]
  finding.attackPath = `An attacker influences the observed input path, reaches ${location.file}:${location.line}, and triggers ${finding.ruleId}; the concrete outcome depends on the deployment path and missing control.`
  finding.attackPathRecord = { attacker: 'Caller able to control the identified input or invoke the affected feature.', entryPoint: finding.validationRecord?.entryPoint ?? 'Static source context.', preconditions: 'The affected code path must be reachable in deployment.', dataflow: `${finding.validationRecord?.entryPoint ?? 'Input'} -> ${finding.validationRecord?.rootControl ?? location.file} -> ${finding.validationRecord?.sink ?? location.excerpt}`, outcome: finding.impact, severityRationale: `${finding.severity} severity is provisional and reflects the sensitive operation with static reachability evidence.`, changeConditions: 'Increase confidence after a targeted test or runtime proof; lower severity if a complete upstream control prevents attacker influence.', sourceReferences: finding.locations.map(item => ({ file: item.file, line: item.line, role: item.role ?? 'root_control' })), recordedAt: new Date().toISOString() }
  finding.evidence.push({ kind: 'attack_path', detail: finding.attackPath, location })
  finding.ledger.push({ at: new Date().toISOString(), phase: 'attack_path', disposition: 'reportable', summary: finding.attackPath })
}

function diffPath(value: string): string {
  if (!value || value === '/dev/null' || value.startsWith('/') || value.split('/').includes('..')) return 'unknown'
  return value
}

function removedControlCandidate(file: string, line: number, source: string): Candidate | undefined {
  for (const rule of REMOVED_CONTROL_RULES) {
    rule.pattern.lastIndex = 0
    if (!rule.pattern.test(source)) continue
    const excerpt = source.trim().slice(0, 240)
    return { rule: rule.id, severity: rule.severity, file, line, excerpt, rationale: rule.rationale, cwe: rule.cwe, evidence: [
      { kind: 'pattern', detail: `Diff removal matched ${rule.id}.`, location: { file, line, excerpt, role: 'expected_control' } },
      { kind: 'counterevidence', detail: 'The changed hunk removes an explicit security control; no equivalent replacement is established by this diff-only analysis.', location: { file, line, excerpt, role: 'expected_control' } },
    ] }
  }
}

function isGitHubWorkflow(file: string): boolean { return /^\.github\/workflows\/[^/]+\.ya?ml$/i.test(file) }
function workflowCandidate(rule: CiWorkflowRule, file: string, line: number, excerpt: string, detail: string, role: 'entrypoint' | 'sink' | 'root_control' = 'root_control'): Candidate {
  return { rule: rule.id, severity: rule.severity, file, line, excerpt, rationale: rule.rationale, cwe: rule.cwe, evidence: [{ kind: 'pattern', detail, location: { file, line, excerpt, role } }, { kind: 'context', detail: 'This CI/CD workflow finding is anchored to a newly added diff line.', location: { file, line, excerpt, role } }] }
}

interface WorkflowLine { line: number; source: string; indent: number; text: string }
interface WorkflowStep { job: string; start: number; end: number; indent: number; fields: WorkflowLine[] }

function workflowLines(source: string): WorkflowLine[] {
  return source.split(/\r?\n/).map((source, index) => ({ line: index + 1, source, indent: /^(\s*)/.exec(source)?.[1].length ?? 0, text: source.trim() }))
}

function valueAfterKey(line: WorkflowLine, key: string): string | undefined {
  const match = new RegExp(`^(?:-\\s*)?${key}\\s*:\\s*(.*)$`, 'i').exec(line.text)
  return match?.[1]?.replace(/\s+#.*$/, '').trim()
}

/** Parse only the small, indentation-defined Actions subset needed for job and step trust boundaries. */
function workflowSteps(source: string): WorkflowStep[] {
  const lines = workflowLines(source); const jobsIndex = lines.findIndex(line => /^jobs\s*:\s*(?:#.*)?$/i.test(line.text)); if (jobsIndex < 0) return []
  const jobsIndent = lines[jobsIndex].indent; const steps: WorkflowStep[] = []; let job = 'unknown'; let stepStart = -1; let stepIndent = -1
  const closeStep = (end: number): void => {
    if (stepStart < 0) return
    steps.push({ job, start: lines[stepStart].line, end: lines[Math.max(stepStart, end - 1)].line, indent: stepIndent, fields: lines.slice(stepStart, end) })
    stepStart = -1; stepIndent = -1
  }
  for (let index = jobsIndex + 1; index < lines.length; index++) {
    const line = lines[index]
    if (line.text && line.indent <= jobsIndent) { closeStep(index); break }
    if (line.text && line.indent === jobsIndent + 2 && /^[A-Za-z0-9_-]+\s*:/.test(line.text)) { closeStep(index); job = line.text.replace(/\s*:.*$/, ''); continue }
    if (/^-\s+/.test(line.text) && line.indent >= jobsIndent + 4) { closeStep(index); stepStart = index; stepIndent = line.indent }
  }
  closeStep(lines.length)
  return steps
}

function isUntrustedEvent(value: string | undefined): boolean { return !!value && /\$\{\{\s*github\.event\.(?:pull_request|issue|comment)\./i.test(value) }
function isMutableAction(value: string | undefined): boolean { return !!value && /@(?:main|master|develop|next|latest)\s*$/i.test(value) }
function addedLine(line: WorkflowLine, added: Set<number>): boolean { return added.has(line.line) }

function runEventLines(step: WorkflowStep): WorkflowLine[] {
  const results: WorkflowLine[] = []
  for (let index = 0; index < step.fields.length; index++) {
    const line = step.fields[index]; const value = valueAfterKey(line, 'run')
    if (value === undefined) continue
    if (isUntrustedEvent(value)) results.push(line)
    if (!/^[>|]/.test(value)) continue
    for (let child = index + 1; child < step.fields.length && step.fields[child].indent > line.indent; child++) if (isUntrustedEvent(step.fields[child].text)) results.push(step.fields[child])
  }
  return results
}

function writePermissionLines(source: string): WorkflowLine[] {
  const lines = workflowLines(source); const results: WorkflowLine[] = []
  for (let index = 0; index < lines.length; index++) {
    const line = lines[index]; const value = valueAfterKey(line, 'permissions')
    if (value && (value === 'write-all' || /\b(?:contents|actions|pull-requests|issues)\s*:\s*write\b/i.test(value))) results.push(line)
    if (value !== '') continue
    for (let child = index + 1; child < lines.length && lines[child].indent > line.indent; child++) {
      if (/^(?:contents|actions|pull-requests|issues)\s*:\s*write\s*(?:#.*)?$/i.test(lines[child].text)) results.push(lines[child])
    }
  }
  return results
}

/** Analyze a current workflow structure, but produce findings only at added-line evidence. */
function ciWorkflowDiffCandidates(file: string, added: Array<{ line: number; source: string }>, currentSource: string): Candidate[] {
  if (!isGitHubWorkflow(file)) return []
  const candidates: Candidate[] = []; const currentLines = workflowLines(currentSource); const addedNumbers = new Set(added.map(item => item.line)); const pullRequestTarget = currentLines.find(line => /^pull_request_target\s*(?::|$)/i.test(line.text))
  if (pullRequestTarget) {
    for (const permission of writePermissionLines(currentSource).filter(line => addedLine(line, addedNumbers))) candidates.push(workflowCandidate(CI_WORKFLOW_RULES['write-permissions'], file, permission.line, permission.text.slice(0, 240), `Current pull_request_target trigger at ${file}:${pullRequestTarget.line} has newly added write permission at ${file}:${permission.line}.`, 'root_control'))
    for (const step of workflowSteps(currentSource)) {
      for (const run of runEventLines(step).filter(line => addedLine(line, addedNumbers))) candidates.push(workflowCandidate(CI_WORKFLOW_RULES['untrusted-shell'], file, run.line, run.text.slice(0, 240), `Added pull_request_target workflow shell command interpolates untrusted GitHub event data at ${file}:${run.line}.`, 'sink'))
      const checkout = step.fields.find(line => /^-\s*uses\s*:\s*actions\/checkout@/i.test(line.text))
      const untrustedCheckoutField = checkout && step.fields.find(line => /^(?:ref|repository)\s*:/i.test(line.text) && isUntrustedEvent(valueAfterKey(line, 'ref') ?? valueAfterKey(line, 'repository')))
      if (!checkout || !untrustedCheckoutField) continue
      const laterRun = workflowSteps(currentSource).flatMap(other => other.job === step.job && other.start > step.start ? other.fields.filter(line => valueAfterKey(line, 'run') !== undefined) : [])
      const anchor = [untrustedCheckoutField, checkout, ...laterRun].find(line => addedLine(line, addedNumbers))
      if (laterRun.length && anchor) candidates.push(workflowCandidate(CI_WORKFLOW_RULES['untrusted-checkout-execution'], file, anchor.line, anchor.text.slice(0, 240), `pull_request_target at ${file}:${pullRequestTarget.line} checks out pull-request head data at ${file}:${untrustedCheckoutField.line} before a later run step in job ${step.job}.`, anchor === untrustedCheckoutField || anchor === checkout ? 'entrypoint' : 'sink'))
    }
  }
  for (const step of workflowSteps(currentSource)) for (const action of step.fields.filter(line => /^-\s*uses\s*:/i.test(line.text) && isMutableAction(valueAfterKey(line, 'uses')) && addedLine(line, addedNumbers))) candidates.push(workflowCandidate(CI_WORKFLOW_RULES['mutable-action-ref'], file, action.line, action.text.slice(0, 240), `Added GitHub Action uses mutable ref at ${file}:${action.line}; pin an immutable commit SHA.`, 'root_control'))
  return candidates
}

function candidateTouchesAddedLine(candidate: Candidate, addedLines: Map<string, Set<number>>): boolean {
  if (addedLines.get(candidate.file)?.has(candidate.line)) return true
  return candidate.evidence.some(item => item.location && addedLines.get(item.location.file)?.has(item.location.line))
}

/**
 * Run the existing language analyzers against current source, then retain only
 * results whose sink or propagation evidence is a newly added diff line. This
 * proves a new call path without restating unchanged historical findings.
 */
async function semanticDiffCandidates(root: string, addedLines: Map<string, Set<number>>): Promise<{ candidates: Candidate[]; counts: Record<string, number>; parseErrors: number }> {
  const inventory = await collectFiles(root, { maxFiles: 10_000, maxFileBytes: 1_048_576 })
  const goModuleCache = new Map<string, string | undefined>()
  const modules = await Promise.all(inventory.files.map(async file => ({ file: relative(root, file), source: await readFile(file, 'utf8'), modulePath: extname(file) === '.go' ? await localGoModulePath(root, file, goModuleCache) : undefined })))
  const javascript = analyzeJavaScriptModuleGraph(modules.filter(module => ['.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx'].includes(extname(module.file))))
  const python = analyzePythonModuleGraph(modules.filter(module => extname(module.file) === '.py'))
  const go = analyzeGoPackageGraph(modules.filter(module => extname(module.file) === '.go'))
  const structuredInputs: Record<StructuredLanguage, Array<{ file: string; source: string }>> = { java: [], csharp: [], php: [], ruby: [], c: [], cpp: [], rust: [] }
  for (const module of modules) {
    const language = ({ '.java': 'java', '.cs': 'csharp', '.php': 'php', '.rb': 'ruby', '.c': 'c', '.cc': 'cpp', '.cpp': 'cpp', '.rs': 'rust' } as Record<string, StructuredLanguage>)[extname(module.file)]
    if (language) structuredInputs[language].push(module)
  }
  const structured = Object.fromEntries((Object.keys(structuredInputs) as StructuredLanguage[]).map(language => [language, analyzeStructuredFlow(structuredInputs[language], language).candidates])) as Record<StructuredLanguage, Candidate[]>
  const byEngine: Record<string, Candidate[]> = { 'ast.diff-semantic-taint': javascript.candidates, 'python.diff-semantic-taint': python.candidates, 'go.diff-semantic-taint': go.candidates, ...Object.fromEntries((Object.keys(structured) as StructuredLanguage[]).map(language => [`${language}.diff-semantic-taint`, structured[language]])) }
  const counts: Record<string, number> = {}; const candidates: Candidate[] = []
  for (const [engine, results] of Object.entries(byEngine)) { const retained = results.filter(candidate => candidateTouchesAddedLine(candidate, addedLines)); counts[engine] = retained.length; candidates.push(...retained) }
  return { candidates, counts, parseErrors: javascript.parseErrors.length }
}

export async function runScan(directory: string, limits: ScanLimits, mode: 'standard' | 'deep', threatModel: string, scopeRequested = false, stateDirectory = '', automaticValidation = true): Promise<ScanRecord> {
  const deep = mode === 'deep'; const now = new Date().toISOString(); const result = await assessDirectory(directory, limits, deep); const [policy, preflight, generatedThreatModel] = await Promise.all([resolvePolicyGuidance(result.root), nativePreflight(result.root, result.receipts, result.complete, stateDirectory), threatModel.trim() ? Promise.resolve('') : generateSourceThreatModel(result.root, limits)])
  const findings = reduceCandidates(result.candidates); if (automaticValidation) { for (const finding of findings) validateCandidate(finding); for (const finding of findings) analyzeAttackPath(finding) }
  const snapshot = await targetSnapshot(result.root, result.receipts); const id = createScanId(); const closed = findings.every(finding => finding.ledger.some(row => row.phase === 'validation') && (finding.disposition !== 'reportable' || finding.ledger.some(row => row.phase === 'attack_path'))); const complete = result.complete && closed
  const record: ScanRecord = { schemaVersion: 3, id, mode, lifecycle: automaticValidation ? complete ? 'completed' : 'incomplete' : 'validation', target: result.root, targetSnapshot: snapshot, createdAt: now, completedAt: automaticValidation ? new Date().toISOString() : undefined, threatModel: threatModel.trim() || generatedThreatModel, policyGuidance: policy.text, preflight, findings, coverage: { mode: deep && !scopeRequested ? 'deep_repository' : scopeRequested ? 'scoped_path' : 'repository', reviewedFiles: result.filesScanned, skippedFiles: result.filesSkipped, exclusions: [...IGNORED_DIRECTORIES], complete: result.complete, receipts: result.receipts, ruleReceipts: result.ruleReceipts, policyFiles: [...new Set([...result.policyFiles, ...policy.files])], surfaces: result.ruleReceipts.filter(receipt => receipt.pass === 'baseline').map(receipt => ({ id: receipt.ruleId, label: receipt.ruleId, disposition: automaticValidation && findings.some(finding => finding.ruleId === receipt.ruleId && finding.disposition === 'reportable') ? 'reported' : automaticValidation && findings.some(finding => finding.ruleId === receipt.ruleId) ? 'rejected' : 'needs_follow_up', receiptRefs: ['artifacts/02_discovery/finding_discovery_report.md'], riskArea: receipt.ruleId })), deferred: result.complete ? [] : [{ id: 'coverage-limits', reason: 'File limit, unreadable path, or file-size limit prevented complete review.' }] }, activity: [activity('preflight', `Native preflight ${preflight.status}.`), activity('inventory', `Inventoried ${result.filesScanned} eligible source files.`), activity('policy', policy.files.length ? `Resolved policy files: ${policy.files.join(', ')}.` : 'No SECURITY.md policy file found in the scan scope.'), activity('threat_model', threatModel.trim() ? 'Recorded user-supplied threat model.' : 'Generated source-evidenced threat model.'), activity('discovery', `Ran ${deep ? 3 : 1} native discovery pass(es) and collected ${result.candidates.length} observations.`), activity('reduction', `Reduced observations to ${findings.length} unique candidates.`), ...(automaticValidation ? [activity('validation', `Recorded static validation receipts for ${findings.length} candidates.`), activity('attack_path', `Recorded attack-path receipts for ${findings.filter(finding => finding.disposition === 'reportable').length} reportable candidates.`), activity('complete', complete ? 'Scan completed with closed candidate ledgers.' : 'Scan incomplete because coverage or candidate closure is incomplete.')] : [activity('validation', 'Scan is awaiting structured validation receipts for each candidate.')])], tasks: automaticValidation ? [] : validationTasks(id, findings), recipe: { mode, scopeRequested, passes: deep ? ['baseline', 'injection', 'boundaries'] : ['baseline'] }, artifacts: { directory: scanArtifactDir(getStateDir(stateDirectory), result.root, id) }, seal: '' }
  record.seal = sealScan(record); return record
}

export function resolveSafeTarget(workspace: string, requested: string | undefined): string { const root = resolve(workspace); const target = resolve(root, requested ?? '.'); if (!isContained(root, target)) throw new Error('Scan target must remain inside the current workspace.'); return target }

export async function reviewGitDiff(workspace: string, base: string | undefined): Promise<{ mode: string; diff: string; truncated: boolean }> {
  if (base !== undefined && (!/^[A-Za-z0-9][A-Za-z0-9._/-]*$/.test(base) || base.startsWith('-'))) throw new Error('Git base ref contains unsupported characters.')
  const args = ['diff', '--no-ext-diff', '--unified=20']; const mode = base === undefined ? 'working-tree' : `base:${base}`; if (base !== undefined) args.push(`${base}...HEAD`)
  const { stdout } = await execFileAsync('git', args, { cwd: resolve(workspace), encoding: 'utf8', maxBuffer: MAX_DIFF_BYTES + 1 }); return { mode, diff: stdout.slice(0, MAX_DIFF_BYTES), truncated: Buffer.byteLength(stdout, 'utf8') > MAX_DIFF_BYTES }
}

export async function runDiffScan(workspace: string, base: string | undefined, threatModel: string, stateDirectory = '', automaticValidation = true): Promise<ScanRecord> {
  const review = await reviewGitDiff(workspace, base); const candidates: Candidate[] = []; const receipts: FileReceipt[] = []; const ruleReceipts: RuleReceipt[] = []; const changedPaths = new Set<string>(); const addedLineMap = new Map<string, Set<number>>(); const addedSourceMap = new Map<string, Array<{ line: number; source: string }>>(); let currentFile = ''; let oldLine = 0; let newLine = 0; let addedLines: Array<{ line: number; source: string }> = []
  const flushAddedLines = (): void => {
    if (!addedLines.length) return
    const analyzed = analyzeText(resolve(workspace), join(resolve(workspace), currentFile || 'unknown'), addedLines.map(item => item.source).join('\n'), 'diff-added')
    for (const candidate of analyzed.candidates) {
      const source = addedLines[candidate.line - 1]
      if (!source) continue
      candidate.file = currentFile || 'unknown'; candidate.line = source.line; candidate.excerpt = source.source.trim().slice(0, 240); candidate.evidence[0].location = location(candidate.file, source.line, candidate.excerpt); candidates.push(candidate)
    }
    addedLines = []
  }
  for (const diffLine of review.diff.split(/\r?\n/)) {
    if (diffLine.startsWith('+++ b/')) { flushAddedLines(); currentFile = diffPath(diffLine.slice(6)); continue }
    const hunk = /^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(diffLine); if (hunk) { flushAddedLines(); oldLine = Number(hunk[1]); newLine = Number(hunk[2]); continue }
    if (diffLine.startsWith('+') && !diffLine.startsWith('+++')) {
      if (currentFile !== 'unknown') changedPaths.add(currentFile)
      addedLines.push({ line: newLine, source: diffLine.slice(1) })
      if (currentFile !== 'unknown') { const lines = addedLineMap.get(currentFile) ?? new Set<number>(); lines.add(newLine); addedLineMap.set(currentFile, lines); const source = addedSourceMap.get(currentFile) ?? []; source.push({ line: newLine, source: diffLine.slice(1) }); addedSourceMap.set(currentFile, source) }
      newLine++; continue
    }
    if (diffLine.startsWith('-') && !diffLine.startsWith('---')) {
      if (currentFile !== 'unknown') changedPaths.add(currentFile)
      const candidate = removedControlCandidate(currentFile || 'unknown', oldLine, diffLine.slice(1)); if (candidate) candidates.push(candidate)
      oldLine++; continue
    }
    oldLine++; newLine++
  }
  flushAddedLines()
  for (const [file, lines] of addedSourceMap) {
    if (!isGitHubWorkflow(file)) continue
    try { candidates.push(...ciWorkflowDiffCandidates(file, lines, await readFile(join(resolve(workspace), file), 'utf8'))) } catch { /* A deleted or unreadable workflow cannot be analyzed as current configuration. */ }
  }
  const semantic = await semanticDiffCandidates(resolve(workspace), addedLineMap); candidates.push(...semantic.candidates)
  for (const path of [...changedPaths].sort()) { const patch = review.diff.split(`diff --git a/${path} b/${path}`)[1] ?? ''; receipts.push({ path, bytes: Buffer.byteLength(patch, 'utf8'), sha256: sha256(patch), language: languageFor(path) }) }
  for (const rule of [...RULES.map(rule => rule.id), ...REMOVED_CONTROL_RULES.map(rule => rule.id), ...Object.values(CI_WORKFLOW_RULES).map(rule => rule.id)]) ruleReceipts.push({ ruleId: rule, pass: 'diff', matches: candidates.filter(candidate => candidate.rule === rule).length })
  for (const [ruleId, matches] of Object.entries(semantic.counts)) ruleReceipts.push({ ruleId, pass: 'semantic', matches }); if (semantic.parseErrors) ruleReceipts.push({ ruleId: 'ast.diff-semantic-parse-error', pass: 'semantic', matches: semantic.parseErrors })
  const root = resolve(workspace); const now = new Date().toISOString(); const findings = reduceCandidates(candidates); if (automaticValidation) { for (const finding of findings) validateCandidate(finding); for (const finding of findings) analyzeAttackPath(finding) }; const policy = await resolvePolicyGuidance(root); const id = createScanId(); const closed = findings.every(finding => finding.ledger.some(row => row.phase === 'validation') && (finding.disposition !== 'reportable' || finding.ledger.some(row => row.phase === 'attack_path'))); const complete = !review.truncated && closed; const [head, baseRevision, remote] = await Promise.all([execFileAsync('git', ['rev-parse', '--verify', 'HEAD'], { cwd: root, encoding: 'utf8' }).catch(() => ({ stdout: '' })), base ? execFileAsync('git', ['rev-parse', '--verify', base], { cwd: root, encoding: 'utf8' }).catch(() => ({ stdout: '' })) : Promise.resolve({ stdout: '' }), execFileAsync('git', ['config', '--get', 'remote.origin.url'], { cwd: root, encoding: 'utf8' }).catch(() => ({ stdout: '' }))]); const remoteValue = remote.stdout.trim().replace(/^[^@]+@/, '').replace(/[?#].*$/, ''); const record: ScanRecord = { schemaVersion: 3, id, mode: 'diff', lifecycle: automaticValidation ? complete ? 'completed' : 'incomplete' : 'validation', target: root, targetSnapshot: { kind: 'git_diff', targetId: `dsh-security-suite-target/v1:sha256:${sha256(remoteValue || root)}`, displayName: basename(root) || root, baseRevision: baseRevision.stdout.trim() || undefined, headRevision: head.stdout.trim() || undefined, snapshotDigest: `dsh-security-suite-snapshot/v1:sha256:${sha256(review.diff)}` }, createdAt: now, completedAt: automaticValidation ? new Date().toISOString() : undefined, threatModel: threatModel || 'Review changed behavior for attacker-controlled inputs, authorization boundaries, sensitive sinks, and CI/CD trust boundaries.', policyGuidance: policy.text, preflight: { status: review.truncated ? 'warn' : 'ready', checks: [{ id: 'git-diff', status: review.truncated ? 'warn' : 'pass', detail: `Reviewed ${review.mode}; ${changedPaths.size} changed source path(s) received.` }, { id: 'semantic-diff', status: semantic.parseErrors ? 'warn' : 'pass', detail: `Analyzed current local JS/TS, Python, Go, Java, C#, PHP, Ruby, C, C++, and Rust modules; retained ${semantic.candidates.length} finding(s) anchored to added lines.${semantic.parseErrors ? ` ${semantic.parseErrors} JS/TS module parse error(s) were retained as coverage limitations.` : ''}` }, { id: 'ci-workflow-diff', status: 'pass', detail: `Analyzed ${[...addedSourceMap.keys()].filter(isGitHubWorkflow).length} changed GitHub Actions workflow(s) for untrusted event shell, write permissions, and mutable action refs.` }, { id: 'worker-orchestration', status: 'warn', detail: 'Investigation tasks are durable and claimable by DSH reviewers. This plugin does not assume a private subagent API.' }], projectFiles: [], languages: [...new Set(receipts.map(item => item.language))], suggestedCommands: [] }, findings, coverage: { mode: 'diff', reviewedFiles: receipts.length, skippedFiles: review.truncated ? 1 : 0, exclusions: review.truncated ? ['diff truncated at 1 MB'] : [], complete: !review.truncated, receipts, ruleReceipts, policyFiles: policy.files, surfaces: [{ id: 'git-diff', label: review.mode, disposition: automaticValidation && findings.some(finding => finding.disposition === 'reportable') ? 'reported' : findings.length ? 'needs_follow_up' : 'no_issue_found', receiptRefs: ['artifacts/02_discovery/finding_discovery_report.md'], riskArea: 'changed-code-and-ci' }], deferred: [...(review.truncated ? [{ id: 'diff-truncated', reason: 'Diff exceeded the 1 MB safe processing limit.' }] : []), ...(semantic.parseErrors ? [{ id: 'semantic-diff-parse-errors', reason: `${semantic.parseErrors} current JS/TS module(s) could not be parsed for semantic diff analysis.` }] : [])] }, activity: [activity('preflight', 'Git diff preflight completed.'), activity('policy', policy.files.length ? `Resolved policy files: ${policy.files.join(', ')}.` : 'No SECURITY.md policy file found in the scan scope.'), activity('discovery', `Analyzed added lines, local multi-language semantic call paths, removed security controls, and CI/CD workflow boundaries in ${review.mode}.`), activity('reduction', `Reduced observations to ${findings.length} unique candidates.`), ...(automaticValidation ? [activity('validation', `Recorded static validation receipts for ${findings.length} candidates.`), activity('attack_path', `Recorded attack-path receipts for ${findings.filter(finding => finding.disposition === 'reportable').length} reportable candidates.`), activity('complete', complete ? 'Diff scan completed with closed candidate ledgers.' : 'Diff scan incomplete because the diff was truncated.')] : [activity('validation', 'Diff candidates are awaiting structured validation receipts.')])], tasks: automaticValidation ? [] : validationTasks(id, findings), recipe: { mode: 'diff', scopeRequested: true, passes: ['diff-added-lines', 'diff-semantic-multilanguage', 'diff-ci-workflows', 'diff-removed-controls'] }, artifacts: { directory: scanArtifactDir(getStateDir(stateDirectory), root, id) }, seal: '' }; record.seal = sealScan(record); return record
}
