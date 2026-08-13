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
interface ConfigurationRule { id: string; cwe: string; severity: Severity; rationale: string }

const RULES: Rule[] = [
  { id: 'dangerous-dynamic-code', title: 'Dynamic code execution', cwe: 'CWE-95', severity: 'high', rationale: 'Dynamic evaluation can turn attacker-controlled data into code execution.', pattern: /\beval\s*\(|\bnew\s+Function\s*\(/, languages: [] },
  { id: 'shell-command-construction', title: 'Constructed shell command', cwe: 'CWE-78', severity: 'high', rationale: 'A constructed process command needs an attacker-to-shell data-flow review.', pattern: /(?:exec|execSync|spawn|spawnSync|system|popen|subprocess\.(?:run|call|Popen))\s*\([^\n]*(?:\+|`|\$\{|f["'])/i, context: /(?:req\.|params\.|query\.|argv|input|user)/i },
  { id: 'path-traversal-sink', title: 'Request-derived filesystem path', cwe: 'CWE-22', severity: 'medium', rationale: 'A filesystem sink receives request-derived data and needs canonical containment validation.', pattern: /(?:readFile|writeFile|createReadStream|createWriteStream|sendFile|open)\s*\([^\n]*(?:req\.|params\.|query\.|body\.|input)/i },
  { id: 'tls-verification-disabled', title: 'TLS verification disabled', cwe: 'CWE-295', severity: 'high', rationale: 'TLS certificate verification is explicitly disabled.', pattern: /(?:CURLOPT_SSL_VERIFYPEER\s*,\s*(?:false|0))/, languages: ['php', 'c', 'cpp', 'csharp'] },
  { id: 'ssrf-request-sink', title: 'Request-derived outbound request', cwe: 'CWE-918', severity: 'medium', rationale: 'An outbound request appears to use request-derived input and needs destination allowlisting.', pattern: /(?:fetch|axios\.(?:get|post|request)|requests\.(?:get|post|request)|http\.request)\s*\([^\n]*(?:req\.|params\.|query\.|body\.|input)/i },
  { id: 'sql-injection-query-construction', title: 'Constructed SQL query', cwe: 'CWE-89', severity: 'high', rationale: 'A database query appears to construct SQL syntax from request-derived input.', pattern: /(?:query|execute|raw)\s*\([^\n]*(?:req\.|params\.|query\.|body\.|input|\+|\$\{)/i, context: /(?:select|insert|update|delete|from|where)/i },
]

const CONFIGURATION_RULES: Record<'jwt' | 'cors' | 'tls' | 'xml', ConfigurationRule> = {
  jwt: { id: 'jwt-verification-disabled', cwe: 'CWE-347', severity: 'high', rationale: 'JWT signature validation is disabled or the token algorithm allowlist accepts the unsigned none algorithm.' },
  cors: { id: 'cors-wildcard-credentials', cwe: 'CWE-942', severity: 'medium', rationale: 'A credentialed CORS policy allows every origin or reflects the caller origin without an explicit allowlist.' },
  tls: { id: 'tls-verification-disabled', cwe: 'CWE-295', severity: 'high', rationale: 'TLS certificate verification is explicitly disabled for a supported HTTP client request.' },
  xml: { id: 'xml-external-entity-risk', cwe: 'CWE-611', severity: 'high', rationale: 'A Java XML parser factory creates a parser without recognized external-entity hardening controls.' },
}

const SECRET_FIELD_NAME = /(?:api[_-]?key|access[_-]?key|secret|password|token|private[_-]?key|credential)/i
const PLACEHOLDER_SECRET_VALUE = /(?:^|[-_\s])(example|sample|test|dummy|placeholder|replace|changeme|your[-_\s]?)(?:[-_\s]|$)|\.example(?:\.com|\.org|\.net)?$/i

function languageFor(file: string): string {
  return ({ '.js': 'javascript', '.jsx': 'javascript', '.mjs': 'javascript', '.cjs': 'javascript', '.ts': 'typescript', '.tsx': 'typescript', '.py': 'python', '.go': 'go', '.java': 'java', '.php': 'php', '.rb': 'ruby', '.rs': 'rust', '.sh': 'shell', '.bash': 'shell', '.c': 'c', '.cc': 'cpp', '.cpp': 'cpp', '.cs': 'csharp' } as Record<string, string>)[extname(file)] ?? 'text'
}

function hash(value: string): string { return createHash('sha256').update(value).digest('hex') }
function isContained(root: string, candidate: string): boolean { return candidate === root || candidate.startsWith(root + sep) }
function location(file: string, line: number, excerpt: string, role: 'root_control' = 'root_control'): { file: string; line: number; excerpt: string; role: 'root_control' } { return { file, line, excerpt: excerpt.trim().slice(0, 240), role } }
function lineAt(source: string, offset: number): number { return source.slice(0, offset).split(/\r?\n/).length }
function sourceLine(lines: string[], number: number): string { return lines[number - 1]?.trim().slice(0, 240) ?? '' }

function dedupeCandidateObservations(candidates: Candidate[]): Candidate[] {
  const unique = new Map<string, Candidate>()
  for (const candidate of candidates) {
    const key = `${candidate.rule}:${candidate.file}:${candidate.line}:${candidate.excerpt}`
    const existing = unique.get(key)
    if (!existing) { unique.set(key, candidate); continue }
    for (const evidence of candidate.evidence) {
      const evidenceKey = `${evidence.kind}:${evidence.detail}:${evidence.location?.file ?? ''}:${evidence.location?.line ?? ''}:${evidence.location?.role ?? ''}`
      if (!existing.evidence.some(item => `${item.kind}:${item.detail}:${item.location?.file ?? ''}:${item.location?.line ?? ''}:${item.location?.role ?? ''}` === evidenceKey)) existing.evidence.push(evidence)
    }
  }
  return [...unique.values()]
}

function configurationCandidate(rule: ConfigurationRule, file: string, lines: string[], line: number, detail: string, controlLine?: number): Candidate {
  const excerpt = sourceLine(lines, line)
  return {
    rule: rule.id, severity: rule.severity, file, line, excerpt, rationale: rule.rationale, cwe: rule.cwe,
    evidence: [
      { kind: 'pattern', detail, location: { file, line, excerpt, role: 'root_control' } },
      ...(controlLine ? [{ kind: 'counterevidence' as const, detail: 'The paired security control was configured in the same effective configuration block.', location: { file, line: controlLine, excerpt: sourceLine(lines, controlLine), role: 'expected_control' as const } }] : []),
    ],
  }
}

const ROUTE_AUTHORIZATION_RULE = { id: 'missing-authorization-route', cwe: 'CWE-862', severity: 'medium' as const, rationale: 'A state-changing route accepts a request handler without a local or previously registered explicit authorization middleware.' }
const AUTHORIZATION_MIDDLEWARE = /(?:auth(?:enticate|orize|entication|orization)?|permission|role|rbac|access(?:control)?|guard|csrf|(?:require|ensure|verify|check)Session)/i
interface RouteCall { receiver: string; method: string; start: number; args: Array<{ text: string; start: number }> }

function closingParenthesis(source: string, open: number): number | undefined {
  let depth = 0; let quote = ''
  for (let index = open; index < source.length; index++) {
    const character = source[index]
    if (quote) { if (character === quote && source[index - 1] !== '\\') quote = ''; continue }
    if (character === '"' || character === "'" || character === '`') { quote = character; continue }
    if (character === '(') depth++
    if (character === ')' && --depth === 0) return index
  }
  return undefined
}

function topLevelArguments(source: string, start: number, end: number): Array<{ text: string; start: number }> {
  const values: Array<{ text: string; start: number }> = []; let offset = start; let depth = 0; let quote = ''
  for (let index = start; index <= end; index++) {
    const character = source[index] ?? ','
    if (quote) { if (character === quote && source[index - 1] !== '\\') quote = ''; continue }
    if (character === '"' || character === "'" || character === '`') { quote = character; continue }
    if ('([{'.includes(character)) depth++
    if (')]}'.includes(character)) depth--
    if ((character === ',' && depth === 0) || index === end) {
      const text = source.slice(offset, index).trim()
      if (text) values.push({ text, start: offset + source.slice(offset, index).search(/\S/) })
      offset = index + 1
    }
  }
  return values
}

function memberCalls(source: string, methods: readonly string[]): RouteCall[] {
  const escaped = methods.map(method => method.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|')
  const expression = new RegExp(`\\b([A-Za-z_$][\\w$]*)\\.(${escaped})\\s*\\(`, 'gi'); const calls: RouteCall[] = []
  for (const match of source.matchAll(expression)) {
    const start = match.index ?? 0; const open = start + match[0].lastIndexOf('('); const close = closingParenthesis(source, open)
    if (close === undefined) continue
    calls.push({ receiver: match[1]!, method: match[2]!.toLowerCase(), start, args: topLevelArguments(source, open + 1, close) })
  }
  return calls
}

function routerVariables(source: string): Set<string> {
  const result = new Set<string>()
  for (const match of source.matchAll(/\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:(?:[A-Za-z_$][\w$]*\.)?Router)\s*\(/g)) result.add(match[1]!)
  return result
}

function literalRoute(argument: string | undefined): boolean {
  return Boolean(argument && (/^['"][\s\S]*['"]$/.test(argument) || /^`[^$]*`$/.test(argument)))
}

function explicitHandler(argument: string | undefined): boolean {
  if (!argument || AUTHORIZATION_MIDDLEWARE.test(argument)) return false
  return /^(?:async\s+)?(?:function\b|\(?\s*(?:req|request|ctx)\b)|^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*$|^\[/.test(argument)
}

function explicitAuthorization(value: string): boolean {
  return AUTHORIZATION_MIDDLEWARE.test(value) || /(?:PreAuthorize|Secured|RolesAllowed|PermitAll|DenyAll|Depends\s*\([^)]*(?:current[_-]?user|authenticated|require[_-]?(?:auth|role|permission|session)|authorize|guard))/i.test(value)
}

function analyzeRouteAuthorization(file: string, content: string, onlyRules?: Set<string>): Candidate[] {
  if (onlyRules && !onlyRules.has(ROUTE_AUTHORIZATION_RULE.id)) return []
  const lines = content.split(/\r?\n/); const candidates: Candidate[] = []; const uses = memberCalls(content, ['use']); const routers = routerVariables(content); const globallyProtected = new Map<string, number[]>()
  for (const use of uses) if (!literalRoute(use.args[0]?.text) && use.args.some(argument => AUTHORIZATION_MIDDLEWARE.test(argument.text))) {
    const positions = globallyProtected.get(use.receiver) ?? []; positions.push(use.start); globallyProtected.set(use.receiver, positions)
  }
  const hasPriorGlobalControl = (receiver: string, position: number): boolean => globallyProtected.get(receiver)?.some(control => control < position) ?? false
  // A protected parent mount protects a child router independently of where its routes are declared.
  const protectedByMount = new Set<string>()
  for (let pass = 0; pass < Math.max(1, routers.size); pass++) {
    let changed = false
    for (const use of uses) {
      const mounted = use.args.map(argument => argument.text).filter(argument => routers.has(argument))
      const control = protectedByMount.has(use.receiver) || hasPriorGlobalControl(use.receiver, use.start) || use.args.some(argument => AUTHORIZATION_MIDDLEWARE.test(argument.text))
      if (!control) continue
      for (const target of mounted) if (!protectedByMount.has(target)) { protectedByMount.add(target); changed = true }
    }
    if (!changed) break
  }
  for (const route of memberCalls(content, ['post', 'put', 'patch', 'delete'])) {
    const handler = route.args.at(-1)
    if (route.args.length < 2 || !literalRoute(route.args[0]?.text) || !explicitHandler(handler?.text)) continue
    const protectedByRoute = route.args.slice(1, -1).some(argument => AUTHORIZATION_MIDDLEWARE.test(argument.text))
    if (protectedByMount.has(route.receiver) || hasPriorGlobalControl(route.receiver, route.start) || protectedByRoute) continue
    const line = lineAt(content, route.start); const excerpt = sourceLine(lines, line)
    candidates.push({ rule: ROUTE_AUTHORIZATION_RULE.id, severity: ROUTE_AUTHORIZATION_RULE.severity, file, line, excerpt, rationale: ROUTE_AUTHORIZATION_RULE.rationale, cwe: ROUTE_AUTHORIZATION_RULE.cwe, evidence: [{ kind: 'pattern', detail: 'Route authorization analysis found a state-changing request handler without an explicit local, preceding global, or protected parent-mount authorization middleware.', location: { file, line, excerpt, role: 'root_control' } }] })
  }
  return candidates
}

function frameworkRouteCandidate(file: string, lines: string[], offset: number, detail: string): Candidate {
  const line = lineAt(lines.join('\n'), offset); const excerpt = sourceLine(lines, line)
  return { rule: ROUTE_AUTHORIZATION_RULE.id, severity: ROUTE_AUTHORIZATION_RULE.severity, file, line, excerpt, rationale: ROUTE_AUTHORIZATION_RULE.rationale, cwe: ROUTE_AUTHORIZATION_RULE.cwe, evidence: [{ kind: 'pattern', detail, location: { file, line, excerpt, role: 'root_control' } }] }
}

function protectedPythonRouters(source: string): Set<string> {
  const protectedRouters = new Set<string>(); const routers = new Set<string>()
  for (const match of source.matchAll(/\b([A-Za-z_]\w*)\s*=\s*APIRouter\s*\(/g)) {
    const open = (match.index ?? 0) + match[0].lastIndexOf('('); const close = closingParenthesis(source, open); if (close === undefined) continue
    routers.add(match[1]!); if (explicitAuthorization(source.slice(open + 1, close))) protectedRouters.add(match[1]!)
  }
  for (const match of source.matchAll(/\b[A-Za-z_]\w*\.include_router\s*\(/g)) {
    const open = (match.index ?? 0) + match[0].lastIndexOf('('); const close = closingParenthesis(source, open); if (close === undefined) continue
    const args = topLevelArguments(source, open + 1, close); if (!explicitAuthorization(source.slice(open + 1, close))) continue
    for (const argument of args) if (routers.has(argument.text)) protectedRouters.add(argument.text)
  }
  return protectedRouters
}

function analyzePythonRouteAuthorization(file: string, content: string): Candidate[] {
  const lines = content.split(/\r?\n/); const candidates: Candidate[] = []; const protectedRouters = protectedPythonRouters(content)
  for (const match of content.matchAll(/@([A-Za-z_]\w*)\.(?:post|put|patch|delete)\s*\(/gi)) {
    const receiver = match[1]!; const start = match.index ?? 0; const open = start + match[0].lastIndexOf('('); const close = closingParenthesis(content, open); if (close === undefined) continue
    const routeArguments = content.slice(open + 1, close); if (!/^\s*['"]/.test(routeArguments)) continue
    const following = content.slice(close + 1, close + 1 + 2_000); const header = /(?:^|\n)\s*(?:async\s+)?def\s+[A-Za-z_]\w*\s*\(([\s\S]{0,1200}?)\)\s*(?:->[^:\n]+)?\s*:/.exec(following)
    if (!header) continue
    const decorators = following.slice(0, header.index); const protectedRoute = protectedRouters.has(receiver) || explicitAuthorization(routeArguments) || explicitAuthorization(decorators) || explicitAuthorization(header[1] ?? '')
    if (!protectedRoute) candidates.push(frameworkRouteCandidate(file, lines, start, 'FastAPI-style route analysis found a state-changing handler without an explicit route, decorator, parameter dependency, or explicit protected-router authorization control.'))
  }
  return candidates
}

function contiguousLeadingAnnotations(content: string, position: number): string {
  const lines = content.slice(0, position).split(/\r?\n/); const values: string[] = []
  for (let index = lines.length - 1; index >= 0; index--) {
    const value = lines[index]!.trim()
    if (!value) continue
    if (!value.startsWith('@')) break
    values.unshift(value)
  }
  return values.join('\n')
}

function closingBrace(source: string, open: number): number | undefined {
  let depth = 0; let quote = ''
  for (let index = open; index < source.length; index++) {
    const character = source[index]
    if (quote) { if (character === quote && source[index - 1] !== '\\') quote = ''; continue }
    if (character === '"' || character === "'" || character === '`') { quote = character; continue }
    if (character === '{') depth++
    if (character === '}' && --depth === 0) return index
  }
  return undefined
}

function classAuthorizationAt(source: string, position: number): boolean {
  for (const match of source.matchAll(/\bclass\s+[A-Za-z_]\w*(?:\s+(?:extends|implements)\s+[^\{]+)?\s*\{/g)) {
    const start = match.index ?? 0; const open = start + match[0].lastIndexOf('{'); const close = closingBrace(source, open)
    if (close !== undefined && position > open && position < close) return explicitAuthorization(contiguousLeadingAnnotations(source, start))
  }
  return false
}

function analyzeJavaRouteAuthorization(file: string, content: string): Candidate[] {
  const lines = content.split(/\r?\n/); const candidates: Candidate[] = []
  const mapping = /@(PostMapping|PutMapping|PatchMapping|DeleteMapping|RequestMapping)\b(?:\s*\(([^)]*)\))?/gi
  for (const match of content.matchAll(mapping)) {
    const method = match[1]!.toLowerCase(); const argumentsText = match[2] ?? ''
    if (method === 'requestmapping' && !/RequestMethod\.(?:POST|PUT|PATCH|DELETE)\b/i.test(argumentsText)) continue
    const start = match.index ?? 0; const following = content.slice(start + match[0].length, start + match[0].length + 2_000)
    const header = /(?:^|\n)\s*(?:public|protected|private)?\s*(?:static\s+)?[\w<>\[\],? ]+\s+[A-Za-z_]\w*\s*\([^)]*\)\s*(?:throws\s+[\w,. ]+)?\{/.exec(following)
    if (!header) continue
    const annotations = `${contiguousLeadingAnnotations(content, start)}\n${following.slice(0, header.index)}`
    if (!classAuthorizationAt(content, start) && !explicitAuthorization(annotations)) candidates.push(frameworkRouteCandidate(file, lines, start, 'Spring-style route analysis found a state-changing handler without an explicit method or enclosing-class authorization annotation.'))
  }
  return candidates
}

function analyzeFrameworkRouteAuthorization(file: string, content: string, onlyRules?: Set<string>): Candidate[] {
  if (onlyRules && !onlyRules.has(ROUTE_AUTHORIZATION_RULE.id)) return []
  const language = languageFor(file)
  if (language === 'python') return analyzePythonRouteAuthorization(file, content)
  if (language === 'java') return analyzeJavaRouteAuthorization(file, content)
  return []
}

function pythonJwtConfigurationCandidates(file: string, content: string, lines: string[]): Candidate[] {
  const candidates: Candidate[] = []; const options = new Map<string, { line: number; excerpt: string }>()
  for (const match of content.matchAll(/\b([A-Za-z_]\w*)\s*=\s*\{([\s\S]{0,1200}?)\}/g)) {
    const control = /["']verify_signature["']\s*:\s*False\b/i.exec(match[2])
    if (!control) continue
    const number = lineAt(content, (match.index ?? 0) + match[0].indexOf(match[2]) + (control.index ?? 0))
    options.set(match[1], { line: number, excerpt: sourceLine(lines, number) })
  }
  for (const match of content.matchAll(/\bjwt\.(?:decode|verify)\s*\(/gi)) {
    const open = (match.index ?? 0) + match[0].lastIndexOf('('); const close = closingParenthesis(content, open)
    if (close === undefined || close - open > 4_000) continue
    const call = content.slice(open, close + 1); const callLine = lineAt(content, match.index ?? 0); const callExcerpt = sourceLine(lines, callLine)
    const controls: Array<{ line: number; excerpt: string; detail: string }> = []
    const direct = /\bverify\s*=\s*False\b/i.exec(call)
    if (direct) { const line = lineAt(content, open + (direct.index ?? 0)); controls.push({ line, excerpt: sourceLine(lines, line), detail: 'JWT call explicitly sets verify=False.' }) }
    const inlineOptions = /\boptions\s*=\s*\{([\s\S]{0,1200}?)\}/i.exec(call)
    const inlineControl = inlineOptions && /["']verify_signature["']\s*:\s*False\b/i.exec(inlineOptions[1])
    if (inlineOptions && inlineControl) { const line = lineAt(content, open + (inlineOptions.index ?? 0) + inlineOptions[0].indexOf(inlineOptions[1]) + (inlineControl.index ?? 0)); controls.push({ line, excerpt: sourceLine(lines, line), detail: 'JWT call passes options with verify_signature disabled.' }) }
    const namedOptions = /\boptions\s*=\s*([A-Za-z_]\w*)\b/i.exec(call)?.[1]; const bound = namedOptions ? options.get(namedOptions) : undefined
    if (bound) controls.push({ ...bound, detail: `JWT call passes local options object ${namedOptions} with verify_signature disabled.` })
    const noneAlgorithm = /\balgorithms\s*=\s*\[[^\]]*["']none["'][^\]]*\]/i.exec(call)
    if (noneAlgorithm) { const line = lineAt(content, open + (noneAlgorithm.index ?? 0)); controls.push({ line, excerpt: sourceLine(lines, line), detail: 'JWT call allows the unsigned none algorithm.' }) }
    for (const control of controls) {
      const candidate = configurationCandidate(CONFIGURATION_RULES.jwt, file, lines, control.line, `Configuration analysis found ${control.detail}`)
      candidate.evidence.push({ kind: 'context', detail: 'The disabled JWT verification control is used by this PyJWT decode or verify call.', location: { file, line: callLine, excerpt: callExcerpt, role: 'sink' } })
      candidates.push(candidate)
    }
  }
  return candidates
}

/**
 * Keep Python TLS findings tied to an actual requests/httpx operation.  A
 * disabled value in an unrelated mapping or another library's function is not
 * proof that certificate verification is disabled on an outbound connection.
 */
function pythonTlsConfigurationCandidates(file: string, content: string, lines: string[]): Candidate[] {
  const options = new Map<string, { line: number; excerpt: string }>()
  for (const match of content.matchAll(/\b([A-Za-z_]\w*)\s*=\s*\{([\s\S]{0,1200}?)\}/g)) {
    const disabled = /["']verify["']\s*:\s*False\b/i.exec(match[2])
    if (!disabled) continue
    const line = lineAt(content, (match.index ?? 0) + match[0].indexOf(match[2]) + (disabled.index ?? 0))
    options.set(match[1], { line, excerpt: sourceLine(lines, line) })
  }
  const candidates: Candidate[] = []
  for (const match of content.matchAll(/\b(?:requests|httpx)\.(?:get|post|put|patch|delete|head|options|request)\s*\(/gi)) {
    const open = (match.index ?? 0) + match[0].lastIndexOf('('); const close = closingParenthesis(content, open)
    if (close === undefined || close - open > 4_000) continue
    const call = content.slice(open, close + 1); const callLine = lineAt(content, match.index ?? 0); const callExcerpt = sourceLine(lines, callLine)
    const controls: Array<{ line: number; excerpt: string; detail: string }> = []
    const direct = /\bverify\s*=\s*False\b/i.exec(call)
    if (direct) {
      const line = lineAt(content, open + (direct.index ?? 0))
      controls.push({ line, excerpt: sourceLine(lines, line), detail: 'the request explicitly sets verify=False' })
    }
    const named = /\*\*\s*([A-Za-z_]\w*)\b/.exec(call)?.[1]; const bound = named ? options.get(named) : undefined
    if (bound) controls.push({ ...bound, detail: `the request expands local options object ${named} with verify disabled` })
    for (const control of controls) {
      const candidate = configurationCandidate(CONFIGURATION_RULES.tls, file, lines, control.line, `Configuration analysis found ${control.detail}.`)
      candidate.evidence.push({ kind: 'context', detail: 'The disabled verification setting is consumed by this supported requests/httpx outbound call.', location: { file, line: callLine, excerpt: callExcerpt, role: 'sink' } })
      candidates.push(candidate)
    }
  }
  return candidates
}

/**
 * A credential finding is evidence-bearing only when source assigns a
 * non-placeholder literal to a field whose name denotes credential material.
 * Runtime/environment lookups and comments deliberately remain out of scope.
 */
function embeddedCredentialCandidates(file: string, content: string, lines: string[]): Candidate[] {
  const candidates: Candidate[] = []
  const assignment = /(?:\b[A-Za-z_$][\w$]*\s*\.\s*)?\$?([A-Za-z_$][\w$]*)\s*(?::=|=|:)\s*(["'])((?:\\.|(?!\2)[\s\S])*)\2/g
  for (const match of content.matchAll(assignment)) {
    const offset = match.index ?? 0; const number = lineAt(content, offset); const excerpt = sourceLine(lines, number)
    if (/^\s*(?:\/\/|#|\/\*|\*)/.test(excerpt) || !SECRET_FIELD_NAME.test(match[1]!)) continue
    const value = match[3]!.replace(/\\(?:[\\'"nrt])/g, '').trim()
    if (value.length < 8 || PLACEHOLDER_SECRET_VALUE.test(value)) continue
    const candidate = configurationCandidate({ id: 'hardcoded-secret-marker', cwe: 'CWE-798', severity: 'medium', rationale: 'A credential-named field contains a non-placeholder string literal that should be moved to managed secret storage.' }, file, lines, number, `Configuration analysis found a ${match[1]} field assigned a non-placeholder embedded credential literal.`)
    candidate.evidence.push({ kind: 'context', detail: `The embedded literal is ${value.length} characters; no environment or secret-manager reference is present in this assignment.`, location: { file, line: number, excerpt, role: 'sink' } })
    candidates.push(candidate)
  }
  return candidates
}

/**
 * Reconstruct the ordinary local Go construction chain from tls.Config through
 * http.Transport and http.Client to a request. This deliberately leaves
 * dynamic, cross-function, and opaque client construction unresolved.
 */
function goTlsConfigurationCandidates(file: string, content: string, lines: string[]): Candidate[] {
  const candidates: Candidate[] = []
  for (const match of content.matchAll(/\b([A-Za-z_]\w*)\s*:=\s*&?tls\.Config\s*\{([\s\S]{0,1200}?)\}/g)) {
    const disabled = /\bInsecureSkipVerify\s*:\s*true\b/i.exec(match[2]); if (!disabled) continue
    const config = match[1]!; const start = match.index ?? 0; const block = containingJavaBlock(content, start); if (!block) continue
    const window = content.slice(block.start, block.end); const configOffset = start - block.start
    const configLine = lineAt(content, start + match[0].indexOf(match[2]) + (disabled.index ?? 0))
    const transports = new Map<string, number>()
    const transportPattern = /\b([A-Za-z_]\w*)\s*:=\s*&?http\.Transport\s*\{([\s\S]{0,1200}?)\}/g
    for (const transport of window.matchAll(transportPattern)) {
      const bindsConfig = transport[2].replace(/\s+/g, '').includes(`TLSClientConfig:${config}`) || transport[2].replace(/\s+/g, '').includes(`TLSClientConfig:&${config}`)
      if ((transport.index ?? 0) <= configOffset || !bindsConfig) continue
      transports.set(transport[1]!, block.start + (transport.index ?? 0))
    }
    for (const [transport, transportOffset] of transports) {
      const clients = new Map<string, number>()
      const clientPattern = /\b([A-Za-z_]\w*)\s*:=\s*&?http\.Client\s*\{([\s\S]{0,1200}?)\}/g
      for (const client of window.matchAll(clientPattern)) {
        const bindsTransport = client[2].replace(/\s+/g, '').includes(`Transport:${transport}`) || client[2].replace(/\s+/g, '').includes(`Transport:&${transport}`)
        if ((client.index ?? 0) <= transportOffset - block.start || !bindsTransport) continue
        clients.set(client[1]!, block.start + (client.index ?? 0))
      }
      for (const [client, clientOffset] of clients) {
        const invocation = new RegExp(`\\b${client}\\.(?:Get|Post|Head|Do)\\s*\\(`).exec(window.slice(clientOffset - block.start))
        if (!invocation) continue
        const sinkOffset = clientOffset + (invocation.index ?? 0); const sinkLine = lineAt(content, sinkOffset); const sinkExcerpt = sourceLine(lines, sinkLine)
        const candidate = configurationCandidate(CONFIGURATION_RULES.tls, file, lines, configLine, `Configuration analysis found tls.Config ${config} disabling certificate verification before a supported Go HTTP client request.`)
        candidate.evidence.push({ kind: 'context', detail: `The disabled tls.Config is attached to http.Transport ${transport}, http.Client ${client}, and a supported client request.`, location: { file, line: sinkLine, excerpt: sinkExcerpt, role: 'sink' } })
        candidates.push(candidate)
      }
    }
  }
  return candidates
}

function containingJavaBlock(source: string, offset: number): { start: number; end: number } | undefined {
  for (let open = source.lastIndexOf('{', offset); open >= 0; open = source.lastIndexOf('{', open - 1)) {
    const end = closingBrace(source, open)
    if (end !== undefined && end >= offset) return { start: open + 1, end }
  }
  return undefined
}

/** Analyze security-sensitive configuration blocks that require paired controls. */
function analyzeSecurityConfiguration(file: string, content: string, onlyRules?: Set<string>): Candidate[] {
  const lines = content.split(/\r?\n/); const candidates: Candidate[] = []
  const enabled = (rule: ConfigurationRule): boolean => !onlyRules || onlyRules.has(rule.id)
  if (enabled(CONFIGURATION_RULES.jwt) && languageFor(file) === 'python') candidates.push(...pythonJwtConfigurationCandidates(file, content, lines))
  if ((!onlyRules || onlyRules.has('hardcoded-secret-marker')) && !['javascript', 'typescript'].includes(languageFor(file))) candidates.push(...embeddedCredentialCandidates(file, content, lines))
  if (enabled(CONFIGURATION_RULES.tls) && languageFor(file) === 'python') candidates.push(...pythonTlsConfigurationCandidates(file, content, lines))
  if (enabled(CONFIGURATION_RULES.tls) && languageFor(file) === 'go') candidates.push(...goTlsConfigurationCandidates(file, content, lines))
  if (enabled(CONFIGURATION_RULES.cors) && !['javascript', 'typescript'].includes(languageFor(file))) {
    for (const match of content.matchAll(/\bcors\s*\(\s*\{([\s\S]{0,1200}?)\}\s*\)/gi)) {
      const block = match[1]
      const credential = /\b(?:credentials|supportsCredentials)\s*:\s*true\b|Access-Control-Allow-Credentials\s*['":=]+\s*['"]true/i.exec(block)
      const origin = /\b(?:origin|origins)\s*:\s*(?:['"]\*['"]|true)\b|Access-Control-Allow-Origin\s*['":=]+\s*['"]\*/i.exec(block)
      if (!credential || !origin) continue
      const base = (match.index ?? 0) + match[0].indexOf(block); const originLine = lineAt(content, base + (origin.index ?? 0)); const controlLine = lineAt(content, base + (credential.index ?? 0))
      const candidate = configurationCandidate(CONFIGURATION_RULES.cors, file, lines, originLine, 'Configuration analysis found a wildcard or reflected CORS origin paired with credential support in one CORS policy.')
      candidate.evidence.push({ kind: 'context', detail: 'Credential support is configured in the same effective CORS policy.', location: { file, line: controlLine, excerpt: sourceLine(lines, controlLine), role: 'expected_control' } })
      candidates.push(candidate)
    }
  }
  if (enabled(CONFIGURATION_RULES.xml) && languageFor(file) === 'java') {
    for (const match of content.matchAll(/\b(?:DocumentBuilderFactory|SAXParserFactory|XMLInputFactory)\s+(\w+)\s*=\s*(?:DocumentBuilderFactory\.newInstance|SAXParserFactory\.newInstance|XMLInputFactory\.newFactory)\s*\(\s*\)/g)) {
      const variable = match[1]; const start = match.index ?? 0; const block = containingJavaBlock(content, start)
      if (!block) continue
      const window = content.slice(start, block.end)
      const builder = new RegExp(`\\b${variable}\\.(?:newDocumentBuilder|newSAXParser|createXMLStreamReader)\\s*\\(`).exec(window)
      if (!builder) continue
      const hardening = new RegExp(`\\b${variable}\\.(?:setFeature|setAttribute|setProperty)\\s*\\([\\s\\S]{0,500}?(?:disallow-doctype-decl|external-general-entities|external-parameter-entities|ACCESS_EXTERNAL_(?:DTD|SCHEMA)|SUPPORT_DTD|IS_SUPPORTING_EXTERNAL_ENTITIES)`, 'i').exec(window.slice(0, builder.index))
      if (hardening) continue
      const line = lineAt(content, start + builder.index)
      candidates.push(configurationCandidate(CONFIGURATION_RULES.xml, file, lines, line, `Configuration analysis found ${variable} creating an XML parser without a recognized external-entity hardening control before parser creation.`))
    }
  }
  const unique = new Map<string, Candidate>(); for (const item of candidates) unique.set(`${item.rule}:${item.file}:${item.line}`, item)
  return [...unique.values()]
}

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
    if (['javascript', 'typescript'].includes(language) && new Set(['dangerous-dynamic-code', 'shell-command-construction', 'path-traversal-sink', 'ssrf-request-sink', 'sql-injection-query-construction']).has(rule.id)) { receipts.push({ ruleId: rule.id, pass, matches: 0 }); continue }
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
  const configuration = analyzeSecurityConfiguration(rel, content, onlyRules)
  candidates.push(...configuration)
  for (const rule of Object.values(CONFIGURATION_RULES)) if (!onlyRules || onlyRules.has(rule.id)) receipts.push({ ruleId: rule.id, pass, matches: configuration.filter(item => item.rule === rule.id).length })
  const routes = analyzeRouteAuthorization(rel, content, onlyRules)
  const frameworkRoutes = analyzeFrameworkRouteAuthorization(rel, content, onlyRules)
  candidates.push(...routes, ...frameworkRoutes)
  if (!onlyRules || onlyRules.has(ROUTE_AUTHORIZATION_RULE.id)) receipts.push({ ruleId: ROUTE_AUTHORIZATION_RULE.id, pass, matches: routes.length + frameworkRoutes.length })
  return { candidates, receipts }
}

export async function assessDirectory(directory: string, limits: ScanLimits, deep = false): Promise<ScanResult> {
  const root = resolve(directory); const { files, skipped, complete } = await collectFiles(root, limits); const candidates: Candidate[] = []; const ruleReceipts: RuleReceipt[] = []; const fileReceipts: FileReceipt[] = []; const policyFiles: string[] = []; const modules: JavaScriptModule[] = []; const pythonModules: Array<{ file: string; source: string }> = []; const goModules: Array<{ file: string; source: string; modulePath?: string }> = []; const goModuleCache = new Map<string, string | undefined>(); const structuredModules: Record<StructuredLanguage, Array<{ file: string; source: string }>> = { java: [], csharp: [], php: [], ruby: [], c: [], cpp: [], rust: [] }; const passes = deep ? [['baseline', undefined], ['injection', new Set(['dangerous-dynamic-code', 'shell-command-construction'])], ['boundaries', new Set(['path-traversal-sink', 'ssrf-request-sink', 'tls-verification-disabled', 'hardcoded-secret-marker'])]] as const : [['baseline', undefined]] as const
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
      ruleReceipts.push({ ruleId: 'ast.cors-configuration', pass: 'semantic', matches: ast.candidates.filter(candidate => candidate.rule === 'cors-wildcard-credentials').length })
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
  return { root, filesScanned: files.length, filesSkipped: skipped, candidates: dedupeCandidateObservations(candidates), receipts: fileReceipts, ruleReceipts, policyFiles, complete }
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
interface WorkflowEnvironment { name: string; line: WorkflowLine }

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
  const jobsIndent = lines[jobsIndex].indent; const steps: WorkflowStep[] = []; let job = 'unknown'; let stepsIndent = -1; let stepStart = -1; let stepIndent = -1
  const closeStep = (end: number): void => {
    if (stepStart < 0) return
    steps.push({ job, start: lines[stepStart].line, end: lines[Math.max(stepStart, end - 1)].line, indent: stepIndent, fields: lines.slice(stepStart, end) })
    stepStart = -1; stepIndent = -1
  }
  for (let index = jobsIndex + 1; index < lines.length; index++) {
    const line = lines[index]
    if (line.text && line.indent <= jobsIndent) { closeStep(index); break }
    if (line.text && line.indent === jobsIndent + 2 && /^[A-Za-z0-9_-]+\s*:/.test(line.text)) { closeStep(index); job = line.text.replace(/\s*:.*$/, ''); stepsIndent = -1; continue }
    if (/^steps\s*:\s*(?:#.*)?$/i.test(line.text) && line.indent > jobsIndent + 2) { closeStep(index); stepsIndent = line.indent; continue }
    if (/^-\s+/.test(line.text) && stepsIndent >= 0 && line.indent === stepsIndent + 2) { closeStep(index); stepStart = index; stepIndent = line.indent }
  }
  closeStep(lines.length)
  return steps
}

function isUntrustedEvent(value: string | undefined): boolean { return !!value && /\$\{\{\s*github\.event\.(?:pull_request|issue|comment)\./i.test(value) }
function isMutableAction(value: string | undefined): boolean { return !!value && /@(?:main|master|develop|next|latest)\s*$/i.test(value) }
function addedLine(line: WorkflowLine, added: Set<number>): boolean { return added.has(line.line) }

interface WorkflowShellFlow { entry: WorkflowLine; sink: WorkflowLine; detail: string }
interface WorkflowEnvironmentWrite extends WorkflowEnvironment { stepStart: number }

function runLines(step: WorkflowStep): Array<{ run: WorkflowLine; body: WorkflowLine[] }> {
  const results: Array<{ run: WorkflowLine; body: WorkflowLine[] }> = []
  for (let index = 0; index < step.fields.length; index++) {
    const line = step.fields[index]; const value = valueAfterKey(line, 'run')
    if (value === undefined) continue
    const body: WorkflowLine[] = [line]
    if (/^[>|]/.test(value)) for (let child = index + 1; child < step.fields.length && step.fields[child].indent > line.indent; child++) body.push(step.fields[child])
    results.push({ run: line, body })
  }
  return results
}

function stepUntrustedEnvironment(step: WorkflowStep): WorkflowEnvironment[] {
  const values: WorkflowEnvironment[] = []
  for (let index = 0; index < step.fields.length; index++) {
    const environment = step.fields[index]
    if (valueAfterKey(environment, 'env') !== '') continue
    for (let child = index + 1; child < step.fields.length && step.fields[child].indent > environment.indent; child++) {
      const match = /^([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.*)$/.exec(step.fields[child].text)
      if (match && isUntrustedEvent(match[2])) values.push({ name: match[1], line: step.fields[child] })
    }
  }
  return values
}

function stepEnvironmentNames(step: WorkflowStep): Set<string> {
  const names = new Set<string>()
  for (let index = 0; index < step.fields.length; index++) {
    const environment = step.fields[index]
    if (valueAfterKey(environment, 'env') !== '') continue
    for (let child = index + 1; child < step.fields.length && step.fields[child].indent > environment.indent; child++) {
      const match = /^([A-Za-z_][A-Za-z0-9_]*)\s*:/.exec(step.fields[child].text)
      if (match) names.add(match[1])
    }
  }
  return names
}

/** Parse direct job-level env mappings only; cross-job and transformed values remain unproven. */
function jobUntrustedEnvironment(source: string): Map<string, WorkflowEnvironment[]> {
  const lines = workflowLines(source); const jobsIndex = lines.findIndex(line => /^jobs\s*:\s*(?:#.*)?$/i.test(line.text)); const environments = new Map<string, WorkflowEnvironment[]>()
  if (jobsIndex < 0) return environments
  const jobsIndent = lines[jobsIndex].indent
  for (let index = jobsIndex + 1; index < lines.length;) {
    const jobLine = lines[index]
    if (jobLine.text && jobLine.indent <= jobsIndent) break
    if (!(jobLine.text && jobLine.indent === jobsIndent + 2 && /^[A-Za-z0-9_-]+\s*:/.test(jobLine.text))) { index++; continue }
    const job = jobLine.text.replace(/\s*:.*$/, ''); let jobEnd = index + 1
    while (jobEnd < lines.length && (!lines[jobEnd].text || lines[jobEnd].indent > jobsIndent + 2)) jobEnd++
    const values: WorkflowEnvironment[] = []
    for (let field = index + 1; field < jobEnd; field++) {
      const environment = lines[field]
      if (environment.indent !== jobsIndent + 4 || !/^env\s*:\s*(?:#.*)?$/i.test(environment.text)) continue
      for (let child = field + 1; child < jobEnd && lines[child].indent > environment.indent; child++) {
        const match = /^([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.*)$/.exec(lines[child].text)
        if (match && isUntrustedEvent(match[2])) values.push({ name: match[1], line: lines[child] })
      }
    }
    if (values.length) environments.set(job, values)
    index = jobEnd
  }
  return environments
}

/**
 * Track only a direct event-expression assignment appended to GITHUB_ENV. The
 * runner applies this file between steps, so a value becomes available solely
 * to later steps in the same job. Shell transformations and other environment
 * files are intentionally outside this static proof boundary.
 */
function githubEnvironmentWrites(steps: WorkflowStep[]): Map<string, WorkflowEnvironmentWrite[]> {
  const writes = new Map<string, WorkflowEnvironmentWrite[]>()
  for (const step of steps) {
    for (const { body } of runLines(step)) {
      for (const line of body) {
        const match = /^echo\s+(["'])?([A-Za-z_][A-Za-z0-9_]*)=(\$\{\{\s*github\.event\.(?:pull_request|issue|comment)\.[^}]+\}\})\1?\s*>>\s*(?:["']?\$GITHUB_ENV["']?|\$\{GITHUB_ENV\})\s*$/i.exec(line.text)
        if (!match) continue
        const values = writes.get(step.job) ?? []
        values.push({ name: match[2], line, stepStart: step.start })
        writes.set(step.job, values)
      }
    }
  }
  return writes
}

function environmentReference(value: string, name: string): boolean {
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  return new RegExp(`(?:\\$${escaped}\\b|\\$\\{${escaped}(?:[?:+\-][^}]*)?\\}|\\$\\{\\{\\s*env\\.${escaped}\\s*\\}\\})`).test(value)
}

function writesRunnerEnvironment(line: WorkflowLine): boolean {
  return />>\s*(?:["']?\$GITHUB_(?:ENV|OUTPUT)["']?|\$\{GITHUB_(?:ENV|OUTPUT)\})\s*$/i.test(line.text)
}

function untrustedShellFlows(step: WorkflowStep, jobEnvironment: WorkflowEnvironment[] = [], githubEnvironment: WorkflowEnvironmentWrite[] = []): WorkflowShellFlow[] {
  const flows: WorkflowShellFlow[] = []
  const stepEnvironment = stepUntrustedEnvironment(step)
  const stepOverrides = stepEnvironmentNames(step)
  const environments = [...stepEnvironment, ...jobEnvironment.filter(environment => !stepOverrides.has(environment.name)), ...githubEnvironment.filter(environment => environment.stepStart < step.start && !stepOverrides.has(environment.name))]
  for (const { run, body } of runLines(step)) {
    for (const line of body) if (isUntrustedEvent(line.text) && !writesRunnerEnvironment(line)) flows.push({ entry: line, sink: line, detail: 'shell command interpolates untrusted GitHub event data directly' })
    for (const environment of environments) {
      const sink = body.find(line => environmentReference(line.text, environment.name))
      if (sink) flows.push({ entry: environment.line, sink, detail: `shell command references ${environment.name}, which is assigned from untrusted GitHub event data ${stepEnvironment.includes(environment) ? 'in the same step' : 'stepStart' in environment ? `through GITHUB_ENV in an earlier step of job ${step.job}` : `at job scope for ${step.job}`}` })
    }
  }
  const unique = new Map<string, WorkflowShellFlow>(); for (const flow of flows) unique.set(`${flow.entry.line}:${flow.sink.line}`, flow)
  return [...unique.values()]
}

function workflowShellCandidate(file: string, flow: WorkflowShellFlow, added: Set<number>): Candidate | undefined {
  const anchor = addedLine(flow.sink, added) ? flow.sink : addedLine(flow.entry, added) ? flow.entry : undefined
  if (!anchor) return undefined
  const rule = CI_WORKFLOW_RULES['untrusted-shell']
  return { rule: rule.id, severity: rule.severity, file, line: anchor.line, excerpt: anchor.text.slice(0, 240), rationale: rule.rationale, cwe: rule.cwe, evidence: [
    { kind: 'pattern', detail: `pull_request_target ${flow.detail}.`, location: { file, line: flow.sink.line, excerpt: flow.sink.text.slice(0, 240), role: 'sink' } },
    { kind: 'context', detail: 'The event-derived value is the source for this shell execution path.', location: { file, line: flow.entry.line, excerpt: flow.entry.text.slice(0, 240), role: 'entrypoint' } },
    { kind: 'context', detail: 'This CI/CD workflow finding is anchored to a newly added diff line.', location: { file, line: anchor.line, excerpt: anchor.text.slice(0, 240), role: anchor === flow.sink ? 'sink' : 'entrypoint' } },
  ] }
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
    const steps = workflowSteps(currentSource); const jobEnvironment = jobUntrustedEnvironment(currentSource); const githubEnvironment = githubEnvironmentWrites(steps)
    for (const permission of writePermissionLines(currentSource).filter(line => addedLine(line, addedNumbers))) candidates.push(workflowCandidate(CI_WORKFLOW_RULES['write-permissions'], file, permission.line, permission.text.slice(0, 240), `Current pull_request_target trigger at ${file}:${pullRequestTarget.line} has newly added write permission at ${file}:${permission.line}.`, 'root_control'))
    for (const step of steps) {
      for (const flow of untrustedShellFlows(step, jobEnvironment.get(step.job), githubEnvironment.get(step.job))) { const candidate = workflowShellCandidate(file, flow, addedNumbers); if (candidate) candidates.push(candidate) }
      const checkout = step.fields.find(line => /^-\s*uses\s*:\s*actions\/checkout@/i.test(line.text))
      const untrustedCheckoutField = checkout && step.fields.find(line => /^(?:ref|repository)\s*:/i.test(line.text) && isUntrustedEvent(valueAfterKey(line, 'ref') ?? valueAfterKey(line, 'repository')))
      if (!checkout || !untrustedCheckoutField) continue
      const laterRun = steps.flatMap(other => other.job === step.job && other.start > step.start ? other.fields.filter(line => valueAfterKey(line, 'run') !== undefined) : [])
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
  const javascriptModules = modules.filter(module => ['.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx'].includes(extname(module.file)))
  const javascriptGraph = analyzeJavaScriptModuleGraph(javascriptModules)
  const javascriptLocal = javascriptModules.map(module => analyzeJavaScriptAst(module.source, module.file))
  const javascriptCandidates = dedupeCandidateObservations([...javascriptGraph.candidates, ...javascriptLocal.flatMap(result => result.candidates)])
  const python = analyzePythonModuleGraph(modules.filter(module => extname(module.file) === '.py'))
  const go = analyzeGoPackageGraph(modules.filter(module => extname(module.file) === '.go'))
  const structuredInputs: Record<StructuredLanguage, Array<{ file: string; source: string }>> = { java: [], csharp: [], php: [], ruby: [], c: [], cpp: [], rust: [] }
  for (const module of modules) {
    const language = ({ '.java': 'java', '.cs': 'csharp', '.php': 'php', '.rb': 'ruby', '.c': 'c', '.cc': 'cpp', '.cpp': 'cpp', '.rs': 'rust' } as Record<string, StructuredLanguage>)[extname(module.file)]
    if (language) structuredInputs[language].push(module)
  }
  const structured = Object.fromEntries((Object.keys(structuredInputs) as StructuredLanguage[]).map(language => [language, analyzeStructuredFlow(structuredInputs[language], language).candidates])) as Record<StructuredLanguage, Candidate[]>
  const byEngine: Record<string, Candidate[]> = { 'ast.diff-semantic-taint': javascriptCandidates, 'python.diff-semantic-taint': python.candidates, 'go.diff-semantic-taint': go.candidates, ...Object.fromEntries((Object.keys(structured) as StructuredLanguage[]).map(language => [`${language}.diff-semantic-taint`, structured[language]])) }
  const counts: Record<string, number> = {}; const candidates: Candidate[] = []
  for (const [engine, results] of Object.entries(byEngine)) { const retained = results.filter(candidate => candidateTouchesAddedLine(candidate, addedLines)); counts[engine] = retained.length; candidates.push(...retained) }
  return { candidates, counts, parseErrors: javascriptGraph.parseErrors.length + javascriptLocal.filter(result => result.parseError).length }
}

export async function runScan(directory: string, limits: ScanLimits, mode: 'standard' | 'deep', threatModel: string, scopeRequested = false, stateDirectory = '', automaticValidation = false): Promise<ScanRecord> {
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

export async function runDiffScan(workspace: string, base: string | undefined, threatModel: string, stateDirectory = '', automaticValidation = false): Promise<ScanRecord> {
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
  const configurationRuleIds = new Set(Object.values(CONFIGURATION_RULES).map(rule => rule.id))
  for (const file of addedSourceMap.keys()) {
    try {
      const content = await readFile(join(resolve(workspace), file), 'utf8')
      const configuration = analyzeText(resolve(workspace), join(resolve(workspace), file), content, 'diff-configuration', configurationRuleIds).candidates
      candidates.push(...configuration.filter(candidate => candidateTouchesAddedLine(candidate, addedLineMap)))
    } catch { /* Deleted or unreadable paths cannot provide current configuration evidence. */ }
  }
  for (const path of [...changedPaths].sort()) { const patch = review.diff.split(`diff --git a/${path} b/${path}`)[1] ?? ''; receipts.push({ path, bytes: Buffer.byteLength(patch, 'utf8'), sha256: sha256(patch), language: languageFor(path) }) }
  for (const rule of [...RULES.map(rule => rule.id), ...REMOVED_CONTROL_RULES.map(rule => rule.id), ...Object.values(CI_WORKFLOW_RULES).map(rule => rule.id)]) ruleReceipts.push({ ruleId: rule, pass: 'diff', matches: candidates.filter(candidate => candidate.rule === rule).length })
  for (const [ruleId, matches] of Object.entries(semantic.counts)) ruleReceipts.push({ ruleId, pass: 'semantic', matches }); if (semantic.parseErrors) ruleReceipts.push({ ruleId: 'ast.diff-semantic-parse-error', pass: 'semantic', matches: semantic.parseErrors })
  const root = resolve(workspace); const now = new Date().toISOString(); const findings = reduceCandidates(candidates); if (automaticValidation) { for (const finding of findings) validateCandidate(finding); for (const finding of findings) analyzeAttackPath(finding) }; const policy = await resolvePolicyGuidance(root); const id = createScanId(); const closed = findings.every(finding => finding.ledger.some(row => row.phase === 'validation') && (finding.disposition !== 'reportable' || finding.ledger.some(row => row.phase === 'attack_path'))); const complete = !review.truncated && closed; const [head, baseRevision, remote] = await Promise.all([execFileAsync('git', ['rev-parse', '--verify', 'HEAD'], { cwd: root, encoding: 'utf8' }).catch(() => ({ stdout: '' })), base ? execFileAsync('git', ['rev-parse', '--verify', base], { cwd: root, encoding: 'utf8' }).catch(() => ({ stdout: '' })) : Promise.resolve({ stdout: '' }), execFileAsync('git', ['config', '--get', 'remote.origin.url'], { cwd: root, encoding: 'utf8' }).catch(() => ({ stdout: '' }))]); const remoteValue = remote.stdout.trim().replace(/^[^@]+@/, '').replace(/[?#].*$/, ''); const record: ScanRecord = { schemaVersion: 3, id, mode: 'diff', lifecycle: automaticValidation ? complete ? 'completed' : 'incomplete' : 'validation', target: root, targetSnapshot: { kind: 'git_diff', targetId: `dsh-security-suite-target/v1:sha256:${sha256(remoteValue || root)}`, displayName: basename(root) || root, baseRevision: baseRevision.stdout.trim() || undefined, headRevision: head.stdout.trim() || undefined, snapshotDigest: `dsh-security-suite-snapshot/v1:sha256:${sha256(review.diff)}` }, createdAt: now, completedAt: automaticValidation ? new Date().toISOString() : undefined, threatModel: threatModel || 'Review changed behavior for attacker-controlled inputs, authorization boundaries, sensitive sinks, and CI/CD trust boundaries.', policyGuidance: policy.text, preflight: { status: review.truncated ? 'warn' : 'ready', checks: [{ id: 'git-diff', status: review.truncated ? 'warn' : 'pass', detail: `Reviewed ${review.mode}; ${changedPaths.size} changed source path(s) received.` }, { id: 'semantic-diff', status: semantic.parseErrors ? 'warn' : 'pass', detail: `Analyzed current local JS/TS, Python, Go, Java, C#, PHP, Ruby, C, C++, and Rust modules; retained ${semantic.candidates.length} finding(s) anchored to added lines.${semantic.parseErrors ? ` ${semantic.parseErrors} JS/TS module parse error(s) were retained as coverage limitations.` : ''}` }, { id: 'ci-workflow-diff', status: 'pass', detail: `Analyzed ${[...addedSourceMap.keys()].filter(isGitHubWorkflow).length} changed GitHub Actions workflow(s) for untrusted event shell, write permissions, and mutable action refs.` }, { id: 'worker-orchestration', status: 'warn', detail: 'Investigation tasks are durable and claimable by DSH reviewers. This plugin does not assume a private subagent API.' }], projectFiles: [], languages: [...new Set(receipts.map(item => item.language))], suggestedCommands: [] }, findings, coverage: { mode: 'diff', reviewedFiles: receipts.length, skippedFiles: review.truncated ? 1 : 0, exclusions: review.truncated ? ['diff truncated at 1 MB'] : [], complete: !review.truncated, receipts, ruleReceipts, policyFiles: policy.files, surfaces: [{ id: 'git-diff', label: review.mode, disposition: automaticValidation && findings.some(finding => finding.disposition === 'reportable') ? 'reported' : findings.length ? 'needs_follow_up' : 'no_issue_found', receiptRefs: ['artifacts/02_discovery/finding_discovery_report.md'], riskArea: 'changed-code-and-ci' }], deferred: [...(review.truncated ? [{ id: 'diff-truncated', reason: 'Diff exceeded the 1 MB safe processing limit.' }] : []), ...(semantic.parseErrors ? [{ id: 'semantic-diff-parse-errors', reason: `${semantic.parseErrors} current JS/TS module(s) could not be parsed for semantic diff analysis.` }] : [])] }, activity: [activity('preflight', 'Git diff preflight completed.'), activity('policy', policy.files.length ? `Resolved policy files: ${policy.files.join(', ')}.` : 'No SECURITY.md policy file found in the scan scope.'), activity('discovery', `Analyzed added lines, local multi-language semantic call paths, removed security controls, and CI/CD workflow boundaries in ${review.mode}.`), activity('reduction', `Reduced observations to ${findings.length} unique candidates.`), ...(automaticValidation ? [activity('validation', `Recorded static validation receipts for ${findings.length} candidates.`), activity('attack_path', `Recorded attack-path receipts for ${findings.filter(finding => finding.disposition === 'reportable').length} reportable candidates.`), activity('complete', complete ? 'Diff scan completed with closed candidate ledgers.' : 'Diff scan incomplete because the diff was truncated.')] : [activity('validation', 'Diff candidates are awaiting structured validation receipts.')])], tasks: automaticValidation ? [] : validationTasks(id, findings), recipe: { mode: 'diff', scopeRequested: true, passes: ['diff-added-lines', 'diff-semantic-multilanguage', 'diff-ci-workflows', 'diff-removed-controls'] }, artifacts: { directory: scanArtifactDir(getStateDir(stateDirectory), root, id) }, seal: '' }; record.seal = sealScan(record); return record
}
