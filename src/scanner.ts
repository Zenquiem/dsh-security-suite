import { createHash } from 'node:crypto'
import { readdir, readFile, stat } from 'node:fs/promises'
import { execFile } from 'node:child_process'
import { extname, join, relative, resolve, sep } from 'node:path'
import { promisify } from 'node:util'
import type { Confidence, Evidence, FileReceipt, Finding, RuleReceipt, ScanActivity, ScanRecord, Severity } from './contracts.js'
import { createScanId, findingId, sealScan } from './state.js'

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
]

function languageFor(file: string): string {
  return ({ '.js': 'javascript', '.jsx': 'javascript', '.mjs': 'javascript', '.cjs': 'javascript', '.ts': 'typescript', '.tsx': 'typescript', '.py': 'python', '.go': 'go', '.java': 'java', '.php': 'php', '.rb': 'ruby', '.rs': 'rust', '.sh': 'shell', '.bash': 'shell', '.c': 'c', '.cc': 'cpp', '.cpp': 'cpp', '.cs': 'csharp' } as Record<string, string>)[extname(file)] ?? 'text'
}

function hash(value: string): string { return createHash('sha256').update(value).digest('hex') }
function isContained(root: string, candidate: string): boolean { return candidate === root || candidate.startsWith(root + sep) }
function location(file: string, line: number, excerpt: string): { file: string; line: number; excerpt: string } { return { file, line, excerpt: excerpt.trim().slice(0, 240) } }

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
  const root = resolve(directory); const { files, skipped, complete } = await collectFiles(root, limits); const candidates: Candidate[] = []; const ruleReceipts: RuleReceipt[] = []; const fileReceipts: FileReceipt[] = []; const policyFiles: string[] = []; const passes = deep ? [['baseline', undefined], ['injection', new Set(['dangerous-dynamic-code', 'shell-command-construction', 'unsafe-deserialization'])], ['boundaries', new Set(['path-traversal-sink', 'ssrf-request-sink', 'tls-verification-disabled', 'weak-randomness-security', 'hardcoded-secret-marker'])]] as const : [['baseline', undefined]] as const
  for (const file of files) {
    const content = await readFile(file, 'utf8'); const rel = relative(root, file)
    fileReceipts.push({ path: rel, bytes: Buffer.byteLength(content, 'utf8'), sha256: hash(content), language: languageFor(file) })
    if (/(?:^|\/)SECURITY\.md$/i.test(rel)) policyFiles.push(rel)
    for (const [pass, ruleSet] of passes) { const analyzed = analyzeText(root, file, content, pass, ruleSet); candidates.push(...analyzed.candidates); ruleReceipts.push(...analyzed.receipts) }
  }
  return { root, filesScanned: files.length, filesSkipped: skipped, candidates, receipts: fileReceipts, ruleReceipts, policyFiles, complete }
}

function candidateToFinding(candidate: Candidate): Finding {
  const fingerprint = hash(`${candidate.rule}:${candidate.file}:${candidate.excerpt.replace(/\s+/g, ' ')}`)
  const hasContext = candidate.evidence.some(item => item.kind === 'context')
  const confidence: Confidence = hasContext && candidate.rule === 'tls-verification-disabled' ? 'medium' : 'low'
  return { id: findingId(candidate.rule, candidate.file, candidate.line), fingerprint, ruleId: candidate.rule, title: candidate.rule.replaceAll('-', ' '), severity: candidate.severity, confidence, cwe: candidate.cwe, status: 'open', locations: [location(candidate.file, candidate.line, candidate.excerpt)], rootCause: candidate.rationale, validation: 'Candidate generated by native static analysis. Confirm attacker control, reachability, controls, and impact before reporting a vulnerability.', attackPath: 'Not established by static analysis.', impact: 'Not established by static analysis.', remediation: 'Review the data flow and apply a context-appropriate safe API, validation, authorization, or containment control.', counterevidence: 'No control analysis has been completed.', evidence: candidate.evidence }
}

function reduceCandidates(candidates: Candidate[]): Finding[] {
  const byFingerprint = new Map<string, Finding>()
  for (const candidate of candidates) { const finding = candidateToFinding(candidate); const existing = byFingerprint.get(finding.fingerprint); if (existing) existing.evidence.push(...finding.evidence); else byFingerprint.set(finding.fingerprint, finding) }
  return [...byFingerprint.values()].sort((a, b) => a.locations[0].file.localeCompare(b.locations[0].file) || a.locations[0].line - b.locations[0].line)
}

function activity(phase: ScanActivity['phase'], message: string): ScanActivity { return { at: new Date().toISOString(), phase, message } }

export async function runScan(directory: string, limits: ScanLimits, mode: 'standard' | 'deep', threatModel: string, scopeRequested = false): Promise<ScanRecord> {
  const deep = mode === 'deep'; const result = await assessDirectory(directory, limits, deep); const now = new Date().toISOString(); const record: ScanRecord = { schemaVersion: 2, id: createScanId(), mode, lifecycle: result.complete ? 'completed' : 'incomplete', target: result.root, createdAt: now, completedAt: now, threatModel: threatModel || 'No user-supplied threat model. Review public inputs, identities, protected assets, trust boundaries, and sensitive operations before finalizing findings.', findings: reduceCandidates(result.candidates), coverage: { mode: scopeRequested ? 'scoped_path' : 'repository', reviewedFiles: result.filesScanned, skippedFiles: result.filesSkipped, exclusions: [...IGNORED_DIRECTORIES], complete: result.complete, receipts: result.receipts, ruleReceipts: result.ruleReceipts, policyFiles: result.policyFiles }, activity: [activity('inventory', `Inventoried ${result.filesScanned} eligible source files.`), activity('policy', result.policyFiles.length ? `Found policy files: ${result.policyFiles.join(', ')}.` : 'No SECURITY.md policy file found in the scan scope.'), activity('discovery', `Ran ${deep ? 3 : 1} native discovery pass(es) and collected ${result.candidates.length} observations.`), activity('reduction', `Reduced observations to ${reduceCandidates(result.candidates).length} unique candidate findings.`), activity('complete', result.complete ? 'Scan completed.' : 'Scan completed with incomplete coverage due to limits or unreadable paths.')], recipe: { mode, scopeRequested, passes: deep ? ['baseline', 'injection', 'boundaries'] : ['baseline'] }, seal: '' }
  record.seal = sealScan(record); return record
}

export function resolveSafeTarget(workspace: string, requested: string | undefined): string { const root = resolve(workspace); const target = resolve(root, requested ?? '.'); if (!isContained(root, target)) throw new Error('Scan target must remain inside the current workspace.'); return target }

export async function reviewGitDiff(workspace: string, base: string | undefined): Promise<{ mode: string; diff: string; truncated: boolean }> {
  if (base !== undefined && (!/^[A-Za-z0-9][A-Za-z0-9._/-]*$/.test(base) || base.startsWith('-'))) throw new Error('Git base ref contains unsupported characters.')
  const args = ['diff', '--no-ext-diff', '--unified=20']; const mode = base === undefined ? 'working-tree' : `base:${base}`; if (base !== undefined) args.push(`${base}...HEAD`)
  const { stdout } = await execFileAsync('git', args, { cwd: resolve(workspace), encoding: 'utf8', maxBuffer: MAX_DIFF_BYTES + 1 }); return { mode, diff: stdout.slice(0, MAX_DIFF_BYTES), truncated: Buffer.byteLength(stdout, 'utf8') > MAX_DIFF_BYTES }
}

export async function runDiffScan(workspace: string, base: string | undefined, threatModel: string): Promise<ScanRecord> {
  const review = await reviewGitDiff(workspace, base); const candidates: Candidate[] = []; let currentFile = ''; let newLine = 0
  for (const diffLine of review.diff.split(/\r?\n/)) {
    if (diffLine.startsWith('+++ b/')) { currentFile = diffLine.slice(6); newLine = 0; continue }
    const hunk = /^@@ -\d+(?:,\d+)? \+(\d+)/.exec(diffLine); if (hunk) { newLine = Number(hunk[1]); continue }
    if (diffLine.startsWith('+') && !diffLine.startsWith('+++')) { const analyzed = analyzeText(resolve(workspace), join(resolve(workspace), currentFile || 'unknown'), diffLine.slice(1), 'diff'); for (const candidate of analyzed.candidates) { candidate.file = currentFile || 'unknown'; candidate.line = newLine; candidate.evidence[0].location = location(candidate.file, newLine, candidate.excerpt); candidates.push(candidate) }; newLine++; continue }
    if (!diffLine.startsWith('-')) newLine++
  }
  const now = new Date().toISOString(); const record: ScanRecord = { schemaVersion: 2, id: createScanId(), mode: 'diff', lifecycle: review.truncated ? 'incomplete' : 'completed', target: resolve(workspace), createdAt: now, completedAt: now, threatModel: threatModel || 'Review changed behavior for attacker-controlled inputs, authorization boundaries, and sensitive sinks.', findings: reduceCandidates(candidates), coverage: { mode: 'diff', reviewedFiles: review.diff.split('\ndiff --git ').length - 1, skippedFiles: review.truncated ? 1 : 0, exclusions: review.truncated ? ['diff truncated at 1 MB'] : [], complete: !review.truncated, receipts: [], ruleReceipts: [], policyFiles: [] }, activity: [activity('discovery', `Analyzed changed lines in ${review.mode}.`), activity('reduction', `Reduced observations to ${reduceCandidates(candidates).length} unique candidate findings.`), activity('complete', review.truncated ? 'Diff scan incomplete because the diff was truncated.' : 'Diff scan completed.')], recipe: { mode: 'diff', scopeRequested: true, passes: ['diff'] }, seal: '' }; record.seal = sealScan(record); return record
}
