import { readdir, readFile, stat } from 'node:fs/promises'
import { execFile } from 'node:child_process'
import { basename, extname, join, relative, resolve, sep } from 'node:path'
import { promisify } from 'node:util'
import type { Finding, ScanRecord, Severity } from './contracts.js'
import { createScanId, findingId } from './state.js'

export interface ScanLimits {
  maxFiles: number
  maxFileBytes: number
}

export interface Candidate {
  rule: string
  severity: 'high' | 'medium' | 'low'
  file: string
  line: number
  excerpt: string
  rationale: string
}

export interface ScanResult {
  root: string
  filesScanned: number
  filesSkipped: number
  candidates: Candidate[]
}

const IGNORED_DIRECTORIES = new Set(['.git', '.hg', '.svn', 'node_modules', 'dist', 'build', 'coverage', '.next'])
const TEXT_EXTENSIONS = new Set(['.c', '.cc', '.cpp', '.cs', '.go', '.java', '.js', '.jsx', '.mjs', '.cjs', '.php', '.py', '.rb', '.rs', '.sh', '.ts', '.tsx', '.vue', '.yaml', '.yml'])

const RULES: Array<{ rule: string, severity: Candidate['severity'], pattern: RegExp, rationale: string }> = [
  { rule: 'dangerous-dynamic-code', severity: 'high', pattern: /\beval\s*\(|\bnew\s+Function\s*\(/, rationale: 'Dynamic code execution can turn attacker-controlled data into code execution.' },
  { rule: 'shell-command-construction', severity: 'high', pattern: /(?:exec|spawn|system|popen)\s*\([^\n]*(?:\+|`|\$\{)/, rationale: 'Constructed shell commands require a data-flow review for command injection.' },
  { rule: 'path-traversal-sink', severity: 'medium', pattern: /(?:readFile|writeFile|createReadStream|sendFile)\s*\([^\n]*(?:req\.|params\.|query\.|input)/, rationale: 'A filesystem sink receives request-derived data and needs canonical path containment.' },
  { rule: 'tls-verification-disabled', severity: 'high', pattern: /(?:rejectUnauthorized\s*:\s*false|verify\s*=\s*False|CURLOPT_SSL_VERIFYPEER\s*,\s*false)/, rationale: 'TLS certificate verification is disabled.' },
  { rule: 'hardcoded-secret-marker', severity: 'medium', pattern: /(?:api[_-]?key|secret|password|token)\s*[:=]\s*['"][^'"]{8,}['"]/i, rationale: 'A likely credential literal is committed in source.' },
]

const execFileAsync = promisify(execFile)
const MAX_DIFF_BYTES = 1_000_000

function cweForRule(rule: string): string {
  return ({
    'dangerous-dynamic-code': 'CWE-95',
    'shell-command-construction': 'CWE-78',
    'path-traversal-sink': 'CWE-22',
    'tls-verification-disabled': 'CWE-295',
    'hardcoded-secret-marker': 'CWE-798',
  })[rule] ?? 'CWE-693'
}

function normalizeSeverity(severity: Candidate['severity']): Severity {
  return severity
}

function isContained(root: string, candidate: string): boolean {
  return candidate === root || candidate.startsWith(root + sep)
}

async function collectFiles(root: string, limits: ScanLimits): Promise<{ files: string[], skipped: number }> {
  const files: string[] = []
  let skipped = 0
  const visit = async (directory: string): Promise<void> => {
    if (files.length >= limits.maxFiles) return
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      if (files.length >= limits.maxFiles) return
      const target = join(directory, entry.name)
      if (entry.isDirectory()) {
        if (IGNORED_DIRECTORIES.has(entry.name)) {
          skipped++
        } else {
          await visit(target)
        }
      } else if (entry.isFile() && TEXT_EXTENSIONS.has(extname(entry.name))) {
        const details = await stat(target)
        if (details.size <= limits.maxFileBytes) files.push(target)
        else skipped++
      }
    }
  }
  await visit(root)
  return { files, skipped }
}

export async function assessDirectory(directory: string, limits: ScanLimits): Promise<ScanResult> {
  const root = resolve(directory)
  const { files, skipped } = await collectFiles(root, limits)
  const candidates: Candidate[] = []
  for (const file of files) {
    const content = await readFile(file, 'utf8')
    for (const [index, text] of content.split(/\r?\n/).entries()) {
      for (const rule of RULES) {
        if (rule.pattern.test(text)) {
          candidates.push({
            rule: rule.rule,
            severity: rule.severity,
            file: relative(root, file),
            line: index + 1,
            excerpt: text.trim().slice(0, 240),
            rationale: rule.rationale,
          })
        }
      }
    }
  }
  return { root: basename(root) === '' ? root : root, filesScanned: files.length, filesSkipped: skipped, candidates }
}

export async function runScan(directory: string, limits: ScanLimits, mode: 'standard' | 'deep', threatModel: string, scopeRequested = false): Promise<ScanRecord> {
  const result = await assessDirectory(directory, limits)
  const findings: Finding[] = result.candidates.map(candidate => ({
    id: findingId(candidate.rule, candidate.file, candidate.line),
    ruleId: candidate.rule,
    title: candidate.rule.replaceAll('-', ' '),
    severity: normalizeSeverity(candidate.severity),
    confidence: 'low',
    cwe: cweForRule(candidate.rule),
    status: 'open',
    locations: [{ file: candidate.file, line: candidate.line, excerpt: candidate.excerpt }],
    rootCause: candidate.rationale,
    validation: 'Static candidate only. Trace untrusted input, effective controls, and the sensitive sink before treating this as a vulnerability.',
    attackPath: 'Not established by pattern matching.',
    impact: 'Not established by pattern matching.',
    remediation: 'Review the data flow and add context-appropriate validation, authorization, or safe API usage.',
    counterevidence: 'No control analysis has been completed.',
  }))
  const now = new Date().toISOString()
  return {
    schemaVersion: 1,
    id: createScanId(),
    mode,
    target: result.root,
    createdAt: now,
    completedAt: now,
    threatModel: threatModel || 'No user-supplied threat model. Review public inputs, identities, protected assets, trust boundaries, and sensitive operations before finalizing findings.',
    findings,
    coverage: {
      mode: scopeRequested ? 'scoped_path' : 'repository',
      reviewedFiles: result.filesScanned,
      skippedFiles: result.filesSkipped,
      exclusions: [...IGNORED_DIRECTORIES],
      complete: result.filesScanned < limits.maxFiles,
    },
  }
}

export function resolveSafeTarget(workspace: string, requested: string | undefined): string {
  const root = resolve(workspace)
  const target = resolve(root, requested ?? '.')
  if (!isContained(root, target)) throw new Error('Scan target must remain inside the current workspace.')
  return target
}

export async function reviewGitDiff(workspace: string, base: string | undefined): Promise<{ mode: string, diff: string, truncated: boolean }> {
  if (base !== undefined && (!/^[A-Za-z0-9][A-Za-z0-9._/-]*$/.test(base) || base.startsWith('-'))) {
    throw new Error('Git base ref contains unsupported characters.')
  }
  const args = ['diff', '--no-ext-diff', '--unified=20']
  const mode = base === undefined ? 'working-tree' : `base:${base}`
  if (base !== undefined) args.push(`${base}...HEAD`)
  const { stdout } = await execFileAsync('git', args, {
    cwd: resolve(workspace),
    encoding: 'utf8',
    maxBuffer: MAX_DIFF_BYTES + 1,
  })
  return {
    mode,
    diff: stdout.slice(0, MAX_DIFF_BYTES),
    truncated: Buffer.byteLength(stdout, 'utf8') > MAX_DIFF_BYTES,
  }
}

export async function runDiffScan(workspace: string, base: string | undefined, threatModel: string): Promise<ScanRecord> {
  const review = await reviewGitDiff(workspace, base)
  const findings: Finding[] = []
  let currentFile = ''
  for (const line of review.diff.split(/\r?\n/)) {
    if (line.startsWith('+++ b/')) currentFile = line.slice(6)
    if (!line.startsWith('+') || line.startsWith('+++')) continue
    for (const rule of RULES) {
      if (rule.pattern.test(line.slice(1))) {
        findings.push({
          id: findingId(rule.rule, currentFile || 'unknown', findings.length + 1),
          ruleId: rule.rule,
          title: rule.rule.replaceAll('-', ' '),
          severity: normalizeSeverity(rule.severity),
          confidence: 'low',
          cwe: cweForRule(rule.rule),
          status: 'open',
          locations: [{ file: currentFile || 'unknown', line: 0, excerpt: line.slice(1).trim().slice(0, 240) }],
          rootCause: rule.rationale,
          validation: 'Changed-line candidate only. Validate reachability and controls in the surrounding source.',
          attackPath: 'Not established by pattern matching.',
          impact: 'Not established by pattern matching.',
          remediation: 'Review the changed data flow and use a safe, context-appropriate alternative.',
          counterevidence: 'No control analysis has been completed.',
        })
      }
    }
  }
  const now = new Date().toISOString()
  return {
    schemaVersion: 1,
    id: createScanId(),
    mode: 'diff',
    target: resolve(workspace),
    createdAt: now,
    completedAt: now,
    threatModel: threatModel || 'Review changed behavior for attacker-controlled inputs, authorization boundaries, and sensitive sinks.',
    findings,
    coverage: { mode: 'diff', reviewedFiles: review.diff.split('\ndiff --git ').length - 1, skippedFiles: review.truncated ? 1 : 0, exclusions: review.truncated ? ['diff truncated at 1 MB'] : [], complete: !review.truncated },
  }
}
