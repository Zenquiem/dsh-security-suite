import { readdir, readFile, stat } from 'node:fs/promises'
import { execFile } from 'node:child_process'
import { basename, extname, join, relative, resolve, sep } from 'node:path'
import { promisify } from 'node:util'

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
