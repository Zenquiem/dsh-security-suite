import { createHash } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { extname, relative } from 'node:path'

/**
 * Ranking and candidate-normalization engine, adapted from openai/codex-security
 * `scripts/generate_rank_input.py`, `scripts/rank_preview.py`, and
 * `scripts/normalize_candidates.py` (Apache-2.0). Algorithm parity is kept
 * byte-for-byte (exclusion sets, identity hash, JSON encoding discipline);
 * the dsh-security-suite namespace is preserved for emitted ids.
 */

/** Excluded directory names (generate_rank_input.py EXCLUDED_DIRS, verbatim). */
export const EXCLUDED_DIRS: ReadonlySet<string> = new Set([
  '.cache', '.circleci', '.devcontainer', '.git', '.github', '.idea', '.mypy_cache', '.pytest_cache', '.ruff_cache', '.tox', '.venv', '.vscode', '__pycache__',
  'bench', 'benchmark', 'bintest', 'build', 'build_config', 'build_configs', 'build-tools', 'build_tools', 'ci', 'coverage', 'deps', 'dev', 'dist',
  'doc', 'docs', 'example', 'examples', 'external', 'extern', 'fixture', 'fixtures', 'generated', 'node_modules', 'sample', 'samples', 'target',
  'test', 'tests', 'testing', 'third-party', 'third_party', 'tmp', 'vendor',
])

/** Excluded file names (generate_rank_input.py EXCLUDED_FILENAMES, verbatim). */
export const EXCLUDED_FILENAMES: ReadonlySet<string> = new Set([
  '.DS_Store', 'CHANGELOG', 'CHANGELOG.md', 'CONTRIBUTING.md', 'Dockerfile', 'Gemfile', 'Gemfile.lock', 'LICENSE', 'LICENSE.md', 'Makefile',
  'NEWS', 'NEWS.md', 'NOTICE', 'README', 'README.md', 'README.rst', 'Rakefile', 'SECURITY.md', 'TODO', 'TODO.md',
  'docker-compose.yml', 'package-lock.json', 'pnpm-lock.yaml', 'yarn.lock',
])

/** Source-code extensions considered for ranking (rank_preview.py TEXT_CODE_EXTENSIONS, verbatim). */
export const TEXT_CODE_EXTENSIONS: ReadonlySet<string> = new Set([
  '.c', '.cc', '.cfg', '.clj', '.cpp', '.cs', '.css', '.cue', '.cxx', '.dart', '.ex', '.exs', '.go', '.graphql', '.h', '.hpp', '.hs', '.html',
  '.java', '.js', '.json', '.jsx', '.kt', '.kts', '.lua', '.mjs', '.mm', '.php', '.proto', '.py', '.rb', '.rs', '.scala', '.sh', '.sql',
  '.swift', '.toml', '.ts', '.tsx', '.vue', '.xml', '.yaml', '.yml',
])

/**
 * identity(row) with byte-parity JSON encoding (normalize_candidates.py):
 * sort_keys=True (keys are emitted in alphabetical order), compact
 * separators, ensure_ascii=False (UTF-8 passthrough), and a null instance
 * preserved as `"instance": null`.
 */
export function candidateIdentity(row: Pick<NormalizedCandidate, 'cweIds' | 'locations' | 'instance'>): string {
  return JSON.stringify({ cwe_ids: row.cweIds, instance: row.instance ?? null, locations: row.locations })
}

/** A binary sample contains a NUL byte (rank_preview.py is_binary_sample). */
export function isBinarySample(sample: Buffer): boolean { return sample.includes(0) }

/** path_is_excluded (generate_rank_input.py): any path part in EXCLUDED_DIRS or basename in EXCLUDED_FILENAMES. */
export function pathIsExcluded(path: string): boolean {
  const parts = path.split('/').filter(part => part !== '' && part !== '.')
  return parts.some(part => EXCLUDED_DIRS.has(part)) || EXCLUDED_FILENAMES.has(parts.at(-1) ?? '')
}

/** Structural preview of source bytes (rank_preview.py preview_for_bytes, adapted). */
export function previewForBytes(source: string, previewBytes = 1024): string {
  const outline = structuralOutline(source)
  const lines = [...outline, ...sampleLines(source, 10)]
  let total = 0
  const fitted: string[] = []
  for (const line of lines) {
    const bytes = Buffer.byteLength(line, 'utf8')
    if (total + bytes > previewBytes && fitted.length) break
    fitted.push(line)
    total += bytes
    if (total >= previewBytes) break
  }
  return fitted.join('\n')
}

/** Sample a few spread lines from the source (rank_preview.py select_preview_lines, adapted). */
function sampleLines(source: string, count: number): string[] {
  const lines = source.split(/\r?\n/)
  if (lines.length <= count + 1) return lines.slice(0, Math.min(lines.length, count))
  const step = Math.max(1, Math.floor((lines.length - 1) / (count - 1)))
  const sampled: string[] = []
  for (let index = 0; index < lines.length && sampled.length < count; index += step) sampled.push(lines[index])
  return sampled
}

/**
 * Structural outline per language family (rank_preview.py structural_outline,
 * adapted with regex approximations where the Python version used real ASTs).
 */
export function structuralOutline(source: string): string[] {
  const outline: string[] = []
  const lines = source.split(/\r?\n/).slice(0, 24)
  for (const line of lines) {
    const python = /^\s*(async\s+)?(def|class)\s+([A-Za-z_][A-Za-z0-9_]*)/.exec(line)
    if (python) { outline.push(python[2] === 'class' ? `class ${python[3]}` : `def ${python[3]}`); continue }
    const js = /^\s*(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(/.exec(line)
    if (js) { outline.push(`function ${js[1]}`); continue }
    const arrow = /^\s*(?:export\s+)?(?:const|let)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:async\s*)?\(.*\)\s*=>/.exec(line)
    if (arrow) { outline.push(`arrow ${arrow[1]}`); continue }
    const go = /^\s*func\s+(?:\([^)]*\)\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*\(/.exec(line)
    if (go) { outline.push(`func ${go[1]}`); continue }
    const java = /^\s*(?:public|private|protected|static|final|abstract|\s)*\S+\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*\)\s*\{?/.exec(line)
    if (java && !line.includes('=')) { outline.push(`method ${java[1]}`); continue }
    if (outline.length >= 12) break
  }
  return [...new Set(outline)]
}

/** A normalized discovery candidate (normalize_candidates.py discoveryCandidate shape). */
export interface NormalizedCandidate {
  candidateId: string
  cweIds: string[]
  locations: Array<{ path: string; startLine: number; endLine?: number; role?: string }>
  summary: string
  evidence: string
  context?: string
  instance?: string
}

/** Deterministic candidate id: candidate-<sha256(identity)[:16]> (normalize_candidates.py). */
export function candidateIdFromIdentity(identity: string): string {
  return `candidate-${createHash('sha256').update(identity, 'utf8').digest('hex').slice(0, 16)}`
}

/** Merge text fields across a group (normalize_candidates.py merged_text: sorted unique lines joined). */
export function mergedText(group: NormalizedCandidate[], field: keyof Pick<NormalizedCandidate, 'summary' | 'evidence' | 'context'>): string {
  return [...new Set(group.map(row => row[field]).filter((value): value is string => Boolean(value)))].sort().join('\n')
}

/** Group + combine candidates by identity (normalize_candidates.py combine). */
export function combineCandidates(rows: NormalizedCandidate[]): NormalizedCandidate[] {
  const groups = new Map<string, NormalizedCandidate[]>()
  for (const row of rows) {
    const identity = candidateIdentity(row)
    groups.set(identity, [...(groups.get(identity) ?? []), row])
  }
  const combined: NormalizedCandidate[] = []
  for (const [identity, group] of [...groups.entries()].sort(([a], [b]) => a.localeCompare(b))) {
    const first = group[0]!
    const context = mergedText(group, 'context')
    const result: NormalizedCandidate = {
      candidateId: candidateIdFromIdentity(identity),
      cweIds: first.cweIds,
      locations: first.locations,
      summary: mergedText(group, 'summary'),
      evidence: mergedText(group, 'evidence'),
      ...(context ? { context } : {}),
      ...(first.instance !== undefined ? { instance: first.instance } : {}),
    }
    combined.push(result)
  }
  return combined
}

/** Read a bounded binary-sample-then-preview for one path (rank_preview.py preview_for). */
export async function previewForPath(path: string): Promise<string> {
  const sample = await readFile(path)
  if (isBinarySample(sample)) return ''
  const source = sample.toString('utf8').replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, '')
  return previewForBytes(source)
}

/** Workspace-relative path helper (repositoryPath semantics, adapted). */
export function repositoryRelative(workspace: string, path: string): string {
  const rel = relative(workspace, path)
  if (rel.startsWith('..') || rel.includes('..')) throw new Error(`Path ${path} is outside the repository.`)
  return rel.replaceAll('\\', '/')
}

/** A rank_input.jsonl row (generate_rank_input.py rank input row shape). */
export function rankInputRow(path: string, area: string, preview: string): string {
  return JSON.stringify({ path, area, preview })
}

/** True when a path should be considered for ranking (extension allowlist + exclusions). */
export function qualifiesForRanking(workspace: string, path: string): boolean {
  const rel = repositoryRelative(workspace, path)
  if (pathIsExcluded(rel)) return false
  return TEXT_CODE_EXTENSIONS.has(extname(path).toLowerCase())
}
