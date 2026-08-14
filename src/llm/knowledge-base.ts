import { access, readdir, readFile, stat } from 'node:fs/promises'
import { extname, join, relative, resolve } from 'node:path'
import { sha256 } from '../state.js'

/**
 * Read-only security knowledge base, mirroring codex-security `--knowledge-base`
 * semantics (Apache-2.0, adapted): files or directories searched recursively for
 * Markdown and plain-text documents. PDF/DOCX binaries are skipped (no parser
 * dependency); callers may pre-convert them.
 */

const TEXT_KB_EXTENSIONS = new Set(['.md', '.markdown', '.txt', '.text', '.rst', '.adoc', '.toml', '.yaml', '.yml', '.json'])
const SKIPPED_KB_DIRECTORIES = new Set(['.git', '.hg', '.svn', 'node_modules', 'dist', 'build', 'coverage'])
const MAX_KB_DOC_BYTES = 512 * 1024
const MAX_KB_TOTAL_BYTES = 8 * 1024 * 1024
const MAX_KB_DOCS = 200

export interface KnowledgeBaseDocument {
  path: string
  /** Workspace-relative display path when under the active workspace. */
  name: string
  content: string
  sha256: string
}

export interface KnowledgeBase {
  documents: KnowledgeBaseDocument[]
  /** Documents truncated or skipped due to size/type limits. */
  skipped: Array<{ path: string; reason: string }>
  /** Combined bounded prompt text: a heading per document followed by content. */
  promptText: string
}

function kbName(workspace: string, path: string): string {
  const rel = relative(workspace, path)
  return rel && !rel.startsWith('..') ? rel : path
}

async function isReadableFile(path: string): Promise<boolean> {
  try { const info = await stat(path); return info.isFile() } catch { return false }
}

async function collectKbFiles(workspace: string, candidates: string[], out: string[], skipped: Array<{ path: string; reason: string }>): Promise<void> {
  for (const candidate of candidates) {
    const resolved = resolve(candidate)
    let info
    try { info = await stat(resolved) } catch { skipped.push({ path: candidate, reason: 'Knowledge-base path is not readable.' }); continue }
    if (info.isFile()) {
      if (info.size > MAX_KB_DOC_BYTES) { skipped.push({ path: candidate, reason: 'Knowledge-base document exceeds the 512 KiB size limit.' }); continue }
      out.push(resolved)
    } else if (info.isDirectory()) {
      const entries = await readdir(resolved)
      for (const entry of entries.sort()) {
        if (SKIPPED_KB_DIRECTORIES.has(entry)) continue
        await collectKbFiles(workspace, [join(resolved, entry)], out, skipped)
      }
    }
  }
}

/**
 * Load the configured knowledge base. Returns an empty base (never throws) when
 * nothing is configured or every path is unreadable.
 */
export async function loadKnowledgeBase(workspace: string, configured: string[]): Promise<KnowledgeBase> {
  const docs: KnowledgeBaseDocument[] = []
  const skipped: Array<{ path: string; reason: string }> = []
  const files: string[] = []
  await collectKbFiles(workspace, configured, files, skipped)
  let total = 0
  for (const file of files) {
    if (docs.length >= MAX_KB_DOCS) { skipped.push({ path: file, reason: 'Knowledge base exceeded the 200 document limit.' }); continue }
    const extension = extname(file).toLowerCase()
    if (!TEXT_KB_EXTENSIONS.has(extension)) { skipped.push({ path: file, reason: `Unsupported knowledge-base document type "${extension}"; only Markdown and plain text are read.` }); continue }
    try {
      if (!(await isReadableFile(file))) { skipped.push({ path: file, reason: 'Knowledge-base path is not a readable file.' }); continue }
      const content = await readFile(file, 'utf8')
      if (content.length > MAX_KB_DOC_BYTES) { skipped.push({ path: file, reason: 'Knowledge-base document exceeds the 512 KiB size limit.' }); continue }
      if (total + content.length > MAX_KB_TOTAL_BYTES) { skipped.push({ path: file, reason: 'Knowledge base exceeded the 8 MiB total content limit.' }); continue }
      total += content.length
      docs.push({ path: file, name: kbName(workspace, file), content, sha256: sha256(content) })
    } catch { skipped.push({ path: file, reason: 'Knowledge-base document could not be read.' }) }
  }
  docs.sort((a, b) => a.name.localeCompare(b.name))
  const promptText = docs.length
    ? docs.map(doc => `# Knowledge-base document: ${doc.name}\n\n${doc.content.trim()}`).join('\n\n---\n\n') + '\n'
    : ''
  return { documents: docs, skipped, promptText }
}

/** Guard against accidentally passing a binary or oversized path as a knowledge base. */
export async function checkKnowledgeBasePath(path: string): Promise<{ ok: boolean; reason?: string }> {
  try { const info = await stat(path); if (info.isDirectory()) return { ok: true }; if (!TEXT_KB_EXTENSIONS.has(extname(path).toLowerCase())) return { ok: false, reason: 'Knowledge-base file must be Markdown or plain text.' }; return { ok: true } } catch { return { ok: false, reason: 'Knowledge-base path is not readable.' } }
}

/** Reject knowledge-base paths outside the active workspace. */
export function assertKnowledgeBaseInWorkspace(workspace: string, paths: string[]): void {
  for (const candidate of paths) {
    const resolved = resolve(candidate)
    const rel = relative(workspace, resolved)
    if (rel.startsWith('..') || resolve(rel) === resolve('..')) throw new Error(`Knowledge-base path "${candidate}" is outside the active workspace.`)
    void access(resolved)
  }
}
