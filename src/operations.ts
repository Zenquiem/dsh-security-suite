import { access, mkdir, readFile, writeFile } from 'node:fs/promises'
import { constants } from 'node:fs'
import { isAbsolute, join, relative, resolve } from 'node:path'
import type { Config } from './config.js'
import type { Finding, ScanRecord } from './contracts.js'
import { runScan, resolveSafeTarget } from './scanner.js'
import { getStateDir, loadScan, saveScan } from './state.js'

export interface BulkResult { path: string; scanId?: string; findings?: number; error?: string }

function inside(root: string, target: string): boolean { const rel = relative(root, target); return rel === '' || (!rel.startsWith('..') && !isAbsolute(rel)) }

export async function rerunSavedScan(workspace: string, config: Config, scanId: string): Promise<ScanRecord> {
  const previous = await loadScan(getStateDir(config.stateDir), scanId)
  if (previous.mode === 'diff') throw new Error('Diff scans must be rerun with security_review_diff so the requested base can be supplied explicitly.')
  const root = resolve(workspace); const target = resolve(previous.target)
  if (!inside(root, target)) throw new Error('Saved scan target is outside the active workspace.')
  const scan = await runScan(target, config, previous.mode, previous.threatModel, previous.recipe.scopeRequested)
  await saveScan(getStateDir(config.stateDir), scan)
  return scan
}

export async function bulkScan(workspace: string, config: Config, paths: string[], mode: 'standard' | 'deep', threatModel: string, concurrency: number): Promise<BulkResult[]> {
  const unique = [...new Set(paths)].sort()
  if (unique.length === 0) throw new Error('At least one workspace-relative path is required.')
  const capped = Math.max(1, Math.min(concurrency, 4)); const output: BulkResult[] = new Array(unique.length); let cursor = 0
  const worker = async (): Promise<void> => {
    while (true) {
      const index = cursor++; if (index >= unique.length) return
      const item = unique[index]
      try { const scan = await runScan(resolveSafeTarget(workspace, item), config, mode, threatModel, true); await saveScan(getStateDir(config.stateDir), scan); output[index] = { path: item, scanId: scan.id, findings: scan.findings.length } } catch (error) { output[index] = { path: item, error: error instanceof Error ? error.message : String(error) } }
    }
  }
  await Promise.all(Array.from({ length: Math.min(capped, unique.length) }, worker)); return output
}

export async function installPreCommitHook(workspace: string, approved: boolean): Promise<{ installed: boolean; path: string; reason?: string }> {
  if (!approved) throw new Error('Installing a Git hook changes the repository. Set approved to true only after the hook content has been reviewed.')
  const root = resolve(workspace); const hookDirectory = join(root, '.git', 'hooks'); const hookPath = join(hookDirectory, 'pre-commit')
  try { await access(hookPath, constants.F_OK); return { installed: false, path: hookPath, reason: 'An existing pre-commit hook was preserved.' } } catch { /* absent is expected */ }
  await mkdir(hookDirectory, { recursive: true })
  const content = `#!/bin/sh\n# Installed by dsh-security-suite. Run DSH security review before committing.\n# This hook intentionally does not modify files or send data off-machine.\nif command -v dsh >/dev/null 2>&1; then\n  dsh run "Review the current Git diff for security findings using security_review_diff. Report high-confidence issues only." || exit $?\nfi\n`
  await writeFile(hookPath, content, { encoding: 'utf8', mode: 0o755 })
  return { installed: true, path: hookPath }
}

function replacementFor(finding: Finding, source: string): string | undefined {
  if (finding.ruleId === 'tls-verification-disabled') return source.replace(/rejectUnauthorized\s*:\s*false/, 'rejectUnauthorized: true').replace(/verify\s*=\s*False/, 'verify = True').replace(/InsecureSkipVerify\s*:\s*true/, 'InsecureSkipVerify: false')
  if (finding.ruleId === 'dangerous-dynamic-code') return source.replace(/\beval\s*\(([^)]*)\)/, '/* Replace dynamic evaluation with a fixed operation over validated input: $1 */')
  if (finding.ruleId === 'hardcoded-secret-marker') return source.replace(/((?:api[_-]?key|secret|password|token|private[_-]?key)\s*[:=]\s*)["'][^"']+["']/i, '$1process.env.APP_SECRET')
  return undefined
}

export async function remediationPlan(workspace: string, config: Config, scanId: string, findingId: string): Promise<{ findingId: string; file: string; line: number; patch: string; requiresReview: boolean }> {
  const scan = await loadScan(getStateDir(config.stateDir), scanId); const finding = scan.findings.find(item => item.id === findingId)
  if (!finding) throw new Error('Finding was not found in this scan.')
  const location = finding.locations[0]; const file = resolve(scan.target, location.file); const root = resolve(workspace)
  if (!inside(root, file)) throw new Error('Finding location is outside the active workspace.')
  const before = await readFile(file, 'utf8'); const after = replacementFor(finding, before)
  const patch = after && after !== before ? `--- a/${location.file}\n+++ b/${location.file}\n@@ line ${location.line} @@\n- ${location.excerpt}\n+ ${after.split(/\r?\n/)[location.line - 1]?.trim() ?? '<review replacement>'}` : `No mechanically safe replacement is available for ${finding.ruleId}.\nReview ${location.file}:${location.line} and implement: ${finding.remediation}`
  return { findingId: finding.id, file: location.file, line: location.line, patch, requiresReview: true }
}
