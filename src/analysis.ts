import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { basename, isAbsolute, join, relative, resolve } from 'node:path'
import { randomUUID } from 'node:crypto'
import type { Config } from './config.js'
import type { Finding, ScanRecord } from './contracts.js'
import { getStateDir, loadScan, sha256 } from './state.js'

export interface ImportedFinding { id: string; title: string; description: string; severity?: string; cwe?: string; locations: Array<{ file: string; line?: number }>; sourcePath: string; sourceSha256: string }
export interface TriageResult { id: string; importedFindingId: string; target: string; status: 'affected' | 'not_affected' | 'needs_information'; confidence: 'high' | 'medium' | 'low'; rationale: string; evidence: string[]; limitations: string[]; createdAt: string }
export interface HardeningResult { id: string; scanId: string; outcome: 'structural_hardening_recommended' | 'local_remediation_preferred'; directory: string; portfolio: string; structured: string; opportunities: number[] }

function inside(root: string, target: string): boolean { const item = relative(root, target); return item === '' || (!item.startsWith('..') && !isAbsolute(item)) }
function text(value: unknown): string { return typeof value === 'string' ? value.trim() : '' }
function list(value: unknown): unknown[] { return Array.isArray(value) ? value : [] }
function slug(value: string): string { return value.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '') || 'imported-finding' }

export async function importFindings(workspace: string, sourcePath: string): Promise<ImportedFinding[]> {
  const root = resolve(workspace); const file = resolve(root, sourcePath); if (!inside(root, file)) throw new Error('Imported finding file must remain inside the active workspace.')
  const raw = await readFile(file, 'utf8'); const sourceSha256 = sha256(raw); let parsed: unknown
  try { parsed = JSON.parse(raw) } catch { parsed = raw }
  const entries = Array.isArray(parsed) ? parsed : typeof parsed === 'object' && parsed !== null ? list((parsed as Record<string, unknown>).findings).length ? list((parsed as Record<string, unknown>).findings) : [parsed] : [{ title: basename(file), description: raw }]
  return entries.map((entry, index) => {
    const item = typeof entry === 'object' && entry !== null ? entry as Record<string, unknown> : { description: String(entry) }
    const locations = list(item.locations).map(value => { const location = value as Record<string, unknown>; return { file: text(location.file) || text(location.path), line: typeof location.line === 'number' ? location.line : typeof location.startLine === 'number' ? location.startLine : undefined } }).filter(location => location.file)
    const title = text(item.title) || text(item.name) || `Imported finding ${index + 1}`
    return { id: `imp_${sha256(`${sourceSha256}:${index}:${title}`).slice(0, 24)}`, title, description: text(item.description) || text(item.summary) || JSON.stringify(item), severity: text(item.severity), cwe: text(item.cwe), locations, sourcePath, sourceSha256 }
  })
}

export async function triageImportedFinding(workspace: string, config: Config, imported: ImportedFinding): Promise<TriageResult> {
  const root = resolve(workspace); const evidence: string[] = []; const limitations: string[] = []; let referencedExisting = 0
  for (const location of imported.locations) {
    const file = resolve(root, location.file)
    if (!inside(root, file)) { limitations.push(`Imported location ${location.file} is outside the workspace.`); continue }
    try { const content = await readFile(file, 'utf8'); const line = location.line ? content.split(/\r?\n/)[location.line - 1] : content; if (line && (imported.description.toLowerCase().includes('tls') ? /rejectUnauthorized\s*:\s*false|verify\s*=\s*False|InsecureSkipVerify\s*:\s*true/.test(content) : true)) { referencedExisting++; evidence.push(`Reopened ${location.file}${location.line ? `:${location.line}` : ''} from imported evidence.`) } else limitations.push(`Imported location ${location.file}${location.line ? `:${location.line}` : ''} did not contain enough matching local context.`) } catch { limitations.push(`Imported location ${location.file} could not be read.`) }
  }
  const keywords = `${imported.title}\n${imported.description}`.toLowerCase(); const files = await Promise.all(imported.locations.slice(0, 8).map(async location => { const file = resolve(root, location.file); return inside(root, file) ? readFile(file, 'utf8').catch(() => '') : '' }))
  const localMatch = files.some(content => keywords.includes('tls') ? /rejectUnauthorized\s*:\s*false|verify\s*=\s*False|InsecureSkipVerify\s*:\s*true/.test(content) : keywords.includes('eval') ? /\beval\s*\(/.test(content) : content.length > 0)
  const status: TriageResult['status'] = localMatch && referencedExisting ? 'affected' : imported.locations.length && !referencedExisting ? 'not_affected' : 'needs_information'
  const confidence: TriageResult['confidence'] = status === 'affected' && imported.locations.length ? 'medium' : status === 'not_affected' ? 'medium' : 'low'
  const rationale = status === 'affected' ? 'The imported report names a local location that was reopened and still contains a compatible security-relevant construct. It remains a triage result, not a replacement for candidate validation.' : status === 'not_affected' ? 'The imported location could be inspected, but the claimed local construct was not established from the supplied evidence.' : 'The imported evidence does not provide enough readable local location or behavior context to establish repository impact.'
  const result: TriageResult = { id: `tri_${randomUUID()}`, importedFindingId: imported.id, target: basename(root), status, confidence, rationale, evidence, limitations, createdAt: new Date().toISOString() }
  const directory = join(getStateDir(config.stateDir), 'triage'); await mkdir(directory, { recursive: true }); await writeFile(join(directory, `${result.id}.json`), `${JSON.stringify({ imported, result }, null, 2)}\n`, 'utf8'); return result
}

function opportunityFor(findings: Finding[]): { title: string; invariant: string; evidence: Finding[] } | undefined {
  const groups = new Map<string, Finding[]>()
  for (const finding of findings) { const family = finding.ruleId.split('.').slice(0, 2).join('.'); groups.set(family, [...(groups.get(family) ?? []), finding]) }
  const repeated = [...groups.entries()].find(([, group]) => group.length >= 2)
  if (repeated) return { title: `Centralize ${repeated[0]} controls`, invariant: `Every ${repeated[0]} operation must cross one owned enforcement boundary before reaching its sensitive sink.`, evidence: repeated[1] }
  const highImpact = findings.find(finding => finding.severity === 'critical' || finding.severity === 'high')
  return highImpact ? { title: `Consolidate the control behind ${highImpact.ruleId}`, invariant: `Every path to ${highImpact.ruleId} must apply the same explicit guard before the sensitive operation.`, evidence: [highImpact] } : undefined
}

export async function generateHardeningPortfolio(config: Config, scanId: string): Promise<HardeningResult> {
  const scan = await loadScan(getStateDir(config.stateDir), scanId); const findings = scan.findings.filter(finding => finding.disposition === 'reportable'); const opportunity = opportunityFor(findings); const directory = join(scan.artifacts.directory, 'hardening'); await mkdir(join(directory, 'proposals'), { recursive: true })
  const id = `hard_${randomUUID()}`; const outcome: HardeningResult['outcome'] = opportunity ? 'structural_hardening_recommended' : 'local_remediation_preferred'; const evidence = opportunity?.evidence ?? []
  const structured = { id, scanId, outcome, evidence: evidence.map(finding => ({ findingId: finding.id, title: finding.title, ruleId: finding.ruleId, location: finding.locations[0] })), opportunities: opportunity ? [{ id: slug(opportunity.title), title: opportunity.title, violatedInvariant: opportunity.invariant, options: [{ id: 'central-owned-boundary', title: 'Central owned enforcement boundary', securityEffect: 'Moves duplicated or implicit controls into one reviewed owner.', tradeoffs: { performance: 'One additional wrapper or policy check on sensitive paths.', reliability: 'Central owner must fail closed and be observable.', migration: 'Incremental migration with old callsites rejected after adoption.' } }, { id: 'local-strengthening', title: 'Strengthen each local callsite', securityEffect: 'Addresses observed sites without a larger ownership change.', tradeoffs: { performance: 'Minimal runtime overhead.', reliability: 'Control drift remains likely as new callsites are added.', migration: 'Low immediate disruption but repeated review work.' } }] }] : [], limitations: scan.coverage.deferred }
  const portfolio = ['# Security Hardening Portfolio', '', `- Scan: \`${scan.id}\``, `- Outcome: ${outcome}`, '', '## Evidence', ...(evidence.length ? evidence.map(finding => `- ${finding.title} (${finding.id}) at \`${finding.locations[0].file}:${finding.locations[0].line}\`: ${finding.rootCause}`) : ['- No reportable findings share a demonstrated structural cause.']), '', '## Assessment', opportunity ? `The observed evidence indicates that ${opportunity.title.toLowerCase()}. The proposed invariant is: ${opportunity.invariant}` : 'The current evidence favors focused local remediations. A larger design change would not be justified without repeated or cross-boundary evidence.', '', '## Options', ...(opportunity ? ['1. **Central owned enforcement boundary**: move the sensitive control into one reviewed API; retain focused fixes during migration.', '2. **Local strengthening**: patch each observed callsite; lower disruption but retain drift risk.', '', '## Recommendation', 'Adopt the central boundary when the affected operations are expected to grow or are owned by multiple components. Prefer local strengthening when the evidence remains isolated and the migration cost is disproportionate.'] : ['Use the verified local remediation plan for each finding, then rescan before considering architectural changes.'])].join('\n') + '\n'
  const structuredPath = join(directory, 'hardening.json'); const portfolioPath = join(directory, 'hardening.md'); await writeFile(structuredPath, `${JSON.stringify(structured, null, 2)}\n`, 'utf8'); await writeFile(portfolioPath, portfolio, 'utf8'); if (opportunity) await writeFile(join(directory, 'proposals', `${slug(opportunity.title)}.md`), portfolio, 'utf8')
  return { id, scanId, outcome, directory, portfolio: portfolioPath, structured: structuredPath, opportunities: opportunity ? [1] : [] }
}
