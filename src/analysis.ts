import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { basename, isAbsolute, join, relative, resolve } from 'node:path'
import { randomUUID } from 'node:crypto'
import type { Config } from './config.js'
import type { Finding, ScanRecord } from './contracts.js'
import { assessDirectory } from './scanner.js'
import { getStateDir, loadScan, sha256 } from './state.js'

export interface ImportedFinding { id: string; title: string; description: string; severity?: string; cwe?: string; ruleId?: string; sourceType: 'sarif' | 'generic' | 'text'; locations: Array<{ file: string; line?: number }>; sourcePath: string; sourceSha256: string }
export interface TriageResult { id: string; importedFindingId: string; target: string; status: 'affected' | 'not_affected' | 'needs_information'; confidence: 'high' | 'medium' | 'low'; rationale: string; evidence: string[]; limitations: string[]; createdAt: string }
export interface HardeningResult { id: string; scanId: string; outcome: 'structural_hardening_recommended' | 'local_remediation_preferred'; directory: string; portfolio: string; structured: string; opportunities: number[] }

function inside(root: string, target: string): boolean { const item = relative(root, target); return item === '' || (!item.startsWith('..') && !isAbsolute(item)) }
function text(value: unknown): string { return typeof value === 'string' ? value.trim() : '' }
function list(value: unknown): unknown[] { return Array.isArray(value) ? value : [] }
function slug(value: string): string { return value.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '') || 'imported-finding' }
function object(value: unknown): Record<string, unknown> { return typeof value === 'object' && value !== null && !Array.isArray(value) ? value as Record<string, unknown> : {} }
function stringList(value: unknown): string[] { return list(value).map(text).filter(Boolean) }

function importedLocations(value: unknown): ImportedFinding['locations'] {
  return list(value).map(raw => {
    const location = object(raw); const physical = object(location.physicalLocation); const artifact = object(physical.artifactLocation); const region = object(physical.region)
    const line = typeof location.line === 'number' ? location.line : typeof location.startLine === 'number' ? location.startLine : typeof region.startLine === 'number' ? region.startLine : undefined
    return { file: text(location.file) || text(location.path) || text(artifact.uri), line }
  }).filter(location => location.file)
}

function sarifEntries(parsed: Record<string, unknown>): Array<Record<string, unknown>> {
  const entries: Array<Record<string, unknown>> = []
  for (const runRaw of list(parsed.runs)) {
    const run = object(runRaw); const driver = object(object(run.tool).driver); const rules = new Map<string, Record<string, unknown>>()
    for (const ruleRaw of list(driver.rules)) { const rule = object(ruleRaw); const id = text(rule.id); if (id) rules.set(id, rule) }
    for (const resultRaw of list(run.results)) {
      const result = object(resultRaw); const ruleId = text(result.ruleId); const rule = rules.get(ruleId) ?? {}; const message = text(object(result.message).text) || text(object(result.message).markdown)
      const properties = object(result.properties); const ruleProperties = object(rule.properties); const tags = [...stringList(properties.tags), ...stringList(ruleProperties.tags)]
      const cwe = tags.find(tag => /^CWE-\d+$/i.test(tag)) ?? text(properties.cwe) ?? text(ruleProperties.cwe)
      entries.push({ title: text(object(rule.shortDescription).text) || text(object(rule.fullDescription).text) || ruleId || message, description: message || text(object(rule.fullDescription).text), severity: text(result.level), cwe, ruleId, locations: list(result.locations), sourceType: 'sarif' })
    }
  }
  return entries
}

export async function importFindings(workspace: string, sourcePath: string): Promise<ImportedFinding[]> {
  const root = resolve(workspace); const file = resolve(root, sourcePath); if (!inside(root, file)) throw new Error('Imported finding file must remain inside the active workspace.')
  const raw = await readFile(file, 'utf8'); const sourceSha256 = sha256(raw); let parsed: unknown
  try { parsed = JSON.parse(raw) } catch { parsed = raw }
  const rootValue = object(parsed); const entries = rootValue.version === '2.1.0' && Array.isArray(rootValue.runs) ? sarifEntries(rootValue) : Array.isArray(parsed) ? parsed : typeof parsed === 'object' && parsed !== null ? list(rootValue.findings).length ? list(rootValue.findings) : [parsed] : [{ title: basename(file), description: raw, sourceType: 'text' }]
  return entries.map((entry, index) => {
    const item = object(entry); const locations = importedLocations(item.locations)
    const title = text(item.title) || text(item.name) || `Imported finding ${index + 1}`
    const sourceType = item.sourceType === 'sarif' ? 'sarif' : item.sourceType === 'text' ? 'text' : 'generic'
    return { id: `imp_${sha256(`${sourceSha256}:${index}:${title}`).slice(0, 24)}`, title, description: text(item.description) || text(item.summary) || JSON.stringify(item), severity: text(item.severity), cwe: text(item.cwe), ruleId: text(item.ruleId) || undefined, sourceType, locations, sourcePath, sourceSha256 }
  })
}

function compatibleRules(imported: ImportedFinding): Set<string> {
  const value = `${imported.ruleId ?? ''}\n${imported.title}\n${imported.description}\n${imported.cwe ?? ''}`.toLowerCase()
  const rules = new Set<string>()
  const matches: Array<[RegExp, string[]]> = [
    [/(?:tls|certificate|cwe-295|rejectunauthorized|insecureskipverify)/, ['tls-verification-disabled']],
    [/(?:eval|dynamic.code|code.injection|cwe-95)/, ['dangerous-dynamic-code']],
    [/(?:command|shell|process.execution|cwe-78)/, ['shell-command-construction']],
    [/(?:path.traversal|directory.traversal|cwe-22)/, ['path-traversal-sink']],
    [/(?:ssrf|server.side.request|cwe-918)/, ['ssrf-request-sink']],
    [/(?:deserial|cwe-502)/, ['unsafe-deserialization']],
    [/(?:jwt|signature.verification|cwe-347)/, ['jwt-verification-disabled']],
    [/(?:credential|hardcoded.secret|cwe-798)/, ['hardcoded-secret-marker']],
    [/(?:sql.injection|cwe-89)/, ['sql-injection-query-construction']],
    [/(?:xml|xxe|cwe-611)/, ['xml-external-entity-risk']],
    [/(?:cors|cwe-942)/, ['cors-wildcard-credentials']],
    [/(?:authori[sz]|permission|access.control|cwe-862)/, ['missing-authorization-route']],
  ]
  for (const [pattern, values] of matches) if (pattern.test(value)) for (const rule of values) rules.add(rule)
  return rules
}

export async function triageImportedFinding(workspace: string, config: Config, imported: ImportedFinding): Promise<TriageResult> {
  const root = resolve(workspace); const evidence: string[] = []; const limitations: string[] = []; const compatible = compatibleRules(imported)
  if (!imported.locations.length) limitations.push('The imported finding has no local file location to reopen.')
  if (!compatible.size) limitations.push('The imported rule, CWE, title, and message do not identify a locally supported vulnerability family.')
  const local = compatible.size ? await assessDirectory(root, { maxFiles: config.maxFiles, maxFileBytes: config.maxFileBytes }, true) : undefined
  let readableLocations = 0; let exactCandidateMatches = 0
  for (const location of imported.locations) {
    const file = resolve(root, location.file)
    if (!inside(root, file)) { limitations.push(`Imported location ${location.file} is outside the workspace.`); continue }
    try {
      const content = await readFile(file, 'utf8'); readableLocations++
      const candidates = local?.candidates.filter(candidate => candidate.file === location.file && compatible.has(candidate.rule) && (location.line === undefined || candidate.line === location.line)) ?? []
      const unique = [...new Map(candidates.map(candidate => [`${candidate.rule}:${candidate.file}:${candidate.line}`, candidate])).values()]
      if (unique.length) { exactCandidateMatches += unique.length; evidence.push(...unique.map(candidate => `Local ${candidate.rule} evidence matches imported location ${location.file}${location.line ? `:${location.line}` : ''} at ${candidate.file}:${candidate.line}.`)) }
      else limitations.push(`No compatible local native-analysis evidence matched ${location.file}${location.line ? `:${location.line}` : ''}.`)
    } catch { limitations.push(`Imported location ${location.file} could not be read.`) }
  }
  const status: TriageResult['status'] = exactCandidateMatches ? 'affected' : compatible.size && imported.locations.length && readableLocations === imported.locations.length ? 'not_affected' : 'needs_information'
  const confidence: TriageResult['confidence'] = status === 'affected' ? 'medium' : status === 'not_affected' ? 'medium' : 'low'
  const rationale = status === 'affected' ? 'A local native-analysis candidate of the same vulnerability family was found at the imported location. This remains triage evidence and requires the normal candidate-validation and attack-path gates before a reportable conclusion.' : status === 'not_affected' ? 'Every supplied local location was readable, but no compatible local native-analysis candidate matched the cited line range. This conclusion applies only to the imported claim and does not prove other locations safe.' : 'The imported evidence lacks a supported vulnerability family, a readable local location, or enough location detail to establish repository impact.'
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
