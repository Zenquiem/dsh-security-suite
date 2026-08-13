import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { basename, isAbsolute, join, relative, resolve } from 'node:path'
import { randomUUID } from 'node:crypto'
import type { Config } from './config.js'
import type { Finding, ScanRecord } from './contracts.js'
import { assessDirectory } from './scanner.js'
import { generateDerivedHardening, getStateDir, loadScan, sha256 } from './state.js'

export interface ImportedFinding { id: string; title: string; description: string; severity?: string; cwe?: string; ruleId?: string; sourceType: 'sarif' | 'cve' | 'advisory' | 'scanner_ticket' | 'bug_bounty' | 'freeform' | 'generic' | 'text'; locations: Array<{ file: string; line?: number }>; sourcePath: string; sourceSha256: string; inputId?: string; references?: string[]; component?: string; provenance?: Record<string, string> }
export interface TriageResult { id: string; importedFindingId: string; target: string; status: 'affected' | 'not_affected' | 'needs_information'; confidence: 'high' | 'medium' | 'low'; rationale: string; evidence: string[]; limitations: string[]; staticAssessment: { exactCandidateMatches: number; requestContextMatches: number }; createdAt: string }
export interface HardeningResult { id: string; scanId: string; outcome: 'structural_hardening_recommended' | 'local_remediation_preferred'; directory: string; portfolio: string; structured: string; opportunities: number[] }
export type GitHubFindingSource = 'code_scanning' | 'dependabot' | 'advisories' | 'all'
export interface BacklogTriageItem {
  triageItemId: string
  inputId: string
  sourceType: 'sarif' | 'cve' | 'advisory' | 'scanner_ticket' | 'bug_bounty' | 'freeform' | 'unknown'
  title: string
  normalizedInput: { component?: string; claimedSource?: string; claimedSink?: string; affectedVersion?: string; preconditions?: string; impact?: string; references: string[] }
  verdict: 'confirmed' | 'not_actionable' | 'needs_review'
  confidence: 'high' | 'medium' | 'low'
  affectedLocations: Array<{ file: string; line?: number }>
  boundaryAssessment: { productSurface: string; actor: string; source: string; boundaryCrossed: boolean | null; policyBasis: string }
  exploitabilityStackRank: { rankQueue: 'confirmed' | 'needs_review' | null; rank: number | null; rationale: string; drivers: string[] }
  evidence: string[]
  counterevidence: string[]
  proofGaps: string[]
  recommendedNextStep: 'fix_finding' | 'validation' | 'collect_information' | 'close'
  fixFindingHandoff: string | null
}
export interface BacklogTriageResult { schemaVersion: 'dsh-security-suite.triage/v1'; id: string; repository: { path: string; policyFiles: string[] }; items: BacklogTriageItem[]; createdAt: string; artifactPath: string }

function inside(root: string, target: string): boolean { const item = relative(root, target); return item === '' || (!item.startsWith('..') && !isAbsolute(item)) }
function text(value: unknown): string { return typeof value === 'string' ? value.trim() : '' }
function list(value: unknown): unknown[] { return Array.isArray(value) ? value : [] }
function object(value: unknown): Record<string, unknown> { return typeof value === 'object' && value !== null && !Array.isArray(value) ? value as Record<string, unknown> : {} }
function stringList(value: unknown): string[] { return list(value).map(text).filter(Boolean) }
function stringValue(value: unknown): string | undefined { const result = typeof value === 'number' && Number.isFinite(value) ? String(value) : text(value); return result || undefined }
function sourceType(value: unknown): ImportedFinding['sourceType'] { const source = text(value); return ['sarif', 'cve', 'advisory', 'scanner_ticket', 'bug_bounty', 'freeform', 'generic', 'text'].includes(source) ? source as ImportedFinding['sourceType'] : 'generic' }
function githubHeaders(token: string): Record<string, string> { if (!token.trim()) throw new Error('A GitHub token is required for GitHub security finding intake.'); return { authorization: `Bearer ${token}`, accept: 'application/vnd.github+json', 'user-agent': 'dsh-security-suite' } }
function githubRepository(repository: string): [string, string] { const parts = repository.split('/'); if (parts.length !== 2 || !parts[0] || !parts[1]) throw new Error('GitHub intake requires repository in owner/name form.'); return [parts[0], parts[1]] }
function digestImported(value: unknown): string { return sha256(JSON.stringify(value)) }

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
    const source = sourceType(item.sourceType)
    return { id: `imp_${sha256(`${sourceSha256}:${index}:${title}`).slice(0, 24)}`, inputId: stringValue(item.id) ?? stringValue(item.inputId), title, description: text(item.description) || text(item.summary) || JSON.stringify(item), severity: text(item.severity), cwe: text(item.cwe), ruleId: text(item.ruleId) || undefined, sourceType: source, locations, sourcePath, sourceSha256, references: stringList(item.references), component: stringValue(item.component) }
  })
}

function nextLink(value: string | null): string | undefined {
  const match = value?.split(',').map(part => part.trim()).find(part => /rel="next"/.test(part))
  return match ? /^<([^>]+)>/.exec(match)?.[1] : undefined
}

async function githubPages(url: string, token: string): Promise<unknown[]> {
  const output: unknown[] = []; let next: string | undefined = url; let pages = 0
  while (next) {
    if (++pages > 20) throw new Error('GitHub intake exceeded the 20-page safety limit; narrow the requested source before continuing.')
    const response = await fetch(next, { headers: githubHeaders(token) }); let value: unknown
    try { value = await response.json() } catch { value = await response.text() }
    if (!response.ok) throw new Error(`GitHub security finding intake failed with HTTP ${response.status}.`)
    if (!Array.isArray(value)) throw new Error('GitHub security finding intake returned an unexpected response shape.')
    output.push(...value); next = nextLink(response.headers.get('link'))
  }
  return output
}

function githubLocation(value: unknown): ImportedFinding['locations'] {
  const row = object(value); const instance = object(row.most_recent_instance); const physical = object((Object.keys(instance).length ? instance : row).location); const path = stringValue(physical.path) ?? stringValue(row.path); const line = typeof physical.start_line === 'number' ? physical.start_line : typeof row.line === 'number' ? row.line : undefined
  return path ? [{ file: path, line }] : []
}

function githubImported(value: Record<string, unknown>, index: number, repository: string, source: GitHubFindingSource, instances: unknown[] = []): ImportedFinding {
  const number = stringValue(value.number) ?? stringValue(value.ghsa_id) ?? `${source}-${index + 1}`; const rule = object(value.rule); const advisory = object(value.security_advisory); const dependency = object(value.dependency); const packageValue = object(dependency.package)
  const cve = stringList(advisory.cve_id ? [advisory.cve_id] : advisory.cve_ids).find(item => /^CVE-/i.test(item))
  const locations = source === 'code_scanning' ? instances.flatMap(githubLocation) : githubLocation(value)
  const title = stringValue(rule.description) ?? stringValue(advisory.summary) ?? stringValue(value.summary) ?? `GitHub ${source} finding ${number}`
  const description = [stringValue(value.html_url) ? `GitHub finding: ${value.html_url}` : '', stringValue(rule.full_description) ?? stringValue(advisory.description) ?? stringValue(value.description) ?? '', stringValue(value.dismissed_reason) ? `Dismissal context: ${value.dismissed_reason}` : ''].filter(Boolean).join('\n\n')
  const references = [stringValue(value.html_url), stringValue(value.url)].filter((item): item is string => Boolean(item))
  const provenance: Record<string, string> = { repository, source, number, ...(stringValue(value.state) ? { state: stringValue(value.state)! } : {}), ...(stringValue(advisory.ghsa_id) ? { ghsaId: stringValue(advisory.ghsa_id)! } : {}), ...(cve ? { cve } : {}) }
  return { id: `gh_${sha256(`${repository}:${source}:${number}`).slice(0, 24)}`, inputId: `${repository}:${source}:${number}`, title, description: description || title, severity: stringValue(rule.severity) ?? stringValue(advisory.severity) ?? stringValue(value.security_advisory ? object(value.security_advisory).severity : undefined), cwe: stringValue(rule.cwe_id) ?? cve, ruleId: stringValue(rule.id), sourceType: source === 'code_scanning' ? 'sarif' : cve ? 'cve' : 'advisory', locations, sourcePath: `github://${repository}/${source}/${number}`, sourceSha256: digestImported(value), references, component: stringValue(packageValue.name) ?? stringValue(value.manifest_path), provenance }
}

/** Read selected GitHub security sources through REST and normalize them as untrusted local triage inputs. */
export async function importGitHubSecurityFindings(repository: string, source: GitHubFindingSource, token: string): Promise<ImportedFinding[]> {
  const [owner, repo] = githubRepository(repository); const base = `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`; const imported: ImportedFinding[] = []
  if (source === 'code_scanning' || source === 'all') {
    const alerts = await githubPages(`${base}/code-scanning/alerts?state=open&per_page=100`, token)
    for (const [index, raw] of alerts.entries()) {
      const alert = object(raw); const number = stringValue(alert.number); const instances = number ? await githubPages(`${base}/code-scanning/alerts/${encodeURIComponent(number)}/instances?per_page=100`, token) : []
      imported.push(githubImported(alert, index, repository, 'code_scanning', instances))
    }
  }
  if (source === 'dependabot' || source === 'all') for (const classification of ['general', 'malware']) {
    const alerts = await githubPages(`${base}/dependabot/alerts?classification=${classification}&state=open&per_page=100`, token)
    imported.push(...alerts.map((raw, index) => githubImported(object(raw), index, repository, 'dependabot')))
  }
  if (source === 'advisories' || source === 'all') for (const state of ['triage', 'draft', 'published', 'closed']) {
    const advisories = await githubPages(`${base}/security-advisories?state=${state}&per_page=100`, token)
    imported.push(...advisories.map((raw, index) => githubImported(object(raw), index, repository, 'advisories')))
  }
  return imported
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

async function evaluateImportedFinding(root: string, imported: ImportedFinding, local: Awaited<ReturnType<typeof assessDirectory>> | undefined): Promise<Omit<TriageResult, 'id' | 'target' | 'createdAt'>> {
  const evidence: string[] = []; const limitations: string[] = []; const compatible = compatibleRules(imported)
  if (!imported.locations.length) limitations.push('The imported finding has no local file location to reopen.')
  if (!compatible.size) limitations.push('The imported rule, CWE, title, and message do not identify a locally supported vulnerability family.')
  let readableLocations = 0; let exactCandidateMatches = 0; let requestContextMatches = 0
  for (const location of imported.locations) {
    const file = resolve(root, location.file)
    if (!inside(root, file)) { limitations.push(`Imported location ${location.file} is outside the workspace.`); continue }
    try {
      const content = await readFile(file, 'utf8'); readableLocations++
      const candidates = local?.candidates.filter(candidate => candidate.file === location.file && compatible.has(candidate.rule) && (location.line === undefined || candidate.line === location.line)) ?? []
      const unique = [...new Map(candidates.map(candidate => [`${candidate.rule}:${candidate.file}:${candidate.line}`, candidate])).values()]
      if (unique.length) { exactCandidateMatches += unique.length; requestContextMatches += unique.filter(candidate => candidate.evidence.some(item => item.kind === 'context')).length; evidence.push(...unique.map(candidate => `Local ${candidate.rule} evidence matches imported location ${location.file}${location.line ? `:${location.line}` : ''} at ${candidate.file}:${candidate.line}.`)) }
      else limitations.push(`No compatible local native-analysis evidence matched ${location.file}${location.line ? `:${location.line}` : ''}.`)
    } catch { limitations.push(`Imported location ${location.file} could not be read.`) }
  }
  const status: TriageResult['status'] = exactCandidateMatches ? 'affected' : compatible.size && imported.locations.length && readableLocations === imported.locations.length ? 'not_affected' : 'needs_information'
  const confidence: TriageResult['confidence'] = status === 'affected' ? 'medium' : status === 'not_affected' ? 'medium' : 'low'
  const rationale = status === 'affected' ? 'A local native-analysis candidate of the same vulnerability family was found at the imported location. This remains triage evidence and requires the normal candidate-validation and attack-path gates before a reportable conclusion.' : status === 'not_affected' ? 'Every supplied local location was readable, but no compatible local native-analysis candidate matched the cited line range. This conclusion applies only to the imported claim and does not prove other locations safe.' : 'The imported evidence lacks a supported vulnerability family, a readable local location, or enough location detail to establish repository impact.'
  return { importedFindingId: imported.id, status, confidence, rationale, evidence, limitations, staticAssessment: { exactCandidateMatches, requestContextMatches } }
}

async function persistTriageResult(config: Config, root: string, imported: ImportedFinding, value: Omit<TriageResult, 'id' | 'target' | 'createdAt'>): Promise<TriageResult> {
  const result: TriageResult = { id: `tri_${randomUUID()}`, target: basename(root), createdAt: new Date().toISOString(), ...value }
  const directory = join(getStateDir(config.stateDir), 'triage'); await mkdir(directory, { recursive: true }); await writeFile(join(directory, `${result.id}.json`), `${JSON.stringify({ imported, result }, null, 2)}\n`, 'utf8'); return result
}

export async function triageImportedFinding(workspace: string, config: Config, imported: ImportedFinding): Promise<TriageResult> {
  const root = resolve(workspace); const local = compatibleRules(imported).size ? await assessDirectory(root, { maxFiles: config.maxFiles, maxFileBytes: config.maxFileBytes }, true) : undefined
  return persistTriageResult(config, root, imported, await evaluateImportedFinding(root, imported, local))
}

async function policyFilesFor(root: string): Promise<string[]> {
  const candidates = ['SECURITY.md', '.github/SECURITY.md']; const files: string[] = []
  for (const candidate of candidates) { try { await readFile(join(root, candidate), 'utf8'); files.push(candidate) } catch { /* policy is optional evidence, not an assumed boundary. */ } }
  return files
}

async function policySupportsRuntimeBoundary(root: string, files: string[]): Promise<boolean> {
  const values = await Promise.all(files.map(file => readFile(join(root, file), 'utf8')))
  return values.some(value => /\b(runtime|production|service|api|server)\b[\s\S]{0,160}\b(in scope|supported|security boundary)\b/i.test(value) || /\b(in scope|supported|security boundary)\b[\s\S]{0,160}\b(runtime|production|service|api|server)\b/i.test(value))
}

function surfaceFor(finding: ImportedFinding): { productSurface: string; actor: string; source: string; boundaryCrossed: boolean | null } {
  const files = finding.locations.map(location => location.file)
  if (!files.length) return { productSurface: 'unknown', actor: 'unknown', source: 'External finding claim has no local location.', boundaryCrossed: null }
  if (files.every(file => /(?:^|\/)(?:test|tests|fixtures?|examples?|docs?)(?:\/|$)/i.test(file))) return { productSurface: 'test/example/documentation', actor: 'unknown', source: 'Imported location is in a non-product path.', boundaryCrossed: false }
  return { productSurface: 'repository runtime surface requires local confirmation', actor: 'unknown external or lower-privilege caller', source: 'Imported finding and local source location.', boundaryCrossed: null }
}

function triageSourceType(finding: ImportedFinding): BacklogTriageItem['sourceType'] { return ['sarif', 'cve', 'advisory', 'scanner_ticket', 'bug_bounty', 'freeform'].includes(finding.sourceType) ? finding.sourceType as BacklogTriageItem['sourceType'] : 'unknown' }
function triageScore(item: BacklogTriageItem): number { const severity = /critical/i.test(item.title + item.normalizedInput.impact) ? 4 : /high/i.test(item.title + item.normalizedInput.impact) ? 3 : /medium/i.test(item.title + item.normalizedInput.impact) ? 2 : 1; return severity * 10 + (item.affectedLocations.length ? 3 : 0) + (item.boundaryAssessment.boundaryCrossed ? 4 : 0) + (item.confidence === 'high' ? 3 : item.confidence === 'medium' ? 2 : 1) }

/** Triage a complete supplied backlog without dropping duplicate-looking inputs; each source item remains auditable. */
export async function triageFindingBacklog(workspace: string, config: Config, imported: ImportedFinding[]): Promise<BacklogTriageResult> {
  if (!imported.length) throw new Error('At least one imported finding is required for backlog triage.')
  const root = resolve(workspace); const policyFiles = await policyFilesFor(root); const [runtimePolicy, local] = await Promise.all([policySupportsRuntimeBoundary(root, policyFiles), imported.some(finding => compatibleRules(finding).size) ? assessDirectory(root, { maxFiles: config.maxFiles, maxFileBytes: config.maxFileBytes }, true) : Promise.resolve(undefined)]); const results: BacklogTriageItem[] = []
  for (const [index, finding] of imported.entries()) {
    const raw = await persistTriageResult(config, root, finding, await evaluateImportedFinding(root, finding, local)); const surface = surfaceFor(finding)
    if (raw.staticAssessment.requestContextMatches > 0 && runtimePolicy && surface.boundaryCrossed === null) surface.boundaryCrossed = true
    const status = raw.status === 'affected' && surface.boundaryCrossed !== false ? 'needs_review' : raw.status === 'not_affected' || surface.boundaryCrossed === false ? 'not_actionable' : 'needs_review'
    const confirmed = status === 'needs_review' && raw.status === 'affected' && surface.boundaryCrossed === true
    const verdict: BacklogTriageItem['verdict'] = confirmed ? 'confirmed' : status
    const proofGaps = [...raw.limitations, ...(surface.boundaryCrossed === null ? ['The supported product surface, attacker privilege, and boundary crossing remain unproven by the imported claim and local static match.'] : [])]
    const counterevidence = raw.status === 'not_affected' ? ['The cited local locations were readable but no compatible native-analysis candidate matched the imported claim.'] : surface.boundaryCrossed === false ? ['The supplied locations are limited to test, example, fixture, or documentation paths.'] : []
    results.push({ triageItemId: `triage-${String(index + 1).padStart(3, '0')}`, inputId: finding.inputId ?? finding.id, sourceType: triageSourceType(finding), title: finding.title, normalizedInput: { component: finding.component, claimedSource: finding.description.slice(0, 500), claimedSink: finding.ruleId, affectedVersion: finding.provenance?.state, impact: finding.severity, references: finding.references ?? [] }, verdict, confidence: verdict === 'not_actionable' ? raw.confidence : raw.status === 'affected' ? 'medium' : 'low', affectedLocations: finding.locations, boundaryAssessment: { ...surface, policyBasis: policyFiles.length ? `Applicable repository policy files were retained for review: ${policyFiles.join(', ')}.` : 'No repository SECURITY.md policy was found; supported-boundary status remains a proof gap.' }, exploitabilityStackRank: { rankQueue: verdict === 'confirmed' || verdict === 'needs_review' ? verdict : null, rank: null, rationale: verdict === 'not_actionable' ? 'not actionable' : 'Ranking is based on local evidence strength, affected location, and unresolved boundary exposure.', drivers: verdict === 'not_actionable' ? [] : ['local source evidence', 'affected location', 'boundary evidence gap', 'severity claim'] }, evidence: raw.evidence, counterevidence, proofGaps, recommendedNextStep: verdict === 'confirmed' ? 'fix_finding' : verdict === 'needs_review' ? 'validation' : 'close', fixFindingHandoff: verdict === 'confirmed' ? `Validate and remediate ${finding.title} at ${finding.locations.map(location => `${location.file}${location.line ? `:${location.line}` : ''}`).join(', ')}.` : null })
  }
  for (const queue of ['confirmed', 'needs_review'] as const) results.filter(item => item.exploitabilityStackRank.rankQueue === queue).sort((a, b) => triageScore(b) - triageScore(a) || a.triageItemId.localeCompare(b.triageItemId)).forEach((item, index) => { item.exploitabilityStackRank.rank = index + 1 })
  const id = `backlog_${randomUUID()}`; const artifactPath = join(getStateDir(config.stateDir), 'triage', `${id}.json`); const result: BacklogTriageResult = { schemaVersion: 'dsh-security-suite.triage/v1', id, repository: { path: root, policyFiles }, items: results, createdAt: new Date().toISOString(), artifactPath }
  await mkdir(join(getStateDir(config.stateDir), 'triage'), { recursive: true }); await writeFile(artifactPath, `${JSON.stringify(result, null, 2)}\n`, 'utf8'); return result
}

export async function generateHardeningPortfolio(config: Config, scanId: string): Promise<HardeningResult> {
  const scan = await loadScan(getStateDir(config.stateDir), scanId); const generated = await generateDerivedHardening(scan)
  if (!generated) throw new Error('No reportable findings are available for a hardening portfolio.')
  return { id: `hard_${randomUUID()}`, scanId, outcome: generated.outcome, directory: join(scan.artifacts.directory, 'hardening'), portfolio: join(scan.artifacts.directory, generated.portfolioPath), structured: join(scan.artifacts.directory, generated.structuredPath), opportunities: generated.outcome === 'structural_hardening_recommended' ? [1] : [] }
}
