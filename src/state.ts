import { createHash, randomUUID } from 'node:crypto'
import { mkdir, readFile, readdir, rename, stat, writeFile } from 'node:fs/promises'
import { basename, isAbsolute, join, relative, resolve, sep } from 'node:path'
import { homedir } from 'node:os'
import type { Finding, ScanRecord } from './contracts.js'

const SCAN_ID = /^scan_[0-9a-f-]+$/
const SHA256 = /^[a-f0-9]{64}$/

export function getStateDir(configured: string): string { return resolve(configured || process.env.DSH_SECURITY_SUITE_STATE_DIR || join(homedir(), '.dsh-security-suite')) }
export function createScanId(): string { return `scan_${randomUUID()}` }
export function sha256(value: string | Buffer): string { return createHash('sha256').update(value).digest('hex') }
export function findingId(ruleId: string, anchor: string, instance = ''): string { return `dsf_${sha256(`${ruleId}:${anchor}:${instance}`).slice(0, 24)}` }
export function candidateId(ruleId: string, file: string, line: number): string { return `cand_${sha256(`${ruleId}:${file}:${line}`).slice(0, 16)}` }

function scanPath(stateDir: string, id: string): string { if (!SCAN_ID.test(id)) throw new Error('Invalid scan id.'); return join(stateDir, 'scans', `${id}.json`) }
function canonical(record: ScanRecord): string { const { seal: _seal, ...unsealed } = record; return JSON.stringify(unsealed) }
export function sealScan(record: ScanRecord): string { return sha256(canonical(record)) }
export function verifySeal(record: ScanRecord): boolean { return record.seal === sealScan(record) }

function contained(root: string, path: string): boolean { const item = relative(root, path); return item === '' || (!item.startsWith(`..${sep}`) && item !== '..' && !isAbsolute(item)) }
function safeRelative(value: string): string {
  if (!value || isAbsolute(value) || value.includes('\\') || value.split('/').includes('..')) throw new Error(`Unsafe artifact path: ${value}`)
  return value
}

async function atomicWrite(path: string, content: string | Buffer): Promise<void> {
  await mkdir(dirname(path), { recursive: true })
  const temporary = `${path}.${randomUUID()}.tmp`
  await writeFile(temporary, content)
  await rename(temporary, path)
}

function dirname(path: string): string { return path.slice(0, Math.max(path.lastIndexOf('/'), path.lastIndexOf('\\'))) || '.' }
function json(value: unknown): string { return `${JSON.stringify(value, null, 2)}\n` }

export function scanArtifactDir(stateDir: string, target: string, scanId: string): string {
  if (!SCAN_ID.test(scanId)) throw new Error('Invalid scan id.')
  const targetName = basename(resolve(target)).replace(/[^a-zA-Z0-9._-]/g, '_') || 'workspace'
  return join(stateDir, 'artifacts', targetName, scanId)
}

export interface DerivedHardening {
  outcome: 'structural_hardening_recommended' | 'local_remediation_preferred'
  portfolioPath: string
  structuredPath: string
  evidenceDigest: string
}

export async function writeArtifact(scan: ScanRecord, path: string, content: string | Buffer): Promise<string> {
  const rel = safeRelative(path); const root = resolve(scan.artifacts.directory); const destination = resolve(root, rel)
  if (!contained(root, destination)) throw new Error('Artifact path must remain inside the scan directory.')
  await atomicWrite(destination, content); return rel
}

export async function readArtifact(scan: ScanRecord, path: string): Promise<string> {
  const rel = safeRelative(path); const root = resolve(scan.artifacts.directory); const source = resolve(root, rel)
  if (!contained(root, source)) throw new Error('Artifact path must remain inside the scan directory.')
  const metadata = await stat(source); if (!metadata.isFile() || metadata.isSymbolicLink()) throw new Error('Artifact must be a regular non-symlink file.')
  return readFile(source, 'utf8')
}

function findingsDocument(scan: ScanRecord): Record<string, unknown> {
  return {
    documentType: 'dsh-security-suite.findings', schemaVersion: '1.0', scanId: scan.id,
    findings: scan.findings.filter(finding => finding.disposition === 'reportable').map(finding => ({
      findingId: finding.id, occurrenceId: `occ_${sha256(`${scan.id}:${finding.fingerprint}`).slice(0, 24)}`, ruleId: finding.ruleId, identity: finding.identity,
      fingerprints: { algorithm: 'dsh-security-suite/v1', primary: `dsh-security-suite/v1:sha256:${finding.fingerprint}` }, title: finding.title,
      summary: `${finding.rootCause} Impact: ${finding.impact}`,
      severity: { level: finding.severity, rationale: finding.attackPathRecord?.severityRationale ?? finding.impact, changeConditions: finding.attackPathRecord?.changeConditions ?? 'Reassess if the entry point, authorization boundary, deployment exposure, or sink behavior changes.' },
      confidence: { level: finding.confidence, rationale: finding.validationRecord?.directEvidence ?? finding.validation, missingProof: finding.validationRecord?.limitations ?? 'No additional proof gap was recorded.' },
      taxonomy: { category: finding.ruleId.split('.')[0], cwe: [finding.cwe] }, locations: finding.locations.map(location => ({ path: location.file, startLine: location.line, endLine: location.line, role: location.role })),
      codeEvidence: finding.evidence.filter(item => item.location).map((item, index) => ({ id: `evidence-${index + 1}`, label: item.kind, path: item.location?.file, startLine: item.location?.line, endLine: item.location?.line, role: item.location?.role ?? 'root_control', code: item.location?.excerpt, explanation: item.detail })),
      rootCause: { summary: finding.rootCause, evidenceRefs: finding.evidence.filter(item => item.location).map((_item, index) => `evidence-${index + 1}`) },
      validation: finding.validationRecord ? { ...finding.validationRecord, evidenceRefs: finding.evidence.filter(item => item.location).map((_item, index) => `evidence-${index + 1}`) } : { method: 'static', conclusion: 'reportable', directEvidence: finding.validation, counterevidence: finding.counterevidence, limitations: 'No structured validation receipt was retained.' },
      attackPath: finding.attackPathRecord ? { ...finding.attackPathRecord, evidenceRefs: finding.attackPathRecord.sourceReferences.map(reference => `${reference.file}:${reference.line}`) } : { dataflow: finding.attackPath, reachability: finding.attackPath, evidenceRefs: [] },
      remediation: { summary: finding.remediation, tests: [`Run the focused regression test plan for ${finding.ruleId}.`], preventiveControls: ['Keep the source-to-sink control centralized, reviewed, and covered by regression tests.'] },
      provenance: { source: 'dsh-security-suite native analysis' }, extensions: { candidateId: finding.candidateId, writeup: finding.writeup ?? null },
    })),
  }
}

function writeupPath(finding: Finding): string { return `findings/${finding.candidateId}/${finding.candidateId}.md` }

function writeupEvidenceDigest(finding: Finding): string {
  return sha256(JSON.stringify({
    id: finding.id, candidateId: finding.candidateId, locations: finding.locations, rootCause: finding.rootCause,
    validation: finding.validationRecord ?? finding.validation, attackPath: finding.attackPathRecord ?? finding.attackPath,
    impact: finding.impact, counterevidence: finding.counterevidence, remediation: finding.remediation,
  }))
}

/** Render one evidence-bound vulnerability report without inventing exploit evidence. */
export function renderFindingWriteup(scan: ScanRecord, finding: Finding): string {
  const location = finding.locations[0]
  const validation = finding.validationRecord
  const attackPath = finding.attackPathRecord
  const evidence = finding.evidence.length
    ? finding.evidence.map(item => `- ${item.kind}: ${item.detail}${item.location ? ` (\`${item.location.file}:${item.location.line}\`)` : ''}`).join('\n')
    : '- No additional evidence was retained.'
  const reproduction = validation?.method === 'runtime' || validation?.method === 'hybrid'
    ? 'Runtime evidence is recorded in the validation receipt. Reproduction remains limited to the documented test environment and prerequisites.'
    : 'No executable PoC is generated: retained evidence is static or isolated-test evidence and does not establish a safe reproducible exploit environment.'
  const locations = finding.locations.map(item => `- \`${item.file}:${item.line}\` (${item.role ?? 'root_control'})\n\n  \`\`\`\n  ${item.excerpt}\n  \`\`\``).join('\n')
  const citations = (references: { file: string; line: number; role: string }[]) => references.map(reference => `\`${reference.file}:${reference.line}\` (${reference.role})`).join(', ')
  return `# ${finding.title}\n\n## Identity\n\n- Scan: \`${scan.id}\`\n- Finding: \`${finding.id}\`\n- Candidate: \`${finding.candidateId}\`\n- Snapshot: \`${scan.targetSnapshot.snapshotDigest}\`\n- CWE: ${finding.cwe}\n- Severity: ${finding.severity}\n- Confidence: ${finding.confidence}\n\n## Affected Code\n\n${locations || `- \`${location.file}:${location.line}\` (${location.role ?? 'root_control'})`}\n\n## Root Cause\n\n${finding.rootCause}\n\n## Evidence\n\n${evidence}\n\n## Validation\n\n${validation ? `- Method: ${validation.method}\n- Attacker: ${validation.attacker}\n- Entry point: ${validation.entryPoint}\n- Trust boundary: ${validation.trustBoundary}\n- Root control: ${validation.rootControl}\n- Sink: ${validation.sink}\n- Source references: ${citations(validation.sourceReferences)}${validation.runtimeReceiptRefs?.length ? `\n- Runtime receipts: ${validation.runtimeReceiptRefs.map(path => `\`${path}\``).join(', ')}` : ''}\n- Direct evidence: ${validation.directEvidence}\n- Counterevidence: ${validation.counterevidence}\n- Limitations: ${validation.limitations}` : finding.validation}\n\n## Attack Path\n\n${attackPath ? `- Attacker: ${attackPath.attacker}\n- Entry point: ${attackPath.entryPoint}\n- Preconditions: ${attackPath.preconditions}\n- Dataflow: ${attackPath.dataflow}\n- Source references: ${citations(attackPath.sourceReferences)}\n- Outcome: ${attackPath.outcome}\n- Severity rationale: ${attackPath.severityRationale}\n- Change conditions: ${attackPath.changeConditions}` : finding.attackPath}\n\n## Reproduction Status\n\n${reproduction}\n\n## Impact\n\n${finding.impact}\n\n## Remediation\n\n${finding.remediation}\n\n## Evidence Boundary\n\nThis report is generated only from this DSH scan's retained local evidence. It does not assert reachability, credentials, production configuration, or exploitability beyond the validation and attack-path records above.\n`
}

async function persistFindingWriteups(record: ScanRecord): Promise<void> {
  for (const finding of record.findings.filter(item => item.disposition === 'reportable')) {
    const reportPath = writeupPath(finding)
    finding.writeup = {
      reportPath,
      generatedAt: new Date().toISOString(),
      evidenceDigest: writeupEvidenceDigest(finding),
      poc: { status: 'not_generated', rationale: 'No standalone exploit artifact is generated without bounded runtime evidence and an explicitly safe reproduction environment.' },
    }
    await writeArtifact(record, reportPath, renderFindingWriteup(record, finding))
  }
}

function hardeningOpportunity(findings: Finding[]): { title: string; invariant: string; evidence: Finding[] } | undefined {
  const groups = new Map<string, Finding[]>()
  for (const finding of findings) {
    const family = finding.ruleId.split('.').slice(0, 2).join('.')
    groups.set(family, [...(groups.get(family) ?? []), finding])
  }
  const repeated = [...groups.entries()].find(([, group]) => group.length >= 2)
  if (repeated) return { title: `Centralize ${repeated[0]} controls`, invariant: `Every ${repeated[0]} operation must cross one owned enforcement boundary before reaching its sensitive sink.`, evidence: repeated[1] }
  const highImpact = findings.find(finding => finding.severity === 'critical' || finding.severity === 'high')
  return highImpact ? { title: `Consolidate the control behind ${highImpact.ruleId}`, invariant: `Every path to ${highImpact.ruleId} must apply the same explicit guard before the sensitive operation.`, evidence: [highImpact] } : undefined
}

function hardeningEvidenceDigest(findings: Finding[]): string {
  return sha256(JSON.stringify(findings.map(finding => ({ id: finding.id, fingerprint: finding.fingerprint, ruleId: finding.ruleId, locations: finding.locations, writeup: finding.writeup?.evidenceDigest }))))
}

/** Generate the scan's derived hardening portfolio from surviving local evidence. */
export async function generateDerivedHardening(record: ScanRecord): Promise<DerivedHardening | undefined> {
  const findings = record.findings.filter(finding => finding.disposition === 'reportable')
  if (!findings.length) return undefined
  const opportunity = hardeningOpportunity(findings); const evidence = opportunity?.evidence ?? []
  const outcome: DerivedHardening['outcome'] = opportunity ? 'structural_hardening_recommended' : 'local_remediation_preferred'
  const portfolioPath = 'hardening/hardening.md'; const structuredPath = 'hardening/hardening.json'
  const evidenceDigest = hardeningEvidenceDigest(findings)
  const structured = { scanId: record.id, outcome, evidenceDigest, evidence: evidence.map(finding => ({ findingId: finding.id, title: finding.title, ruleId: finding.ruleId, location: finding.locations[0], writeupPath: finding.writeup?.reportPath })), opportunities: opportunity ? [{ id: opportunity.title.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, ''), title: opportunity.title, violatedInvariant: opportunity.invariant, options: [{ id: 'central-owned-boundary', title: 'Central owned enforcement boundary', securityEffect: 'Moves duplicated or implicit controls into one reviewed owner.', tradeoffs: { performance: 'One additional wrapper or policy check on sensitive paths.', reliability: 'Central owner must fail closed and be observable.', migration: 'Incremental migration with old callsites rejected after adoption.' } }, { id: 'local-strengthening', title: 'Strengthen each local callsite', securityEffect: 'Addresses observed sites without a larger ownership change.', tradeoffs: { performance: 'Minimal runtime overhead.', reliability: 'Control drift remains likely as new callsites are added.', migration: 'Low immediate disruption but repeated review work.' } }] }] : [], limitations: record.coverage.deferred }
  const portfolio = ['# Security Hardening Portfolio', '', `- Scan: \`${record.id}\``, `- Outcome: ${outcome}`, `- Evidence digest: \`${evidenceDigest}\``, '', '## Evidence', ...(evidence.length ? evidence.map(finding => `- [${finding.title}](../${finding.writeup?.reportPath ?? ''}) at \`${finding.locations[0].file}:${finding.locations[0].line}\`: ${finding.rootCause}`) : findings.map(finding => `- [${finding.title}](../${finding.writeup?.reportPath ?? ''}) at \`${finding.locations[0].file}:${finding.locations[0].line}\`.`)), '', '## Assessment', opportunity ? `The observed evidence indicates that ${opportunity.title.toLowerCase()}. The proposed invariant is: ${opportunity.invariant}` : 'The current evidence favors focused local remediations. A larger design change would not be justified without repeated or cross-boundary evidence.', '', '## Options', ...(opportunity ? ['1. **Central owned enforcement boundary**: move the sensitive control into one reviewed API; retain focused fixes during migration.', '2. **Local strengthening**: patch each observed callsite; lower disruption but retain drift risk.', '', '## Recommendation', 'Adopt the central boundary when the affected operations are expected to grow or are owned by multiple components. Prefer local strengthening when the evidence remains isolated and the migration cost is disproportionate.'] : ['Use the verified local remediation plan for each finding, then rescan before considering architectural changes.'])].join('\n') + '\n'
  await writeArtifact(record, portfolioPath, portfolio)
  await writeArtifact(record, structuredPath, json(structured))
  return { outcome, portfolioPath, structuredPath, evidenceDigest }
}

function coverageDocument(scan: ScanRecord): Record<string, unknown> {
  return {
    documentType: 'dsh-security-suite.coverage', schemaVersion: '1.0', scanId: scan.id, mode: scan.coverage.mode,
    completeness: scan.coverage.complete ? 'complete' : 'partial', inventoryStrategy: scan.mode === 'diff' ? 'diff' : scan.recipe.scopeRequested ? 'scoped_path' : 'directory',
    includePaths: [scan.recipe.scopeRequested ? '.' : '.'], excludePaths: scan.coverage.exclusions,
    surfaces: scan.coverage.surfaces, explicitExclusions: scan.coverage.exclusions.map(pattern => ({ pattern, reason: 'Generated, dependency, VCS, unreadable, oversized, or configured exclusion.' })), deferred: scan.coverage.deferred,
    receipts: scan.coverage.receipts,
  }
}

function manifestDocument(scan: ScanRecord, artifacts: Array<{ path: string; sha256: string; mediaType: string }>): Record<string, unknown> {
  return {
    documentType: 'dsh-security-suite.scan-manifest', schemaVersion: '1.0',
    scan: { id: scan.id, producer: { name: 'dsh-security-suite', version: '0.54.28' }, status: 'completed', startedAt: scan.createdAt, completedAt: scan.completedAt, sealedAt: scan.completedAt, target: scan.targetSnapshot,
      scope: { includePaths: ['.'], excludePaths: scan.coverage.exclusions, summary: `${scan.coverage.reviewedFiles} source files reviewed.`, limitations: scan.coverage.deferred.map(item => item.reason) },
      threatModel: { summary: scan.threatModel }, coverageRef: 'coverage.json', findingsRef: 'findings.json', artifacts },
  }
}

type ArtifactDescriptor = { path: string; sha256: string; mediaType: string }

function mediaTypeForArtifact(path: string): string {
  if (path.endsWith('.json') || path.endsWith('.jsonl') || path.endsWith('.sarif')) return 'application/json'
  return 'text/markdown'
}

/**
 * Freeze every regular evidence file rather than maintaining a hand-written
 * allowlist. Deep worker receipts and closure records are produced outside the
 * baseline bundle writer, so an allowlist could accidentally omit them.
 */
async function inventoryArtifacts(record: ScanRecord, exclude: Set<string> = new Set()): Promise<ArtifactDescriptor[]> {
  const root = resolve(record.artifacts.directory)
  const paths: string[] = []
  const visit = async (directory: string): Promise<void> => {
    const entries = await readdir(directory, { withFileTypes: true })
    for (const entry of entries.sort((left, right) => left.name.localeCompare(right.name))) {
      const absolute = join(directory, entry.name)
      if (entry.isSymbolicLink()) throw new Error(`Artifact inventory refuses symbolic link: ${relative(root, absolute)}`)
      if (entry.isDirectory()) { await visit(absolute); continue }
      if (!entry.isFile()) continue
      const path = relative(root, absolute).replaceAll('\\', '/')
      if (!exclude.has(path)) paths.push(path)
    }
  }
  await visit(root)
  const descriptors: ArtifactDescriptor[] = []
  for (const path of paths.sort((left, right) => left.localeCompare(right))) descriptors.push({ path, sha256: sha256(await readArtifact(record, path)), mediaType: mediaTypeForArtifact(path) })
  return descriptors
}

export async function persistScanBundle(stateDir: string, record: ScanRecord): Promise<ScanRecord> {
  if (!record.artifacts.directory) record.artifacts.directory = scanArtifactDir(stateDir, record.target, record.id)
  const root = resolve(record.artifacts.directory); await mkdir(root, { recursive: true }); await persistFindingWriteups(record)
  const hardening = await generateDerivedHardening(record)
  record.hardening = hardening && { ...hardening, generatedAt: new Date().toISOString() }
  await Promise.all(record.findings.map(async finding => {
    const base = `artifacts/05_findings/${finding.candidateId}`
    await writeArtifact(record, `${base}/candidate_ledger.jsonl`, `${finding.ledger.map(row => JSON.stringify(row)).join('\n')}\n`)
    if (finding.validationRecord) await writeArtifact(record, `${base}/validation_report.md`, renderValidationReport(finding))
    if (finding.attackPathRecord) await writeArtifact(record, `${base}/attack_path_analysis_report.md`, renderAttackPathReport(finding))
  }))
  await writeArtifact(record, 'artifacts/01_context/security_guidance.md', record.policyGuidance)
  await writeArtifact(record, 'artifacts/01_context/threat_model.md', record.threatModel)
  await writeArtifact(record, 'artifacts/02_discovery/finding_discovery_report.md', renderDiscoveryReport(record))
  await writeArtifact(record, 'artifacts/02_discovery/audit_tasks.json', json(record.tasks))
  for (const task of record.tasks) {
    const finding = record.findings.find(item => item.candidateId === task.candidateId)
    if (!finding) continue
    await writeArtifact(record, `artifacts/04_reconciliation/tasks/${task.id}.md`, renderAuditTask(task, finding, record))
  }
  await writeArtifact(record, 'artifacts/03_coverage/reviewed_surfaces.json', json(record.coverage.surfaces))
  const coverageRef = await writeArtifact(record, 'coverage.json', json(coverageDocument(record)))
  const findingsRef = await writeArtifact(record, 'findings.json', json(findingsDocument(record)))
  record.artifacts = { directory: root, manifest: 'scan-manifest.json', findings: findingsRef, coverage: coverageRef, report: 'report.md' }
  record.seal = sealScan(record)
  await writeArtifact(record, 'report.md', renderMarkdownReport(record))
  const artifacts = await inventoryArtifacts(record, new Set(['scan-manifest.json']))
  await writeArtifact(record, 'scan-manifest.json', json(manifestDocument(record, artifacts)))
  return record
}

/** Persist mutable workbench evidence. Completed-scan canonical documents are written only at finalization. */
export async function persistInvestigationArtifacts(stateDir: string, record: ScanRecord): Promise<ScanRecord> {
  if (!record.artifacts.directory) record.artifacts.directory = scanArtifactDir(stateDir, record.target, record.id)
  await mkdir(resolve(record.artifacts.directory), { recursive: true })
  await writeArtifact(record, 'artifacts/01_context/security_guidance.md', record.policyGuidance)
  await writeArtifact(record, 'artifacts/01_context/threat_model.md', record.threatModel)
  await writeArtifact(record, 'artifacts/02_discovery/finding_discovery_report.md', renderDiscoveryReport(record))
  await writeArtifact(record, 'artifacts/02_discovery/audit_tasks.json', json(record.tasks))
  await writeArtifact(record, 'artifacts/03_coverage/reviewed_surfaces.json', json(record.coverage.surfaces))
  for (const finding of record.findings) {
    const base = `artifacts/05_findings/${finding.candidateId}`
    await writeArtifact(record, `${base}/candidate_ledger.jsonl`, `${finding.ledger.map(row => JSON.stringify(row)).join('\n')}\n`)
    if (finding.validationRecord) await writeArtifact(record, `${base}/validation_report.md`, renderValidationReport(finding))
    if (finding.attackPathRecord) await writeArtifact(record, `${base}/attack_path_analysis_report.md`, renderAttackPathReport(finding))
  }
  for (const task of record.tasks) {
    const finding = record.findings.find(item => item.candidateId === task.candidateId)
    if (finding) await writeArtifact(record, `artifacts/04_reconciliation/tasks/${task.id}.md`, renderAuditTask(task, finding, record))
  }
  await writeArtifact(record, 'artifacts/04_reconciliation/workbench-manifest.json', json({ documentType: 'dsh-security-suite.workbench', scanId: record.id, lifecycle: record.lifecycle, updatedAt: new Date().toISOString(), tasks: record.tasks.map(task => ({ id: task.id, candidateId: task.candidateId, phase: task.phase, status: task.status, artifactRef: `artifacts/04_reconciliation/tasks/${task.id}.md` })) }))
  return record
}

export async function finalizeAndSaveScan(stateDir: string, record: ScanRecord): Promise<ScanRecord> {
  if (record.lifecycle !== 'completed') { await persistInvestigationArtifacts(stateDir, record); await saveScan(stateDir, record); return record }
  await persistScanBundle(stateDir, record)
  await saveScan(stateDir, record)
  return record
}

export async function verifyScanBundle(record: ScanRecord): Promise<{ valid: boolean; errors: string[] }> {
  const errors: string[] = []
  if (!verifySeal(record)) errors.push('Scan state seal does not match.')
  if (!record.artifacts.manifest || !record.artifacts.findings || !record.artifacts.coverage || !record.artifacts.report) errors.push('Scan bundle paths are incomplete.')
  if (record.findings.some(finding => finding.disposition === 'reportable') && !record.hardening) errors.push('Reportable findings require a derived hardening portfolio.')
  if (record.hardening) {
    if (record.hardening.evidenceDigest !== hardeningEvidenceDigest(record.findings.filter(finding => finding.disposition === 'reportable'))) errors.push('Derived hardening portfolio evidence digest is stale.')
    for (const path of [record.hardening.portfolioPath, record.hardening.structuredPath]) {
      try { await readArtifact(record, path) } catch (error) { errors.push(error instanceof Error ? error.message : String(error)) }
    }
  }
  for (const candidate of record.findings) {
    const phases = new Set(candidate.ledger.map(item => item.phase))
    if (!phases.has('discovery')) errors.push(`${candidate.candidateId} has no discovery receipt.`)
    if (!phases.has('validation')) errors.push(`${candidate.candidateId} has no validation receipt.`)
    if (candidate.disposition === 'reportable' && !phases.has('attack_path')) errors.push(`${candidate.candidateId} has no attack-path receipt.`)
    if (candidate.disposition === 'reportable') {
      if (!candidate.writeup) errors.push(`${candidate.candidateId} has no derived vulnerability report.`)
      else {
        try {
          const content = await readArtifact(record, candidate.writeup.reportPath)
          if (!content.includes(`Finding: \`${candidate.id}\``)) errors.push(`${candidate.candidateId} vulnerability report does not identify its finding.`)
          if (candidate.writeup.evidenceDigest !== writeupEvidenceDigest(candidate)) errors.push(`${candidate.candidateId} vulnerability report evidence digest is stale.`)
        } catch (error) { errors.push(error instanceof Error ? error.message : String(error)) }
      }
    }
  }
  for (const path of [record.artifacts.manifest, record.artifacts.findings, record.artifacts.coverage, record.artifacts.report].filter(Boolean) as string[]) {
    try { await readArtifact(record, path) } catch (error) { errors.push(error instanceof Error ? error.message : String(error)) }
  }
  if (record.artifacts.manifest) {
    try {
      const manifest = JSON.parse(await readArtifact(record, record.artifacts.manifest)) as { scan?: { id?: string; artifacts?: Array<{ path?: string; sha256?: string }> } }
      if (manifest.scan?.id !== record.id) errors.push('Manifest scan id does not match scan state.')
      const artifacts = manifest.scan?.artifacts
      if (!Array.isArray(artifacts)) errors.push('Manifest artifact inventory is missing.')
      else {
        const seen = new Set<string>()
        for (const item of artifacts) {
          if (!item.path || !item.sha256 || !SHA256.test(item.sha256)) { errors.push('Manifest contains an invalid artifact descriptor.'); continue }
          if (seen.has(item.path)) errors.push(`Manifest repeats artifact ${item.path}.`)
          seen.add(item.path)
          try { if (sha256(await readArtifact(record, item.path)) !== item.sha256) errors.push(`Artifact digest mismatch: ${item.path}.`) } catch (error) { errors.push(error instanceof Error ? error.message : String(error)) }
        }
        for (const canonical of [record.artifacts.findings, record.artifacts.coverage, record.artifacts.report]) if (canonical && !seen.has(canonical)) errors.push(`Manifest does not seal canonical artifact ${canonical}.`)
        try {
          const actual = await inventoryArtifacts(record, new Set([record.artifacts.manifest]))
          const actualPaths = new Set(actual.map(item => item.path))
          for (const item of actual) if (!seen.has(item.path)) errors.push(`Manifest does not seal retained artifact ${item.path}.`)
          for (const path of seen) if (!actualPaths.has(path)) errors.push(`Manifest references missing retained artifact ${path}.`)
        } catch (error) { errors.push(error instanceof Error ? error.message : String(error)) }
      }
    } catch (error) { errors.push(error instanceof Error ? error.message : String(error)) }
  }
  return { valid: errors.length === 0, errors }
}

export async function saveTriageAnnotation(stateDir: string, scan: ScanRecord, finding: Finding): Promise<void> {
  if (scan.lifecycle === 'completed') {
    const annotations = resolve(stateDir, 'annotations', `${scan.id}.json`)
    const payload = await readAnnotations(annotations)
    payload.findings[finding.id] = { status: finding.status, validation: finding.validation, attackPath: finding.attackPath, impact: finding.impact, remediation: finding.remediation, severity: finding.severity, confidence: finding.confidence, updatedAt: new Date().toISOString() }
    await atomicWrite(annotations, json(payload))
    return
  }
  const annotations = resolve(stateDir, 'annotations', `${scan.id}.json`)
  const payload = await readAnnotations(annotations)
  payload.findings[finding.id] = { status: finding.status, validation: finding.validation, attackPath: finding.attackPath, impact: finding.impact, remediation: finding.remediation, severity: finding.severity, confidence: finding.confidence, updatedAt: new Date().toISOString() }
  await atomicWrite(annotations, json(payload))
  scan.annotations = { path: annotations, updatedAt: new Date().toISOString() }
  await saveScan(stateDir, scan)
}

async function readAnnotations(path: string): Promise<{ findings: Record<string, unknown> }> {
  try { const value = JSON.parse(await readFile(path, 'utf8')) as { findings?: Record<string, unknown> }; return { findings: value.findings ?? {} } } catch (error: unknown) { if (typeof error === 'object' && error !== null && 'code' in error && error.code === 'ENOENT') return { findings: {} }; throw error }
}

export async function saveScan(stateDir: string, record: ScanRecord): Promise<void> {
  const directory = join(stateDir, 'scans'); await mkdir(directory, { recursive: true }); record.seal = sealScan(record)
  await atomicWrite(scanPath(stateDir, record.id), json(record))
}

export async function loadScan(stateDir: string, id: string): Promise<ScanRecord> {
  const record = JSON.parse(await readFile(scanPath(stateDir, id), 'utf8')) as ScanRecord
  if (record.schemaVersion !== 3 || !verifySeal(record)) throw new Error('Scan record failed integrity verification.')
  return record
}

export async function listScans(stateDir: string): Promise<ScanRecord[]> {
  try { const names = await readdir(join(stateDir, 'scans')); return (await Promise.all(names.filter(name => name.endsWith('.json')).map(name => readFile(join(stateDir, 'scans', name), 'utf8').then(text => JSON.parse(text) as ScanRecord)))).filter(verifySeal).sort((a, b) => b.createdAt.localeCompare(a.createdAt)) } catch (error: unknown) { if (typeof error === 'object' && error !== null && 'code' in error && error.code === 'ENOENT') return []; throw error }
}

export function severityRank(severity: Finding['severity']): number { return ({ critical: 5, high: 4, medium: 3, low: 2, informational: 1 })[severity] }
function csv(value: unknown): string { const text = String(value ?? ''); return /[",\n\r]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text }
export function renderCsv(scan: ScanRecord): string { const header = ['id', 'candidate_id', 'fingerprint', 'rule', 'severity', 'confidence', 'cwe', 'disposition', 'status', 'file', 'line', 'title', 'validation', 'attack_path', 'impact', 'remediation']; const rows = scan.findings.map(f => [f.id, f.candidateId, f.fingerprint, f.ruleId, f.severity, f.confidence, f.cwe, f.disposition, f.status, f.locations[0]?.file, f.locations[0]?.line, f.title, f.validation, f.attackPath, f.impact, f.remediation].map(csv).join(',')); return `${[header.join(','), ...rows].join('\n')}\n` }

export function renderMarkdownReport(scan: ScanRecord): string {
  const finalFindings = scan.findings.filter(finding => finding.disposition === 'reportable').sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || a.id.localeCompare(b.id)); const summary = finalFindings.reduce<Record<string, number>>((counts, finding) => { counts[finding.severity] = (counts[finding.severity] ?? 0) + 1; return counts }, {}); const confidence = finalFindings.reduce<Record<string, number>>((counts, finding) => { counts[finding.confidence] = (counts[finding.confidence] ?? 0) + 1; return counts }, {})
  const lines = ['# Security Review: DSH Security Suite', '', '## Scope', '', `- Target: \`${scan.targetSnapshot.displayName}\``, `- Scan mode: ${scan.mode}`, `- Snapshot: \`${scan.targetSnapshot.snapshotDigest}\``, `- Validation mode: DSH-native source, isolated-test, or runtime evidence as recorded per finding.`, `- Coverage: ${scan.coverage.reviewedFiles} reviewed, ${scan.coverage.skippedFiles} skipped, ${scan.coverage.complete ? 'complete' : 'partial'}`, `- Limitations: ${scan.coverage.deferred.length ? scan.coverage.deferred.map(item => item.reason).join(' ') : 'No deferred coverage was recorded.'}`, '', '### Scan Summary', '', '| Field | Value |', '| --- | --- |', `| Reportable findings | ${finalFindings.length} |`, `| Severity mix | critical ${summary.critical ?? 0}; high ${summary.high ?? 0}; medium ${summary.medium ?? 0}; low ${summary.low ?? 0} |`, `| Confidence mix | high ${confidence.high ?? 0}; medium ${confidence.medium ?? 0}; low ${confidence.low ?? 0} |`, `| Lifecycle | ${scan.lifecycle} |`, `| Integrity seal | \`${scan.seal}\` |`, ...(scan.hardening ? ['', `Structural hardening portfolio: \`${scan.hardening.portfolioPath}\``] : []), '', '## Threat Model', '', scan.threatModel, '', '## Findings', '', '| Finding | Severity | Confidence | Detailed write-up |', '| --- | --- | --- | --- |']
  if (finalFindings.length === 0) lines.push('', 'No candidates survived the discovery, validation, and attack-path reportability gates.')
  for (const finding of finalFindings) lines.push(`| [${finding.title}](#${finding.id}) | ${finding.severity} | ${finding.confidence} | ${finding.writeup?.reportPath ? `[report](./${finding.writeup.reportPath})` : 'not generated'} |`)
  lines.push('', '### Confidence Scale', '', '| Label | Meaning |', '| --- | --- |', '| high | Direct source, configuration, or runtime evidence with no material unresolved blocker. |', '| medium | Source evidence supports a plausible issue, but deployment, reachability, or exploit reliability needs proof. |', '| low | Weak or incomplete evidence retained for follow-up. |', '', '## Reviewed Surfaces', '')
  for (const surface of scan.coverage.surfaces) lines.push(`- ${surface.label}: ${surface.disposition}${surface.notes ? ` - ${surface.notes}` : ''}`)
  for (const finding of finalFindings) {
    const validation = finding.validationRecord; const attackPath = finding.attackPathRecord
    lines.push('', `### ${finding.id}`, '', `#### ${finding.title}`, '', '| Field | Value |', '| --- | --- |', `| Severity | ${finding.severity} |`, `| Confidence | ${finding.confidence} |`, `| Category | ${finding.ruleId.split('.')[0]} |`, `| CWE | ${finding.cwe} |`, `| Affected lines | ${finding.locations.map(location => `${location.file}:${location.line}`).join(', ')} |`, '', '#### Summary', `${finding.rootCause} ${finding.impact}`, '', '#### Root Cause', finding.rootCause, '', '#### Validation', validation ? `${validation.method}: ${validation.directEvidence}\n\nRemaining uncertainty: ${validation.limitations}` : finding.validation, '', '#### Dataflow', attackPath?.dataflow ?? finding.attackPath, '', '#### Reachability', attackPath ? `${attackPath.attacker} via ${attackPath.entryPoint}. Preconditions: ${attackPath.preconditions}. Outcome: ${attackPath.outcome}` : finding.attackPath, '', '#### Severity', `${finding.severity}: ${attackPath?.severityRationale ?? finding.impact}`, '', '#### Counterevidence', finding.counterevidence || 'None identified during the completed review.', '', '#### Remediation', finding.remediation)
  }
  return `${lines.join('\n')}\n`
}

function renderDiscoveryReport(scan: ScanRecord): string { return `# Finding Discovery\n\n- Scan: \`${scan.id}\`\n- Candidates: ${scan.findings.length}\n\n${scan.findings.map(finding => `- \`${finding.candidateId}\`: ${finding.title} at ${finding.locations[0]?.file}:${finding.locations[0]?.line}`).join('\n')}\n` }
function renderValidationReport(finding: Finding): string { const record = finding.validationRecord; if (!record) return ''; return `# Validation: ${finding.title}\n\n- Conclusion: ${record.conclusion}\n- Method: ${record.method}\n- Attacker: ${record.attacker}\n- Entry point: ${record.entryPoint}\n- Trust boundary: ${record.trustBoundary}\n- Root control: ${record.rootControl}\n- Sink: ${record.sink}\n- Impact: ${record.impact}\n\n## Source References\n${record.sourceReferences.map(reference => `- \`${reference.file}:${reference.line}\` (${reference.role})`).join('\n')}\n${record.runtimeReceiptRefs?.length ? `\n## Runtime Receipts\n${record.runtimeReceiptRefs.map(path => `- \`${path}\``).join('\n')}\n` : ''}\n## Direct Evidence\n${record.directEvidence}\n\n## Counterevidence\n${record.counterevidence || 'None identified.'}\n\n## Limitations\n${record.limitations || 'Static validation only.'}\n` }
function renderAttackPathReport(finding: Finding): string { const record = finding.attackPathRecord; if (!record) return ''; return `# Attack Path: ${finding.title}\n\n- Attacker: ${record.attacker}\n- Entry point: ${record.entryPoint}\n- Preconditions: ${record.preconditions}\n- Outcome: ${record.outcome}\n\n## Source References\n${record.sourceReferences.map(reference => `- \`${reference.file}:${reference.line}\` (${reference.role})`).join('\n')}\n\n## Dataflow\n${record.dataflow}\n\n## Severity Rationale\n${record.severityRationale}\n` }
function renderAuditTask(task: ScanRecord['tasks'][number], finding: Finding, scan: ScanRecord): string { return `# Security Audit Task\n\n- Task: \`${task.id}\`\n- Scan: \`${scan.id}\`\n- Candidate: \`${task.candidateId}\`\n- Phase: ${task.phase}\n- Status: ${task.status}\n\n## Focus\n${task.focus}\n\n## Candidate\n${finding.title}\n\n- Rule: ${finding.ruleId}\n- CWE: ${finding.cwe}\n- Root location: ${finding.locations[0]?.file}:${finding.locations[0]?.line}\n- Evidence: ${finding.evidence.map(item => item.detail).join(' ')}\n\n## Threat Model\n${scan.threatModel}\n\n## Policy Guidance\n${scan.policyGuidance}\n` }

export function toSarif(scan: ScanRecord): Record<string, unknown> {
  const reportable = scan.findings.filter(finding => finding.disposition === 'reportable'); const rules = [...new Map(reportable.map(finding => [finding.ruleId, { id: finding.ruleId, shortDescription: { text: finding.title }, fullDescription: { text: finding.rootCause }, properties: { cwe: finding.cwe } }])).values()]
  return { version: '2.1.0', $schema: 'https://json.schemastore.org/sarif-2.1.0.json', runs: [{ tool: { driver: { name: 'dsh-security-suite', informationUri: 'https://github.com/Zenquiem/dsh-security-suite', rules } }, invocations: [{ executionSuccessful: scan.lifecycle === 'completed', properties: { scanId: scan.id, integritySeal: scan.seal, snapshotDigest: scan.targetSnapshot.snapshotDigest } }], results: reportable.map(finding => ({ ruleId: finding.ruleId, level: finding.severity === 'critical' || finding.severity === 'high' ? 'error' : finding.severity === 'medium' ? 'warning' : 'note', message: { text: finding.rootCause }, partialFingerprints: { 'dsh-security-suite/v1': finding.fingerprint }, locations: finding.locations.map(location => ({ physicalLocation: { artifactLocation: { uri: location.file }, region: { startLine: Math.max(location.line, 1), snippet: { text: location.excerpt } } } })), properties: { findingId: finding.id, candidateId: finding.candidateId, status: finding.status, confidence: finding.confidence, cwe: finding.cwe, validation: finding.validation } })) }] }
}
