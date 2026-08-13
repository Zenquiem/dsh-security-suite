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
      fingerprints: { algorithm: 'dsh-security-suite/v1', primary: `dsh-security-suite/v1:sha256:${finding.fingerprint}` }, title: finding.title, summary: finding.rootCause,
      severity: { level: finding.severity, rationale: finding.attackPathRecord?.severityRationale ?? finding.impact }, confidence: { level: finding.confidence, rationale: finding.validationRecord?.directEvidence ?? finding.validation },
      taxonomy: { category: finding.ruleId.split('.')[0], cwe: [finding.cwe] }, locations: finding.locations.map(location => ({ path: location.file, startLine: location.line, endLine: location.line, role: location.role })),
      codeEvidence: finding.evidence.filter(item => item.location).map((item, index) => ({ id: `evidence-${index + 1}`, label: item.kind, path: item.location?.file, startLine: item.location?.line, endLine: item.location?.line, role: item.location?.role ?? 'root_control', code: item.location?.excerpt, explanation: item.detail })),
      rootCause: { summary: finding.rootCause }, validation: finding.validationRecord ?? null, attackPath: finding.attackPathRecord ?? null, remediation: finding.remediation,
      provenance: { source: 'dsh-security-suite native analysis' }, extensions: { candidateId: finding.candidateId },
    })),
  }
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
    scan: { id: scan.id, producer: { name: 'dsh-security-suite', version: '0.23.0' }, status: 'completed', startedAt: scan.createdAt, completedAt: scan.completedAt, sealedAt: scan.completedAt, target: scan.targetSnapshot,
      scope: { includePaths: ['.'], excludePaths: scan.coverage.exclusions, summary: `${scan.coverage.reviewedFiles} source files reviewed.`, limitations: scan.coverage.deferred.map(item => item.reason) },
      threatModel: { summary: scan.threatModel }, coverageRef: 'coverage.json', findingsRef: 'findings.json', artifacts },
  }
}

export async function persistScanBundle(stateDir: string, record: ScanRecord): Promise<ScanRecord> {
  if (!record.artifacts.directory) record.artifacts.directory = scanArtifactDir(stateDir, record.target, record.id)
  const root = resolve(record.artifacts.directory); await mkdir(root, { recursive: true })
  const findingPaths = await Promise.all(record.findings.map(async finding => {
    const base = `artifacts/05_findings/${finding.candidateId}`
    await writeArtifact(record, `${base}/candidate_ledger.jsonl`, `${finding.ledger.map(row => JSON.stringify(row)).join('\n')}\n`)
    if (finding.validationRecord) await writeArtifact(record, `${base}/validation_report.md`, renderValidationReport(finding))
    if (finding.attackPathRecord) await writeArtifact(record, `${base}/attack_path_analysis_report.md`, renderAttackPathReport(finding))
    return `${base}/candidate_ledger.jsonl`
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
  const artifactRefs = [...new Set(['coverage.json', 'findings.json', 'artifacts/01_context/security_guidance.md', 'artifacts/01_context/threat_model.md', 'artifacts/02_discovery/finding_discovery_report.md', 'artifacts/02_discovery/audit_tasks.json', 'artifacts/03_coverage/reviewed_surfaces.json', ...record.tasks.map(task => `artifacts/04_reconciliation/tasks/${task.id}.md`), ...findingPaths])]
  const artifacts: Array<{ path: string; sha256: string; mediaType: string }> = []
  for (const path of artifactRefs) artifacts.push({ path, sha256: sha256(await readArtifact(record, path)), mediaType: path.endsWith('.json') || path.endsWith('.jsonl') ? 'application/json' : 'text/markdown' })
  await writeArtifact(record, 'scan-manifest.json', json(manifestDocument(record, artifacts)))
  record.artifacts = { directory: root, manifest: 'scan-manifest.json', findings: findingsRef, coverage: coverageRef, report: 'report.md' }
  record.seal = sealScan(record)
  await writeArtifact(record, 'report.md', renderMarkdownReport(record))
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
  for (const candidate of record.findings) {
    const phases = new Set(candidate.ledger.map(item => item.phase))
    if (!phases.has('discovery')) errors.push(`${candidate.candidateId} has no discovery receipt.`)
    if (!phases.has('validation')) errors.push(`${candidate.candidateId} has no validation receipt.`)
    if (candidate.disposition === 'reportable' && !phases.has('attack_path')) errors.push(`${candidate.candidateId} has no attack-path receipt.`)
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
        for (const canonical of [record.artifacts.findings, record.artifacts.coverage]) if (canonical && !seen.has(canonical)) errors.push(`Manifest does not seal canonical artifact ${canonical}.`)
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
  const finalFindings = scan.findings.filter(finding => finding.disposition === 'reportable'); const summary = finalFindings.reduce<Record<string, number>>((counts, finding) => { counts[finding.severity] = (counts[finding.severity] ?? 0) + 1; return counts }, {})
  const lines = ['# DSH Security Suite Report', '', `- Scan ID: \`${scan.id}\``, `- Mode: ${scan.mode}`, `- Lifecycle: ${scan.lifecycle}`, `- Target: \`${scan.targetSnapshot.displayName}\``, `- Snapshot: \`${scan.targetSnapshot.snapshotDigest}\``, `- Completed: ${scan.completedAt ?? 'not completed'}`, `- Integrity seal: \`${scan.seal}\``, `- Coverage: ${scan.coverage.reviewedFiles} reviewed, ${scan.coverage.skippedFiles} skipped, ${scan.coverage.complete ? 'complete' : 'partial'}`, `- Reportable findings: critical ${summary.critical ?? 0}, high ${summary.high ?? 0}, medium ${summary.medium ?? 0}, low ${summary.low ?? 0}`, '', '## Threat Model', '', scan.threatModel, '', '## Reviewed Surfaces', '']
  for (const surface of scan.coverage.surfaces) lines.push(`- ${surface.label}: ${surface.disposition}`)
  lines.push('', '## Findings')
  if (finalFindings.length === 0) lines.push('', 'No candidates survived the discovery, validation, and attack-path reportability gates.')
  for (const finding of finalFindings) lines.push('', `### ${finding.title}`, '', `- Finding ID: \`${finding.id}\``, `- Candidate ID: \`${finding.candidateId}\``, `- Severity: ${finding.severity}`, `- Confidence: ${finding.confidence}`, `- CWE: ${finding.cwe}`, `- Location: ${finding.locations[0]?.file}:${finding.locations[0]?.line}`, '', '#### Root Cause', finding.rootCause, '', '#### Validation', finding.validation, '', '#### Attack Path', finding.attackPath, '', '#### Impact', finding.impact, '', '#### Counterevidence', finding.counterevidence || 'None identified during the completed review.', '', '#### Remediation', finding.remediation)
  return `${lines.join('\n')}\n`
}

function renderDiscoveryReport(scan: ScanRecord): string { return `# Finding Discovery\n\n- Scan: \`${scan.id}\`\n- Candidates: ${scan.findings.length}\n\n${scan.findings.map(finding => `- \`${finding.candidateId}\`: ${finding.title} at ${finding.locations[0]?.file}:${finding.locations[0]?.line}`).join('\n')}\n` }
function renderValidationReport(finding: Finding): string { const record = finding.validationRecord; if (!record) return ''; return `# Validation: ${finding.title}\n\n- Conclusion: ${record.conclusion}\n- Method: ${record.method}\n- Attacker: ${record.attacker}\n- Entry point: ${record.entryPoint}\n- Trust boundary: ${record.trustBoundary}\n- Root control: ${record.rootControl}\n- Sink: ${record.sink}\n- Impact: ${record.impact}\n\n## Direct Evidence\n${record.directEvidence}\n\n## Counterevidence\n${record.counterevidence || 'None identified.'}\n\n## Limitations\n${record.limitations || 'Static validation only.'}\n` }
function renderAttackPathReport(finding: Finding): string { const record = finding.attackPathRecord; if (!record) return ''; return `# Attack Path: ${finding.title}\n\n- Attacker: ${record.attacker}\n- Entry point: ${record.entryPoint}\n- Preconditions: ${record.preconditions}\n- Outcome: ${record.outcome}\n\n## Dataflow\n${record.dataflow}\n\n## Severity Rationale\n${record.severityRationale}\n` }
function renderAuditTask(task: ScanRecord['tasks'][number], finding: Finding, scan: ScanRecord): string { return `# Security Audit Task\n\n- Task: \`${task.id}\`\n- Scan: \`${scan.id}\`\n- Candidate: \`${task.candidateId}\`\n- Phase: ${task.phase}\n- Status: ${task.status}\n\n## Focus\n${task.focus}\n\n## Candidate\n${finding.title}\n\n- Rule: ${finding.ruleId}\n- CWE: ${finding.cwe}\n- Root location: ${finding.locations[0]?.file}:${finding.locations[0]?.line}\n- Evidence: ${finding.evidence.map(item => item.detail).join(' ')}\n\n## Threat Model\n${scan.threatModel}\n\n## Policy Guidance\n${scan.policyGuidance}\n` }

export function toSarif(scan: ScanRecord): Record<string, unknown> {
  const reportable = scan.findings.filter(finding => finding.disposition === 'reportable'); const rules = [...new Map(reportable.map(finding => [finding.ruleId, { id: finding.ruleId, shortDescription: { text: finding.title }, fullDescription: { text: finding.rootCause }, properties: { cwe: finding.cwe } }])).values()]
  return { version: '2.1.0', $schema: 'https://json.schemastore.org/sarif-2.1.0.json', runs: [{ tool: { driver: { name: 'dsh-security-suite', informationUri: 'https://github.com/Zenquiem/dsh-security-suite', rules } }, invocations: [{ executionSuccessful: scan.lifecycle === 'completed', properties: { scanId: scan.id, integritySeal: scan.seal, snapshotDigest: scan.targetSnapshot.snapshotDigest } }], results: reportable.map(finding => ({ ruleId: finding.ruleId, level: finding.severity === 'critical' || finding.severity === 'high' ? 'error' : finding.severity === 'medium' ? 'warning' : 'note', message: { text: finding.rootCause }, partialFingerprints: { 'dsh-security-suite/v1': finding.fingerprint }, locations: finding.locations.map(location => ({ physicalLocation: { artifactLocation: { uri: location.file }, region: { startLine: Math.max(location.line, 1), snippet: { text: location.excerpt } } } })), properties: { findingId: finding.id, candidateId: finding.candidateId, status: finding.status, confidence: finding.confidence, cwe: finding.cwe, validation: finding.validation } })) }] }
}
