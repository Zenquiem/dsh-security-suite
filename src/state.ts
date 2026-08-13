import { mkdir, readFile, readdir, rename, writeFile } from 'node:fs/promises'
import { createHash, randomUUID } from 'node:crypto'
import { join, resolve } from 'node:path'
import { homedir } from 'node:os'
import type { Finding, ScanRecord } from './contracts.js'

export function getStateDir(configured: string): string { return resolve(configured || process.env.DSH_SECURITY_SUITE_STATE_DIR || join(homedir(), '.dsh-security-suite')) }
export function createScanId(): string { return `scan_${randomUUID()}` }
export function findingId(ruleId: string, file: string, line: number): string { return createHash('sha256').update(`${ruleId}:${file}:${line}`).digest('hex').slice(0, 16) }

function scanPath(stateDir: string, id: string): string { if (!/^scan_[0-9a-f-]+$/.test(id)) throw new Error('Invalid scan id.'); return join(stateDir, 'scans', `${id}.json`) }
function canonical(record: ScanRecord): string { const { seal: _seal, ...unsealed } = record; return JSON.stringify(unsealed) }
export function sealScan(record: ScanRecord): string { return createHash('sha256').update(canonical(record)).digest('hex') }
export function verifySeal(record: ScanRecord): boolean { return record.seal === sealScan(record) }

export async function saveScan(stateDir: string, record: ScanRecord): Promise<void> {
  const directory = join(stateDir, 'scans'); await mkdir(directory, { recursive: true }); record.seal = sealScan(record)
  const finalPath = scanPath(stateDir, record.id); const temporary = `${finalPath}.${randomUUID()}.tmp`
  await writeFile(temporary, `${JSON.stringify(record, null, 2)}\n`, 'utf8'); await rename(temporary, finalPath)
}

export async function loadScan(stateDir: string, id: string): Promise<ScanRecord> {
  const record = JSON.parse(await readFile(scanPath(stateDir, id), 'utf8')) as ScanRecord
  if (record.schemaVersion !== 2 || !verifySeal(record)) throw new Error('Scan record failed integrity verification.')
  return record
}

export async function listScans(stateDir: string): Promise<ScanRecord[]> {
  try { const names = await readdir(join(stateDir, 'scans')); return (await Promise.all(names.filter(name => name.endsWith('.json')).map(name => readFile(join(stateDir, 'scans', name), 'utf8').then(text => JSON.parse(text) as ScanRecord)))).filter(verifySeal).sort((a, b) => b.createdAt.localeCompare(a.createdAt)) } catch (error: unknown) { if (typeof error === 'object' && error !== null && 'code' in error && error.code === 'ENOENT') return []; throw error }
}

export function severityRank(severity: Finding['severity']): number { return ({ critical: 4, high: 3, medium: 2, low: 1 })[severity] }
function csv(value: unknown): string { const text = String(value ?? ''); return /[",\n\r]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text }

export function renderCsv(scan: ScanRecord): string {
  const header = ['id', 'fingerprint', 'rule', 'severity', 'confidence', 'cwe', 'status', 'file', 'line', 'title', 'validation', 'attack_path', 'impact', 'remediation']
  const rows = scan.findings.map(f => [f.id, f.fingerprint, f.ruleId, f.severity, f.confidence, f.cwe, f.status, f.locations[0]?.file, f.locations[0]?.line, f.title, f.validation, f.attackPath, f.impact, f.remediation].map(csv).join(','))
  return `${[header.join(','), ...rows].join('\n')}\n`
}

export function renderMarkdownReport(scan: ScanRecord): string {
  const summary = scan.findings.reduce<Record<string, number>>((counts, finding) => { counts[finding.severity] = (counts[finding.severity] ?? 0) + 1; return counts }, {})
  const lines = ['# Security Scan Report', '', `- Scan ID: \`${scan.id}\``, `- Mode: ${scan.mode}`, `- Lifecycle: ${scan.lifecycle}`, `- Target: \`${scan.target}\``, `- Completed: ${scan.completedAt}`, `- Integrity seal: \`${scan.seal}\``, `- Coverage: ${scan.coverage.reviewedFiles} reviewed, ${scan.coverage.skippedFiles} skipped, ${scan.coverage.complete ? 'complete' : 'incomplete'}`, `- Findings: critical ${summary.critical ?? 0}, high ${summary.high ?? 0}, medium ${summary.medium ?? 0}, low ${summary.low ?? 0}`, '', '## Threat Model', '', scan.threatModel, '', '## Scan Receipts', '', `- Policy files: ${scan.coverage.policyFiles.length ? scan.coverage.policyFiles.map(file => `\`${file}\``).join(', ') : 'none found'}`, `- Rule executions: ${scan.coverage.ruleReceipts.length}`, '', '## Findings']
  if (scan.findings.length === 0) lines.push('', 'No static candidates were found. This does not establish that the target is free of vulnerabilities.')
  for (const finding of scan.findings) lines.push('', `### ${finding.title}`, '', `- ID: \`${finding.id}\``, `- Fingerprint: \`${finding.fingerprint}\``, `- Severity: ${finding.severity}`, `- Confidence: ${finding.confidence}`, `- Status: ${finding.status}`, `- CWE: ${finding.cwe}`, `- Location: ${finding.locations[0]?.file}:${finding.locations[0]?.line}`, '', finding.rootCause, '', `**Validation:** ${finding.validation}`, '', `**Attack path:** ${finding.attackPath}`, '', `**Impact:** ${finding.impact}`, '', `**Counterevidence:** ${finding.counterevidence}`, '', `**Remediation:** ${finding.remediation}`)
  return `${lines.join('\n')}\n`
}

export function toSarif(scan: ScanRecord): Record<string, unknown> {
  const rules = [...new Map(scan.findings.map(finding => [finding.ruleId, { id: finding.ruleId, shortDescription: { text: finding.title }, fullDescription: { text: finding.rootCause }, properties: { cwe: finding.cwe } }])).values()]
  return { version: '2.1.0', $schema: 'https://json.schemastore.org/sarif-2.1.0.json', runs: [{ tool: { driver: { name: 'dsh-security-suite', informationUri: 'https://github.com/Zenquiem/dsh-security-suite', rules } }, invocations: [{ executionSuccessful: scan.lifecycle === 'completed', properties: { scanId: scan.id, integritySeal: scan.seal } }], results: scan.findings.map(finding => ({ ruleId: finding.ruleId, level: finding.severity === 'critical' || finding.severity === 'high' ? 'error' : 'warning', message: { text: finding.rootCause }, partialFingerprints: { 'dsh-security-suite/v1': finding.fingerprint }, locations: finding.locations.map(location => ({ physicalLocation: { artifactLocation: { uri: location.file }, region: { startLine: Math.max(location.line, 1), snippet: { text: location.excerpt } } } })), properties: { status: finding.status, confidence: finding.confidence, cwe: finding.cwe, validation: finding.validation } })) }] }
}
