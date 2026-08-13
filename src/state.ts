import { mkdir, readFile, readdir, writeFile } from 'node:fs/promises'
import { createHash, randomUUID } from 'node:crypto'
import { join, resolve } from 'node:path'
import { tmpdir } from 'node:os'
import type { Finding, ScanRecord } from './contracts.js'

export function getStateDir(configured: string): string {
  return resolve(configured || process.env.DSH_SECURITY_SUITE_STATE_DIR || join(tmpdir(), 'dsh-security-suite'))
}

export function createScanId(): string {
  return `scan_${randomUUID()}`
}

export function findingId(ruleId: string, file: string, line: number): string {
  return createHash('sha256').update(`${ruleId}:${file}:${line}`).digest('hex').slice(0, 16)
}

function scanPath(stateDir: string, id: string): string {
  if (!/^scan_[0-9a-f-]+$/.test(id)) throw new Error('Invalid scan id.')
  return join(stateDir, 'scans', `${id}.json`)
}

export async function saveScan(stateDir: string, record: ScanRecord): Promise<void> {
  await mkdir(join(stateDir, 'scans'), { recursive: true })
  await writeFile(scanPath(stateDir, record.id), `${JSON.stringify(record, null, 2)}\n`, 'utf8')
}

export async function loadScan(stateDir: string, id: string): Promise<ScanRecord> {
  return JSON.parse(await readFile(scanPath(stateDir, id), 'utf8')) as ScanRecord
}

export async function listScans(stateDir: string): Promise<ScanRecord[]> {
  try {
    const names = await readdir(join(stateDir, 'scans'))
    return (await Promise.all(names.filter(name => name.endsWith('.json')).map(name =>
      readFile(join(stateDir, 'scans', name), 'utf8').then(text => JSON.parse(text) as ScanRecord),
    ))).sort((a, b) => b.createdAt.localeCompare(a.createdAt))
  } catch (error: unknown) {
    if (typeof error === 'object' && error !== null && 'code' in error && error.code === 'ENOENT') return []
    throw error
  }
}

export function severityRank(severity: Finding['severity']): number {
  return ({ critical: 4, high: 3, medium: 2, low: 1 })[severity]
}

export function renderMarkdownReport(scan: ScanRecord): string {
  const summary = scan.findings.reduce<Record<string, number>>((counts, finding) => {
    counts[finding.severity] = (counts[finding.severity] ?? 0) + 1
    return counts
  }, {})
  const lines = [
    '# Security Scan Report',
    '',
    `- Scan ID: \`${scan.id}\``,
    `- Mode: ${scan.mode}`,
    `- Target: \`${scan.target}\``,
    `- Completed: ${scan.completedAt}`,
    `- Coverage: ${scan.coverage.reviewedFiles} reviewed, ${scan.coverage.skippedFiles} skipped`,
    `- Findings: critical ${summary.critical ?? 0}, high ${summary.high ?? 0}, medium ${summary.medium ?? 0}, low ${summary.low ?? 0}`,
    '',
    '## Threat Model',
    '',
    scan.threatModel,
    '',
    '## Findings',
  ]
  if (scan.findings.length === 0) lines.push('', 'No static candidates were found. This does not establish that the target is free of vulnerabilities.')
  for (const finding of scan.findings) {
    lines.push('', `### ${finding.title}`, '', `- ID: \`${finding.id}\``, `- Severity: ${finding.severity}`, `- Confidence: ${finding.confidence}`, `- CWE: ${finding.cwe}`, `- Location: ${finding.locations[0].file}:${finding.locations[0].line}`, '', finding.rootCause, '', `**Attack path:** ${finding.attackPath}`, '', `**Impact:** ${finding.impact}`, '', `**Remediation:** ${finding.remediation}`)
  }
  return `${lines.join('\n')}\n`
}

export function toSarif(scan: ScanRecord): Record<string, unknown> {
  return {
    version: '2.1.0',
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    runs: [{
      tool: { driver: { name: 'dsh-security-suite', rules: scan.findings.map(finding => ({ id: finding.ruleId, shortDescription: { text: finding.title } })) } },
      results: scan.findings.map(finding => ({
        ruleId: finding.ruleId,
        level: finding.severity === 'critical' || finding.severity === 'high' ? 'error' : 'warning',
        message: { text: finding.rootCause },
        locations: finding.locations.map(location => ({ physicalLocation: { artifactLocation: { uri: location.file }, region: { startLine: location.line } } })),
      })),
    }],
  }
}
