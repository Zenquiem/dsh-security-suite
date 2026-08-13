import { mkdir, readFile, rename, writeFile } from 'node:fs/promises'
import { join, resolve } from 'node:path'
import { randomUUID } from 'node:crypto'
import type { Config } from './config.js'
import type { Finding } from './contracts.js'
import { getStateDir, loadScan } from './state.js'

export type TrackingProvider = 'github' | 'jira' | 'linear'
export interface TrackingRequest { provider: TrackingProvider; scanId: string; findingId: string; endpoint?: string; project?: string; repository?: string; token: string; approved: boolean }
export interface TrackingPreview { provider: TrackingProvider; title: string; body: string; duplicates: Array<{ id: string; title: string; url?: string }>; requiresApproval: true }
export interface TrackingReceipt { id: string; provider: TrackingProvider; scanId: string; findingId: string; status: 'created' | 'duplicate' | 'failed'; externalId?: string; url?: string; duplicateOf?: string; createdAt: string; requestDigest: string; responseStatus?: number; error?: string }

function bodyFor(finding: Finding): string { const location = finding.locations[0]; return `## Summary\n${finding.rootCause}\n\n## Evidence\n- Severity: ${finding.severity}\n- CWE: ${finding.cwe}\n- Confidence: ${finding.confidence}\n- Location: ${location.file}:${location.line}\n\n## Validation\n${finding.validation}\n\n## Attack Path\n${finding.attackPath}\n\n## Impact\n${finding.impact}\n\n## Remediation\n${finding.remediation}` }
function titleFor(finding: Finding): string { return `[${finding.severity.toUpperCase()}] ${finding.title}` }
function digest(value: string): string { let h = 0x811c9dc5; for (const char of value) { h ^= char.charCodeAt(0); h = Math.imul(h, 0x01000193) } return `fnv1a32:${(h >>> 0).toString(16).padStart(8, '0')}` }
function headers(token: string): Record<string, string> { if (!token.trim()) throw new Error('A provider token is required for external tracking.'); return { authorization: `Bearer ${token}`, accept: 'application/json', 'content-type': 'application/json', 'user-agent': 'dsh-security-suite' } }
async function responseJson(response: Response): Promise<unknown> { try { return await response.json() } catch { return await response.text() } }
async function atomicWrite(path: string, content: string): Promise<void> { await mkdir(resolve(path, '..'), { recursive: true }); const temp = `${path}.${randomUUID()}.tmp`; await writeFile(temp, content, 'utf8'); await rename(temp, path) }
async function receipt(config: Config, value: TrackingReceipt): Promise<TrackingReceipt> { await atomicWrite(join(getStateDir(config.stateDir), 'tracking', `${value.id}.json`), `${JSON.stringify(value, null, 2)}\n`); return value }

async function findingFor(config: Config, scanId: string, findingId: string): Promise<Finding> { const scan = await loadScan(getStateDir(config.stateDir), scanId); const finding = scan.findings.find(item => item.id === findingId); if (!finding) throw new Error('Finding was not found in this scan.'); if (finding.disposition !== 'reportable') throw new Error('Only reportable findings can be tracked externally.'); return finding }

export async function previewTracking(config: Config, request: Omit<TrackingRequest, 'token' | 'approved'> & { token?: string }): Promise<TrackingPreview> {
  const finding = await findingFor(config, request.scanId, request.findingId); const title = titleFor(finding); const body = bodyFor(finding); const duplicates: TrackingPreview['duplicates'] = []
  if (!request.token?.trim()) return { provider: request.provider, title, body, duplicates, requiresApproval: true }
  if (request.provider === 'github') {
    if (!request.repository) throw new Error('GitHub duplicate lookup requires repository in owner/name form.')
    const url = `https://api.github.com/repos/${encodeURIComponent(request.repository.split('/')[0] ?? '')}/${encodeURIComponent(request.repository.split('/')[1] ?? '')}/issues?state=open&per_page=100`
    const response = await fetch(url, { headers: headers(request.token) }); if (!response.ok) throw new Error(`GitHub duplicate lookup failed with HTTP ${response.status}.`)
    const issues = await responseJson(response) as Array<{ number?: number; title?: string; html_url?: string }>; for (const issue of Array.isArray(issues) ? issues : []) if (issue.title?.includes(finding.ruleId) || issue.title === title) duplicates.push({ id: String(issue.number ?? ''), title: issue.title ?? '', url: issue.html_url })
  }
  return { provider: request.provider, title, body, duplicates, requiresApproval: true }
}

export async function createTracking(config: Config, request: TrackingRequest): Promise<TrackingReceipt> {
  if (!request.approved) throw new Error('Creating an external issue changes a third-party system. Set approved to true only after reviewing the exact preview.')
  const finding = await findingFor(config, request.scanId, request.findingId); const preview = await previewTracking(config, request)
  if (preview.duplicates.length) return receipt(config, { id: `trk_${randomUUID()}`, provider: request.provider, scanId: request.scanId, findingId: request.findingId, status: 'duplicate', duplicateOf: preview.duplicates[0].id, url: preview.duplicates[0].url, createdAt: new Date().toISOString(), requestDigest: digest(JSON.stringify({ provider: request.provider, title: preview.title, body: preview.body })) })
  try {
    if (request.provider === 'github') {
      if (!request.repository?.includes('/')) throw new Error('GitHub issue creation requires repository in owner/name form.')
      const [owner, repo] = request.repository.split('/'); const response = await fetch(`https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/issues`, { method: 'POST', headers: headers(request.token), body: JSON.stringify({ title: preview.title, body: preview.body }) }); const payload = await responseJson(response) as { number?: number; html_url?: string; message?: string }; if (!response.ok) throw new Error(`GitHub issue creation failed with HTTP ${response.status}: ${payload.message ?? ''}`); return receipt(config, { id: `trk_${randomUUID()}`, provider: 'github', scanId: request.scanId, findingId: finding.id, status: 'created', externalId: String(payload.number ?? ''), url: payload.html_url, createdAt: new Date().toISOString(), requestDigest: digest(JSON.stringify({ title: preview.title, body: preview.body })), responseStatus: response.status })
    }
    if (request.provider === 'jira') {
      if (!request.endpoint || !request.project) throw new Error('Jira creation requires endpoint and project key.')
      const response = await fetch(`${request.endpoint.replace(/\/$/, '')}/rest/api/3/issue`, { method: 'POST', headers: headers(request.token), body: JSON.stringify({ fields: { project: { key: request.project }, summary: preview.title, description: { type: 'doc', version: 1, content: [{ type: 'paragraph', content: [{ type: 'text', text: preview.body }] }] }, issuetype: { name: 'Task' } } }) }); const payload = await responseJson(response) as { key?: string; self?: string; errorMessages?: string[] }; if (!response.ok) throw new Error(`Jira issue creation failed with HTTP ${response.status}: ${(payload.errorMessages ?? []).join(' ')}`); return receipt(config, { id: `trk_${randomUUID()}`, provider: 'jira', scanId: request.scanId, findingId: finding.id, status: 'created', externalId: payload.key, url: payload.self, createdAt: new Date().toISOString(), requestDigest: digest(JSON.stringify({ title: preview.title, body: preview.body })), responseStatus: response.status })
    }
    if (!request.endpoint || !request.project) throw new Error('Linear creation requires endpoint and team id in project.')
    const query = 'mutation IssueCreate($input: IssueCreateInput!) { issueCreate(input: $input) { success issue { id identifier url } } }'; const response = await fetch(request.endpoint, { method: 'POST', headers: headers(request.token), body: JSON.stringify({ query, variables: { input: { teamId: request.project, title: preview.title, description: preview.body } } }) }); const payload = await responseJson(response) as { data?: { issueCreate?: { success?: boolean; issue?: { id?: string; identifier?: string; url?: string } } }; errors?: Array<{ message?: string }> }; const issue = payload.data?.issueCreate?.issue; if (!response.ok || !payload.data?.issueCreate?.success || !issue) throw new Error(`Linear issue creation failed with HTTP ${response.status}: ${(payload.errors ?? []).map(item => item.message).join(' ')}`); return receipt(config, { id: `trk_${randomUUID()}`, provider: 'linear', scanId: request.scanId, findingId: finding.id, status: 'created', externalId: issue.identifier ?? issue.id, url: issue.url, createdAt: new Date().toISOString(), requestDigest: digest(JSON.stringify({ title: preview.title, body: preview.body })), responseStatus: response.status })
  } catch (error) { return receipt(config, { id: `trk_${randomUUID()}`, provider: request.provider, scanId: request.scanId, findingId: finding.id, status: 'failed', createdAt: new Date().toISOString(), requestDigest: digest(JSON.stringify({ provider: request.provider, finding: finding.id })), error: error instanceof Error ? error.message : String(error) }) }
}
