import { mkdir, readFile, readdir, rename, writeFile } from 'node:fs/promises'
import { join, resolve } from 'node:path'
import { randomUUID } from 'node:crypto'
import type { Config } from './config.js'
import type { Finding } from './contracts.js'
import { getStateDir, loadScan, sha256 } from './state.js'

export type TrackingProvider = 'github' | 'jira' | 'linear'
export interface TrackingRequest { provider: TrackingProvider; scanId: string; findingId: string; endpoint?: string; project?: string; repository?: string; token: string; approved: boolean }
export interface TrackingQueryReceipt { provider: TrackingProvider; operation: 'duplicate_lookup' | 'post_create_readback'; status: 'not_requested' | 'succeeded' | 'failed'; requestDigest: string; responseStatus?: number; resultCount?: number; error?: string }
export interface TrackingPreview { provider: TrackingProvider; title: string; body: string; duplicates: Array<{ id: string; title: string; url?: string }>; requiresApproval: true; lookup: TrackingQueryReceipt }
export interface TrackingReceipt {
  id: string
  provider: TrackingProvider
  scanId: string
  findingId: string
  status: 'created' | 'created_unverified' | 'duplicate' | 'failed'
  writeSucceeded?: boolean
  externalId?: string
  url?: string
  duplicateOf?: string
  createdAt: string
  requestDigest: string
  responseStatus?: number
  duplicateLookup: TrackingQueryReceipt
  readback?: TrackingQueryReceipt & { externalId?: string; titleMatched?: boolean; bodyMatched?: boolean }
  error?: string
}

interface RemoteIssue { id: string; title: string; body?: unknown; url?: string; readUrl?: string }
interface CreatedIssue { id: string; url?: string; readUrl?: string; responseStatus: number }
interface IssuePayload { title: string; body: string; marker: string }

function bodyFor(finding: Finding): string {
  const location = finding.locations[0]
  const marker = `<!-- dsh-security-suite finding:${finding.id} fingerprint:${finding.fingerprint} -->`
  return `## Summary\n${finding.rootCause}\n\n## Evidence\n- Severity: ${finding.severity}\n- CWE: ${finding.cwe}\n- Confidence: ${finding.confidence}\n- Location: ${location.file}:${location.line}\n\n## Validation\n${finding.validation}\n\n## Attack Path\n${finding.attackPath}\n\n## Impact\n${finding.impact}\n\n## Remediation\n${finding.remediation}\n\n${marker}`
}
function titleFor(finding: Finding): string { return `[${finding.severity.toUpperCase()}] ${finding.title}` }
function payloadFor(finding: Finding): IssuePayload { const body = bodyFor(finding); return { title: titleFor(finding), body, marker: `<!-- dsh-security-suite finding:${finding.id} fingerprint:${finding.fingerprint} -->` } }
function digest(value: unknown): string { return `sha256:${sha256(JSON.stringify(value))}` }
function headers(token: string): Record<string, string> { if (!token.trim()) throw new Error('A provider token is required for external tracking.'); return { authorization: `Bearer ${token}`, accept: 'application/json', 'content-type': 'application/json', 'user-agent': 'dsh-security-suite' } }
function requestDigest(provider: TrackingProvider, payload: IssuePayload): string { return digest({ provider, title: payload.title, bodySha256: sha256(payload.body) }) }
function providerConfigDigest(request: Pick<TrackingRequest, 'provider' | 'endpoint' | 'project' | 'repository'>): string { return digest({ provider: request.provider, endpoint: request.endpoint, project: request.project, repository: request.repository }) }
function safeError(error: unknown): string { return String(error instanceof Error ? error.message : error).replace(/Bearer\s+[^\s,]+/gi, 'Bearer [redacted]').slice(0, 1_000) }
function plainText(value: unknown): string {
  if (typeof value === 'string') return value
  if (Array.isArray(value)) return value.map(plainText).join(' ')
  if (value && typeof value === 'object') return Object.values(value as Record<string, unknown>).map(plainText).join(' ')
  return ''
}
function githubRepository(repository?: string): [string, string] {
  const parts = repository?.split('/') ?? []
  if (parts.length !== 2 || !parts[0] || !parts[1]) throw new Error('GitHub tracking requires repository in owner/name form.')
  return [parts[0], parts[1]]
}
function validateProvider(request: Pick<TrackingRequest, 'provider' | 'endpoint' | 'project' | 'repository'>): void {
  if (request.provider === 'github') { githubRepository(request.repository); return }
  if (!request.endpoint?.trim() || !request.project?.trim()) throw new Error(`${request.provider === 'jira' ? 'Jira' : 'Linear'} tracking requires endpoint and ${request.provider === 'jira' ? 'project key' : 'team id'}.`)
}
async function responseJson(response: Response): Promise<unknown> { try { return await response.json() } catch { return await response.text() } }
async function atomicWrite(path: string, content: string): Promise<void> { await mkdir(resolve(path, '..'), { recursive: true }); const temp = `${path}.${randomUUID()}.tmp`; await writeFile(temp, content, 'utf8'); await rename(temp, path) }
async function receipt(config: Config, value: TrackingReceipt): Promise<TrackingReceipt> { await atomicWrite(join(getStateDir(config.stateDir), 'tracking', `${value.id}.json`), `${JSON.stringify(value, null, 2)}\n`); return value }

async function findingFor(config: Config, scanId: string, findingId: string): Promise<Finding> {
  const scan = await loadScan(getStateDir(config.stateDir), scanId)
  const finding = scan.findings.find(item => item.id === findingId)
  if (!finding) throw new Error('Finding was not found in this scan.')
  if (finding.disposition !== 'reportable') throw new Error('Only reportable findings can be tracked externally.')
  return finding
}

async function githubIssues(request: TrackingRequest, payload: IssuePayload): Promise<{ issues: RemoteIssue[]; status: number }> {
  const [owner, repository] = githubRepository(request.repository)
  const response = await fetch(`https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repository)}/issues?state=open&per_page=100`, { headers: headers(request.token) })
  const value = await responseJson(response)
  if (!response.ok) throw new Error(`GitHub duplicate lookup failed with HTTP ${response.status}.`)
  const issues = Array.isArray(value) ? value.map(issue => {
    const row = issue as { number?: number; title?: string; body?: string; html_url?: string; url?: string }
    return { id: String(row.number ?? ''), title: row.title ?? '', body: row.body, url: row.html_url, readUrl: row.url }
  }) : []
  return { issues: issues.filter(issue => issue.title === payload.title || plainText(issue.body).includes(payload.marker)), status: response.status }
}

async function jiraIssues(request: TrackingRequest, payload: IssuePayload): Promise<{ issues: RemoteIssue[]; status: number }> {
  const base = request.endpoint!.replace(/\/$/, '')
  const jql = `project = "${request.project!.replaceAll('"', '\\"')}" AND summary ~ "${payload.title.replaceAll('"', '\\"')}"`
  const response = await fetch(`${base}/rest/api/3/search/jql?jql=${encodeURIComponent(jql)}&maxResults=50&fields=summary,description`, { headers: headers(request.token) })
  const value = await responseJson(response) as { issues?: Array<{ key?: string; self?: string; fields?: { summary?: string; description?: unknown } }> }
  if (!response.ok) throw new Error(`Jira duplicate lookup failed with HTTP ${response.status}.`)
  const issues = (value.issues ?? []).map(issue => ({ id: issue.key ?? '', title: issue.fields?.summary ?? '', body: issue.fields?.description, url: issue.self, readUrl: issue.self }))
  return { issues: issues.filter(issue => issue.title === payload.title || plainText(issue.body).includes(payload.marker)), status: response.status }
}

async function linearIssues(request: TrackingRequest, payload: IssuePayload): Promise<{ issues: RemoteIssue[]; status: number }> {
  const query = 'query IssueSearch($teamId: String!, $query: String!) { issues(filter: { team: { id: { eq: $teamId } }, title: { containsIgnoreCase: $query } }) { nodes { id identifier title url description } } }'
  const response = await fetch(request.endpoint!, { method: 'POST', headers: headers(request.token), body: JSON.stringify({ query, variables: { teamId: request.project, query: payload.title } }) })
  const value = await responseJson(response) as { data?: { issues?: { nodes?: Array<{ id?: string; identifier?: string; title?: string; url?: string; description?: string }> } }; errors?: Array<{ message?: string }> }
  if (!response.ok || value.errors?.length) throw new Error(`Linear duplicate lookup failed with HTTP ${response.status}.`)
  const issues = (value.data?.issues?.nodes ?? []).map(issue => ({ id: issue.identifier ?? issue.id ?? '', title: issue.title ?? '', body: issue.description, url: issue.url, readUrl: issue.id }))
  return { issues: issues.filter(issue => issue.title === payload.title || plainText(issue.body).includes(payload.marker)), status: response.status }
}

async function lookupRemote(request: TrackingRequest, payload: IssuePayload): Promise<{ issues: RemoteIssue[]; lookup: TrackingQueryReceipt }> {
  const requestDigest = providerConfigDigest(request)
  try {
    const result = request.provider === 'github' ? await githubIssues(request, payload) : request.provider === 'jira' ? await jiraIssues(request, payload) : await linearIssues(request, payload)
    return { issues: result.issues, lookup: { provider: request.provider, operation: 'duplicate_lookup', status: 'succeeded', requestDigest, responseStatus: result.status, resultCount: result.issues.length } }
  } catch (error) {
    return { issues: [], lookup: { provider: request.provider, operation: 'duplicate_lookup', status: 'failed', requestDigest, error: safeError(error) } }
  }
}

function noLookup(request: Pick<TrackingRequest, 'provider' | 'endpoint' | 'project' | 'repository'>): TrackingQueryReceipt {
  return { provider: request.provider, operation: 'duplicate_lookup', status: 'not_requested', requestDigest: providerConfigDigest(request) }
}

export async function previewTracking(config: Config, request: Omit<TrackingRequest, 'token' | 'approved'> & { token?: string }): Promise<TrackingPreview> {
  const finding = await findingFor(config, request.scanId, request.findingId)
  const payload = payloadFor(finding)
  if (!request.token?.trim()) return { provider: request.provider, title: payload.title, body: payload.body, duplicates: [], requiresApproval: true, lookup: noLookup(request) }
  validateProvider(request)
  const remote = await lookupRemote({ ...request, token: request.token, approved: false }, payload)
  return { provider: request.provider, title: payload.title, body: payload.body, duplicates: remote.issues.map(issue => ({ id: issue.id, title: issue.title, url: issue.url })), requiresApproval: true, lookup: remote.lookup }
}

async function localDuplicate(config: Config, request: TrackingRequest): Promise<TrackingReceipt | undefined> {
  const directory = join(getStateDir(config.stateDir), 'tracking')
  try {
    const names = await readdir(directory)
    const matches = (await Promise.all(names.filter(name => name.endsWith('.json')).map(async name => {
      try { return JSON.parse(await readFile(join(directory, name), 'utf8')) as TrackingReceipt } catch { return undefined }
    }))).filter((value): value is TrackingReceipt => Boolean(value && value.provider === request.provider && value.scanId === request.scanId && value.findingId === request.findingId && ['created', 'created_unverified', 'duplicate'].includes(value.status)))
    return matches.sort((a, b) => b.createdAt.localeCompare(a.createdAt))[0]
  } catch (error: unknown) { if (typeof error === 'object' && error !== null && 'code' in error && error.code === 'ENOENT') return undefined; throw error }
}

async function createRemote(request: TrackingRequest, payload: IssuePayload): Promise<CreatedIssue> {
  if (request.provider === 'github') {
    const [owner, repository] = githubRepository(request.repository)
    const response = await fetch(`https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repository)}/issues`, { method: 'POST', headers: headers(request.token), body: JSON.stringify({ title: payload.title, body: payload.body }) })
    const value = await responseJson(response) as { number?: number; html_url?: string; url?: string; message?: string }
    if (!response.ok || !value.number) throw new Error(`GitHub issue creation failed with HTTP ${response.status}: ${value.message ?? ''}`)
    return { id: String(value.number), url: value.html_url, readUrl: value.url, responseStatus: response.status }
  }
  if (request.provider === 'jira') {
    const response = await fetch(`${request.endpoint!.replace(/\/$/, '')}/rest/api/3/issue`, { method: 'POST', headers: headers(request.token), body: JSON.stringify({ fields: { project: { key: request.project }, summary: payload.title, description: { type: 'doc', version: 1, content: [{ type: 'paragraph', content: [{ type: 'text', text: payload.body }] }] }, issuetype: { name: 'Task' } } }) })
    const value = await responseJson(response) as { key?: string; self?: string; errorMessages?: string[] }
    if (!response.ok || !value.key || !value.self) throw new Error(`Jira issue creation failed with HTTP ${response.status}: ${(value.errorMessages ?? []).join(' ')}`)
    return { id: value.key, url: value.self, readUrl: value.self, responseStatus: response.status }
  }
  const query = 'mutation IssueCreate($input: IssueCreateInput!) { issueCreate(input: $input) { success issue { id identifier url } } }'
  const response = await fetch(request.endpoint!, { method: 'POST', headers: headers(request.token), body: JSON.stringify({ query, variables: { input: { teamId: request.project, title: payload.title, description: payload.body } } }) })
  const value = await responseJson(response) as { data?: { issueCreate?: { success?: boolean; issue?: { id?: string; identifier?: string; url?: string } } }; errors?: Array<{ message?: string }> }
  const issue = value.data?.issueCreate?.issue
  if (!response.ok || !value.data?.issueCreate?.success || !issue?.id) throw new Error(`Linear issue creation failed with HTTP ${response.status}: ${(value.errors ?? []).map(item => item.message).join(' ')}`)
  return { id: issue.identifier ?? issue.id, url: issue.url, readUrl: issue.id, responseStatus: response.status }
}

async function readbackRemote(request: TrackingRequest, created: CreatedIssue): Promise<{ issue?: RemoteIssue; responseStatus?: number; error?: string }> {
  try {
    if (request.provider === 'github') {
      const [owner, repository] = githubRepository(request.repository)
      const response = await fetch(created.readUrl || `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repository)}/issues/${encodeURIComponent(created.id)}`, { headers: headers(request.token) })
      const value = await responseJson(response) as { number?: number; title?: string; body?: string; html_url?: string; url?: string }
      if (!response.ok) throw new Error(`GitHub readback failed with HTTP ${response.status}.`)
      return { issue: { id: String(value.number ?? ''), title: value.title ?? '', body: value.body, url: value.html_url, readUrl: value.url }, responseStatus: response.status }
    }
    if (request.provider === 'jira') {
      const response = await fetch(created.readUrl!, { headers: headers(request.token) })
      const value = await responseJson(response) as { key?: string; self?: string; fields?: { summary?: string; description?: unknown } }
      if (!response.ok) throw new Error(`Jira readback failed with HTTP ${response.status}.`)
      return { issue: { id: value.key ?? '', title: value.fields?.summary ?? '', body: value.fields?.description, url: value.self, readUrl: value.self }, responseStatus: response.status }
    }
    const query = 'query IssueReadback($id: String!) { issue(id: $id) { id identifier title description url } }'
    const response = await fetch(request.endpoint!, { method: 'POST', headers: headers(request.token), body: JSON.stringify({ query, variables: { id: created.readUrl } }) })
    const value = await responseJson(response) as { data?: { issue?: { id?: string; identifier?: string; title?: string; description?: string; url?: string } }; errors?: Array<{ message?: string }> }
    const issue = value.data?.issue
    if (!response.ok || value.errors?.length || !issue?.id) throw new Error(`Linear readback failed with HTTP ${response.status}.`)
    return { issue: { id: issue.identifier ?? issue.id, title: issue.title ?? '', body: issue.description, url: issue.url, readUrl: issue.id }, responseStatus: response.status }
  } catch (error) { return { error: safeError(error) } }
}

export async function createTracking(config: Config, request: TrackingRequest): Promise<TrackingReceipt> {
  if (!request.approved) throw new Error('Creating an external issue changes a third-party system. Set approved to true only after reviewing the exact preview.')
  const finding = await findingFor(config, request.scanId, request.findingId)
  validateProvider(request)
  headers(request.token)
  const existing = await localDuplicate(config, request)
  if (existing) return existing
  const payload = payloadFor(finding)
  const remote = await lookupRemote(request, payload)
  const base = { id: `trk_${randomUUID()}`, provider: request.provider, scanId: request.scanId, findingId: finding.id, createdAt: new Date().toISOString(), requestDigest: requestDigest(request.provider, payload), duplicateLookup: remote.lookup }
  if (remote.lookup.status === 'failed') return receipt(config, { ...base, status: 'failed', error: `Duplicate lookup was not completed: ${remote.lookup.error ?? 'unknown error'}` })
  if (remote.issues.length) return receipt(config, { ...base, status: 'duplicate', duplicateOf: remote.issues[0].id, url: remote.issues[0].url })
  try {
    const created = await createRemote(request, payload)
    const readback = await readbackRemote(request, created)
    const readbackReceipt: TrackingReceipt['readback'] = {
      provider: request.provider, operation: 'post_create_readback', status: readback.error ? 'failed' : 'succeeded', requestDigest: digest({ provider: request.provider, externalId: created.id }), responseStatus: readback.responseStatus,
      ...(readback.error ? { error: readback.error } : { externalId: readback.issue?.id, titleMatched: readback.issue?.title === payload.title, bodyMatched: plainText(readback.issue?.body).includes(payload.marker) }),
    }
    if (readbackReceipt.status === 'succeeded' && readbackReceipt.externalId === created.id && readbackReceipt.titleMatched && readbackReceipt.bodyMatched) return receipt(config, { ...base, status: 'created', writeSucceeded: true, externalId: created.id, url: created.url, responseStatus: created.responseStatus, readback: readbackReceipt })
    return receipt(config, { ...base, status: 'created_unverified', writeSucceeded: true, externalId: created.id, url: created.url, responseStatus: created.responseStatus, readback: readbackReceipt, error: 'The external issue was created but post-create readback did not verify the exact title, identity marker, and identifier.' })
  } catch (error) {
    return receipt(config, { ...base, status: 'failed', error: safeError(error) })
  }
}
