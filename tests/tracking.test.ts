import assert from 'node:assert/strict'
import { mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { createGitHubAdvisory, createTracking, previewGitHubAdvisory, previewTracking } from '../src/tracking.ts'
import { runScan } from '../src/scanner.ts'
import { finalizeAndSaveScan } from '../src/state.ts'

const token = 'private-test-token'

async function setup() {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  const state = await mkdtemp(join(tmpdir(), 'dsh-security-suite-state-'))
  const config = { enabled: true, maxFiles: 10, maxFileBytes: 4096, stateDir: state }
  await writeFile(join(root, 'client.ts'), 'request({ rejectUnauthorized: false })\n')
  const scan = await runScan(root, config, 'standard', '', false, state)
  const finding = scan.findings[0]
  finding.disposition = 'reportable'
  finding.ledger.push({ at: new Date().toISOString(), phase: 'validation', disposition: 'reportable', summary: 'Static evidence.' })
  finding.ledger.push({ at: new Date().toISOString(), phase: 'attack_path', disposition: 'reportable', summary: 'Attacker path.' })
  scan.lifecycle = 'completed'; scan.completedAt = new Date().toISOString()
  await finalizeAndSaveScan(state, scan)
  return { root, state, config, scan, finding, async dispose() { await rm(root, { recursive: true, force: true }); await rm(state, { recursive: true, force: true }) } }
}

function mockFetch(handler: (url: string, init?: RequestInit) => Response | Promise<Response>): () => void {
  const original = globalThis.fetch
  globalThis.fetch = (async (input, init) => handler(String(input), init)) as typeof fetch
  return () => { globalThis.fetch = original }
}

test('tracking preview is local without a token and creation rejects missing approval', async () => {
  const fixture = await setup()
  try {
    const preview = await previewTracking(fixture.config, { provider: 'github', scanId: fixture.scan.id, findingId: fixture.finding.id, repository: 'owner/repo' })
    assert.equal(preview.requiresApproval, true)
    assert.equal(preview.duplicates.length, 0)
    assert.equal(preview.lookup.status, 'not_requested')
    await assert.rejects(() => createTracking(fixture.config, { provider: 'github', scanId: fixture.scan.id, findingId: fixture.finding.id, token, repository: 'owner/repo', approved: false }), /approved/)
  } finally { await fixture.dispose() }
})

test('GitHub preview finds marker-bound duplicates with a read-only receipt', async () => {
  const fixture = await setup()
  let requests = 0
  const restore = mockFetch((url, init) => {
    requests++
    assert.match(url, /api\.github\.com\/repos\/owner\/repo\/issues\?state=open/)
    assert.equal(init?.method, undefined)
    return Response.json([{ number: 17, title: '[HIGH] unrelated title', body: `body\n<!-- dsh-security-suite finding:${fixture.finding.id} fingerprint:${fixture.finding.fingerprint} -->`, html_url: 'https://github.com/owner/repo/issues/17' }])
  })
  try {
    const preview = await previewTracking(fixture.config, { provider: 'github', scanId: fixture.scan.id, findingId: fixture.finding.id, repository: 'owner/repo', token })
    assert.deepEqual(preview.duplicates, [{ id: '17', title: '[HIGH] unrelated title', url: 'https://github.com/owner/repo/issues/17' }])
    assert.equal(preview.lookup.status, 'succeeded')
    assert.equal(preview.lookup.resultCount, 1)
    assert.equal(requests, 1)
  } finally { restore(); await fixture.dispose() }
})

test('Jira and Linear previews use provider-scoped duplicate searches', async () => {
  const fixture = await setup()
  const restore = mockFetch((url, init) => {
    if (url.startsWith('https://jira.example/rest/api/3/search/jql')) {
      assert.match(decodeURIComponent(url), /project = "SEC"/)
      return Response.json({ issues: [{ key: 'SEC-4', self: 'https://jira.example/rest/api/3/issue/SEC-4', fields: { summary: `[HIGH] ${fixture.finding.title}`, description: `<!-- dsh-security-suite finding:${fixture.finding.id} fingerprint:${fixture.finding.fingerprint} -->` } }] })
    }
    assert.equal(url, 'https://linear.example/graphql')
    const request = JSON.parse(String(init?.body)) as { query: string; variables: { teamId: string } }
    assert.match(request.query, /IssueSearch/)
    assert.equal(request.variables.teamId, 'team-1')
    return Response.json({ data: { issues: { nodes: [{ id: 'linear-id', identifier: 'SEC-8', title: `[HIGH] ${fixture.finding.title}`, description: `<!-- dsh-security-suite finding:${fixture.finding.id} fingerprint:${fixture.finding.fingerprint} -->`, url: 'https://linear.app/acme/issue/SEC-8' }] } } })
  })
  try {
    const jira = await previewTracking(fixture.config, { provider: 'jira', scanId: fixture.scan.id, findingId: fixture.finding.id, endpoint: 'https://jira.example', project: 'SEC', token })
    const linear = await previewTracking(fixture.config, { provider: 'linear', scanId: fixture.scan.id, findingId: fixture.finding.id, endpoint: 'https://linear.example/graphql', project: 'team-1', token })
    assert.equal(jira.duplicates[0].id, 'SEC-4')
    assert.equal(linear.duplicates[0].id, 'SEC-8')
    assert.equal(jira.lookup.status, 'succeeded')
    assert.equal(linear.lookup.status, 'succeeded')
  } finally { restore(); await fixture.dispose() }
})

test('GitHub tracking creates once, verifies readback, and never persists a token', async () => {
  const fixture = await setup()
  let posts = 0
  const restore = mockFetch((url, init) => {
    if (url.includes('?state=open')) return Response.json([])
    if (init?.method === 'POST') { posts++; const body = JSON.parse(String(init.body)) as { title: string; body: string }; return Response.json({ number: 19, html_url: 'https://github.com/owner/repo/issues/19', url: 'https://api.github.com/repos/owner/repo/issues/19', ...body }, { status: 201 }) }
    assert.match(url, /issues\/19$/)
    return Response.json({ number: 19, title: `[HIGH] ${fixture.finding.title}`, body: `saved\n<!-- dsh-security-suite finding:${fixture.finding.id} fingerprint:${fixture.finding.fingerprint} -->`, html_url: 'https://github.com/owner/repo/issues/19' })
  })
  try {
    const request = { provider: 'github' as const, scanId: fixture.scan.id, findingId: fixture.finding.id, token, repository: 'owner/repo', approved: true }
    const receipt = await createTracking(fixture.config, request)
    assert.equal(receipt.status, 'created')
    assert.equal(receipt.writeSucceeded, true)
    assert.equal(receipt.readback?.titleMatched, true)
    assert.equal(receipt.readback?.bodyMatched, true)
    assert.equal(posts, 1)
    const repeated = await createTracking(fixture.config, request)
    assert.equal(repeated.id, receipt.id)
    assert.equal(posts, 1)
    const files = await readdir(join(fixture.state, 'tracking'))
    const saved = await readFile(join(fixture.state, 'tracking', files[0]), 'utf8')
    assert.doesNotMatch(saved, /private-test-token/)
  } finally { restore(); await fixture.dispose() }
})

test('a successful write with failed readback is retained as created_unverified without retry', async () => {
  const fixture = await setup()
  let posts = 0
  const restore = mockFetch((url, init) => {
    if (url.includes('?state=open')) return Response.json([])
    if (init?.method === 'POST') { posts++; return Response.json({ number: 25, html_url: 'https://github.com/owner/repo/issues/25', url: 'https://api.github.com/repos/owner/repo/issues/25' }, { status: 201 }) }
    return Response.json({ message: 'unavailable' }, { status: 503 })
  })
  try {
    const receipt = await createTracking(fixture.config, { provider: 'github', scanId: fixture.scan.id, findingId: fixture.finding.id, token, repository: 'owner/repo', approved: true })
    assert.equal(receipt.status, 'created_unverified')
    assert.equal(receipt.writeSucceeded, true)
    assert.equal(receipt.readback?.status, 'failed')
    assert.equal(posts, 1)
  } finally { restore(); await fixture.dispose() }
})

test('a remote duplicate is persisted and does not create an external issue', async () => {
  const fixture = await setup()
  let posts = 0
  const restore = mockFetch((url, init) => {
    if (init?.method === 'POST') posts++
    return Response.json([{ number: 42, title: `[HIGH] ${fixture.finding.title}`, body: '', html_url: 'https://github.com/owner/repo/issues/42' }])
  })
  try {
    const receipt = await createTracking(fixture.config, { provider: 'github', scanId: fixture.scan.id, findingId: fixture.finding.id, token, repository: 'owner/repo', approved: true })
    assert.equal(receipt.status, 'duplicate')
    assert.equal(receipt.duplicateOf, '42')
    assert.equal(posts, 0)
    assert.equal(receipt.duplicateLookup.status, 'succeeded')
  } finally { restore(); await fixture.dispose() }
})

test('Jira and Linear issue writes are read back and verified', async () => {
  const fixture = await setup()
  const restore = mockFetch((url, init) => {
    if (url.startsWith('https://jira.example/rest/api/3/search/jql')) return Response.json({ issues: [] })
    if (url === 'https://jira.example/rest/api/3/issue' && init?.method === 'POST') return Response.json({ key: 'SEC-10', self: 'https://jira.example/rest/api/3/issue/SEC-10' }, { status: 201 })
    if (url === 'https://jira.example/rest/api/3/issue/SEC-10') return Response.json({ key: 'SEC-10', self: url, fields: { summary: `[HIGH] ${fixture.finding.title}`, description: `saved <!-- dsh-security-suite finding:${fixture.finding.id} fingerprint:${fixture.finding.fingerprint} -->` } })
    const request = JSON.parse(String(init?.body)) as { query: string }
    if (request.query.includes('IssueSearch')) return Response.json({ data: { issues: { nodes: [] } } })
    if (request.query.includes('IssueCreate')) return Response.json({ data: { issueCreate: { success: true, issue: { id: 'linear-id', identifier: 'SEC-11', url: 'https://linear.app/acme/issue/SEC-11' } } } })
    assert.match(request.query, /IssueReadback/)
    return Response.json({ data: { issue: { id: 'linear-id', identifier: 'SEC-11', title: `[HIGH] ${fixture.finding.title}`, description: `saved <!-- dsh-security-suite finding:${fixture.finding.id} fingerprint:${fixture.finding.fingerprint} -->`, url: 'https://linear.app/acme/issue/SEC-11' } } })
  })
  try {
    const jira = await createTracking(fixture.config, { provider: 'jira', scanId: fixture.scan.id, findingId: fixture.finding.id, token, endpoint: 'https://jira.example', project: 'SEC', approved: true })
    assert.equal(jira.status, 'created')
    const linear = await createTracking(fixture.config, { provider: 'linear', scanId: fixture.scan.id, findingId: fixture.finding.id, token, endpoint: 'https://linear.example/graphql', project: 'team-1', approved: true })
    assert.equal(linear.status, 'created')
  } finally { restore(); await fixture.dispose() }
})

test('GitHub advisory refuses scans without a verified clean GitHub revision', async () => {
  const fixture = await setup()
  try {
    await assert.rejects(() => previewGitHubAdvisory(fixture.config, { scanId: fixture.scan.id, findingId: fixture.finding.id }), /clean GitHub worktree/)
    await assert.rejects(() => createGitHubAdvisory(fixture.config, { scanId: fixture.scan.id, findingId: fixture.finding.id, token, approved: true }), /clean GitHub worktree/)
  } finally { await fixture.dispose() }
})

test('GitHub advisory creates one private draft, verifies it, and never calls an Issue endpoint', async () => {
  const fixture = await setup()
  fixture.scan.targetSnapshot = { kind: 'git_revision', targetId: 'verified-source', displayName: 'repo', sourceRepository: 'owner/repo', revision: 'a'.repeat(40), snapshotDigest: fixture.scan.targetSnapshot.snapshotDigest }
  await finalizeAndSaveScan(fixture.state, fixture.scan)
  let posts = 0
  const restore = mockFetch((url, init) => {
    assert.doesNotMatch(url, /\/issues(?:\?|$)/)
    if (url.includes('?per_page=100')) return Response.json([])
    if (init?.method === 'POST') {
      posts++
      assert.match(url, /\/security-advisories$/)
      const body = JSON.parse(String(init.body)) as { summary: string; description: string; severity: string; vulnerabilities: unknown[]; start_private_fork: boolean }
      assert.equal(body.severity, 'high')
      assert.equal(body.start_private_fork, false)
      assert.equal(body.vulnerabilities.length, 1)
      assert.match(body.description, /Verified revision: a{40}/)
      return Response.json({ ghsa_id: 'GHSA-test-1234', html_url: 'https://github.com/owner/repo/security/advisories/GHSA-test-1234', url: 'https://api.github.com/repos/owner/repo/security-advisories/GHSA-test-1234' }, { status: 201 })
    }
    assert.match(url, /\/security-advisories\/GHSA-test-1234$/)
    return Response.json({ ghsa_id: 'GHSA-test-1234', summary: `[HIGH] ${fixture.finding.title}`, description: `saved\n<!-- dsh-security-suite advisory finding:${fixture.finding.id} fingerprint:${fixture.finding.fingerprint} source:owner/repo@${'a'.repeat(40)} -->`, state: 'draft' })
  })
  try {
    const preview = await previewGitHubAdvisory(fixture.config, { scanId: fixture.scan.id, findingId: fixture.finding.id, token })
    assert.equal(preview.repository, 'owner/repo')
    assert.equal(preview.sourceRevision, 'a'.repeat(40))
    assert.equal(preview.lookup.status, 'succeeded')
    const receipt = await createGitHubAdvisory(fixture.config, { scanId: fixture.scan.id, findingId: fixture.finding.id, token, approved: true })
    assert.equal(receipt.status, 'created')
    assert.equal(receipt.provider, 'github_advisory')
    assert.equal(receipt.readback?.draftMatched, true)
    assert.equal(posts, 1)
    const repeated = await createGitHubAdvisory(fixture.config, { scanId: fixture.scan.id, findingId: fixture.finding.id, token, approved: true })
    assert.equal(repeated.id, receipt.id)
    assert.equal(posts, 1)
    const files = await readdir(join(fixture.state, 'tracking'))
    assert.doesNotMatch(await readFile(join(fixture.state, 'tracking', files[0]), 'utf8'), /private-test-token/)
  } finally { restore(); await fixture.dispose() }
})

test('GitHub advisory retains an unverified create after failed readback without retrying', async () => {
  const fixture = await setup()
  fixture.scan.targetSnapshot = { kind: 'git_revision', targetId: 'verified-source', displayName: 'repo', sourceRepository: 'owner/repo', revision: 'b'.repeat(40), snapshotDigest: fixture.scan.targetSnapshot.snapshotDigest }
  await finalizeAndSaveScan(fixture.state, fixture.scan)
  let posts = 0
  const restore = mockFetch((url, init) => {
    if (url.includes('?per_page=100')) return Response.json([])
    if (init?.method === 'POST') { posts++; return Response.json({ ghsa_id: 'GHSA-unverified', url: 'https://api.github.com/repos/owner/repo/security-advisories/GHSA-unverified' }, { status: 201 }) }
    return Response.json({ message: 'unavailable' }, { status: 503 })
  })
  try {
    const receipt = await createGitHubAdvisory(fixture.config, { scanId: fixture.scan.id, findingId: fixture.finding.id, token, approved: true })
    assert.equal(receipt.status, 'created_unverified')
    assert.equal(receipt.readback?.status, 'failed')
    assert.equal(posts, 1)
  } finally { restore(); await fixture.dispose() }
})
