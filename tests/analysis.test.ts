import assert from 'node:assert/strict'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { generateHardeningPortfolio, importFindings, importGitHubSecurityFindings, triageFindingBacklog, triageImportedFinding } from '../src/analysis.ts'
import { runScan } from '../src/scanner.ts'
import { finalizeAndSaveScan } from '../src/state.ts'

const limits = { enabled: true, maxFiles: 30, maxFileBytes: 4096, stateDir: '' }

test('imported findings remain evidence until local triage establishes repository impact', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  const state = await mkdtemp(join(tmpdir(), 'dsh-security-suite-state-'))
  try {
    await writeFile(join(root, 'client.ts'), 'request({ rejectUnauthorized: false })\n')
    await writeFile(join(root, 'external.json'), JSON.stringify([{ title: 'TLS verification disabled', description: 'TLS verification is disabled', locations: [{ file: 'client.ts', line: 1 }] }]))
    const imported = await importFindings(root, 'external.json')
    const triage = await triageImportedFinding(root, { ...limits, stateDir: state }, imported[0])
    assert.equal(triage.status, 'affected')
    assert.equal(triage.confidence, 'medium')
    assert.equal(triage.evidence.length >= 1, true)
  } finally { await rm(root, { recursive: true, force: true }); await rm(state, { recursive: true, force: true }) }
})

test('SARIF intake preserves rule and location provenance and requires a matching local candidate', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  const state = await mkdtemp(join(tmpdir(), 'dsh-security-suite-state-'))
  try {
    await writeFile(join(root, 'client.ts'), 'request({ rejectUnauthorized: false })\nconst value = 1\n')
    await writeFile(join(root, 'results.sarif'), JSON.stringify({ version: '2.1.0', runs: [{ tool: { driver: { rules: [{ id: 'tls-disabled', shortDescription: { text: 'TLS verification disabled' }, properties: { tags: ['CWE-295'] } }] } }, results: [{ ruleId: 'tls-disabled', level: 'error', message: { text: 'Certificate verification is disabled.' }, locations: [{ physicalLocation: { artifactLocation: { uri: 'client.ts' }, region: { startLine: 1 } } }] }] }] }))
    const [imported] = await importFindings(root, 'results.sarif')
    assert.equal(imported.sourceType, 'sarif')
    assert.equal(imported.ruleId, 'tls-disabled')
    assert.deepEqual(imported.locations, [{ file: 'client.ts', line: 1 }])
    const triage = await triageImportedFinding(root, { ...limits, stateDir: state }, imported)
    assert.equal(triage.status, 'affected')
    assert.match(triage.evidence.join('\n'), /tls-verification-disabled/)

    const mismatch = { ...imported, locations: [{ file: 'client.ts', line: 2 }] }
    const noMatch = await triageImportedFinding(root, { ...limits, stateDir: state }, mismatch)
    assert.equal(noMatch.status, 'not_affected')
  } finally { await rm(root, { recursive: true, force: true }); await rm(state, { recursive: true, force: true }) }
})

test('unknown imported claims do not become affected merely because their file is readable', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  const state = await mkdtemp(join(tmpdir(), 'dsh-security-suite-state-'))
  try {
    await writeFile(join(root, 'app.ts'), 'export const value = 1\n')
    await writeFile(join(root, 'unknown.json'), JSON.stringify([{ title: 'Unspecified scanner alert', description: 'No rule family or CWE is available.', locations: [{ file: 'app.ts', line: 1 }] }]))
    const [imported] = await importFindings(root, 'unknown.json')
    const triage = await triageImportedFinding(root, { ...limits, stateDir: state }, imported)
    assert.equal(triage.status, 'needs_information')
    assert.equal(triage.evidence.length, 0)
    assert.match(triage.limitations.join('\n'), /do not identify a locally supported vulnerability family/)
  } finally { await rm(root, { recursive: true, force: true }); await rm(state, { recursive: true, force: true }) }
})

test('GitHub security intake uses REST pagination and preserves code-scanning instance locations as untrusted evidence', async () => {
  const original = globalThis.fetch
  const requests: Array<{ url: string; method?: string }> = []
  globalThis.fetch = (async (input, init) => {
    const url = String(input); requests.push({ url, method: init?.method })
    if (url.includes('alerts?state=open') && url.includes('page=2')) return Response.json([])
    if (url.includes('/code-scanning/alerts?')) return new Response(JSON.stringify([{ number: 12, html_url: 'https://github.com/owner/repo/security/code-scanning/12', rule: { id: 'js/eval', description: 'Dynamic code execution', severity: 'high' } }]), { headers: { link: '<https://api.github.com/repos/owner/repo/code-scanning/alerts?state=open&per_page=100&page=2>; rel="next"' } })
    if (url.includes('/code-scanning/alerts/12/instances')) return Response.json([{ location: { path: 'src/route.ts', start_line: 7 } }])
    throw new Error(`Unexpected request ${url}`)
  }) as typeof fetch
  try {
    const findings = await importGitHubSecurityFindings('owner/repo', 'code_scanning', 'token')
    assert.equal(findings.length, 1)
    assert.equal(findings[0]?.sourceType, 'sarif')
    assert.equal(findings[0]?.inputId, 'owner/repo:code_scanning:12')
    assert.deepEqual(findings[0]?.locations, [{ file: 'src/route.ts', line: 7 }])
    assert.equal(requests.every(request => request.method === undefined), true)
  } finally { globalThis.fetch = original }
})

test('GitHub all-source intake requests each selected REST family without calling issues', async () => {
  const original = globalThis.fetch
  const requests: string[] = []
  globalThis.fetch = (async input => {
    const url = String(input); requests.push(url)
    if (url.includes('/code-scanning/alerts/')) return Response.json([])
    return Response.json([])
  }) as typeof fetch
  try {
    const findings = await importGitHubSecurityFindings('owner/repo', 'all', 'token')
    assert.deepEqual(findings, [])
    assert.equal(requests.some(url => url.includes('/code-scanning/alerts?')), true)
    assert.equal(requests.some(url => url.includes('/dependabot/alerts?classification=general')), true)
    assert.equal(requests.some(url => url.includes('/dependabot/alerts?classification=malware')), true)
    for (const state of ['triage', 'draft', 'published', 'closed']) assert.equal(requests.some(url => url.includes(`/security-advisories?state=${state}`)), true)
    assert.equal(requests.some(url => /\/issues(?:\?|\/|$)/.test(url)), false)
  } finally { globalThis.fetch = original }
})

test('backlog triage preserves every supplied item and ranks needs-review entries separately', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  const state = await mkdtemp(join(tmpdir(), 'dsh-security-suite-state-'))
  try {
    await writeFile(join(root, 'client.ts'), 'request({ rejectUnauthorized: false })\n')
    await writeFile(join(root, 'SECURITY.md'), 'Security reports for runtime components are in scope.\n')
    const imported = [
      { id: 'first', title: 'TLS verification disabled', description: 'CWE-295', sourceType: 'advisory' as const, cwe: 'CWE-295', locations: [{ file: 'client.ts', line: 1 }], sourcePath: 'github://owner/repo/advisories/1', sourceSha256: 'one', references: ['https://github.com/owner/repo/security/advisories/GHSA-one'] },
      { id: 'second', title: 'TLS verification disabled duplicate claim', description: 'CWE-295', sourceType: 'advisory' as const, cwe: 'CWE-295', locations: [{ file: 'client.ts', line: 1 }], sourcePath: 'github://owner/repo/advisories/2', sourceSha256: 'two', references: ['https://github.com/owner/repo/security/advisories/GHSA-two'] },
    ]
    const result = await triageFindingBacklog(root, { enabled: true, maxFiles: 10, maxFileBytes: 4096, stateDir: state }, imported)
    assert.equal(result.schemaVersion, 'dsh-security-suite.triage/v1')
    assert.equal(result.items.length, 2)
    assert.deepEqual(result.items.map(item => item.inputId), ['first', 'second'])
    assert.equal(result.items.every(item => item.verdict === 'needs_review'), true)
    assert.deepEqual(result.items.map(item => item.exploitabilityStackRank.rank), [1, 2])
    assert.equal(result.items.every(item => item.exploitabilityStackRank.rankQueue === 'needs_review'), true)
    assert.match(await readFile(result.artifactPath, 'utf8'), /triage-001/)
  } finally { await rm(root, { recursive: true, force: true }); await rm(state, { recursive: true, force: true }) }
})

test('backlog triage confirms only a policy-supported request-to-sink match', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  const state = await mkdtemp(join(tmpdir(), 'dsh-security-suite-state-'))
  try {
    await writeFile(join(root, 'route.ts'), 'export function route(req) { eval(req.query.code) }\n')
    await writeFile(join(root, 'SECURITY.md'), 'The production API runtime is in scope for supported security boundaries.\n')
    const [item] = (await triageFindingBacklog(root, { enabled: true, maxFiles: 10, maxFileBytes: 4096, stateDir: state }, [{ id: 'eval-1', title: 'Dynamic code execution', description: 'CWE-95', sourceType: 'sarif', cwe: 'CWE-95', locations: [{ file: 'route.ts', line: 1 }], sourcePath: 'github://owner/repo/code_scanning/1', sourceSha256: 'eval' }])).items
    assert.equal(item?.verdict, 'confirmed')
    assert.equal(item?.exploitabilityStackRank.rankQueue, 'confirmed')
    assert.equal(item?.exploitabilityStackRank.rank, 1)
    assert.equal(item?.recommendedNextStep, 'fix_finding')
    assert.match(item?.fixFindingHandoff ?? '', /Dynamic code execution/)
  } finally { await rm(root, { recursive: true, force: true }); await rm(state, { recursive: true, force: true }) }
})

test('hardening portfolio records a structural recommendation from surviving scan evidence', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  const state = await mkdtemp(join(tmpdir(), 'dsh-security-suite-state-'))
  try {
    await writeFile(join(root, 'a.ts'), 'request({ rejectUnauthorized: false })\n')
    await writeFile(join(root, 'b.ts'), 'request({ rejectUnauthorized: false })\n')
    const scan = await runScan(root, { ...limits, stateDir: state }, 'standard', '', false, state)
    for (const finding of scan.findings) {
      finding.disposition = 'reportable'
      finding.ledger.push({ at: new Date().toISOString(), phase: 'validation', disposition: 'reportable', summary: 'Source validation.' })
      finding.ledger.push({ at: new Date().toISOString(), phase: 'attack_path', disposition: 'reportable', summary: 'Source path.' })
    }
    scan.lifecycle = 'completed'; scan.completedAt = new Date().toISOString()
    await finalizeAndSaveScan(state, scan)
    const portfolio = await generateHardeningPortfolio({ ...limits, stateDir: state }, scan.id)
    assert.equal(portfolio.outcome, 'structural_hardening_recommended')
    assert.match(await readFile(portfolio.portfolio, 'utf8'), /centralize/i)
    assert.match(await readFile(portfolio.structured, 'utf8'), /central-owned-boundary/)
  } finally { await rm(root, { recursive: true, force: true }); await rm(state, { recursive: true, force: true }) }
})
