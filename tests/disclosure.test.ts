import assert from 'node:assert/strict'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { createDisclosureCampaign, getDisclosureAssignment, loadDisclosureCampaign, readDisclosureExperimentArtifact, readDisclosureSource, runDisclosureCampaign, submitDisclosureReport } from '../src/disclosure.ts'

const report = (status: 'not_run' | 'built_only' | 'executed_safely' = 'not_run') => ({ summary: 'An untrusted request reaches dynamic evaluation without an enforcement boundary.', attacker: 'A remote unauthenticated caller can provide the request parameter.', entryPoint: 'The public request handler reads an attacker-controlled query parameter.', vulnerablePath: 'The handler passes the request parameter directly into dynamic evaluation.', badState: 'Application execution interprets attacker-controlled text as executable code.', impact: 'An attacker may execute application actions with the service identity.', exploitability: 'Exploitability depends on the route being deployed and reachable without an upstream guard.', counterevidence: 'The frozen source excerpt contains no local authorization or sanitization control.', limitations: 'No live target or production configuration was inspected during this report.', remediation: 'Remove dynamic evaluation and use an explicit allowlisted operation map.', reproductionStatus: status, reproductionNotes: 'No executable reproduction was run; this report is based on frozen source evidence.', sourceReferences: [{ path: 'app.ts', line: 1, explanation: 'The request-derived value reaches the dynamic evaluation call on this line.' }] })

function writerContext(config: { stateDir: string }) {
  let created = 0; const restrictions: string[][] = []
  const ctx = { agents: { async create(options: { setup?: (ctx: { tools: { restrict(filter: { allow: string[] }): void }; systemPrompt: { section(): void } }) => void }) {
    const index = ++created; let prompt = ''; options.setup?.({ tools: { restrict(filter) { restrictions.push(filter.allow) } }, systemPrompt: { section() {} } })
    return { agent: { followup(message: { content: Array<{ text?: string }> }) { prompt = message.content[0]?.text ?? '' }, async whenIdle() {
      const campaignId = /campaign_id (disclosure_[0-9a-f-]+)/.exec(prompt)?.[1]; const workerId = /worker_id (writer_[a-z0-9._-]+)/.exec(prompt)?.[1]; const token = /claim_token ([0-9a-f-]+)/.exec(prompt)?.[1]
      if (!campaignId || !workerId || !token) throw new Error('disclosure writer brief was incomplete')
      const assignment = await getDisclosureAssignment(config as never, campaignId, workerId, token); assert.equal(['eval', 'shell'].includes(assignment.vulnerability.id), true)
      await readDisclosureSource(config as never, campaignId, workerId, token, 'app.ts')
      await submitDisclosureReport(config as never, campaignId, workerId, token, report())
    }, session: { deriveMessages: () => [{ role: 'assistant', content: [{ type: 'text', text: 'report submitted' }] }] } }, async dispose() {} }
  } } }
  return { ctx, count: () => created, restrictions }
}

test('disclosure campaign assigns one restricted DSH writer per vulnerability and writes standalone reports', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-')); const state = await mkdtemp(join(tmpdir(), 'dsh-security-suite-state-')); const config = { enabled: true, maxFiles: 10, maxFileBytes: 4096, stateDir: state }
  try {
    await writeFile(join(root, 'app.ts'), 'export function h(req) { return eval(req.query.code) }\n')
    const campaign = await createDisclosureCampaign(root, config, '.', [{ id: 'eval', title: 'Request reaches dynamic evaluation', notes: 'The report notes that request input appears to flow directly into dynamic evaluation.', sourcePaths: ['app.ts'] }, { id: 'shell', title: 'Request reaches shell execution', notes: 'The report notes a separate suspected shell path in the same focused source material.', sourcePaths: ['app.ts'] }], false, 'v1.2.3')
    const fake = writerContext(config); const result = await runDisclosureCampaign(fake.ctx as never, config, campaign.id)
    assert.equal(result.lifecycle, 'completed'); assert.equal(fake.count(), 2); assert.deepEqual(fake.restrictions[0], ['security_disclosure_get_assignment', 'security_disclosure_read_source', 'security_disclosure_read_experiment_artifact', 'security_disclosure_submit_report'])
    assert.match(await readFile(join(result.reportsDirectory, 'eval.md'), 'utf8'), /Source revision: `v1\.2\.3`/)
    assert.match(await readFile(join(result.reportsDirectory, 'shell.md'), 'utf8'), /Evidence Boundary/)
  } finally { await rm(root, { recursive: true, force: true }); await rm(state, { recursive: true, force: true }) }
})

test('authorized disclosure freezes user-supplied experiment evidence without executing it', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-')); const state = await mkdtemp(join(tmpdir(), 'dsh-security-suite-state-')); const config = { enabled: true, maxFiles: 10, maxFileBytes: 4096, stateDir: state }
  try {
    await writeFile(join(root, 'app.ts'), 'export function h(req) { return eval(req.query.code) }\n')
    await writeFile(join(root, 'evidence.txt'), 'Controlled local experiment observed request text reaching the test-only evaluator.\n')
    await assert.rejects(() => createDisclosureCampaign(root, config, '.', [{ id: 'eval', title: 'Request reaches dynamic evaluation', notes: 'The report notes that request input appears to flow directly into dynamic evaluation.', sourcePaths: ['app.ts'], experimentArtifactPaths: ['evidence.txt'] }], false), /require explicit campaign experiment authorization/)
    const campaign = await createDisclosureCampaign(root, config, '.', [{ id: 'eval', title: 'Request reaches dynamic evaluation', notes: 'The report notes that request input appears to flow directly into dynamic evaluation.', sourcePaths: ['app.ts'], experimentArtifactPaths: ['evidence.txt'] }], true)
    const saved = await loadDisclosureCampaign(config, campaign.id); const writer = saved.workers[0]!
    saved.lifecycle = 'running'; writer.status = 'running'; await writeFile(join(state, 'disclosures', `${campaign.id}.json`), `${JSON.stringify(saved)}\n`)
    const assignment = await getDisclosureAssignment(config, campaign.id, writer.id, writer.token)
    assert.deepEqual(assignment.experimentArtifacts.map(item => item.path), ['evidence.txt'])
    assert.match((await readDisclosureExperimentArtifact(config, campaign.id, writer.id, writer.token, 'evidence.txt')).content, /Controlled local experiment/)
    await assert.rejects(() => submitDisclosureReport(config, campaign.id, writer.id, writer.token, report('executed_safely')), /requires a cited user-supplied experiment artifact/)
    const receipt = await submitDisclosureReport(config, campaign.id, writer.id, writer.token, { ...report('executed_safely'), reproductionNotes: 'The user-supplied frozen evidence records a controlled local experiment; the plugin did not execute it.', experimentReferences: [{ path: 'evidence.txt', explanation: 'This frozen user-supplied record documents the controlled local observation.' }] })
    assert.match(await readFile(receipt.reportPath, 'utf8'), /Frozen Experiment Evidence/)
    assert.match(await readFile(receipt.reportPath, 'utf8'), /does not generate or execute experiment artifacts/)
    await writeFile(join(root, 'evidence.txt'), 'changed\n')
    await assert.rejects(() => readDisclosureExperimentArtifact(config, campaign.id, writer.id, writer.token, 'evidence.txt'), /changed after campaign creation/)
  } finally { await rm(root, { recursive: true, force: true }); await rm(state, { recursive: true, force: true }) }
})

test('disclosure sources are immutable and unapproved campaigns reject executed reproduction claims', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-')); const state = await mkdtemp(join(tmpdir(), 'dsh-security-suite-state-')); const config = { enabled: true, maxFiles: 10, maxFileBytes: 4096, stateDir: state }
  try {
    await writeFile(join(root, 'app.ts'), 'export function h(req) { return eval(req.query.code) }\n')
    const campaign = await createDisclosureCampaign(root, config, '.', [{ id: 'eval', title: 'Request reaches dynamic evaluation', notes: 'The report notes that request input appears to flow directly into dynamic evaluation.', sourcePaths: ['app.ts'] }], false)
    const saved = await loadDisclosureCampaign(config, campaign.id); const worker = saved.workers[0]!
    saved.lifecycle = 'running'; worker.status = 'running'; await writeFile(join(state, 'disclosures', `${campaign.id}.json`), `${JSON.stringify(saved)}\n`)
    await assert.rejects(() => submitDisclosureReport(config, campaign.id, worker.id, worker.token, report('executed_safely')), /without campaign experiment authorization/)
    await writeFile(join(root, 'app.ts'), 'export const changed = true\n')
    await assert.rejects(() => readDisclosureSource(config, campaign.id, worker.id, worker.token, 'app.ts'), /changed after campaign creation/)
  } finally { await rm(root, { recursive: true, force: true }); await rm(state, { recursive: true, force: true }) }
})
