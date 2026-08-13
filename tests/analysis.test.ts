import assert from 'node:assert/strict'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { generateHardeningPortfolio, importFindings, triageImportedFinding } from '../src/analysis.ts'
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
    assert.equal(triage.evidence.length, 1)
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
