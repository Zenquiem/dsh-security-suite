import assert from 'node:assert/strict'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { createTracking, previewTracking } from '../src/tracking.ts'
import { runScan } from '../src/scanner.ts'
import { finalizeAndSaveScan } from '../src/state.ts'

test('tracking preview is local without a token and creation rejects missing approval', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-suite-'))
  const state = await mkdtemp(join(tmpdir(), 'dsh-security-suite-state-'))
  const config = { enabled: true, maxFiles: 10, maxFileBytes: 4096, stateDir: state }
  try {
    await writeFile(join(root, 'client.ts'), 'request({ rejectUnauthorized: false })\n')
    const scan = await runScan(root, config, 'standard', '', false, state)
    const finding = scan.findings[0]
    finding.disposition = 'reportable'
    finding.ledger.push({ at: new Date().toISOString(), phase: 'validation', disposition: 'reportable', summary: 'Static evidence.' })
    finding.ledger.push({ at: new Date().toISOString(), phase: 'attack_path', disposition: 'reportable', summary: 'Attacker path.' })
    scan.lifecycle = 'completed'; scan.completedAt = new Date().toISOString()
    await finalizeAndSaveScan(state, scan)
    const preview = await previewTracking(config, { provider: 'github', scanId: scan.id, findingId: finding.id })
    assert.equal(preview.requiresApproval, true)
    assert.equal(preview.duplicates.length, 0)
    await assert.rejects(() => createTracking(config, { provider: 'github', scanId: scan.id, findingId: finding.id, token: 'not-used', repository: 'owner/repo', approved: false }), /approved/)
  } finally { await rm(root, { recursive: true, force: true }); await rm(state, { recursive: true, force: true }) }
})
