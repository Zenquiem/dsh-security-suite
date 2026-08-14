import assert from 'node:assert/strict'
import test from 'node:test'
import { draftingPrompt, reportAcceptanceChecklist, validateWriteupSections, WRITEUP_SECTIONS } from '../src/llm/writeup.ts'

test('the seven required headings are in report-format order', () => {
  assert.deepEqual(WRITEUP_SECTIONS.map(section => section.heading), [
    '## Executive Summary', '## Background', '## Vulnerability Details', '## Exploitability Analysis',
    '## Proof of Concept', '## Remediation', '## Summary',
  ])
})

test('validateWriteupSections accepts a complete ordered report and rejects missing or reordered sections', () => {
  const complete = WRITEUP_SECTIONS.map(section => `${section.heading}\n\ncontent\n`).join('\n')
  assert.deepEqual(validateWriteupSections(complete), { valid: true, errors: [] })
  const missing = validateWriteupSections('## Background\n\n## Summary\n')
  assert.equal(missing.valid, false)
  assert.ok(missing.errors.some(error => error.includes('Executive Summary')))
  const reordered = validateWriteupSections(['## Background', '## Executive Summary', '## Vulnerability Details', '## Exploitability Analysis', '## Proof of Concept', '## Remediation', '## Summary'].map(heading => `${heading}\n\nx\n`).join('\n'))
  assert.equal(reordered.valid, false, 'background before executive summary must fail order validation')
})

test('the drafting prompt is self-contained and carries the required disciplines', () => {
  const prompt = draftingPrompt({ slug: 'vuln-1', rawFindingPaths: ['notes.md'], sourceRoot: '/repo', revision: 'abc123', pocPaths: [], reportDirectory: '/out' })
  assert.match(prompt, /Write one self-contained vulnerability disclosure report for vuln-1/)
  assert.match(prompt, /seven required report headings/)
  assert.match(prompt, /author-machine-specific absolute path/)
  assert.match(prompt, /attacker-controlled entry point/)
})

test('the acceptance checklist covers the report-format gates', () => {
  const checklist = reportAcceptanceChecklist()
  assert.ok(checklist.length >= 10)
  assert.ok(checklist.some(item => item.id === 'provenance'))
  assert.ok(checklist.some(item => item.id === 'calibration'))
})
