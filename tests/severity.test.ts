import assert from 'node:assert/strict'
import test from 'node:test'
import { calibrateSeverity, confidenceFromEvidence, hardSuppression, matrixSeverity, meetsCriticalCriteria, severityRank, weightedLikelihood } from '../src/llm/severity.ts'

test('severity matrix matches severity-policy.md', () => {
  assert.equal(matrixSeverity('high', 'high'), 'high')
  assert.equal(matrixSeverity('high', 'medium'), 'medium')
  assert.equal(matrixSeverity('high', 'low'), 'low')
  assert.equal(matrixSeverity('high', 'unknown'), 'medium')
  assert.equal(matrixSeverity('medium', 'high'), 'medium')
  assert.equal(matrixSeverity('medium', 'medium'), 'low')
  assert.equal(matrixSeverity('medium', 'low'), 'low')
  assert.equal(matrixSeverity('medium', 'unknown'), 'low')
  assert.equal(matrixSeverity('low', 'high'), 'low')
  assert.equal(matrixSeverity('ignore', 'high'), 'ignore')
  assert.equal(matrixSeverity('unknown', 'unknown'), 'low')
})

test('network scope weights likelihood', () => {
  assert.equal(weightedLikelihood('medium', 'remote'), 'high')
  assert.equal(weightedLikelihood('high', 'local_network'), 'medium')
  assert.equal(weightedLikelihood('high', 'localhost'), 'low')
  assert.equal(weightedLikelihood('high', 'none'), 'high')
  assert.equal(weightedLikelihood('unknown', 'remote'), 'unknown')
})

test('critical escalation requires the codex critical criteria', () => {
  const cal = calibrateSeverity({ impact: 'high', likelihood: 'high', scope: 'remote', criteria: { codeExecution: true } })
  assert.equal(cal.severity, 'critical')
  assert.equal(cal.priority, 'P0')
  const noCriteria = calibrateSeverity({ impact: 'high', likelihood: 'high', scope: 'remote' })
  assert.equal(noCriteria.severity, 'high')
  assert.equal(noCriteria.priority, 'P1')
})

test('hard suppressions produce ignore', () => {
  assert.equal(hardSuppression({ selfOnly: true, privilegedOnly: false, operatorOnly: false, developerOnly: false, physicalAccessOnly: false, unreachable: false, unrealisticPreconditions: false }), true)
  const cal = calibrateSeverity({ impact: 'high', likelihood: 'high', suppressions: { selfOnly: true } })
  assert.equal(cal.severity, 'ignore')
  assert.equal(cal.decision, 'ignore')
  assert.equal(cal.priority, undefined)
})

test('priority mapping is P0-P3 by severity', () => {
  assert.equal(calibrateSeverity({ impact: 'high', likelihood: 'high' }).priority, 'P1')
  assert.equal(calibrateSeverity({ impact: 'high', likelihood: 'medium' }).priority, 'P2')
  assert.equal(calibrateSeverity({ impact: 'high', likelihood: 'low' }).priority, 'P3')
  assert.equal(calibrateSeverity({ impact: 'low', likelihood: 'high' }).priority, 'P3')
  assert.equal(severityRank('critical'), 5)
  assert.equal(severityRank('ignore'), 0)
})

test('confidence calibration follows the evidence ladder', () => {
  assert.equal(confidenceFromEvidence({ reproducedCrash: true, sanitizerReproduction: false, debuggerTrace: false, sourceTrace: false, counterevidenceDefeats: false }), 'high')
  assert.equal(confidenceFromEvidence({ reproducedCrash: false, sanitizerReproduction: false, debuggerTrace: true, sourceTrace: false, counterevidenceDefeats: false }), 'high')
  assert.equal(confidenceFromEvidence({ reproducedCrash: false, sanitizerReproduction: false, debuggerTrace: false, sourceTrace: true, counterevidenceDefeats: false }), 'medium')
  assert.equal(confidenceFromEvidence({ reproducedCrash: false, sanitizerReproduction: false, debuggerTrace: false, sourceTrace: false, counterevidenceDefeats: false }), 'low')
  assert.equal(confidenceFromEvidence({ reproducedCrash: true, sanitizerReproduction: false, debuggerTrace: false, sourceTrace: false, counterevidenceDefeats: true }), 'low')
})

test('meetsCriticalCriteria is a disjunction of the critical classes', () => {
  assert.equal(meetsCriticalCriteria({ codeExecution: false, accountTakeover: true, authBypass: false, privilegeGain: false, sensitiveDataExposure: false, sandboxEscape: false, memorySafetyExploitation: false }), true)
  assert.equal(meetsCriticalCriteria({ codeExecution: false, accountTakeover: false, authBypass: false, privilegeGain: false, sensitiveDataExposure: false, sandboxEscape: false, memorySafetyExploitation: false }), false)
})
