import assert from 'node:assert/strict'
import test from 'node:test'
import { buildValidationRubric, confidenceFromScore, confidenceScore, proofTupleFor, PROOF_TUPLES, suppressionAllowed } from '../src/llm/validation.ts'

test('proof tuple routing covers the core vulnerability classes', () => {
  assert.equal(proofTupleFor('sql-injection.query-builder', 'CWE-89').id, 'query-parser-injection')
  assert.equal(proofTupleFor('path-traversal.archive-extraction', 'CWE-22').id, 'resource-path-control')
  assert.equal(proofTupleFor('ssrf-request-sink', 'CWE-918').id, 'ssrf')
  assert.equal(proofTupleFor('dynamic-code.eval', 'CWE-95').id, 'deserialization-code-exec')
  assert.equal(proofTupleFor('unsafe-deserialization', 'CWE-502').id, 'deserializer-codec')
  assert.equal(proofTupleFor('jwt-verification-disabled', 'CWE-347').id, 'auth-token-protocol')
  assert.equal(proofTupleFor('xml-external-entity-risk', 'CWE-611').id, 'xml-parser-hardening')
  assert.equal(proofTupleFor('authorization-bypass.object-update', 'CWE-639').id, 'authz-tenant-object')
  assert.equal(proofTupleFor('embedded-credential', 'CWE-798').id, 'secret-data-exposure')
  assert.equal(proofTupleFor('shell.command.construction', 'CWE-78').id, 'injection-path')
  assert.equal(proofTupleFor('unknown-rule', '').id, 'generic')
})

test('every proof tuple has all four fields', () => {
  for (const [id, tuple] of Object.entries(PROOF_TUPLES)) {
    assert.ok(tuple.attackerInput.length > 0, `${id} attackerInput`)
    assert.ok(tuple.control.length > 0, `${id} control`)
    assert.ok(tuple.sink.length > 0, `${id} sink`)
    assert.ok(tuple.impact.length > 0, `${id} impact`)
  }
})

test('the validation rubric is bounded to five criteria and includes the proof tuple', () => {
  const rubric = buildValidationRubric({ ruleId: 'ssrf-request-sink', cwe: 'CWE-918', hasReachableInterface: true, sourceLocations: 2 })
  assert.ok(rubric.length <= 5)
  assert.ok(rubric.some(criterion => criterion.kind === 'realistic-interface'))
  assert.ok(rubric[0]?.criterion.includes('attacker-controlled source'))
  assert.ok(rubric[1]?.criterion.includes('closest control'))
  assert.equal(buildValidationRubric({ ruleId: 'x' }).length, 4)
})

test('confidence follows the numerical ladder', () => {
  assert.equal(confidenceScore({ reproducedCrash: true, sanitizerReproduction: false, debuggerTrace: false, focusedTest: false, realisticInterface: false, sourceTrace: false, counterevidenceDefeats: false }), 1)
  assert.equal(confidenceScore({ reproducedCrash: false, sanitizerReproduction: true, debuggerTrace: false, focusedTest: false, realisticInterface: false, sourceTrace: false, counterevidenceDefeats: false }), 0.9)
  assert.equal(confidenceScore({ reproducedCrash: false, sanitizerReproduction: false, debuggerTrace: true, focusedTest: false, realisticInterface: false, sourceTrace: false, counterevidenceDefeats: false }), 0.8)
  assert.equal(confidenceScore({ reproducedCrash: false, sanitizerReproduction: false, debuggerTrace: false, focusedTest: false, realisticInterface: false, sourceTrace: true, counterevidenceDefeats: false }), 0.3)
  assert.equal(confidenceScore({ reproducedCrash: false, sanitizerReproduction: false, debuggerTrace: false, focusedTest: false, realisticInterface: false, sourceTrace: false, counterevidenceDefeats: true }), 0)
  assert.equal(confidenceFromScore(1), 'high')
  assert.equal(confidenceFromScore(0.8), 'high')
  assert.equal(confidenceFromScore(0.6), 'medium')
  assert.equal(confidenceFromScore(0.3), 'low')
})

test('instance-preserving suppression rules', () => {
  assert.equal(suppressionAllowed({ seededRow: true, siblingInstance: false, missingExternalFact: false, adjacencyPassRan: false }).allowed, false)
  assert.equal(suppressionAllowed({ seededRow: true, siblingInstance: false, exactCounterevidenceControl: 'exact guard', missingExternalFact: false, adjacencyPassRan: false }).allowed, true)
  assert.equal(suppressionAllowed({ seededRow: false, siblingInstance: true, missingExternalFact: false, adjacencyPassRan: false }).allowed, false)
  assert.equal(suppressionAllowed({ seededRow: false, siblingInstance: false, missingExternalFact: true, adjacencyPassRan: false }).allowed, false)
  assert.equal(suppressionAllowed({ seededRow: false, siblingInstance: false, missingExternalFact: true, adjacencyPassRan: true }).allowed, true)
})
