import assert from 'node:assert/strict'
import test from 'node:test'
import { COUNTEREVIDENCE_CHECKLIST, mechanicalPolicyPass, renderAttackPathFacts, type AttackPathFacts } from '../src/llm/attack-path.ts'

test('the mechanical policy pass hard-suppresses privileged-only and self-only paths', () => {
  const suppressed = mechanicalPolicyPass({ impact: 'high', likelihood: 'high', vector: 'remote', authScope: 'public', preconditions: 'plausible', attackerInputControl: 'yes', selfOnly: true, privilegedOnly: false, operatorOnly: false, developerOnly: false, physicalAccessOnly: false, unreachable: false, unrealisticPreconditions: false })
  assert.equal(suppressed.decision, 'ignore')
  const privileged = mechanicalPolicyPass({ impact: 'high', likelihood: 'high', vector: 'remote', authScope: 'public', preconditions: 'plausible', attackerInputControl: 'yes', selfOnly: false, privilegedOnly: true, operatorOnly: false, developerOnly: false, physicalAccessOnly: false, unreachable: false, unrealisticPreconditions: false })
  assert.equal(privileged.decision, 'ignore')
})

test('the mechanical policy pass weights remote exposure to high likelihood', () => {
  const result = mechanicalPolicyPass({ impact: 'high', likelihood: 'medium', vector: 'remote', authScope: 'public', preconditions: 'plausible', attackerInputControl: 'yes', selfOnly: false, privilegedOnly: false, operatorOnly: false, developerOnly: false, physicalAccessOnly: false, unreachable: false, unrealisticPreconditions: false })
  assert.equal(result.severity, 'high')
  assert.equal(result.priority, 'P1')
})

test('the mechanical policy pass escalates to critical only with critical criteria', () => {
  const critical = mechanicalPolicyPass({ impact: 'high', likelihood: 'high', vector: 'remote', authScope: 'public', preconditions: 'plausible', attackerInputControl: 'yes', selfOnly: false, privilegedOnly: false, operatorOnly: false, developerOnly: false, physicalAccessOnly: false, unreachable: false, unrealisticPreconditions: false, criticalCriteria: { codeExecution: true } })
  assert.equal(critical.severity, 'critical')
  assert.equal(critical.priority, 'P0')
  const noCriteria = mechanicalPolicyPass({ impact: 'high', likelihood: 'high', vector: 'remote', authScope: 'public', preconditions: 'plausible', attackerInputControl: 'yes', selfOnly: false, privilegedOnly: false, operatorOnly: false, developerOnly: false, physicalAccessOnly: false, unreachable: false, unrealisticPreconditions: false })
  assert.equal(noCriteria.severity, 'high')
})

test('no attacker-controlled input is hard-suppressed', () => {
  const result = mechanicalPolicyPass({ impact: 'high', likelihood: 'high', vector: 'remote', authScope: 'public', preconditions: 'plausible', attackerInputControl: 'no', selfOnly: false, privilegedOnly: false, operatorOnly: false, developerOnly: false, physicalAccessOnly: false, unreachable: false, unrealisticPreconditions: false })
  assert.equal(result.decision, 'ignore')
})

test('the counterevidence checklist has the seven dimensions', () => {
  assert.equal(COUNTEREVIDENCE_CHECKLIST.length, 7)
  assert.deepEqual(COUNTEREVIDENCE_CHECKLIST.map(item => item.id), ['in-scope-status', 'vector', 'auth-scope', 'exposure', 'cross-boundary', 'preconditions', 'impact-surface'])
})

test('renderAttackPathFacts produces a markdown facts section', () => {
  const facts: AttackPathFacts = {
    assumptions: ['Deployment is reachable from the internet.'],
    context: { selfOnly: false, boundaryCrossed: true, evidence: 'Request handler crosses into a privileged service.' },
    inScope: { inScope: true, reasoning: 'Component is part of the product surface.' },
    exposure: { public: true, ports: ['443'], ingress: 'load balancer', evidence: 'manifest exposes port 443.' },
    identity: { effectivePrivileges: 'service account with read access' },
    crossBoundaryBehavior: { verified: true, evidence: 'source shows cross-account call.' },
    vector: 'remote', preconditions: { what: ['valid session'], achievability: 'plausible', evidence: 'auth is weak' },
    attackerInputControl: 'yes', category: 'SSRF', mitigationsAlreadyPresent: [], authScope: 'public',
    impactSurface: ['network', 'data'], targetReach: 'single service', counterevidence: 'none', blindspots: [], controls: [],
    confidence: 'medium', numberedAttackerSteps: ['Attacker sends crafted URL.', 'Handler forwards to internal client.'],
    impact: 'high', likelihood: 'medium', impactRationale: 'internal service access', likelihoodRationale: 'public surface', finalPolicyDecision: 'reportable',
  }
  const rendered = renderAttackPathFacts(facts)
  assert.match(rendered, /### Attack Path Facts/)
  assert.match(rendered, /\*\*Vector:\*\* remote/)
  assert.match(rendered, /\*\*Final policy decision:\*\* reportable/)
  assert.match(rendered, /1\. Attacker sends crafted URL/)
})
