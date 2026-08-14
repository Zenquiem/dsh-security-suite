import assert from 'node:assert/strict'
import test from 'node:test'
import { claimExpired, initialRemediationState, requireRemediationTransition, transitionRemediation } from '../src/remediation-state.ts'

test('the codex remediation transition table is enforced', () => {
  requireRemediationTransition('requested', 'generated')
  requireRemediationTransition('generated', 'applied')
  requireRemediationTransition('applied', 'verifying')
  requireRemediationTransition('verifying', 'verified')
  requireRemediationTransition('verified', 'verifying')
  requireRemediationTransition('failed', 'generated')
  assert.throws(() => requireRemediationTransition('requested', 'verified'), /not allowed/)
  assert.throws(() => requireRemediationTransition('verified', 'applied'), /not allowed/)
})

test('optimistic version locking increments on transition and rejects stale writes', () => {
  const initial = initialRemediationState('2024-01-01T00:00:00.000Z')
  assert.equal(initial.state, 'idle')
  assert.equal(initial.version, 1)
  const requested = transitionRemediation(initial, 'requested', { expectedVersion: 1 })
  assert.equal(requested.state, 'requested')
  assert.equal(requested.version, 2)
  assert.throws(() => transitionRemediation(requested, 'generated', { expectedVersion: 1 }), /optimistic lock failed/)
  const generated = transitionRemediation(requested, 'generated', { expectedVersion: 2, pendingAction: 'apply' })
  assert.equal(generated.pendingAction, 'apply')
  assert.equal(generated.version, 3)
})

test('claim leases expire after the codex windows', () => {
  const now = Date.parse('2024-01-01T00:00:00.000Z')
  assert.equal(claimExpired('2023-12-31T23:58:01.000Z', now, 120), false)
  assert.equal(claimExpired('2023-12-31T23:58:00.000Z', now, 120), false)
  assert.equal(claimExpired('2023-12-31T23:57:59.000Z', now, 120), true)
  assert.equal(claimExpired('2023-12-31T23:45:01.000Z', now, 900), false)
  assert.equal(claimExpired('2023-12-31T23:44:59.000Z', now, 900), true)
})
