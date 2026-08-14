/**
 * Remediation state machine, adapted from openai/codex-security
 * `workbench_db.finding_remediation_attempts` (Apache-2.0): the eight-state
 * transition table, optimistic version locking, and claim-lease semantics.
 * Pure functions; no I/O.
 */

export type RemediationState = 'idle' | 'requested' | 'generated' | 'applied' | 'verifying' | 'verified' | 'failed' | 'superseded'
export type RemediationPendingAction = 'generate' | 'apply' | 'verify'

/** State transition table (codex-security require_remediation_transition). */
export const REMEDIATION_TRANSITIONS: Record<RemediationState, ReadonlySet<RemediationState>> = {
  idle: new Set(['idle', 'requested', 'failed']),
  requested: new Set(['requested', 'generated', 'failed']),
  generated: new Set(['generated', 'applied', 'failed']),
  applied: new Set(['applied', 'verifying', 'failed']),
  verifying: new Set(['verifying', 'verified', 'failed']),
  verified: new Set(['verifying', 'verified']),
  failed: new Set(['idle', 'requested', 'generated', 'applied', 'verifying', 'verified', 'failed', 'superseded']),
  superseded: new Set(['superseded']),
}

/** Allowed pending actions per state (codex-security pending_action). */
export const REMEDIATION_PENDING_ACTIONS: Record<RemediationState, ReadonlySet<RemediationPendingAction>> = {
  idle: new Set(['generate']),
  requested: new Set(['generate']),
  generated: new Set(['apply']),
  applied: new Set(['verify']),
  verifying: new Set(['verify']),
  verified: new Set([]),
  failed: new Set(['generate', 'apply', 'verify']),
  superseded: new Set([]),
}

/** Versioned remediation attempt record (codex-security finding_remediation_attempts). */
export interface RemediationAttemptState {
  state: RemediationState
  /** Optimistic-lock version, >= 1, incremented on every transition. */
  version: number
  pendingAction?: RemediationPendingAction
  error?: string
  verificationSummary?: string
  updatedAt: string
}

export function initialRemediationState(now = new Date().toISOString()): RemediationAttemptState {
  return { state: 'idle', version: 1, updatedAt: now }
}

/** Fail closed when the transition is not in the codex table. */
export function requireRemediationTransition(from: RemediationState, to: RemediationState): void {
  if (!REMEDIATION_TRANSITIONS[from].has(to)) throw new Error(`Remediation state transition ${from} -> ${to} is not allowed by the codex-security state machine.`)
}

/** Optimistic-lock transition: expected version must match, then version increments. */
export function transitionRemediation(current: RemediationAttemptState, to: RemediationState, options: { expectedVersion: number; pendingAction?: RemediationPendingAction; error?: string; verificationSummary?: string; now?: string }): RemediationAttemptState {
  if (current.version !== options.expectedVersion) throw new Error(`Remediation optimistic lock failed: expected version ${options.expectedVersion}, current ${current.version}.`)
  requireRemediationTransition(current.state, to)
  return {
    state: to,
    version: current.version + 1,
    ...(options.pendingAction ? { pendingAction: options.pendingAction } : {}),
    ...(options.error ? { error: options.error } : {}),
    ...(options.verificationSummary ? { verificationSummary: options.verificationSummary } : {}),
    updatedAt: options.now ?? new Date().toISOString(),
  }
}

/** Claim lease semantics (codex-security CLAIM_LEASE_SECONDS=120 / DELIVERED_ACTION_LEASE_SECONDS=900). */
export const CLAIM_LEASE_SECONDS = 120
export const DELIVERED_ACTION_LEASE_SECONDS = 900

export function claimExpired(claimedAt: string, now = Date.now(), leaseSeconds = CLAIM_LEASE_SECONDS): boolean {
  return now - Date.parse(claimedAt) > leaseSeconds * 1000
}
