import type { Confidence } from '../contracts.js'
import { calibrateSeverity, type AttackPathDecision, type ImpactLevel, type LikelihoodLevel, type NetworkScope } from './severity.js'

/**
 * Attack-path analysis engine, adapted from openai/codex-security
 * `skills/attack-path-analysis/references/attack-path-facts.md` and
 * `references/severity-policy.md` (Apache-2.0): the structured facts model,
 * the mechanical final policy pass, and the counterevidence checklist.
 * Pure functions; no I/O.
 */

export type Vector = NetworkScope
export type PreconditionAchievability = 'plausible' | 'unlikely' | 'unachievable' | 'unknown'
export type AttackerInputControl = 'yes' | 'plausible' | 'no' | 'unknown'
export type AuthScope = 'public' | 'internal-only' | 'admin-only' | 'unknown'
export type ImpactSurface = 'build' | 'runtime' | 'data' | 'identity' | 'network' | 'other'
export type TargetReach = 'single service' | 'base image' | 'fleet' | 'unknown'

/** Structured attack-path facts (attack-path-facts.md, adapted). */
export interface AttackPathFacts {
  assumptions: string[]
  context: { selfOnly: boolean; boundaryCrossed: boolean; evidence: string }
  inScope: { inScope: boolean; reasoning: string }
  exposure: { public: boolean; ports?: string[]; ingress?: string; evidence: string }
  identity: { serviceAccount?: string; effectivePrivileges: string }
  crossBoundaryBehavior: { verified: boolean; evidence: string }
  vector: Vector
  preconditions: { what: string[]; achievability: PreconditionAchievability; evidence: string }
  attackerInputControl: AttackerInputControl
  category: string
  mitigationsAlreadyPresent: string[]
  authScope: AuthScope
  impactSurface: ImpactSurface[]
  targetReach: TargetReach
  secretsReferences?: string
  counterevidence: string
  blindspots: string[]
  controls: string[]
  confidence: Confidence
  numberedAttackerSteps: string[]
  impact: ImpactLevel
  likelihood: LikelihoodLevel
  impactRationale: string
  likelihoodRationale: string
  finalPolicyDecision: AttackPathDecision
}

/** The counterevidence checklist (attack-path-analysis skill, adapted). */
export const COUNTEREVIDENCE_CHECKLIST: Array<{ id: string; question: string }> = [
  { id: 'in-scope-status', question: 'How does repository evidence suggest the finding is out of scope per the threat model, and why is that not dispositive?' },
  { id: 'vector', question: 'What conflicting evidence exists about the attack vector, and does it defeat attacker reachability?' },
  { id: 'auth-scope', question: 'What evidence suggests the path is internal-only, admin-only, or not attacker-reachable?' },
  { id: 'exposure', question: 'What evidence contradicts the claimed exposure, and is the surface actually public?' },
  { id: 'cross-boundary', question: 'Is the boundary crossing actually verified, or does evidence show it does not cross a meaningful boundary?' },
  { id: 'preconditions', question: 'What precondition is unrealistic or unachievable, and what evidence supports that?' },
  { id: 'impact-surface', question: 'What evidence limits the impact surface or makes the impact not meaningfully reportable?' },
]

/**
 * Mechanical final policy pass (severity-policy.md, adapted): hard
 * suppressions first, then network-scope likelihood weighting, then the
 * impact x likelihood matrix with critical escalation, then reportability.
 */
export function mechanicalPolicyPass(input: { impact: ImpactLevel; likelihood: LikelihoodLevel; vector: Vector; authScope: AuthScope; preconditions: PreconditionAchievability; attackerInputControl: AttackerInputControl; selfOnly: boolean; privilegedOnly: boolean; operatorOnly: boolean; developerOnly: boolean; physicalAccessOnly: boolean; unreachable: boolean; unrealisticPreconditions: boolean; criticalCriteria?: Parameters<typeof calibrateSeverity>[0]['criteria'] }): { severity: 'critical' | 'high' | 'medium' | 'low' | 'ignore'; decision: AttackPathDecision; priority?: 'P0' | 'P1' | 'P2' | 'P3'; rationale: string } {
  const reasons: string[] = []
  // Hard suppressions from reportability facts.
  if (input.selfOnly) reasons.push('self-only impact is hard-suppressed to ignore')
  if (input.unreachable || input.attackerInputControl === 'no') reasons.push('no attacker-controlled input or unreachable path is hard-suppressed to ignore')
  if (input.unrealisticPreconditions || input.preconditions === 'unachievable') reasons.push('unachievable preconditions are hard-suppressed to ignore')
  if (input.privilegedOnly || input.operatorOnly || input.developerOnly || input.physicalAccessOnly) reasons.push('privileged/operator/developer/physical-access-only preconditions are hard-suppressed to ignore')
  if (reasons.length && !input.selfOnly && !input.unreachable && input.attackerInputControl !== 'no' && !input.unrealisticPreconditions && input.preconditions !== 'unachievable' && !input.privilegedOnly && !input.operatorOnly && !input.developerOnly && !input.physicalAccessOnly) reasons.pop()
  if (reasons.length) return { severity: 'ignore', decision: 'ignore', rationale: reasons.join('; ') }
  const calibrated = calibrateSeverity({ impact: input.impact, likelihood: input.likelihood, scope: input.vector, criteria: input.criticalCriteria })
  if (calibrated.severity === 'ignore') return { severity: 'ignore', decision: 'ignore', rationale: calibrated.rationale }
  // Internal-only or admin-only exposure lowers reportability without hard
  // suppression when repository evidence still shows a real product boundary.
  const scopeNote = input.authScope === 'admin-only' ? ' (authScope admin-only lowers likelihood)' : input.authScope === 'internal-only' ? ' (authScope internal-only lowers likelihood)' : ''
  return { severity: calibrated.severity as 'critical' | 'high' | 'medium' | 'low', decision: 'reportable', priority: calibrated.priority, rationale: `${calibrated.rationale}${scopeNote}` }
}

/** Render the facts as a markdown "### Attack Path Facts" section (attack-path-facts.md). */
export function renderAttackPathFacts(facts: AttackPathFacts): string {
  const lines = ['### Attack Path Facts', '']
  const bullets: string[] = []
  if (facts.assumptions.length) bullets.push(`- **Assumptions:** ${facts.assumptions.join('; ')}`)
  bullets.push(`- **Context:** ${facts.context.selfOnly ? 'self-only' : `crosses ${facts.context.boundaryCrossed ? 'a meaningful' : 'a (unverified)'} boundary`}; evidence: ${facts.context.evidence}`)
  bullets.push(`- **In-scope per threat model:** ${facts.inScope.inScope ? 'yes' : 'no'} (${facts.inScope.reasoning})`)
  bullets.push(`- **Exposure:** ${facts.exposure.public ? 'public' : 'not public'}${facts.exposure.ports?.length ? `, ports ${facts.exposure.ports.join(', ')}` : ''}${facts.exposure.ingress ? `, ingress ${facts.exposure.ingress}` : ''}; evidence: ${facts.exposure.evidence}`)
  bullets.push(`- **Identity:** ${facts.identity.serviceAccount ?? 'none identified'}; effective privileges: ${facts.identity.effectivePrivileges}`)
  bullets.push(`- **Cross-boundary behavior:** ${facts.crossBoundaryBehavior.verified ? 'verified' : 'not verified'}; evidence: ${facts.crossBoundaryBehavior.evidence}`)
  bullets.push(`- **Vector:** ${facts.vector}`)
  bullets.push(`- **Preconditions:** ${facts.preconditions.what.join('; ') || 'none'}; achievability: ${facts.preconditions.achievability}`)
  bullets.push(`- **Attacker input control:** ${facts.attackerInputControl}`)
  bullets.push(`- **Category:** ${facts.category}`)
  if (facts.mitigationsAlreadyPresent.length) bullets.push(`- **Mitigations already present:** ${facts.mitigationsAlreadyPresent.join('; ')}`)
  bullets.push(`- **Auth scope:** ${facts.authScope}`)
  bullets.push(`- **Impact surface:** ${facts.impactSurface.join(', ') || 'unknown'}`)
  bullets.push(`- **Target reach:** ${facts.targetReach}`)
  if (facts.secretsReferences) bullets.push(`- **Secrets references:** ${facts.secretsReferences}`)
  if (facts.counterevidence) bullets.push(`- **Counterevidence:** ${facts.counterevidence}`)
  if (facts.blindspots.length) bullets.push(`- **Blindspots:** ${facts.blindspots.join('; ')}`)
  if (facts.controls.length) bullets.push(`- **Controls:** ${facts.controls.join('; ')}`)
  bullets.push(`- **Confidence:** ${facts.confidence}`)
  lines.push(...bullets, '')
  if (facts.numberedAttackerSteps.length) {
    lines.push('**Factual attack path (numbered attacker steps):**', '', ...facts.numberedAttackerSteps.map((step, index) => `${index + 1}. ${step}`), '')
  }
  lines.push(`- **Impact:** ${facts.impact} — ${facts.impactRationale}`, `- **Likelihood:** ${facts.likelihood} — ${facts.likelihoodRationale}`, `- **Final policy decision:** ${facts.finalPolicyDecision}`, '')
  return lines.join('\n')
}
