import type { Confidence, Severity } from '../contracts.js'

/**
 * Deterministic severity calibration engine, adapted from
 * openai/codex-security `skills/attack-path-analysis/references/severity-policy.md`
 * (Apache-2.0): impact x likelihood matrix, network-scope likelihood weighting,
 * hard suppressions, and P0-P3 priority mapping. Pure functions; no I/O.
 */

export type ImpactLevel = 'high' | 'medium' | 'low' | 'ignore' | 'unknown'
export type LikelihoodLevel = 'high' | 'medium' | 'low' | 'ignore' | 'unknown'
export type NetworkScope = 'remote' | 'local_network' | 'localhost' | 'none' | 'unknown'
export type AttackPathDecision = 'reportable' | 'ignore' | 'deferred'

/** Impact x likelihood severity matrix (severity-policy.md, adapted). */
const SEVERITY_MATRIX: Record<ImpactLevel, Record<LikelihoodLevel, Severity | 'ignore'>> = {
  high: { high: 'high', medium: 'medium', low: 'low', ignore: 'ignore', unknown: 'medium' },
  medium: { high: 'medium', medium: 'low', low: 'low', ignore: 'ignore', unknown: 'low' },
  low: { high: 'low', medium: 'low', low: 'low', ignore: 'ignore', unknown: 'low' },
  ignore: { high: 'ignore', medium: 'ignore', low: 'ignore', ignore: 'ignore', unknown: 'ignore' },
  unknown: { high: 'medium', medium: 'low', low: 'low', ignore: 'ignore', unknown: 'low' },
}

/**
 * Network-scope likelihood weighting (severity-policy.md): remote exposure is
 * usually high likelihood, local_network usually medium, localhost usually low,
 * 'none' does not raise likelihood.
 */
export function weightedLikelihood(likelihood: LikelihoodLevel, scope: NetworkScope): LikelihoodLevel {
  if (likelihood === 'ignore' || likelihood === 'unknown') return likelihood
  if (likelihood === 'high' || likelihood === 'medium' || likelihood === 'low') {
    if (scope === 'remote') return 'high'
    if (scope === 'local_network') return 'medium'
    if (scope === 'localhost') return 'low'
  }
  return likelihood
}

/** Matrix result before the critical-escalation check. */
export function matrixSeverity(impact: ImpactLevel, likelihood: LikelihoodLevel): Severity | 'ignore' {
  return SEVERITY_MATRIX[impact][likelihood]
}

/**
 * Critical escalation: high impact + high likelihood reaches critical only when
 * the codex-security critical criteria are met (account takeover, auth bypass,
 * meaningful privilege gain, significant sensitive-data disclosure, trusted RCE,
 * trivial memory-safety exploitation, sandbox escape, and similar).
 */
export interface CriticalCriteria {
  codeExecution: boolean
  accountTakeover: boolean
  authBypass: boolean
  privilegeGain: boolean
  sensitiveDataExposure: boolean
  sandboxEscape: boolean
  memorySafetyExploitation: boolean
}

export function meetsCriticalCriteria(criteria: CriticalCriteria): boolean {
  return criteria.codeExecution || criteria.accountTakeover || criteria.authBypass || criteria.privilegeGain || criteria.sensitiveDataExposure || criteria.sandboxEscape || criteria.memorySafetyExploitation
}

/** Hard suppressions before reportability (severity-policy.md). */
export interface SuppressionFacts {
  selfOnly: boolean
  privilegedOnly: boolean
  operatorOnly: boolean
  developerOnly: boolean
  physicalAccessOnly: boolean
  unreachable: boolean
  unrealisticPreconditions: boolean
}

export function hardSuppression(facts: SuppressionFacts): boolean {
  return facts.selfOnly || facts.unreachable || facts.unrealisticPreconditions || facts.privilegedOnly || facts.operatorOnly || facts.developerOnly || facts.physicalAccessOnly
}

/**
 * Final severity calibration: matrix -> critical escalation -> hard
 * suppression (returns 'ignore') -> P0-P3 mapping.
 */
export function calibrateSeverity(input: { impact: ImpactLevel; likelihood: LikelihoodLevel; scope?: NetworkScope; criteria?: Partial<CriticalCriteria>; suppressions?: Partial<SuppressionFacts> }): { severity: Severity | 'ignore'; decision: AttackPathDecision; priority?: 'P0' | 'P1' | 'P2' | 'P3'; rationale: string } {
  const likelihood = weightedLikelihood(input.likelihood, input.scope ?? 'unknown')
  let severity = matrixSeverity(input.impact, likelihood)
  const reasons: string[] = []
  if (hardSuppression({ selfOnly: false, privilegedOnly: false, operatorOnly: false, developerOnly: false, physicalAccessOnly: false, unreachable: false, unrealisticPreconditions: false, ...(input.suppressions ?? {}) })) {
    reasons.push('hard suppression applies (self-only, unreachable, or privileged/operator-only preconditions); decision ignore')
    return { severity: 'ignore', decision: 'ignore', rationale: reasons.join('; ') }
  }
  if (severity === 'high' && input.impact === 'high' && likelihood === 'high' && meetsCriticalCriteria({ codeExecution: false, accountTakeover: false, authBypass: false, privilegeGain: false, sensitiveDataExposure: false, sandboxEscape: false, memorySafetyExploitation: false, ...(input.criteria ?? {}) })) {
    severity = 'critical'
    reasons.push('critical criteria met for high impact x high likelihood')
  }
  const decision: AttackPathDecision = severity === 'ignore' ? 'ignore' : 'reportable'
  const priority = severity === 'ignore' ? undefined : severity === 'critical' ? 'P0' : severity === 'high' ? 'P1' : severity === 'medium' ? 'P2' : 'P3'
  reasons.push(`impact ${input.impact} x likelihood ${likelihood} -> ${severity}${priority ? ` (${priority})` : ''}`)
  return { severity, decision, priority, rationale: reasons.join('; ') }
}

/** Confidence calibration from evidence strength (validation-guidance.md, adapted). */
export function confidenceFromEvidence(evidence: { reproducedCrash: boolean; sanitizerReproduction: boolean; debuggerTrace: boolean; sourceTrace: boolean; counterevidenceDefeats: boolean }): Confidence {
  if (evidence.counterevidenceDefeats) return 'low'
  if (evidence.reproducedCrash) return 'high'
  if (evidence.sanitizerReproduction) return 'high'
  if (evidence.debuggerTrace) return 'high'
  if (evidence.sourceTrace) return 'medium'
  return 'low'
}

export function severityRank(severity: Severity | 'ignore'): number {
  return ({ critical: 5, high: 4, medium: 3, low: 2, informational: 1, ignore: 0 })[severity]
}
