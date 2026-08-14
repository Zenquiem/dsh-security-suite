export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'informational'
export type Confidence = 'high' | 'medium' | 'low'
export type FindingStatus = 'open' | 'false_positive' | 'resolved' | 'unknown'
export type CandidateDisposition = 'discovered' | 'reportable' | 'suppressed' | 'deferred' | 'not_applicable'
export type ScanLifecycle = 'queued' | 'preflight' | 'threat_model' | 'discovery' | 'validation' | 'attack_path' | 'reporting' | 'completed' | 'incomplete' | 'failed' | 'cancelled'
export type EvidenceKind = 'pattern' | 'context' | 'policy' | 'validation' | 'counterevidence' | 'attack_path' | 'runtime' | 'test'
export type LocationRole = 'entrypoint' | 'wrapper' | 'propagation' | 'root_control' | 'sink' | 'outcome' | 'expected_control'

export interface Location { file: string; line: number; excerpt: string; role?: LocationRole }
/** An exact, immutable-source location cited by a validation or attack-path receipt. */
export interface ReceiptSourceReference { file: string; line: number; role: LocationRole }
export interface Evidence { kind: EvidenceKind; detail: string; location?: Location; artifactRef?: string }

export interface ValidationRecord {
  method: 'static' | 'test' | 'runtime' | 'hybrid'
  conclusion: 'reportable' | 'suppressed' | 'deferred' | 'not_applicable'
  attacker: string
  entryPoint: string
  trustBoundary: string
  rootControl: string
  sink: string
  impact: string
  directEvidence: string
  counterevidence: string
  limitations: string
  confidence: Confidence
  sourceReferences: ReceiptSourceReference[]
  /** Runtime evidence receipts bound to this candidate validation, when used. */
  runtimeReceiptRefs?: string[]
  recordedAt: string
}

export interface AttackPathRecord {
  attacker: string
  entryPoint: string
  preconditions: string
  dataflow: string
  outcome: string
  severityRationale: string
  changeConditions: string
  sourceReferences: ReceiptSourceReference[]
  recordedAt: string
}

export interface CandidateLedgerEntry {
  at: string
  phase: 'discovery' | 'validation' | 'attack_path' | 'finalization'
  disposition: CandidateDisposition
  summary: string
  artifactRef?: string
}

export interface Finding {
  id: string
  candidateId: string
  fingerprint: string
  ruleId: string
  identity: { anchor: string; instance?: string }
  title: string
  severity: Severity
  confidence: Confidence
  cwe: string
  status: FindingStatus
  disposition: CandidateDisposition
  locations: Location[]
  rootCause: string
  validation: string
  attackPath: string
  impact: string
  remediation: string
  counterevidence: string
  evidence: Evidence[]
  ledger: CandidateLedgerEntry[]
  validationRecord?: ValidationRecord
  attackPathRecord?: AttackPathRecord
  writeup?: {
    reportPath: string
    generatedAt: string
    evidenceDigest: string
    poc: { status: 'not_generated'; rationale: string }
  }
}

export interface FileReceipt { path: string; bytes: number; sha256: string; language: string }
export interface RuleReceipt { ruleId: string; pass: string; matches: number }
export interface ScanActivity { at: string; phase: 'preflight' | 'inventory' | 'policy' | 'threat_model' | 'discovery' | 'validation' | 'attack_path' | 'reduction' | 'reporting' | 'complete'; message: string }
export interface AuditTask {
  id: string
  candidateId: string
  phase: 'validation' | 'attack_path'
  focus: string
  status: 'pending' | 'claimed' | 'completed' | 'cancelled'
  claim?: { owner: string; token: string; claimedAt: string; expiresAt: string }
  completedAt?: string
  receipt?: string
}

export interface TargetSnapshot {
  kind: 'git_worktree' | 'git_revision' | 'directory_snapshot' | 'git_diff'
  targetId: string
  displayName: string
  revision?: string
  /** Canonical GitHub owner/repository for a clean immutable source revision. */
  sourceRepository?: string
  baseRevision?: string
  headRevision?: string
  snapshotDigest: string
}

/** The exact Git change-set workflow represented by a diff scan. */
export type DiffScanMode = 'working_tree' | 'commit' | 'branch_diff'

export interface Preflight {
  status: 'ready' | 'warn' | 'blocked'
  checks: Array<{ id: string; status: 'pass' | 'warn' | 'blocked'; detail: string }>
  projectFiles: string[]
  languages: string[]
  suggestedCommands: string[]
}

export interface Coverage {
  mode: 'repository' | 'scoped_path' | 'diff' | 'commit' | 'branch_diff' | 'working_tree' | 'deep_repository'
  reviewedFiles: number
  skippedFiles: number
  exclusions: string[]
  complete: boolean
  receipts: FileReceipt[]
  ruleReceipts: RuleReceipt[]
  policyFiles: string[]
  surfaces: Array<{ id: string; label: string; disposition: 'reported' | 'no_issue_found' | 'rejected' | 'not_applicable' | 'needs_follow_up'; receiptRefs: string[]; riskArea?: string; notes?: string }>
  deferred: Array<{ id: string; reason: string; paths?: string[] }>
}

export interface ScanRecord {
  schemaVersion: 3
  id: string
  mode: 'standard' | 'deep' | 'diff'
  lifecycle: ScanLifecycle
  target: string
  targetSnapshot: TargetSnapshot
  createdAt: string
  completedAt?: string
  threatModel: string
  policyGuidance: string
  preflight: Preflight
  findings: Finding[]
  coverage: Coverage
  activity: ScanActivity[]
  tasks: AuditTask[]
  recipe: { mode: 'standard' | 'deep' | 'diff'; scopeRequested: boolean; passes: string[]; diffMode?: DiffScanMode; diffBase?: string; diffHead?: string }
  artifacts: { directory: string; manifest?: string; findings?: string; coverage?: string; report?: string }
  /** Derived architecture guidance; absent when no reportable finding survives finalization. */
  hardening?: {
    portfolioPath: string
    structuredPath: string
    outcome: 'structural_hardening_recommended' | 'local_remediation_preferred'
    generatedAt: string
    evidenceDigest: string
  }
  annotations?: { path: string; updatedAt: string }
  seal: string
}
