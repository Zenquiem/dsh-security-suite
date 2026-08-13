export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'informational'
export type Confidence = 'high' | 'medium' | 'low'
export type FindingStatus = 'open' | 'false_positive' | 'resolved' | 'unknown'
export type CandidateDisposition = 'discovered' | 'reportable' | 'suppressed' | 'deferred' | 'not_applicable'
export type ScanLifecycle = 'queued' | 'preflight' | 'threat_model' | 'discovery' | 'validation' | 'attack_path' | 'reporting' | 'completed' | 'incomplete' | 'failed' | 'cancelled'
export type EvidenceKind = 'pattern' | 'context' | 'policy' | 'validation' | 'counterevidence' | 'attack_path' | 'runtime' | 'test'
export type LocationRole = 'entrypoint' | 'wrapper' | 'propagation' | 'root_control' | 'sink' | 'outcome' | 'expected_control'

export interface Location { file: string; line: number; excerpt: string; role?: LocationRole }
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
  kind: 'git_worktree' | 'directory_snapshot' | 'git_diff'
  targetId: string
  displayName: string
  revision?: string
  baseRevision?: string
  headRevision?: string
  snapshotDigest: string
}

export interface Preflight {
  status: 'ready' | 'warn' | 'blocked'
  checks: Array<{ id: string; status: 'pass' | 'warn' | 'blocked'; detail: string }>
  projectFiles: string[]
  languages: string[]
  suggestedCommands: string[]
}

export interface Coverage {
  mode: 'repository' | 'scoped_path' | 'diff' | 'deep_repository'
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
  recipe: { mode: 'standard' | 'deep' | 'diff'; scopeRequested: boolean; passes: string[] }
  artifacts: { directory: string; manifest?: string; findings?: string; coverage?: string; report?: string }
  annotations?: { path: string; updatedAt: string }
  seal: string
}
