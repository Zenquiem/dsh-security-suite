export type Severity = 'critical' | 'high' | 'medium' | 'low'
export type Confidence = 'high' | 'medium' | 'low'
export type FindingStatus = 'open' | 'false_positive' | 'resolved' | 'unknown'
export type ScanLifecycle = 'queued' | 'running' | 'completed' | 'incomplete' | 'failed' | 'cancelled'

export interface Location {
  file: string
  line: number
  excerpt: string
}

export interface Evidence {
  kind: 'pattern' | 'context' | 'policy' | 'validation' | 'counterevidence'
  detail: string
  location?: Location
}

export interface Finding {
  id: string
  fingerprint: string
  ruleId: string
  title: string
  severity: Severity
  confidence: Confidence
  cwe: string
  status: FindingStatus
  locations: Location[]
  rootCause: string
  validation: string
  attackPath: string
  impact: string
  remediation: string
  counterevidence: string
  evidence: Evidence[]
}

export interface FileReceipt {
  path: string
  bytes: number
  sha256: string
  language: string
}

export interface RuleReceipt {
  ruleId: string
  pass: string
  matches: number
}

export interface ScanActivity {
  at: string
  phase: 'inventory' | 'policy' | 'discovery' | 'validation' | 'reduction' | 'complete'
  message: string
}

export interface Coverage {
  mode: 'repository' | 'scoped_path' | 'diff'
  reviewedFiles: number
  skippedFiles: number
  exclusions: string[]
  complete: boolean
  receipts: FileReceipt[]
  ruleReceipts: RuleReceipt[]
  policyFiles: string[]
}

export interface ScanRecord {
  schemaVersion: 2
  id: string
  mode: 'standard' | 'deep' | 'diff'
  lifecycle: ScanLifecycle
  target: string
  createdAt: string
  completedAt: string
  threatModel: string
  findings: Finding[]
  coverage: Coverage
  activity: ScanActivity[]
  recipe: { mode: 'standard' | 'deep' | 'diff', scopeRequested: boolean, passes: string[] }
  seal: string
}
