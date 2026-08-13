export type Severity = 'critical' | 'high' | 'medium' | 'low'
export type Confidence = 'high' | 'medium' | 'low'
export type FindingStatus = 'open' | 'false_positive' | 'resolved' | 'unknown'

export interface Location {
  file: string
  line: number
  excerpt: string
}

export interface Finding {
  id: string
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
}

export interface Coverage {
  mode: 'repository' | 'scoped_path' | 'diff'
  reviewedFiles: number
  skippedFiles: number
  exclusions: string[]
  complete: boolean
}

export interface ScanRecord {
  schemaVersion: 1
  id: string
  mode: 'standard' | 'deep' | 'diff'
  target: string
  createdAt: string
  completedAt: string
  threatModel: string
  findings: Finding[]
  coverage: Coverage
}
