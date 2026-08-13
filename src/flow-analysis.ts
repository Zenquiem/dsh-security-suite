import type { Evidence, Severity } from './contracts.js'
import type { Candidate } from './scanner.js'

interface FlowRule { id: string; title: string; cwe: string; severity: Severity; rationale: string; sink: RegExp }

const PYTHON_RULES: FlowRule[] = [
  { id: 'dangerous-dynamic-code', title: 'Dynamic code execution from request data', cwe: 'CWE-95', severity: 'high', rationale: 'Request-derived data reaches Python dynamic evaluation.', sink: /\b(?:eval|exec)\s*\(/ },
  { id: 'shell-command-construction', title: 'Command execution from request data', cwe: 'CWE-78', severity: 'high', rationale: 'Request-derived data reaches a process execution API.', sink: /\b(?:subprocess\.(?:run|call|Popen|check_output)|os\.(?:system|popen))\s*\(/ },
  { id: 'path-traversal-sink', title: 'Filesystem operation from request data', cwe: 'CWE-22', severity: 'medium', rationale: 'Request-derived data reaches a filesystem API without proven containment.', sink: /\b(?:open|os\.path\.join|send_file)\s*\(/ },
  { id: 'ssrf-request-sink', title: 'Outbound request from request data', cwe: 'CWE-918', severity: 'medium', rationale: 'Request-derived data selects an outbound network destination.', sink: /\b(?:requests\.(?:get|post|request)|httpx\.(?:get|post|request)|urllib\.request\.urlopen)\s*\(/ },
]

const GO_RULES: FlowRule[] = [
  { id: 'shell-command-construction', title: 'Command execution from request data', cwe: 'CWE-78', severity: 'high', rationale: 'Request-derived data reaches an OS command API.', sink: /\bexec\.Command(?:Context)?\s*\(/ },
  { id: 'path-traversal-sink', title: 'Filesystem operation from request data', cwe: 'CWE-22', severity: 'medium', rationale: 'Request-derived data reaches a filesystem API without proven containment.', sink: /\b(?:os\.(?:Open|OpenFile|ReadFile|WriteFile)|http\.ServeFile)\s*\(/ },
  { id: 'ssrf-request-sink', title: 'Outbound request from request data', cwe: 'CWE-918', severity: 'medium', rationale: 'Request-derived data selects an outbound network destination.', sink: /\b(?:http\.(?:Get|Post)|client\.Do)\s*\(/ },
]

function expressionTainted(expression: string, tainted: Set<string>, sources: RegExp): boolean { return sources.test(expression) || [...tainted].some(name => new RegExp(`\\b${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`).test(expression)) }
function candidate(rule: FlowRule, file: string, line: number, excerpt: string): Candidate { const evidence: Evidence[] = [{ kind: 'pattern', detail: `Local flow analysis resolved sensitive operation for ${rule.id}.`, location: { file, line, excerpt, role: 'sink' } }, { kind: 'context', detail: 'Local flow analysis resolved request-derived data in the sensitive operation.', location: { file, line, excerpt, role: 'entrypoint' } }]; return { rule: rule.id, severity: rule.severity, file, line, excerpt, rationale: rule.rationale, cwe: rule.cwe, evidence } }

function analyze(source: string, file: string, rules: FlowRule[], sourcePattern: RegExp, assignment: RegExp): Candidate[] {
  const lines = source.split(/\r?\n/); const tainted = new Set<string>(); const assigned: Array<{ name: string; expression: string }> = []
  for (const line of lines) { const match = assignment.exec(line); assignment.lastIndex = 0; if (match) assigned.push({ name: match[1], expression: match[2] }) }
  for (let pass = 0; pass <= assigned.length; pass++) { let changed = false; for (const item of assigned) if (!tainted.has(item.name) && expressionTainted(item.expression, tainted, sourcePattern)) { tainted.add(item.name); changed = true } if (!changed) break }
  const candidates: Candidate[] = []
  for (const [index, line] of lines.entries()) for (const rule of rules) if (rule.sink.test(line) && expressionTainted(line, tainted, sourcePattern)) candidates.push(candidate(rule, file, index + 1, line.trim().slice(0, 240)))
  return candidates
}

export function analyzePythonFlow(source: string, file: string): Candidate[] { return analyze(source, file, PYTHON_RULES, /\b(?:request\.(?:args|form|json|data|values|headers)|input\s*\()/i, /^\s*([A-Za-z_]\w*)\s*=\s*(.+)$/) }
export function analyzeGoFlow(source: string, file: string): Candidate[] { return analyze(source, file, GO_RULES, /\b(?:r\.(?:URL\.Query\(\)\.Get|FormValue|PostFormValue)|c\.Query|ctx\.Query)\s*\(/, /^\s*([A-Za-z_]\w*)\s*:?=\s*(.+)$/) }
