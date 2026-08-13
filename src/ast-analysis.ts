import { parse } from '@typescript-eslint/typescript-estree'
import type { Candidate } from './scanner.js'
import type { Evidence, Severity } from './contracts.js'

interface AstNode {
  type?: string
  range?: [number, number]
  loc?: { start: { line: number; column: number }; end: { line: number; column: number } }
  [key: string]: unknown
}

interface AstRule { id: string; title: string; cwe: string; severity: Severity; rationale: string; sinks: string[] }

const AST_RULES: AstRule[] = [
  { id: 'dangerous-dynamic-code', title: 'Dynamic code execution from request data', cwe: 'CWE-95', severity: 'high', rationale: 'Request-derived data reaches dynamic code evaluation.', sinks: ['eval', 'function'] },
  { id: 'shell-command-construction', title: 'Command execution from request data', cwe: 'CWE-78', severity: 'high', rationale: 'Request-derived data reaches a process-execution API.', sinks: ['exec', 'execsync', 'spawn', 'spawnsync', 'system', 'popen'] },
  { id: 'path-traversal-sink', title: 'Filesystem operation from request data', cwe: 'CWE-22', severity: 'medium', rationale: 'Request-derived data reaches a filesystem API without a proven containment control.', sinks: ['readfile', 'writefile', 'appendfile', 'open', 'createreadstream', 'createwritestream', 'sendfile'] },
  { id: 'ssrf-request-sink', title: 'Outbound request from request data', cwe: 'CWE-918', severity: 'medium', rationale: 'Request-derived data selects an outbound network destination.', sinks: ['fetch', 'request', 'get', 'post'] },
]

function children(node: AstNode): AstNode[] {
  const values: AstNode[] = []
  for (const [key, value] of Object.entries(node)) {
    if (key === 'parent' || key === 'loc' || key === 'range' || key === 'tokens' || key === 'comments') continue
    if (value && typeof value === 'object' && 'type' in value) values.push(value as AstNode)
    if (Array.isArray(value)) for (const item of value) if (item && typeof item === 'object' && 'type' in item) values.push(item as AstNode)
  }
  return values
}

function walk(node: AstNode, visit: (node: AstNode) => void): void { visit(node); for (const child of children(node)) walk(child, visit) }
function id(node: AstNode | undefined): string | undefined { return node?.type === 'Identifier' && typeof node.name === 'string' ? node.name : undefined }
function line(source: string, number: number): string { return source.split(/\r?\n/)[number - 1]?.trim().slice(0, 240) ?? '' }
function memberName(node: AstNode | undefined): string {
  if (!node) return ''
  if (node.type === 'Identifier' && typeof node.name === 'string') return node.name
  if (node.type === 'ThisExpression') return 'this'
  if (node.type === 'MemberExpression' || node.type === 'OptionalMemberExpression') {
    const object = memberName(node.object as AstNode); const property = node.computed ? literal(node.property as AstNode) : memberName(node.property as AstNode)
    return [object, property].filter(Boolean).join('.')
  }
  return ''
}
function literal(node: AstNode | undefined): string { return node?.type === 'Literal' && typeof node.value === 'string' ? node.value : '' }

function sourceExpression(node: AstNode | undefined, tainted: Set<string>): boolean {
  if (!node) return false
  if (node.type === 'Identifier') return tainted.has(String(node.name))
  if (node.type === 'MemberExpression' || node.type === 'OptionalMemberExpression') {
    const name = memberName(node).toLowerCase()
    if (/^(?:req|request|ctx\.request|event)\.(?:body|query|params|param|headers|cookies|url|path)(?:\.|$)/.test(name)) return true
    return sourceExpression(node.object as AstNode, tainted)
  }
  if (node.type === 'TemplateLiteral') return Array.isArray(node.expressions) && node.expressions.some(expression => sourceExpression(expression as AstNode, tainted))
  if (node.type === 'BinaryExpression' || node.type === 'LogicalExpression' || node.type === 'AssignmentExpression') return sourceExpression(node.left as AstNode, tainted) || sourceExpression(node.right as AstNode, tainted)
  if (node.type === 'ConditionalExpression') return sourceExpression(node.consequent as AstNode, tainted) || sourceExpression(node.alternate as AstNode, tainted)
  if (node.type === 'ArrayExpression') return Array.isArray(node.elements) && node.elements.some(element => sourceExpression(element as AstNode, tainted))
  if (node.type === 'ObjectExpression') return Array.isArray(node.properties) && node.properties.some(property => sourceExpression((property as AstNode).value as AstNode, tainted))
  if (node.type === 'CallExpression' || node.type === 'ChainExpression') {
    const callee = memberName((node.type === 'ChainExpression' ? node.expression : node.callee) as AstNode).toLowerCase()
    const args = (node.type === 'CallExpression' ? node.arguments : []) as AstNode[]
    return /(?:decode|encode|trim|replace|slice|substring|concat|join|tolowercase|touppercase|normalize|format)$/.test(callee) && args.some(argument => sourceExpression(argument, tainted))
  }
  return false
}

function candidate(rule: AstRule, source: string, file: string, node: AstNode, sink: string, taintedArgument: AstNode): Candidate | undefined {
  const number = node.loc?.start.line
  if (!number) return undefined
  const excerpt = line(source, number)
  const evidence: Evidence[] = [
    { kind: 'pattern', detail: `AST resolved sensitive call ${sink}.`, location: { file, line: number, excerpt, role: 'sink' } },
    { kind: 'context', detail: 'AST local data-flow analysis resolved a request-derived value in a sensitive call argument.', location: { file, line: taintedArgument.loc?.start.line ?? number, excerpt: line(source, taintedArgument.loc?.start.line ?? number), role: 'entrypoint' } },
  ]
  return { rule: rule.id, severity: rule.severity, file, line: number, excerpt, rationale: rule.rationale, cwe: rule.cwe, evidence }
}

export function analyzeJavaScriptAst(source: string, file: string): { candidates: Candidate[]; parseError?: string } {
  let program: AstNode
  try { program = parse(source, { loc: true, range: true, jsx: true, comment: false }) as unknown as AstNode } catch (error) { return { candidates: [], parseError: error instanceof Error ? error.message : String(error) } }
  const tainted = new Set<string>(); const assignments: Array<{ name: string; value: AstNode }> = []
  walk(program, node => {
    if (node.type === 'VariableDeclarator') { const name = id(node.id as AstNode); const value = node.init as AstNode | undefined; if (name && value) assignments.push({ name, value }) }
    if (node.type === 'AssignmentExpression') { const name = id(node.left as AstNode); const value = node.right as AstNode | undefined; if (name && value) assignments.push({ name, value }) }
  })
  for (let pass = 0; pass < assignments.length + 1; pass++) { let changed = false; for (const assignment of assignments) if (!tainted.has(assignment.name) && sourceExpression(assignment.value, tainted)) { tainted.add(assignment.name); changed = true } if (!changed) break }
  const candidates: Candidate[] = []
  walk(program, node => {
    if (node.type !== 'CallExpression') return
    const sink = memberName(node.callee as AstNode).toLowerCase(); const final = sink.split('.').at(-1) ?? sink; const argumentsList = (node.arguments ?? []) as AstNode[]
    for (const rule of AST_RULES) {
      if (!rule.sinks.includes(final)) continue
      if (rule.id === 'ssrf-request-sink' && !/(?:fetch|axios|request|http|https)/.test(sink)) continue
      const input = argumentsList.find(argument => sourceExpression(argument, tainted))
      if (input) { const item = candidate(rule, source, file, node, sink, input); if (item) candidates.push(item) }
    }
  })
  return { candidates }
}
