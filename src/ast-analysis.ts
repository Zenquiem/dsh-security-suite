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
interface FunctionRecord { name: string; params: string[]; body: AstNode }
interface FunctionSink { rule: AstRule; sink: string; node: AstNode }

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
function isFunction(node: AstNode): boolean { return node.type === 'FunctionDeclaration' || node.type === 'FunctionExpression' || node.type === 'ArrowFunctionExpression' }
function walkFunction(node: AstNode, visit: (node: AstNode) => void, root = true): void { visit(node); for (const child of children(node)) { if (!root && isFunction(child)) continue; walkFunction(child, visit, false) } }
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

function localFunctions(program: AstNode): FunctionRecord[] {
  const records: FunctionRecord[] = []
  walk(program, node => {
    const declaration = node.type === 'FunctionDeclaration' ? node : node.type === 'VariableDeclarator' && isFunction(node.init as AstNode) ? node.init as AstNode : undefined
    const name = node.type === 'FunctionDeclaration' ? id(node.id as AstNode) : node.type === 'VariableDeclarator' ? id(node.id as AstNode) : undefined
    if (!declaration || !name) return
    const params = Array.isArray(declaration.params) ? declaration.params.map(item => id(item as AstNode)).filter((item): item is string => Boolean(item)) : []
    if (params.length) records.push({ name, params, body: declaration.body as AstNode })
  })
  return records
}

function sinkFor(node: AstNode): Array<{ rule: AstRule; sink: string; argumentsList: AstNode[] }> {
  if (node.type !== 'CallExpression') return []
  const sink = memberName(node.callee as AstNode).toLowerCase(); const final = sink.split('.').at(-1) ?? sink; const argumentsList = (node.arguments ?? []) as AstNode[]
  return AST_RULES.filter(rule => rule.sinks.includes(final) && (rule.id !== 'ssrf-request-sink' || /(?:fetch|axios|request|http|https)/.test(sink))).map(rule => ({ rule, sink, argumentsList }))
}

/** Fixed-point summaries for named local functions: parameter index -> reachable sink. */
function localFunctionSinks(program: AstNode): Map<string, Map<number, FunctionSink[]>> {
  const functions = localFunctions(program); const byName = new Map(functions.map(item => [item.name, item])); const summaries = new Map<string, Map<number, FunctionSink[]>>(functions.map(item => [item.name, new Map()]))
  const add = (name: string, index: number, item: FunctionSink): boolean => {
    const entries = summaries.get(name)?.get(index) ?? []; const key = `${item.rule.id}:${item.node.range?.join(':') ?? item.sink}`
    if (entries.some(existing => `${existing.rule.id}:${existing.node.range?.join(':') ?? existing.sink}` === key)) return false
    const target = summaries.get(name); if (!target) return false; target.set(index, [...entries, item]); return true
  }
  for (let pass = 0; pass < functions.length * Math.max(2, functions.length) + 1; pass++) {
    let changed = false
    for (const record of functions) for (const [index, param] of record.params.entries()) {
      const tainted = new Set([param])
      walkFunction(record.body, node => {
        for (const sink of sinkFor(node)) if (sink.argumentsList.some(argument => sourceExpression(argument, tainted))) changed = add(record.name, index, { rule: sink.rule, sink: sink.sink, node }) || changed
        if (node.type !== 'CallExpression') return
        const callee = id(node.callee as AstNode); const target = callee ? byName.get(callee) : undefined; if (!target) return
        const args = (node.arguments ?? []) as AstNode[]; const nested = summaries.get(target.name)
        for (const [targetIndex] of target.params.entries()) if (args[targetIndex] && sourceExpression(args[targetIndex], tainted)) for (const result of nested?.get(targetIndex) ?? []) changed = add(record.name, index, result) || changed
      })
    }
    if (!changed) break
  }
  return summaries
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
  const candidates: Candidate[] = []; const functions = new Map(localFunctions(program).map(item => [item.name, item])); const summaries = localFunctionSinks(program)
  walk(program, node => {
    if (node.type !== 'CallExpression') return
    for (const sink of sinkFor(node)) { const input = sink.argumentsList.find(argument => sourceExpression(argument, tainted)); if (input) { const item = candidate(sink.rule, source, file, node, sink.sink, input); if (item) candidates.push(item) } }
    const callee = id(node.callee as AstNode); const target = callee ? functions.get(callee) : undefined; if (!target) return
    const argumentsList = (node.arguments ?? []) as AstNode[]
    for (const [index] of target.params.entries()) {
      const input = argumentsList[index]; if (!input || !sourceExpression(input, tainted)) continue
      for (const result of summaries.get(target.name)?.get(index) ?? []) {
        const item = candidate(result.rule, source, file, result.node, result.sink, input)
        if (item) { item.evidence.push({ kind: 'context', detail: `AST local call-chain analysis resolved request-derived input through ${target.name}() to ${result.sink}.`, location: { file, line: node.loc?.start.line ?? item.line, excerpt: line(source, node.loc?.start.line ?? item.line), role: 'propagation' } }); candidates.push(item) }
      }
    }
  })
  const unique = new Map<string, Candidate>(); for (const item of candidates) unique.set(`${item.rule}:${item.file}:${item.line}:${item.excerpt}`, item)
  return { candidates: [...unique.values()] }
}
