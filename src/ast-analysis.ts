import { parse } from '@typescript-eslint/typescript-estree'
import { dirname, extname, join, normalize } from 'node:path'
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
interface ModuleFunction extends FunctionRecord { id: string; file: string; source: string }
interface ModuleRecord { file: string; source: string; program: AstNode; functions: Map<string, ModuleFunction>; exports: Map<string, string>; imports: Map<string, { file: string; exported: string }>; namespaces: Map<string, string> }

export interface JavaScriptModule { file: string; source: string }
export interface ModuleGraphAnalysis { candidates: Candidate[]; parseErrors: Array<{ file: string; message: string }> }

const AST_RULES: AstRule[] = [
  { id: 'dangerous-dynamic-code', title: 'Dynamic code execution from request data', cwe: 'CWE-95', severity: 'high', rationale: 'Request-derived data reaches dynamic code evaluation.', sinks: ['eval', 'function'] },
  { id: 'shell-command-construction', title: 'Command execution from request data', cwe: 'CWE-78', severity: 'high', rationale: 'Request-derived data reaches a process-execution API.', sinks: ['exec', 'execsync', 'spawn', 'spawnsync', 'system', 'popen'] },
  { id: 'path-traversal-sink', title: 'Filesystem operation from request data', cwe: 'CWE-22', severity: 'medium', rationale: 'Request-derived data reaches a filesystem API without a proven containment control.', sinks: ['readfile', 'writefile', 'appendfile', 'open', 'createreadstream', 'createwritestream', 'sendfile'] },
  { id: 'ssrf-request-sink', title: 'Outbound request from request data', cwe: 'CWE-918', severity: 'medium', rationale: 'Request-derived data selects an outbound network destination.', sinks: ['fetch', 'request', 'get', 'post'] },
  { id: 'sql-injection-query-construction', title: 'SQL query construction from request data', cwe: 'CWE-89', severity: 'high', rationale: 'Request-derived data reaches a database query-text API.', sinks: ['query', 'execute', 'raw', 'queryraw', 'executeraw'] },
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

function propertyName(node: AstNode | undefined): string { return node?.computed ? literal(node.key as AstNode).toLowerCase() : id(node?.key as AstNode)?.toLowerCase() ?? '' }

function outboundDestinationArguments(argumentsList: AstNode[]): AstNode[] {
  const first = argumentsList[0]
  if (!first || first.type !== 'ObjectExpression') return first ? [first] : []
  const destinations = new Set(['url', 'uri', 'href', 'host', 'hostname', 'baseurl'])
  return ((first.properties ?? []) as AstNode[]).flatMap(property => property.type === 'Property' && destinations.has(propertyName(property)) ? [property.value as AstNode] : [])
}

function sinkFor(node: AstNode): Array<{ rule: AstRule; sink: string; argumentsList: AstNode[] }> {
  if (node.type !== 'CallExpression') return []
  const sink = memberName(node.callee as AstNode).toLowerCase(); const final = sink.split('.').at(-1) ?? sink; const argumentsList = (node.arguments ?? []) as AstNode[]
  return AST_RULES.filter(rule => rule.sinks.includes(final) && (rule.id !== 'ssrf-request-sink' || /(?:fetch|axios|request|http|https)/.test(sink)) && (rule.id !== 'sql-injection-query-construction' || /(?:^|\.)(?:db|database|pool|client|connection|manager|repository|sequelize|knex)\.(?:query|execute|raw|queryraw|executeraw)$/.test(sink))).map(rule => ({ rule, sink, argumentsList: rule.id === 'ssrf-request-sink' ? outboundDestinationArguments(argumentsList) : rule.id === 'sql-injection-query-construction' ? argumentsList.slice(0, 1) : argumentsList }))
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

function extensionCandidates(path: string): string[] {
  if (extname(path)) return [path]
  return [path, ...['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs'].map(extension => `${path}${extension}`), ...['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs'].map(extension => join(path, `index${extension}`))]
}

function resolveRelativeModule(file: string, specifier: string, known: Set<string>): string | undefined {
  if (!specifier.startsWith('.')) return undefined
  const base = normalize(join(dirname(file), specifier))
  return extensionCandidates(base).find(candidate => known.has(candidate))
}

function exportDeclarationNames(node: AstNode): string[] {
  if (node.type === 'FunctionDeclaration' || node.type === 'ClassDeclaration') return [id(node.id as AstNode)].filter((value): value is string => Boolean(value))
  if (node.type !== 'VariableDeclaration') return []
  return Array.isArray(node.declarations) ? node.declarations.map(item => id((item as AstNode).id as AstNode)).filter((value): value is string => Boolean(value)) : []
}

function requireTarget(node: AstNode | undefined): string | undefined {
  if (node?.type !== 'CallExpression' || id(node.callee as AstNode) !== 'require') return undefined
  const argumentsList = (node.arguments ?? []) as AstNode[]
  return argumentsList.length === 1 ? literal(argumentsList[0]) : undefined
}

function moduleExportProperty(node: AstNode | undefined): string | undefined {
  if (!node || (node.type !== 'MemberExpression' && node.type !== 'OptionalMemberExpression')) return undefined
  const object = memberName(node.object as AstNode)
  if (object !== 'exports' && object !== 'module.exports') return undefined
  return node.computed ? literal(node.property as AstNode) : id(node.property as AstNode)
}

function isModuleExports(node: AstNode | undefined): boolean { return memberName(node) === 'module.exports' }

function addCommonJsImport(target: string, pattern: AstNode | undefined, imports: Map<string, { file: string; exported: string }>, namespaces: Map<string, string>): void {
  if (!pattern) return
  if (pattern.type === 'Identifier') {
    const local = String(pattern.name)
    // The binding may be invoked as a default-exported function or accessed as a namespace.
    namespaces.set(local, target)
    imports.set(local, { file: target, exported: 'default' })
    return
  }
  if (pattern.type !== 'ObjectPattern') return
  for (const property of (pattern.properties ?? []) as AstNode[]) {
    if (property.type !== 'Property') continue
    const exported = property.computed ? literal(property.key as AstNode) : id(property.key as AstNode)
    const local = id(property.value as AstNode)
    if (local && exported) imports.set(local, { file: target, exported })
  }
}

function addCommonJsExports(statement: AstNode, file: string, functions: Map<string, ModuleFunction>, exports: Map<string, string>): void {
  if (statement.type !== 'ExpressionStatement') return
  const expression = statement.expression as AstNode
  if (expression?.type !== 'AssignmentExpression' || expression.operator !== '=') return
  const left = expression.left as AstNode; const right = expression.right as AstNode
  const property = moduleExportProperty(left)
  if (property) { const local = id(right); if (local && functions.has(local)) exports.set(property, `${file}:${local}`); return }
  if (!isModuleExports(left)) return
  const local = id(right)
  if (local && functions.has(local)) { exports.set('default', `${file}:${local}`); return }
  if (right.type !== 'ObjectExpression') return
  for (const entry of (right.properties ?? []) as AstNode[]) {
    if (entry.type !== 'Property') continue
    const exported = entry.computed ? literal(entry.key as AstNode) : id(entry.key as AstNode)
    const localName = id(entry.value as AstNode)
    if (exported && localName && functions.has(localName)) exports.set(exported, `${file}:${localName}`)
  }
}

function createModuleRecord(file: string, source: string, known: Set<string>): { record?: ModuleRecord; parseError?: string } {
  let program: AstNode
  try { program = parse(source, { loc: true, range: true, jsx: true, comment: false }) as unknown as AstNode } catch (error) { return { parseError: error instanceof Error ? error.message : String(error) } }
  const functions = new Map<string, ModuleFunction>()
  for (const item of localFunctions(program)) functions.set(item.name, { ...item, id: `${file}:${item.name}`, file, source })
  const exports = new Map<string, string>(); const imports = new Map<string, { file: string; exported: string }>(); const namespaces = new Map<string, string>()
  const body = Array.isArray(program.body) ? program.body as AstNode[] : []
  for (const statement of body) {
    if (statement.type === 'ImportDeclaration') {
      const specifier = literal(statement.source as AstNode); const target = resolveRelativeModule(file, specifier, known); if (!target) continue
      for (const imported of (statement.specifiers ?? []) as AstNode[]) {
        const local = id(imported.local as AstNode); if (!local) continue
        if (imported.type === 'ImportNamespaceSpecifier') { namespaces.set(local, target); continue }
        const exported = imported.type === 'ImportDefaultSpecifier' ? 'default' : id(imported.imported as AstNode); if (exported) imports.set(local, { file: target, exported })
      }
      continue
    }
    if (statement.type === 'VariableDeclaration') {
      for (const declaration of (statement.declarations ?? []) as AstNode[]) {
        const specifier = requireTarget(declaration.init as AstNode)
        const target = specifier ? resolveRelativeModule(file, specifier, known) : undefined
        if (target) addCommonJsImport(target, declaration.id as AstNode, imports, namespaces)
      }
      continue
    }
    if (statement.type === 'ExportNamedDeclaration') {
      for (const name of exportDeclarationNames(statement.declaration as AstNode)) if (functions.has(name)) exports.set(name, `${file}:${name}`)
      for (const specifier of (statement.specifiers ?? []) as AstNode[]) { const local = id(specifier.local as AstNode); const exported = id(specifier.exported as AstNode); if (local && exported && functions.has(local)) exports.set(exported, `${file}:${local}`) }
      continue
    }
    if (statement.type === 'ExportDefaultDeclaration') {
      const declaration = statement.declaration as AstNode; const local = id(declaration.id as AstNode); if (local && functions.has(local)) exports.set('default', `${file}:${local}`)
    }
    addCommonJsExports(statement, file, functions, exports)
  }
  return { record: { file, source, program, functions, exports, imports, namespaces } }
}

function targetForCall(module: ModuleRecord, node: AstNode, modules: Map<string, ModuleRecord>, functions: Map<string, ModuleFunction>): ModuleFunction | undefined {
  const direct = id(node.callee as AstNode)
  if (direct) {
    const local = module.functions.get(direct); if (local) return local
    const imported = module.imports.get(direct); const target = imported && modules.get(imported.file)?.exports.get(imported.exported); return target ? functions.get(target) : undefined
  }
  const callee = node.callee as AstNode
  if (callee.type !== 'MemberExpression' && callee.type !== 'OptionalMemberExpression') return undefined
  const namespace = id(callee.object as AstNode); const property = callee.computed ? literal(callee.property as AstNode) : id(callee.property as AstNode); const target = namespace && property ? modules.get(module.namespaces.get(namespace) ?? '')?.exports.get(property) : undefined
  return target ? functions.get(target) : undefined
}

/**
 * Summarize parameter-to-sink flows across the scanned relative ES-module graph.
 * External packages and dynamic imports are intentionally unresolved: they require
 * source or runtime evidence rather than an inferred summary.
 */
function moduleFunctionSinks(modules: Map<string, ModuleRecord>, functions: Map<string, ModuleFunction>): Map<string, Map<number, FunctionSink[]>> {
  const summaries = new Map<string, Map<number, FunctionSink[]>>([...functions.values()].map(record => [record.id, new Map()]))
  const add = (record: ModuleFunction, index: number, item: FunctionSink): boolean => {
    const entries = summaries.get(record.id)?.get(index) ?? []; const key = `${item.rule.id}:${item.node.range?.join(':') ?? item.sink}`
    if (entries.some(existing => `${existing.rule.id}:${existing.node.range?.join(':') ?? existing.sink}` === key)) return false
    const target = summaries.get(record.id); if (!target) return false; target.set(index, [...entries, item]); return true
  }
  for (let pass = 0; pass < functions.size * Math.max(2, functions.size) + 1; pass++) {
    let changed = false
    for (const record of functions.values()) for (const [index, param] of record.params.entries()) {
      const tainted = new Set([param]); const module = modules.get(record.file); if (!module) continue
      walkFunction(record.body, node => {
        for (const sink of sinkFor(node)) if (sink.argumentsList.some(argument => sourceExpression(argument, tainted))) changed = add(record, index, { rule: sink.rule, sink: sink.sink, node }) || changed
        if (node.type !== 'CallExpression') return
        const target = targetForCall(module, node, modules, functions); if (!target) return
        const args = (node.arguments ?? []) as AstNode[]; const nested = summaries.get(target.id)
        for (const [targetIndex] of target.params.entries()) if (args[targetIndex] && sourceExpression(args[targetIndex], tainted)) for (const result of nested?.get(targetIndex) ?? []) changed = add(record, index, result) || changed
      })
    }
    if (!changed) break
  }
  return summaries
}

/** Analyze request-input flows that cross local ES-module boundaries inside one scan scope. */
export function analyzeJavaScriptModuleGraph(inputs: JavaScriptModule[]): ModuleGraphAnalysis {
  const normalized = inputs.map(input => ({ ...input, file: normalize(input.file) })); const known = new Set(normalized.map(input => input.file)); const modules = new Map<string, ModuleRecord>(); const parseErrors: ModuleGraphAnalysis['parseErrors'] = []
  for (const input of normalized) { const parsed = createModuleRecord(input.file, input.source, known); if (parsed.record) modules.set(input.file, parsed.record); else if (parsed.parseError) parseErrors.push({ file: input.file, message: parsed.parseError }) }
  const functions = new Map<string, ModuleFunction>(); for (const module of modules.values()) for (const record of module.functions.values()) functions.set(record.id, record)
  const summaries = moduleFunctionSinks(modules, functions); const candidates: Candidate[] = []
  for (const module of modules.values()) {
    const tainted = new Set<string>(); const assignments: Array<{ name: string; value: AstNode }> = []
    walk(module.program, node => { if (node.type === 'VariableDeclarator') { const name = id(node.id as AstNode); const value = node.init as AstNode | undefined; if (name && value) assignments.push({ name, value }) }; if (node.type === 'AssignmentExpression') { const name = id(node.left as AstNode); const value = node.right as AstNode | undefined; if (name && value) assignments.push({ name, value }) } })
    for (let pass = 0; pass < assignments.length + 1; pass++) { let changed = false; for (const assignment of assignments) if (!tainted.has(assignment.name) && sourceExpression(assignment.value, tainted)) { tainted.add(assignment.name); changed = true }; if (!changed) break }
    walk(module.program, node => {
      if (node.type !== 'CallExpression') return
      const target = targetForCall(module, node, modules, functions); if (!target) return
      const args = (node.arguments ?? []) as AstNode[]; const nested = summaries.get(target.id)
      for (const [index] of target.params.entries()) {
        const input = args[index]; if (!input || !sourceExpression(input, tainted)) continue
        for (const result of nested?.get(index) ?? []) {
          const item = candidate(result.rule, target.source, target.file, result.node, result.sink, input)
          if (!item) continue
          const at = node.loc?.start.line ?? item.line
          item.evidence.push({ kind: 'context', detail: `AST cross-module call-chain analysis resolved request-derived input through ${target.name}() in ${target.file} to ${result.sink}.`, location: { file: module.file, line: at, excerpt: line(module.source, at), role: 'propagation' } })
          candidates.push(item)
        }
      }
    })
  }
  const unique = new Map<string, Candidate>(); for (const item of candidates) unique.set(`${item.rule}:${item.file}:${item.line}:${item.excerpt}`, item)
  return { candidates: [...unique.values()], parseErrors }
}
