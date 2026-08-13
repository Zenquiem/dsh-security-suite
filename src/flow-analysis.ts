import { dirname, join, normalize } from 'node:path'
import type { Evidence, Severity } from './contracts.js'
import type { Candidate } from './scanner.js'

interface FlowRule { id: string; title: string; cwe: string; severity: Severity; rationale: string; sink: RegExp }
interface FlowModule { file: string; source: string; modulePath?: string }
interface FlowFunction { id: string; file: string; name: string; params: string[]; start: number; end: number; lines: string[] }
interface SinkResult { rule: FlowRule; line: number; excerpt: string }
interface ImportTarget { file: string; exported: string }
interface ParsedModule { file: string; source: string; lines: string[]; functions: FlowFunction[]; imports: Map<string, ImportTarget>; namespaces: Map<string, string>; packageKey?: string }

export interface FlowGraphAnalysis { candidates: Candidate[] }

const PYTHON_RULES: FlowRule[] = [
  { id: 'dangerous-dynamic-code', title: 'Dynamic code execution from request data', cwe: 'CWE-95', severity: 'high', rationale: 'Request-derived data reaches Python dynamic evaluation.', sink: /\b(?:eval|exec)\s*\(/ },
  { id: 'shell-command-construction', title: 'Command execution from request data', cwe: 'CWE-78', severity: 'high', rationale: 'Request-derived data reaches a process execution API.', sink: /\b(?:subprocess\.(?:run|call|Popen|check_output)|os\.(?:system|popen))\s*\(/ },
  { id: 'path-traversal-sink', title: 'Filesystem operation from request data', cwe: 'CWE-22', severity: 'medium', rationale: 'Request-derived data reaches a filesystem API without proven containment.', sink: /\b(?:open|os\.path\.join|send_file)\s*\(/ },
  { id: 'ssrf-request-sink', title: 'Outbound request from request data', cwe: 'CWE-918', severity: 'medium', rationale: 'Request-derived data selects an outbound network destination.', sink: /\b(?:requests\.(?:get|post|request)|httpx\.(?:get|post|request)|urllib\.request\.urlopen)\s*\(/ },
  { id: 'sql-injection-query-construction', title: 'SQL query construction from request data', cwe: 'CWE-89', severity: 'high', rationale: 'Request-derived data reaches a Python database query-text API.', sink: /\b(?:cursor|connection|conn|db|database|session)\.(?:execute|executemany|executescript)\s*\(/i },
  { id: 'unsafe-deserialization', title: 'Unsafe Python deserialization from request data', cwe: 'CWE-502', severity: 'high', rationale: 'Request-derived bytes reach a Python deserializer that can construct attacker-controlled objects.', sink: /\b(?:pickle\.loads|yaml\.load)\s*\(/i },
]

const GO_RULES: FlowRule[] = [
  { id: 'shell-command-construction', title: 'Command execution from request data', cwe: 'CWE-78', severity: 'high', rationale: 'Request-derived data reaches an OS command API.', sink: /\bexec\.Command(?:Context)?\s*\(/ },
  { id: 'path-traversal-sink', title: 'Filesystem operation from request data', cwe: 'CWE-22', severity: 'medium', rationale: 'Request-derived data reaches a filesystem API without proven containment.', sink: /\b(?:os\.(?:Open|OpenFile|ReadFile|WriteFile)|http\.ServeFile)\s*\(/ },
  { id: 'ssrf-request-sink', title: 'Outbound request from request data', cwe: 'CWE-918', severity: 'medium', rationale: 'Request-derived data selects an outbound network destination.', sink: /\b(?:http\.(?:Get|Post)|client\.Do)\s*\(/ },
  { id: 'sql-injection-query-construction', title: 'SQL query construction from request data', cwe: 'CWE-89', severity: 'high', rationale: 'Request-derived data reaches a Go database query-text API.', sink: /\b(?:db|database|tx|stmt)\.(?:Query|QueryContext|Exec|ExecContext)\s*\(/ },
]

const PYTHON_SOURCE = /\b(?:request\.(?:args|form|json|data|values|headers|get_data|get_json)|input\s*\()/i
const GO_SOURCE = /\b(?:r\.(?:URL\.Query\(\)\.Get|FormValue|PostFormValue)|c\.Query|ctx\.Query)\s*\(/
const IDENTIFIER = /[A-Za-z_]\w*/g

function escaped(value: string): string { return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') }
function identifiers(value: string): string[] { return value.match(IDENTIFIER) ?? [] }
function expressionTainted(expression: string, tainted: Set<string>, sources: RegExp): boolean {
  if (/^(?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')$/.test(expression.trim())) return false
  sources.lastIndex = 0
  if (sources.test(expression)) return true
  return [...tainted].some(name => new RegExp(`\\b${escaped(name)}\\b`).test(expression))
}
function evidence(rule: FlowRule, file: string, line: number, excerpt: string, detail: string, propagation?: { file: string; line: number; excerpt: string }): Candidate {
  const values: Evidence[] = [
    { kind: 'pattern', detail: `Structured ${detail} resolved sensitive operation for ${rule.id}.`, location: { file, line, excerpt, role: 'sink' } },
    { kind: 'context', detail: `Structured ${detail} resolved request-derived data in the sensitive operation.`, location: propagation ? { ...propagation, role: 'propagation' } : { file, line, excerpt, role: 'entrypoint' } },
  ]
  return { rule: rule.id, severity: rule.severity, file, line, excerpt, rationale: rule.rationale, cwe: rule.cwe, evidence: values }
}

function assignment(line: string, language: 'python' | 'go'): { name: string; value: string } | undefined {
  const match = language === 'python' ? /^\s*([A-Za-z_]\w*)\s*=\s*(.+)$/ .exec(line) : /^\s*([A-Za-z_]\w*)\s*:?=\s*(.+)$/ .exec(line)
  return match ? { name: match[1], value: match[2] } : undefined
}

function splitArguments(value: string): string[] {
  const result: string[] = []; let start = 0; let depth = 0; let quote = ''
  for (let index = 0; index < value.length; index++) {
    const character = value[index]
    if (quote) { if (character === quote && value[index - 1] !== '\\') quote = ''; continue }
    if (character === '"' || character === "'") { quote = character; continue }
    if (character === '(' || character === '[' || character === '{') depth++
    if (character === ')' || character === ']' || character === '}') depth--
    if (character === ',' && depth === 0) { const item = value.slice(start, index).trim(); if (item) result.push(item); start = index + 1 }
  }
  const final = value.slice(start).trim(); if (final) result.push(final); return result
}

function calls(line: string, _language: 'python' | 'go'): Array<{ name: string; args: string[] }> {
  const result: Array<{ name: string; args: string[] }> = []; const pattern = /\b([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)?)\s*\(/g
  for (const match of line.matchAll(pattern)) {
    const open = (match.index ?? 0) + match[0].lastIndexOf('('); let depth = 0; let close = -1; let quote = ''
    for (let index = open; index < line.length; index++) {
      const character = line[index]
      if (quote) { if (character === quote && line[index - 1] !== '\\') quote = ''; continue }
      if (character === '"' || character === "'") { quote = character; continue }
      if (character === '(') depth++
      if (character === ')') { depth--; if (depth === 0) { close = index; break } }
    }
    if (close > open) result.push({ name: match[1], args: splitArguments(line.slice(open + 1, close)) })
  }
  return result
}

function sinkTainted(value: string, rule: FlowRule, tainted: Set<string>, sources: RegExp, language: 'python' | 'go'): boolean {
  if (rule.id === 'unsafe-deserialization') {
    if (language !== 'python') return false
    for (const call of calls(value, language)) {
      rule.sink.lastIndex = 0
      if (!rule.sink.test(`${call.name}(`)) continue
      // pickle has no safe loader mode. yaml.load is only in scope when the
      // call does not explicitly select the standard SafeLoader family.
      if (call.name === 'yaml.load' && call.args.some(argument => /(?:^|[.=])SafeLoader\b/.test(argument))) continue
      if (call.args[0] && expressionTainted(call.args[0], tainted, sources)) return true
    }
    return false
  }
  if (rule.id === 'sql-injection-query-construction') {
    for (const call of calls(value, language)) {
      rule.sink.lastIndex = 0
      if (!rule.sink.test(`${call.name}(`)) continue
      // Python DB-API methods take SQL text first. Go Context methods take a
      // context first and SQL text second; binding arguments stay untainted.
      const index = language === 'go' && /(?:QueryContext|ExecContext)$/.test(call.name) ? 1 : 0
      if (call.args[index] && expressionTainted(call.args[index], tainted, sources)) return true
    }
    return false
  }
  if (rule.id !== 'ssrf-request-sink') return expressionTainted(value, tainted, sources)
  for (const call of calls(value, language)) {
    rule.sink.lastIndex = 0
    if (!rule.sink.test(`${call.name}(`)) continue
    // Python request(method, url, ...) places its destination second; ordinary
    // get/post and Go http.Get/Post place it first. client.Do receives a request
    // object and is intentionally not treated as a proven URL flow here.
    const index = language === 'python' && /\.(?:request)$/.test(call.name) ? 1 : 0
    if (call.name === 'client.Do') continue
    if (call.args[index] && expressionTainted(call.args[index], tainted, sources)) return true
  }
  return false
}

function candidateKey(item: Candidate): string { return `${item.rule}:${item.file}:${item.line}:${item.excerpt}` }

function pythonFunctions(file: string, source: string): FlowFunction[] {
  const lines = source.split(/\r?\n/); const starts: Array<{ name: string; params: string[]; start: number; indent: number }> = []
  for (const [index, value] of lines.entries()) {
    const match = /^(\s*)(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(([^)]*)\)\s*(?:->[^:]+)?\s*:/.exec(value)
    if (!match) continue
    starts.push({ name: match[2], params: match[3].split(',').map(item => item.trim().replace(/=.*/, '').replace(/^[*]+/, '')).filter(item => /^[A-Za-z_]\w*$/.test(item)), start: index, indent: match[1].length })
  }
  return starts.map((item, index) => {
    let end = lines.length
    for (let cursor = item.start + 1; cursor < lines.length; cursor++) {
      const value = lines[cursor]; if (!value.trim() || /^\s*#/.test(value)) continue
      const indentation = value.match(/^\s*/)?.[0].length ?? 0
      if (indentation <= item.indent) { end = cursor; break }
    }
    return { id: `${file}:${item.name}`, file, name: item.name, params: item.params, start: item.start, end, lines: lines.slice(item.start, end) }
  })
}

function goFunctions(file: string, source: string): FlowFunction[] {
  const lines = source.split(/\r?\n/); const result: FlowFunction[] = []
  for (const [start, value] of lines.entries()) {
    const match = /^\s*func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*\(([^)]*)\)/.exec(value); if (!match) continue
    const params = match[2].split(',').map(item => item.trim().split(/\s+/)[0]).filter(item => /^[A-Za-z_]\w*$/.test(item)); let depth = 0; let opened = false; let end = start + 1
    for (let cursor = start; cursor < lines.length; cursor++) { for (const character of lines[cursor]) { if (character === '{') { depth++; opened = true }; if (character === '}') depth-- }; if (opened && depth === 0) { end = cursor + 1; break } }
    result.push({ id: `${file}:${match[1]}`, file, name: match[1], params, start, end, lines: lines.slice(start, end) })
  }
  return result
}

function pythonImports(file: string, source: string, known: Set<string>): { imports: Map<string, ImportTarget>; namespaces: Map<string, string> } {
  const imports = new Map<string, ImportTarget>(); const namespaces = new Map<string, string>()
  const resolveModule = (specifier: string): string | undefined => {
    const levels = /^\.+/.exec(specifier)?.[0].length ?? 0; const plain = specifier.slice(levels).replaceAll('.', '/')
    let base = dirname(file); for (let level = 1; level < levels; level++) base = dirname(base)
    const candidate = normalize(join(base, `${plain}.py`)); if (levels && known.has(candidate)) return candidate
    const modulePath = `${specifier.replace(/^\.+/, '').replaceAll('.', '/')}.py`; const matches = [...known].filter(path => path === modulePath || path.endsWith(`/${modulePath}`))
    return matches.length === 1 ? matches[0] : undefined
  }
  for (const line of source.split(/\r?\n/)) {
    const from = /^\s*from\s+([.A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s+import\s+(.+)$/.exec(line)
    if (from) { const target = resolveModule(from[1]); if (!target) continue; for (const part of from[2].split(',')) { const [exported, alias] = part.trim().split(/\s+as\s+/); if (/^[A-Za-z_]\w*$/.test(exported)) imports.set(alias ?? exported, { file: target, exported }) }; continue }
    const direct = /^\s*import\s+([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)(?:\s+as\s+([A-Za-z_]\w*))?/.exec(line)
    if (direct) { const target = resolveModule(direct[1]); if (target) namespaces.set(direct[2] ?? direct[1].split('.').at(-1)!, target) }
  }
  return { imports, namespaces }
}

function goPackage(source: string): string | undefined { return /^\s*package\s+([A-Za-z_]\w*)/m.exec(source)?.[1] }

function goImportReferences(source: string): Array<{ local?: string; path: string }> {
  const values: Array<{ local?: string; path: string }> = []
  const add = (line: string): void => {
    const match = /^\s*(?:(?:[A-Za-z_]\w*)|[._])?\s*"([^"]+)"\s*(?:\/\/.*)?$/.exec(line)
    if (!match) return
    const prefix = /^\s*([A-Za-z_]\w*|[._])\s+"/.exec(line)?.[1]
    if (prefix === '_' || prefix === '.') return
    values.push({ local: prefix, path: match[1] })
  }
  const block = /^\s*import\s*\(([^]*?)^\s*\)/m.exec(source)
  if (block) for (const line of block[1].split(/\r?\n/)) add(line)
  for (const line of source.split(/\r?\n/)) {
    const match = /^\s*import\s+(.+)$/.exec(line)
    if (match && !match[1].trimStart().startsWith('(')) add(match[1])
  }
  return values
}

function goImports(module: ParsedModule, modulePath: string | undefined, modules: Map<string, ParsedModule>): Map<string, string> {
  const namespaces = new Map<string, string>()
  if (!modulePath) return namespaces
  for (const imported of goImportReferences(module.source)) {
    if (!imported.path.startsWith(`${modulePath}/`)) continue
    const directory = normalize(imported.path.slice(modulePath.length + 1))
    const targets = [...modules.values()].filter(candidate => normalize(dirname(candidate.file)) === directory && Boolean(candidate.packageKey))
    const keys = [...new Set(targets.map(candidate => candidate.packageKey!))]
    if (keys.length !== 1) continue
    const local = imported.local ?? targets[0]?.packageKey?.split(':').at(-1)
    if (local) namespaces.set(local, keys[0])
  }
  return namespaces
}

function resolveCall(module: ParsedModule, call: string, functions: Map<string, FlowFunction>, language: 'python' | 'go'): FlowFunction | undefined {
  const [receiver, member] = call.includes('.') ? call.split('.', 2) : [undefined, call]
  if (language === 'python' && receiver) { const target = module.namespaces.get(receiver); return target ? functions.get(`${target}:${member}`) : undefined }
  if (language === 'go' && receiver) { const target = module.namespaces.get(receiver); return target ? functions.get(`${target}:${member}`) : undefined }
  if (!receiver) { const imported = module.imports.get(member); if (imported) return functions.get(`${imported.file}:${imported.exported}`); const local = functions.get(`${module.file}:${member}`); if (local) return local; if (language === 'go' && module.packageKey) return functions.get(`${module.packageKey}:${member}`) }
  return undefined
}

function summaries(modules: Map<string, ParsedModule>, functions: Map<string, FlowFunction>, language: 'python' | 'go', rules: FlowRule[], sources: RegExp): Map<string, Map<number, SinkResult[]>> {
  const summary = new Map<string, Map<number, SinkResult[]>>([...functions.values()].map(fn => [fn.id, new Map()]))
  const add = (fn: FlowFunction, index: number, sink: SinkResult): boolean => { const entries = summary.get(fn.id)?.get(index) ?? []; const key = `${sink.rule.id}:${sink.line}`; if (entries.some(item => `${item.rule.id}:${item.line}` === key)) return false; summary.get(fn.id)?.set(index, [...entries, sink]); return true }
  for (let pass = 0; pass < functions.size * Math.max(2, functions.size) + 1; pass++) {
    let changed = false
    for (const fn of functions.values()) for (const [index, parameter] of fn.params.entries()) {
      const tainted = new Set([parameter]); const assigns: Array<{ name: string; value: string }> = []
      for (const value of fn.lines) { const item = assignment(value, language); if (item) assigns.push(item) }
      for (let fixpoint = 0; fixpoint <= assigns.length; fixpoint++) { let propagated = false; for (const item of assigns) if (!tainted.has(item.name) && expressionTainted(item.value, tainted, sources)) { tainted.add(item.name); propagated = true }; if (!propagated) break }
      const module = modules.get(fn.file); if (!module) continue
      for (const [offset, value] of fn.lines.entries()) {
        for (const rule of rules) { rule.sink.lastIndex = 0; if (rule.sink.test(value) && sinkTainted(value, rule, tainted, sources, language)) changed = add(fn, index, { rule, line: fn.start + offset + 1, excerpt: value.trim().slice(0, 240) }) || changed }
        for (const call of calls(value, language)) { const target = resolveCall(module, call.name, functions, language); if (!target) continue; for (const [targetIndex] of target.params.entries()) if (call.args[targetIndex] && expressionTainted(call.args[targetIndex], tainted, sources)) for (const sink of summary.get(target.id)?.get(targetIndex) ?? []) changed = add(fn, index, sink) || changed }
      }
    }
    if (!changed) break
  }
  return summary
}

function graph(inputs: FlowModule[], language: 'python' | 'go'): FlowGraphAnalysis {
  const extension = language === 'python' ? '.py' : '.go'; const normalized = inputs.filter(input => input.file.endsWith(extension)).map(input => ({ ...input, file: normalize(input.file) })); const known = new Set(normalized.map(input => input.file)); const modules = new Map<string, ParsedModule>()
  for (const input of normalized) { const parsed = language === 'python' ? pythonFunctions(input.file, input.source) : goFunctions(input.file, input.source); const imports = language === 'python' ? pythonImports(input.file, input.source, known) : { imports: new Map<string, ImportTarget>(), namespaces: new Map<string, string>() }; const packageName = language === 'go' ? goPackage(input.source) : undefined; modules.set(input.file, { file: input.file, source: input.source, lines: input.source.split(/\r?\n/), functions: parsed, imports: imports.imports, namespaces: imports.namespaces, packageKey: packageName ? `${normalize(dirname(input.file))}:${packageName}` : undefined }) }
  if (language === 'go') for (const input of normalized) {
    const module = modules.get(input.file)
    if (module) module.namespaces = goImports(module, input.modulePath, modules)
  }
  const functions = new Map<string, FlowFunction>(); for (const module of modules.values()) for (const fn of module.functions) { functions.set(fn.id, fn); if (language === 'go' && module.packageKey) functions.set(`${module.packageKey}:${fn.name}`, fn) }
  const rules = language === 'python' ? PYTHON_RULES : GO_RULES; const sources = language === 'python' ? PYTHON_SOURCE : GO_SOURCE; const summary = summaries(modules, functions, language, rules, sources); const candidates: Candidate[] = []
  for (const module of modules.values()) {
    const tainted = new Set<string>(); const assigns: Array<{ name: string; value: string }> = []
    for (const value of module.lines) { const item = assignment(value, language); if (item) assigns.push(item) }
    for (let pass = 0; pass <= assigns.length; pass++) { let changed = false; for (const item of assigns) if (!tainted.has(item.name) && expressionTainted(item.value, tainted, sources)) { tainted.add(item.name); changed = true }; if (!changed) break }
    for (const [index, value] of module.lines.entries()) for (const call of calls(value, language)) {
      const target = resolveCall(module, call.name, functions, language); if (!target) continue
      for (const [parameter] of target.params.entries()) if (call.args[parameter] && expressionTainted(call.args[parameter], tainted, sources)) for (const sink of summary.get(target.id)?.get(parameter) ?? []) candidates.push(evidence(sink.rule, target.file, sink.line, sink.excerpt, `${language} cross-function data-flow`, { file: module.file, line: index + 1, excerpt: value.trim().slice(0, 240) }))
    }
  }
  const unique = new Map<string, Candidate>(); for (const item of candidates) unique.set(candidateKey(item), item); return { candidates: [...unique.values()] }
}

function local(source: string, file: string, language: 'python' | 'go'): Candidate[] {
  const rules = language === 'python' ? PYTHON_RULES : GO_RULES; const sources = language === 'python' ? PYTHON_SOURCE : GO_SOURCE; const lines = source.split(/\r?\n/); const tainted = new Set<string>(); const assigned: Array<{ name: string; value: string }> = []
  for (const value of lines) { const item = assignment(value, language); if (item) assigned.push(item) }
  for (let pass = 0; pass <= assigned.length; pass++) { let changed = false; for (const item of assigned) if (!tainted.has(item.name) && expressionTainted(item.value, tainted, sources)) { tainted.add(item.name); changed = true }; if (!changed) break }
  const candidates: Candidate[] = []; for (const [index, value] of lines.entries()) for (const rule of rules) { rule.sink.lastIndex = 0; if (rule.sink.test(value) && sinkTainted(value, rule, tainted, sources, language)) candidates.push(evidence(rule, file, index + 1, value.trim().slice(0, 240), `${language} local data-flow`)) }
  return candidates
}

export function analyzePythonFlow(source: string, file: string): Candidate[] { return local(source, file, 'python') }
export function analyzeGoFlow(source: string, file: string): Candidate[] { return local(source, file, 'go') }
export function analyzePythonModuleGraph(inputs: FlowModule[]): FlowGraphAnalysis { return graph(inputs, 'python') }
export function analyzeGoPackageGraph(inputs: FlowModule[]): FlowGraphAnalysis { return graph(inputs, 'go') }
