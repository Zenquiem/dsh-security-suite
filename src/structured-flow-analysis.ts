import { dirname, normalize } from 'node:path'
import type { Evidence, Severity } from './contracts.js'
import type { Candidate } from './scanner.js'

type Language = 'java' | 'csharp' | 'php' | 'ruby' | 'c' | 'cpp' | 'rust'
type Boundary = 'brace' | 'ruby'

interface Rule { id: string; cwe: string; severity: Severity; rationale: string; sink: RegExp }
interface ModuleInput { file: string; source: string }
interface FunctionRecord { id: string; file: string; name: string; params: string[]; start: number; lines: string[] }
interface ModuleRecord { file: string; lines: string[]; functions: FunctionRecord[] }
interface Sink { rule: Rule; line: number; excerpt: string }

export interface StructuredFlowAnalysis { candidates: Candidate[] }

const RULES: Record<Language, Rule[]> = {
  java: [
    { id: 'shell-command-construction', cwe: 'CWE-78', severity: 'high', rationale: 'Request-derived data reaches a Java process execution API.', sink: /\b(?:Runtime\.getRuntime\(\)\.exec|ProcessBuilder)\s*\(/ },
    { id: 'path-traversal-sink', cwe: 'CWE-22', severity: 'medium', rationale: 'Request-derived data reaches a Java filesystem API.', sink: /\b(?:Files\.(?:readAllBytes|readString|write|newInputStream|newOutputStream)|new\s+FileInputStream|new\s+FileOutputStream)\s*\(/ },
    { id: 'ssrf-request-sink', cwe: 'CWE-918', severity: 'medium', rationale: 'Request-derived data reaches a Java outbound request API.', sink: /\b(?:new\s+URL|URI\.create|RestTemplate\.(?:getForObject|exchange))\s*\(/ },
    { id: 'sql-injection-query-construction', cwe: 'CWE-89', severity: 'high', rationale: 'Request-derived data reaches a Java SQL query-text API.', sink: /\b(?:statement|connection|jdbcTemplate|entityManager)\.(?:execute|executeQuery|executeUpdate|query|createNativeQuery)\s*\(/i },
  ],
  csharp: [
    { id: 'shell-command-construction', cwe: 'CWE-78', severity: 'high', rationale: 'Request-derived data reaches a .NET process execution API.', sink: /\bProcess\.Start\s*\(/ },
    { id: 'path-traversal-sink', cwe: 'CWE-22', severity: 'medium', rationale: 'Request-derived data reaches a .NET filesystem API.', sink: /\b(?:File\.(?:ReadAllText|ReadAllBytes|WriteAllText|Open)|Directory\.(?:GetFiles|Delete))\s*\(/ },
    { id: 'ssrf-request-sink', cwe: 'CWE-918', severity: 'medium', rationale: 'Request-derived data reaches a .NET outbound request API.', sink: /\b(?:HttpClient\.)?(?:GetAsync|GetStringAsync|PostAsync|SendAsync)\s*\(/ },
    { id: 'sql-injection-query-construction', cwe: 'CWE-89', severity: 'high', rationale: 'Request-derived data reaches a .NET SQL query-text API.', sink: /\b(?:command|connection|db|context)\.(?:Execute|ExecuteNonQuery|ExecuteScalar|Query|SqlQuery)\s*\(/i },
  ],
  php: [
    { id: 'shell-command-construction', cwe: 'CWE-78', severity: 'high', rationale: 'Request-derived data reaches a PHP command execution API.', sink: /\b(?:system|exec|shell_exec|passthru|popen|proc_open)\s*\(/ },
    { id: 'path-traversal-sink', cwe: 'CWE-22', severity: 'medium', rationale: 'Request-derived data reaches a PHP filesystem API.', sink: /\b(?:file_get_contents|file_put_contents|fopen|unlink|readfile)\s*\(/ },
    { id: 'ssrf-request-sink', cwe: 'CWE-918', severity: 'medium', rationale: 'Request-derived data selects a PHP network destination.', sink: /\b(?:curl_setopt|file_get_contents)\s*\(/ },
    { id: 'sql-injection-query-construction', cwe: 'CWE-89', severity: 'high', rationale: 'Request-derived data reaches a PHP SQL query-text API.', sink: /\b(?:pdo|db|database|connection|stmt)\s*->\s*(?:query|exec|prepare)\s*\(/i },
  ],
  ruby: [
    { id: 'shell-command-construction', cwe: 'CWE-78', severity: 'high', rationale: 'Request-derived data reaches a Ruby command execution API.', sink: /\b(?:system|exec|spawn|Open3\.(?:capture2|capture3|popen3))\s*\(/ },
    { id: 'path-traversal-sink', cwe: 'CWE-22', severity: 'medium', rationale: 'Request-derived data reaches a Ruby filesystem API.', sink: /\b(?:File\.(?:read|write|open|delete)|IO\.read)\s*\(/ },
    { id: 'ssrf-request-sink', cwe: 'CWE-918', severity: 'medium', rationale: 'Request-derived data selects a Ruby outbound request destination.', sink: /\b(?:Net::HTTP\.(?:get|get_response|post)|URI\.open)\s*\(/ },
    { id: 'sql-injection-query-construction', cwe: 'CWE-89', severity: 'high', rationale: 'Request-derived data reaches a Ruby SQL query-text API.', sink: /\b(?:connection|db|database)\.(?:execute|exec_query|select_all|find_by_sql)\s*\(/i },
  ],
  c: [
    { id: 'shell-command-construction', cwe: 'CWE-78', severity: 'high', rationale: 'Externally controlled data reaches a native process execution API.', sink: /\b(?:system|popen|execl|execv|execve)\s*\(/ },
    { id: 'path-traversal-sink', cwe: 'CWE-22', severity: 'medium', rationale: 'Externally controlled data reaches a native filesystem API.', sink: /\b(?:fopen|open|unlink|remove)\s*\(/ },
    { id: 'sql-injection-query-construction', cwe: 'CWE-89', severity: 'high', rationale: 'Externally controlled data reaches a native SQL query-text API.', sink: /\b(?:sqlite3_exec|mysql_query|PQexec)\s*\(/ },
  ],
  cpp: [
    { id: 'shell-command-construction', cwe: 'CWE-78', severity: 'high', rationale: 'Externally controlled data reaches a native process execution API.', sink: /\b(?:system|popen|execl|execv|execve)\s*\(/ },
    { id: 'path-traversal-sink', cwe: 'CWE-22', severity: 'medium', rationale: 'Externally controlled data reaches a native filesystem API.', sink: /\b(?:fopen|open|std::filesystem::remove)\s*\(/ },
    { id: 'sql-injection-query-construction', cwe: 'CWE-89', severity: 'high', rationale: 'Externally controlled data reaches a native SQL query-text API.', sink: /\b(?:sqlite3_exec|mysql_query|PQexec)\s*\(/ },
  ],
  rust: [
    { id: 'shell-command-construction', cwe: 'CWE-78', severity: 'high', rationale: 'Request-derived data reaches a Rust process execution API.', sink: /\b(?:std::process::)?Command::new\s*\(/ },
    { id: 'path-traversal-sink', cwe: 'CWE-22', severity: 'medium', rationale: 'Request-derived data reaches a Rust filesystem API.', sink: /\b(?:std::fs::)?(?:read|read_to_string|write|remove_file|File::open)\s*\(/ },
    { id: 'ssrf-request-sink', cwe: 'CWE-918', severity: 'medium', rationale: 'Request-derived data selects a Rust outbound request destination.', sink: /\b(?:reqwest::)?(?:get|Client::new\(\)\.(?:get|post|request))\s*\(/ },
    { id: 'sql-injection-query-construction', cwe: 'CWE-89', severity: 'high', rationale: 'Request-derived data reaches a Rust SQL query-text API.', sink: /\b(?:client|conn|connection|pool)\.(?:query|execute|batch_execute)\s*\(/i },
  ],
}

const SOURCES: Record<Language, RegExp> = {
  java: /\b(?:request\.(?:getParameter|getHeader|getQueryString|getPathInfo|getInputStream)|ServletRequest\.)/i,
  csharp: /\b(?:Request\.(?:Query|Form|Body|Headers|Path)|HttpContext\.Request\.)/,
  php: /\$_(?:GET|POST|REQUEST|COOKIE|FILES)\b/,
  ruby: /\b(?:params\s*(?:\[|\.fetch)|request\.(?:params|body|query_parameters))/,
  c: /\b(?:argv\s*\[|getenv\s*\(|get_param\s*\(|request_get\s*\()/,
  cpp: /\b(?:argv\s*\[|getenv\s*\(|get_param\s*\(|request_get\s*\()/,
  rust: /\b(?:req|request)\s*\.\s*(?:query|param|path|body|json|form)\s*\(|\b(?:Query|Path|Json|Form)\s*\(/i,
}

const BOUNDARIES: Record<Language, Boundary> = { java: 'brace', csharp: 'brace', php: 'brace', ruby: 'ruby', c: 'brace', cpp: 'brace', rust: 'brace' }
const EXTENSIONS: Record<Language, string[]> = { java: ['.java'], csharp: ['.cs'], php: ['.php'], ruby: ['.rb'], c: ['.c'], cpp: ['.cc', '.cpp'], rust: ['.rs'] }
const KEYWORDS = new Set(['if', 'for', 'while', 'switch', 'catch', 'foreach', 'using', 'return', 'new', 'function', 'def'])

function escaped(value: string): string { return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') }
function sourceTainted(value: string, tainted: Set<string>, source: RegExp): boolean { if (/^(?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')$/.test(value.trim())) return false; source.lastIndex = 0; return source.test(value) || [...tainted].some(name => new RegExp(`\\b${escaped(name)}\\b`).test(value)) }
function variableAssignment(value: string, language: Language): { name: string; expression: string } | undefined {
  const match = language === 'php' ? /^\s*\$([A-Za-z_]\w*)\s*=\s*(.+?);?\s*$/.exec(value) : /^\s*(?:[A-Za-z_][\w<>\[\],?*:\s]*\s+)?([A-Za-z_]\w*)\s*=\s*(.+?);?\s*$/.exec(value)
  return match ? { name: match[1], expression: match[2] } : undefined
}

function splitArguments(value: string): string[] {
  const result: string[] = []; let start = 0; let depth = 0; let quote = ''
  for (let index = 0; index < value.length; index++) { const character = value[index]; if (quote) { if (character === quote && value[index - 1] !== '\\') quote = ''; continue }; if (character === '"' || character === "'") { quote = character; continue }; if ('([{'.includes(character)) depth++; if (')]}'.includes(character)) depth--; if (character === ',' && depth === 0) { const item = value.slice(start, index).trim(); if (item) result.push(item); start = index + 1 } }
  const last = value.slice(start).trim(); if (last) result.push(last); return result
}

function calls(value: string): Array<{ name: string; args: string[] }> {
  const results: Array<{ name: string; args: string[] }> = []; const pattern = /\b(?:[A-Za-z_]\w*(?:::\w+|\.\w+)*\.)?([A-Za-z_]\w*)\s*\(/g
  for (const match of value.matchAll(pattern)) { const open = (match.index ?? 0) + match[0].lastIndexOf('('); let depth = 0; let quote = ''; let close = -1; for (let index = open; index < value.length; index++) { const character = value[index]; if (quote) { if (character === quote && value[index - 1] !== '\\') quote = ''; continue }; if (character === '"' || character === "'") { quote = character; continue }; if (character === '(') depth++; if (character === ')') { depth--; if (depth === 0) { close = index; break } } }; if (close > open) results.push({ name: match[1], args: splitArguments(value.slice(open + 1, close)) }) }
  return results
}

function sinkTainted(value: string, rule: Rule, tainted: Set<string>, source: RegExp, language: Language): boolean {
  if (rule.id === 'sql-injection-query-construction') {
    rule.sink.lastIndex = 0
    if (!rule.sink.test(value)) return false
    for (const call of calls(value)) {
      const queryMethods = new Set(['execute', 'executeQuery', 'executeUpdate', 'query', 'createNativeQuery', 'Execute', 'ExecuteNonQuery', 'ExecuteScalar', 'Query', 'SqlQuery', 'exec', 'prepare', 'exec_query', 'select_all', 'find_by_sql', 'sqlite3_exec', 'mysql_query', 'PQexec', 'batch_execute'])
      if (!queryMethods.has(call.name)) continue
      // C APIs include a connection handle before SQL text; all other supported
      // APIs accept query text first. Parameter/bind values remain unproven.
      const index = (language === 'c' || language === 'cpp') && ['sqlite3_exec', 'mysql_query', 'PQexec'].includes(call.name) ? 1 : 0
      if (call.args[index] && sourceTainted(call.args[index], tainted, source)) return true
    }
    return false
  }
  if (rule.id !== 'ssrf-request-sink') {
    rule.sink.lastIndex = 0
    return rule.sink.test(value) && sourceTainted(value, tainted, source)
  }
  rule.sink.lastIndex = 0
  if (!rule.sink.test(value)) return false
  for (const call of calls(value)) {
    const names: Record<Language, Set<string>> = {
      java: new Set(['URL', 'create', 'getForObject', 'exchange']), csharp: new Set(['GetAsync', 'GetStringAsync', 'PostAsync', 'SendAsync']),
      php: new Set(['curl_setopt', 'file_get_contents']), ruby: new Set(['get', 'get_response', 'post', 'open']), c: new Set(), cpp: new Set(), rust: new Set(['get', 'post', 'request']),
    }
    if (!names[language].has(call.name)) continue
    // curl_setopt(handle, CURLOPT_URL, value) is the sole supported sink whose
    // destination is not first. Request-object APIs stay unresolved by design.
    if (language === 'php' && call.name === 'curl_setopt') {
      if (/CURLOPT_URL/.test(call.args[1] ?? '') && call.args[2] && sourceTainted(call.args[2], tainted, source)) return true
      continue
    }
    if ((language === 'csharp' && call.name === 'SendAsync') || (language === 'rust' && call.name === 'request')) continue
    if (call.args[0] && sourceTainted(call.args[0], tainted, source)) return true
  }
  return false
}

function paramNames(value: string, language?: Language): string[] {
  if (language === 'rust') return value.split(',').map(item => item.trim().replace(/^&(?:mut\s+)?/, '').replace(/^mut\s+/, '').match(/^([A-Za-z_]\w*)\s*(?::|$)/)?.[1] ?? '').filter(item => /^[A-Za-z_]\w*$/.test(item) && item !== 'self')
  return value.split(',').map(item => (item.match(/\$?[A-Za-z_]\w*\s*(?:=[^,]*)?$/)?.[0] ?? '').replace(/^\$/, '').replace(/\s*=.*$/, '').trim()).filter(item => /^[A-Za-z_]\w*$/.test(item))
}
function declaration(value: string, language: Language): { name: string; params: string[] } | undefined {
  const ruby = /^\s*def\s+([A-Za-z_]\w*[!?=]?)\s*(?:\(([^)]*)\)|(.*))\s*$/.exec(value)
  if (language === 'ruby') return ruby ? { name: ruby[1], params: paramNames(ruby[2] ?? ruby[3] ?? '') } : undefined
  const php = /^\s*(?:public|private|protected|static|final|abstract|\s)*function\s+([A-Za-z_]\w*)\s*\(([^)]*)\)\s*\{/.exec(value)
  if (language === 'php') return php ? { name: php[1], params: paramNames(php[2]) } : undefined
  const rust = /^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+([A-Za-z_]\w*)\s*(?:<[^>{}]*>)?\s*\(([^)]*)\)\s*(?:->\s*[^\{]+)?\{/.exec(value)
  if (language === 'rust') return rust ? { name: rust[1], params: paramNames(rust[2], language) } : undefined
  const match = /^\s*(?:[A-Za-z_][\w<>\[\],?*:\s]*\s+)?([A-Za-z_]\w*)\s*\(([^;{}]*)\)\s*(?:throws\s+[\w,\s]+)?\{/.exec(value)
  if (!match || KEYWORDS.has(match[1])) return undefined
  return { name: match[1], params: paramNames(match[2], language) }
}

function functions(file: string, source: string, language: Language): FunctionRecord[] {
  const lines = source.split(/\r?\n/); const result: FunctionRecord[] = []
  for (const [start, value] of lines.entries()) { const item = declaration(value, language); if (!item) continue; let end = lines.length
    if (BOUNDARIES[language] === 'ruby') { let nested = 0; for (let cursor = start + 1; cursor < lines.length; cursor++) { if (/^\s*def\b/.test(lines[cursor])) nested++; if (/^\s*end\b/.test(lines[cursor])) { if (nested-- === 0) { end = cursor + 1; break } } } } else { let depth = 0; let opened = false; for (let cursor = start; cursor < lines.length; cursor++) { for (const character of lines[cursor]) { if (character === '{') { depth++; opened = true }; if (character === '}') depth-- }; if (opened && depth === 0) { end = cursor + 1; break } } }
    result.push({ id: `${file}:${item.name}`, file, name: item.name, params: item.params, start, lines: lines.slice(start, end) })
  }
  return result
}

function candidate(rule: Rule, file: string, line: number, excerpt: string, language: Language, propagation?: { file: string; line: number; excerpt: string }): Candidate {
  const detail = `${language} structured function data-flow`; const evidence: Evidence[] = [{ kind: 'pattern', detail: `${detail} resolved sensitive operation for ${rule.id}.`, location: { file, line, excerpt, role: 'sink' } }, { kind: 'context', detail: `${detail} resolved request-derived data in the sensitive operation.`, location: propagation ? { ...propagation, role: 'propagation' } : { file, line, excerpt, role: 'entrypoint' } }]
  return { rule: rule.id, severity: rule.severity, file, line, excerpt, rationale: rule.rationale, cwe: rule.cwe, evidence }
}

/** Trace parameter-to-sink flows through local functions of one language and directory. */
export function analyzeStructuredFlow(inputs: ModuleInput[], language: Language): StructuredFlowAnalysis {
  const allowed = new Set(EXTENSIONS[language]); const modules = new Map<string, ModuleRecord>(); for (const input of inputs.filter(item => allowed.has(item.file.slice(item.file.lastIndexOf('.'))))) { const file = normalize(input.file); const lines = input.source.split(/\r?\n/); modules.set(file, { file, lines, functions: functions(file, input.source, language) }) }
  const byId = new Map<string, FunctionRecord>(); const byDirectory = new Map<string, Map<string, FunctionRecord>>(); for (const module of modules.values()) { const local = new Map<string, FunctionRecord>(); for (const fn of module.functions) { byId.set(fn.id, fn); local.set(fn.name, fn) }; byDirectory.set(dirname(module.file), local) }
  const lookup = (file: string, name: string): FunctionRecord | undefined => byDirectory.get(dirname(file))?.get(name)
  const summaries = new Map<string, Map<number, Sink[]>>([...byId.values()].map(fn => [fn.id, new Map()])); const rules = RULES[language]; const source = SOURCES[language]
  const add = (fn: FunctionRecord, index: number, sink: Sink): boolean => { const values = summaries.get(fn.id)?.get(index) ?? []; const key = `${sink.rule.id}:${sink.line}`; if (values.some(item => `${item.rule.id}:${item.line}` === key)) return false; summaries.get(fn.id)?.set(index, [...values, sink]); return true }
  for (let pass = 0; pass < byId.size * Math.max(2, byId.size) + 1; pass++) {
    let changed = false
    for (const fn of byId.values()) for (const [parameterIndex, parameter] of fn.params.entries()) {
      const tainted = new Set([parameter])
      const assignments = fn.lines.map(value => variableAssignment(value, language)).filter((item): item is { name: string; expression: string } => Boolean(item))
      for (let round = 0; round <= assignments.length; round++) {
        let propagated = false
        for (const item of assignments) if (!tainted.has(item.name) && sourceTainted(item.expression, tainted, source)) { tainted.add(item.name); propagated = true }
        if (!propagated) break
      }
      for (const [offset, value] of fn.lines.entries()) {
        for (const rule of rules) if (sinkTainted(value, rule, tainted, source, language)) changed = add(fn, parameterIndex, { rule, line: fn.start + offset + 1, excerpt: value.trim().slice(0, 240) }) || changed
        for (const call of calls(value)) {
          const target = lookup(fn.file, call.name); if (!target) continue
          for (const [targetIndex] of target.params.entries()) if (call.args[targetIndex] && sourceTainted(call.args[targetIndex], tainted, source)) for (const sink of summaries.get(target.id)?.get(targetIndex) ?? []) changed = add(fn, parameterIndex, sink) || changed
        }
      }
    }
    if (!changed) break
  }
  const candidates: Candidate[] = []; for (const module of modules.values()) { const tainted = new Set<string>(); const assignments = module.lines.map(value => variableAssignment(value, language)).filter((item): item is { name: string; expression: string } => Boolean(item)); for (let round = 0; round <= assignments.length; round++) { let propagated = false; for (const item of assignments) if (!tainted.has(item.name) && sourceTainted(item.expression, tainted, source)) { tainted.add(item.name); propagated = true }; if (!propagated) break }
    for (const [line, value] of module.lines.entries()) for (const call of calls(value)) { const target = lookup(module.file, call.name); if (!target) continue; for (const [parameterIndex] of target.params.entries()) if (call.args[parameterIndex] && sourceTainted(call.args[parameterIndex], tainted, source)) for (const sink of summaries.get(target.id)?.get(parameterIndex) ?? []) candidates.push(candidate(sink.rule, target.file, sink.line, sink.excerpt, language, { file: module.file, line: line + 1, excerpt: value.trim().slice(0, 240) })) }
  }
  const unique = new Map<string, Candidate>(); for (const item of candidates) unique.set(`${item.rule}:${item.file}:${item.line}:${item.excerpt}`, item); return { candidates: [...unique.values()] }
}

export type StructuredLanguage = Language
