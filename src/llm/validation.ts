import type { Confidence } from '../contracts.js'

/**
 * Deep validation guidance engine, adapted from openai/codex-security
 * `skills/validation/references/validation-guidance.md` (Apache-2.0):
 * class-specific proof tuples, the validation rubric, the confidence
 * numerical ladder, and instance-preserving suppression rules. Pure
 * functions; no I/O.
 */

/** The minimal evidence set validation must establish for one vulnerability class. */
export interface ProofTuple {
  /** Stable class id used for routing. */
  id: string
  /** Attacker-controlled input / source that must be established. */
  attackerInput: string
  /** The control (sanitizer, guard, validator, allowlist) that must be examined. */
  control: string
  /** The dangerous sink, protected operation, or state transition. */
  sink: string
  /** The concrete security impact that must follow. */
  impact: string
  /** Optional class-specific note from validation-guidance.md. */
  note?: string
}

/** Class-specific proof tuples (validation-guidance.md "Use class-specific proof tuples", adapted). */
export const PROOF_TUPLES: Record<string, ProofTuple> = {
  'authz-tenant-object': {
    id: 'authz-tenant-object', attackerInput: 'attacker path and identity/tenant context', control: 'missing or wrong authentication, authorization, permission, tenant, or ownership guard',
    sink: 'protected object, protected comparison, or security-relevant state transition', impact: 'unauthorized access, privilege escalation, or protected-object mutation',
  },
  'injection-path': {
    id: 'injection-path', attackerInput: 'attacker-controlled bytes (query, path, upload, header, redirect target)', control: 'sanitizer, canonicalization, or allowlist result applied to the bytes',
    sink: 'dangerous sink or context (query grammar, filesystem, shell, header, redirect)', impact: 'injection, path traversal, file impact, header injection, or open redirect',
  },
  'xss-template': {
    id: 'xss-template', attackerInput: 'attacker-controlled value', control: 'escaping or template context handling',
    sink: 'browser sink or server-side template execution', impact: 'cross-site scripting or template/ssti execution',
  },
  'recursive-template': {
    id: 'recursive-template', attackerInput: 'request, tenant/client metadata, stored configuration, or error value', control: 'placeholder/template helper that recursively expands, re-parses, or evaluates resolved values; missing escape/non-recursive guard',
    sink: 'recursive expansion or evaluation', impact: 'XSS, expression execution, credential exfiltration, or code execution',
  },
  'deserialization-code-exec': {
    id: 'deserialization-code-exec', attackerInput: 'attacker-controlled serialized, code, or template bytes', control: 'unsafe loader/evaluator without safe-mode controls',
    sink: 'deserialization, evaluation, or object construction', impact: 'code execution or object-construction effect',
  },
  'deserializer-wrapper-control': {
    id: 'deserializer-wrapper-control', attackerInput: 'attacker-controlled, stored, plugin, remoting, import, or persisted-state serialized input', control: 'shared wrapper accepting type tags or default object construction; missing/misordered deny entry, allowlist gap, converter-priority gap, or unsafe class-loader/default-converter behavior',
    sink: 'object construction through the shared wrapper', impact: 'object construction, crash, code execution, or privilege-boundary impact',
  },
  'deserializer-codec': {
    id: 'deserializer-codec', attackerInput: 'attacker-controlled serialized or structured input', control: 'registered codec/converter/deserializer/container handler that recursively parses, resolves types, filters classes, converts values, or constructs objects; missing validation, unsafe fallback, fail-open filter, or unbounded traversal',
    sink: 'recursive parse, type resolution, conversion, or object construction', impact: 'code execution, object construction, parser confusion, denial of service, or privilege-boundary impact',
  },
  'ssrf': {
    id: 'ssrf', attackerInput: 'attacker-controlled destination (URL, URI, host, endpoint)', control: 'destination allow/deny/filter control and its bypass',
    sink: 'network client or server-side callback', impact: 'network/read/side-effect impact',
  },
  'ssrf-optional-filter': {
    id: 'ssrf-optional-filter', attackerInput: 'attacker-controlled download/webhook/callback URL', control: 'optional, empty-by-default, regex-only, pre-request-only, or redirect-following destination control',
    sink: 'internal/LAN/cloud-metadata/file-backed fetch or server-side callback side effect', impact: 'internal service access or side-effect impact',
  },
  'auth-token-protocol': {
    id: 'auth-token-protocol', attackerInput: 'attacker-controlled token, assertion, protocol metadata, or version value', control: 'exact validator/control semantics; mismatch between validated value and trusted value, incomplete canonicalization/equality, unchecked parsing, or missing binding',
    sink: 'authentication, authorization, or protocol decision', impact: 'authentication, authorization, or protocol-security impact',
  },
  'stateful-auth-transition': {
    id: 'stateful-auth-transition', attackerInput: 'attacker-controlled credentials, principal, token, issuer, assertion, server response, or protocol metadata', control: 'state transition after TLS upgrade, bind, redirect, callback, assertion validation, or IdP response; missing rebind/reauthentication, stale identity reuse, incomplete issuer/callback binding, or validated-vs-consumed mismatch',
    sink: 'post-transition credential identity binding', impact: 'authentication bypass or identity confusion',
  },
  'saml-assertion-binding': {
    id: 'saml-assertion-binding', attackerInput: 'attacker-controlled response or assertion set', control: 'protocol/signature validation of one object; later use, clone, serialization, or storage of a different assertion/document node',
    sink: 'session/token consumption of the wrong assertion', impact: 'authentication/session/token impact',
  },
  'sso-response-validator': {
    id: 'sso-response-validator', attackerInput: 'attacker-controlled SSO response containing one or more assertions', control: 'response/assertion validator that selects, indexes, clones, serializes, or returns an assertion; missing recipient/audience/destination/ACS binding',
    sink: 'session/token path consuming a different assertion', impact: 'authentication or authorization bypass',
  },
  'found-valid-mismatch': {
    id: 'found-valid-mismatch', attackerInput: 'attacker-controlled list or set of tokens/assertions/identities', control: 'validator loop or foundValid* flag proves one element while later fixed-index, first/last, clone, serialization, or lookup consumes another',
    sink: 'consumption of an unvalidated element', impact: 'authentication, authorization, or protocol-state impact',
  },
  'xml-parser-hardening': {
    id: 'xml-parser-hardening', attackerInput: 'attacker-controlled XML/SVG/XSLT/SAX/DOM/StAX input', control: 'parser factory, converter, transformer, or resolver setup; fail-open feature configuration, missing entity/DTD controls, caller-supplied parser path, or secure-processing-only hardening',
    sink: 'entity/DTD resolution during parse', impact: 'XXE, SSRF, file read, parser injection, or denial of service',
  },
  'query-parser-injection': {
    id: 'query-parser-injection', attackerInput: 'attacker-controlled bytes', control: 'query/selector/parser API receiving syntax or operators rather than bound values; later business check only limits confidence if it checks the same trusted object and defeats syntax control',
    sink: 'query/selector/parser evaluation', impact: 'read, write, authz, integrity, or availability impact',
  },
  'resource-path-control': {
    id: 'resource-path-control', attackerInput: 'attacker-controlled URL/path/resource name', control: 'allowlist/path-matcher/decoder/canonicalizer/resource-selection control; mismatch, pre-decode/post-decode gap, legacy handler behavior, or unsafe resolver fallback',
    sink: 'resource selection or filesystem access', impact: 'arbitrary file read/write, path traversal, or unauthorized resource access',
  },
  'shared-deserialization-control': {
    id: 'shared-deserialization-control', attackerInput: 'attacker-controlled or privilege-bearing serialized/config/import/plugin/remoting input', control: 'shared loader or converter/allowlist/denylist behavior; unsafe object construction or incomplete control',
    sink: 'shared loader/convert boundary', impact: 'unsafe object construction or incomplete control across affected callsites',
  },
  'protocol-version-parser': {
    id: 'protocol-version-parser', attackerInput: 'attacker-controlled protocol metadata', control: 'missing complete format enforcement before split/parse/compare',
    sink: 'protocol negotiation/comparison', impact: 'parse exception, wrong ordering, feature-gate bypass, or protocol-security impact',
  },
  'file-format-dos': {
    id: 'file-format-dos', attackerInput: 'untrusted document/archive/message parsed into a first-party object model', control: 'low-level array/dictionary/node/helper performing unchecked element conversion, recursion, numeric parsing, or unbounded iteration without validating attacker-controlled structure',
    sink: 'unchecked conversion/recursion/iteration', impact: 'crash, denial of service, parser confusion, or security-control bypass',
  },
  'file-format-primitive-helper': {
    id: 'file-format-primitive-helper', attackerInput: 'untrusted PDF/XML/YAML/archive/message/image/font/protocol structure', control: 'helper such as to*Array, toList, getObject, numeric conversion, parser/iterator, size-based allocation, unchecked cast, or loop over attacker-controlled nodes; missing type/size/shape validation',
    sink: 'object-model helper execution', impact: 'crash, denial of service, parser confusion, or security-control bypass',
  },
  'branch-operation-control': {
    id: 'branch-operation-control', attackerInput: 'request-selected operation or fallback branch', control: 'branch-local split/filter/canonicalize/type-resolution/object-binding line transforming attacker-controlled path/value differently from the shared path',
    sink: 'shared evaluator, binder, or security-sensitive mutation sink', impact: 'branch-specific control bypass',
  },
  'self-service-update-authz': {
    id: 'self-service-update-authz', attackerInput: 'authenticated or externally controlled identity and request object', control: 'update guard over protected profile/account/tenant fields; missing immutable-field, collection-alias, or subject/object binding check',
    sink: 'protected profile/account/tenant mutation', impact: 'account takeover, identity confusion, privilege escalation, or protected-object mutation',
  },
  'secret-data-exposure': {
    id: 'secret-data-exposure', attackerInput: 'secret or sensitive source', control: 'exposure/storage/log/client boundary and missing protection',
    sink: 'exposure, storage, log, or client boundary', impact: 'sensitive data disclosure; validate after high-impact classes unless it directly enables code execution, injection, privilege escalation, auth bypass, or sensitive cross-boundary impact',
  },
  'agent-mcp': {
    id: 'agent-mcp', attackerInput: 'untrusted instruction/data source', control: 'privileged tool/action boundary',
    sink: 'privileged tool or action execution', impact: 'action, code execution, or exfiltration effect',
  },
}

/** Generic fallback tuple for classes without a specific entry. */
export const GENERIC_PROOF_TUPLE: ProofTuple = {
  id: 'generic', attackerInput: 'attacker-controlled input', control: 'closest relevant security control', sink: 'sensitive sink or protected operation', impact: 'concrete security impact',
}

/** Route a candidate (by rule id / CWE) to its class-specific proof tuple. */
export function proofTupleFor(ruleId: string, cwe = ''): ProofTuple {
  const rule = ruleId.toLowerCase()
  const cweId = cwe.toUpperCase()
  if (rule.includes('sql') || rule.includes('nosql') || rule.includes('query') || cweId.startsWith('CWE-89') || cweId.startsWith('CWE-943')) return PROOF_TUPLES['query-parser-injection']
  if (rule.includes('path-traversal') || rule.includes('path') || rule.includes('traversal') || rule.includes('resource') || cweId.startsWith('CWE-22') || cweId.startsWith('CWE-23')) return PROOF_TUPLES['resource-path-control']
  if (rule.includes('ssrf') || rule.includes('request-sink') || cweId.startsWith('CWE-918')) return PROOF_TUPLES['ssrf']
  if (rule.includes('dynamic-code') || rule.includes('eval') || rule.includes('code-exec') || rule.includes('rce') || cweId.startsWith('CWE-94') || cweId.startsWith('CWE-95')) return PROOF_TUPLES['deserialization-code-exec']
  if (rule.includes('deserial') || rule.includes('unserialize') || rule.includes('objectinputstream') || rule.includes('binaryformatter') || rule.includes('pickle') || rule.includes('yaml.load') || cweId.startsWith('CWE-502')) return PROOF_TUPLES['deserializer-codec']
  if (rule.includes('tls') || rule.includes('jwt') || rule.includes('token') || rule.includes('assertion') || rule.includes('crypto') || cweId.startsWith('CWE-295') || cweId.startsWith('CWE-347')) return PROOF_TUPLES['auth-token-protocol']
  if (rule.includes('cors') || cweId.startsWith('CWE-942')) return PROOF_TUPLES['auth-token-protocol']
  if (rule.includes('xml') || rule.includes('xxe') || cweId.startsWith('CWE-611')) return PROOF_TUPLES['xml-parser-hardening']
  if (rule.includes('authorization') || rule.includes('auth') || rule.includes('idor') || rule.includes('access-control') || cweId.startsWith('CWE-862') || cweId.startsWith('CWE-863') || cweId.startsWith('CWE-639')) return PROOF_TUPLES['authz-tenant-object']
  if (rule.includes('weak-random') || rule.includes('randomness')) return PROOF_TUPLES['auth-token-protocol']
  if (rule.includes('credential') || rule.includes('secret') || rule.includes('key') || cweId.startsWith('CWE-798') || cweId.startsWith('CWE-256')) return PROOF_TUPLES['secret-data-exposure']
  if (rule.includes('prototype') || rule.includes('merge')) return PROOF_TUPLES['deserialization-code-exec']
  if (rule.includes('xss') || rule.includes('template') || rule.includes('ssti') || cweId.startsWith('CWE-79')) return PROOF_TUPLES['xss-template']
  if (rule.includes('shell') || rule.includes('command') || cweId.startsWith('CWE-78') || cweId.startsWith('CWE-77')) return PROOF_TUPLES['injection-path']
  if (rule.includes('agent') || rule.includes('mcp')) return PROOF_TUPLES['agent-mcp']
  return GENERIC_PROOF_TUPLE
}

/** One validation criterion for the rubric. */
export interface RubricCriterion { criterion: string; kind: 'proof-tuple' | 'realistic-interface' | 'control' | 'counterevidence' | 'impact' }

/** Build a bounded validation rubric (up to five criteria) from the proof tuple. */
export function buildValidationRubric(input: { ruleId: string; cwe?: string; title?: string; hasReachableInterface?: boolean; sourceLocations?: number }): RubricCriterion[] {
  const tuple = proofTupleFor(input.ruleId, input.cwe ?? '')
  const criteria: RubricCriterion[] = [
    { criterion: `Establish the attacker-controlled source: ${tuple.attackerInput}.`, kind: 'proof-tuple' },
    { criterion: `Examine the closest control and prove or refute it: ${tuple.control}.`, kind: 'control' },
    { criterion: `Show the value reaching the sink or protected operation: ${tuple.sink}.`, kind: 'proof-tuple' },
    { criterion: `State the concrete impact and the strongest counterevidence: ${tuple.impact}.`, kind: 'impact' },
  ]
  if (input.hasReachableInterface === true) criteria.push({ criterion: 'Reproduce through the realistic user-reachable interface (HTTP/CLI/message/file) when feasible.', kind: 'realistic-interface' })
  if (criteria.length < 5 && (input.sourceLocations ?? 0) > 0) criteria.push({ criterion: 'Keep exact source/sink line evidence for the affected locations; suppress only with per-instance counterevidence.', kind: 'counterevidence' })
  return criteria.slice(0, 5)
}

/** Evidence ladder strength for the confidence calibration. */
export interface ValidationEvidence { reproducedCrash: boolean; sanitizerReproduction: boolean; debuggerTrace: boolean; focusedTest: boolean; realisticInterface: boolean; sourceTrace: boolean; counterevidenceDefeats: boolean }

/** Numerical confidence from the strongest evidence actually obtained (validation-guidance.md). */
export function confidenceScore(evidence: ValidationEvidence): number {
  if (evidence.counterevidenceDefeats) return 0
  if (evidence.reproducedCrash) return 1
  if (evidence.sanitizerReproduction) return 0.9
  if (evidence.debuggerTrace) return 0.8
  if (evidence.realisticInterface || evidence.focusedTest) return 0.6
  if (evidence.sourceTrace) return 0.3
  return 0.3
}

export function confidenceFromScore(score: number): Confidence {
  if (score >= 0.8) return 'high'
  if (score >= 0.4) return 'medium'
  return 'low'
}

/** Instance-preserving suppression facts (validation-guidance.md). */
export interface SuppressionFacts {
  /** A seeded advisory/tag row: must close that exact row; same-family neighbors are supporting evidence, not counterevidence. */
  seededRow: boolean
  /** Multiple instances share a family: each instance must survive or be suppressed separately. */
  siblingInstance: boolean
  /** The exact counterevidence control that defeats this specific instance. */
  exactCounterevidenceControl?: string
  /** A missing downstream caller/deployment/artifact fact is a proof gap, not counterevidence. */
  missingExternalFact: boolean
  /** The high-impact candidate is blocked only by a missing consumer/fact and no bounded adjacency pass ran. */
  adjacencyPassRan: boolean
}

/** Decide whether an instance-preserving suppression is allowed. */
export function suppressionAllowed(facts: SuppressionFacts): { allowed: boolean; reason: string } {
  if (facts.missingExternalFact && !facts.adjacencyPassRan) return { allowed: false, reason: 'A missing downstream caller, deployment fact, or artifact-provenance fact is a proof gap or a reason to run a bounded adjacency pass, not counterevidence.' }
  if (facts.seededRow && !facts.exactCounterevidenceControl) return { allowed: false, reason: 'A seeded advisory/tag row must be closed with exact local evidence; a same-family neighbor is supporting evidence, not counterevidence.' }
  if (facts.siblingInstance && !facts.exactCounterevidenceControl) return { allowed: false, reason: 'Each instance must be suppressed with the exact control that makes that instance safe; a safe sibling does not suppress a vulnerable sibling.' }
  return { allowed: true, reason: 'Exact per-instance counterevidence is present.' }
}
