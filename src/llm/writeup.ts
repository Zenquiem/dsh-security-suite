/**
 * Vulnerability report format engine, adapted from openai/codex-security
 * `skills/vulnerability-writeup/references/report-format.md` and the
 * single-finding drafting prompt (Apache-2.0): the seven required headings,
 * section-order validation, the drafting prompt template, and the report
 * acceptance checklist. Pure functions; no I/O.
 */

/** The seven required report headings in order (report-format.md). */
export const WRITEUP_SECTIONS: ReadonlyArray<{ heading: string; purpose: string }> = [
  { heading: '## Executive Summary', purpose: 'Component, assessed software version, attacker position, required configuration, vulnerable operation, narrowest demonstrated impact; verified first affected release and fixed release when established.' },
  { heading: '## Background', purpose: 'Only the component behavior, named actors, controlled values, ownership, permission boundaries, and expected security behavior needed to understand the report.' },
  { heading: '## Vulnerability Details', purpose: 'The claimed trigger sequence in causal order: Mallory\'s actual controlled input, each material check/state change, and the source lines where the expected behavior is not enforced.' },
  { heading: '## Exploitability Analysis', purpose: 'The narrow primitive the evidence actually establishes, which account/privilege/tenant/process boundary it crosses under the verified preconditions, and qualified stronger routes.' },
  { heading: '## Proof of Concept', purpose: 'Real PoC artifacts, target requirements, build steps, execution safety, and the expected state; observed output only when observed.' },
  { heading: '## Remediation', purpose: 'Plain-English statement of what the fixed code must do differently, with suggested regression coverage.' },
  { heading: '## Summary', purpose: 'Restatement of verified preconditions, the actual security failure, affected versions, and demonstrated impact without escalation.' },
]

/** Validate that a written report contains the seven headings in order. */
export function validateWriteupSections(markdown: string): { valid: boolean; errors: string[] } {
  const errors: string[] = []
  let position = -1
  const lines = markdown.split(/\r?\n/)
  for (const section of WRITEUP_SECTIONS) {
    const found = lines.findIndex((line, index) => index > position && line.trim() === section.heading)
    if (found === -1) { errors.push(`Missing required section: ${section.heading}`); continue }
    position = found
  }
  return { valid: errors.length === 0, errors }
}

/** The drafting prompt (vulnerability-writeup single-finding drafting prompt, adapted). */
export function draftingPrompt(input: { slug: string; rawFindingPaths: string[]; sourceRoot?: string; revision?: string; affectedVersions?: string; pocPaths: string[]; reportDirectory: string; language?: string }): string {
  return `Write one self-contained vulnerability disclosure report for ${input.slug}.

You own exactly one finding. Follow the seven required report headings in order: Executive Summary, Background, Vulnerability Details, Exploitability Analysis, Proof of Concept, Remediation, Summary.

Inputs:
- Raw finding and rough report: ${input.rawFindingPaths.join(', ') || 'supplied in this prompt'}
${input.sourceRoot ? `- Source root and pinned revision: ${input.sourceRoot}${input.revision ? ` at ${input.revision}` : ''}; never put the author-machine path in the report` : '- Source: unavailable; keep every source-dependent conclusion visibly conditional and never invent an excerpt or line citation'}
${input.affectedVersions ? `- Assessed release and verified affected versions: ${input.affectedVersions}` : ''}
- Existing PoC, logs and negative controls: ${input.pocPaths.join(', ') || 'none'}
- Report output directory: ${input.reportDirectory}

Treat the supplied finding as a hypothesis. Trace the actual attacker-controlled entry point, the reported state change, existing checks, and the real sink. Open with the actual attack in ordinary language and say what it is not. Name the attacker's legitimate starting credential or input, the separate service, owner, or policy crossed, and the concrete protected sink reached. Put the complete tested prerequisites near the beginning and distinguish defaults from configured features without guessing prevalence.

When source and release history are available, trace when the vulnerable behaviour first appeared and inspect the relevant released versions, fixing change, and backports. Never guess affected versions, prevalence, CVSS, reliability, patch status, or runtime results. Clearly separate the earliest verified vulnerable version from an unproven first affected release.

Before stating impact, challenge deployment assumptions, attacker privileges, cancellation, locks, cleanup, ordering, negative controls, and alternative explanations. Say exactly which claims are established, which remain plausible, and which the source contradicts. If the vulnerability does not hold, report the contradiction; do not manufacture a disclosure.

Use ${input.language ?? 'the user\'s requested language'} with a calm researcher-to-researcher voice. Use "we" naturally to guide the walkthrough; use "I" only to state the exact source review, builds, observations, experiments, or limitations that actually occurred. Never call evidence a "witness"; tell the reader what it actually is and what it proves.

Include a real PoC only when available or safely and explicitly authorized. Separate exact source review, inspected PoC code, syntax or build checks, actual runs, preserved records, and expected-but-unobserved behaviour. Include observed output only when observed; otherwise label the expected result and explain the missing execution condition.

Never copy an author-machine-specific absolute path into the report, PoC, build recipe, screenshots, logs, or output. Before returning, reread the report against the PoC, fix, and any available exact source and release history, and remove generic filler, unsupported certainty, jargon, inconsistent actor names, and claims the artefacts cannot support.`
}

/** The report acceptance checklist (report-format.md acceptance, adapted). */
export function reportAcceptanceChecklist(): Array<{ id: string; check: string }> {
  return [
    { id: 'audience', check: 'A new reader can understand the component, named actors, and relevant security boundary.' },
    { id: 'scope', check: 'Verified release, configuration, attacker preconditions, and affected-version history are accurately bounded.' },
    { id: 'trigger', check: 'Source establishes the same trigger sequence and security failure described (or report-only with every source-dependent claim conditional).' },
    { id: 'excerpts', check: 'Every excerpt is exact, attributed to a repository-relative path and verified software version, necessary, and explained.' },
    { id: 'evidence', check: 'Source proof, inference, reported claims, and runtime observation are distinguishable.' },
    { id: 'controls', check: 'Meaningful guards, negative controls, and alternative explanations are handled.' },
    { id: 'calibration', check: 'Impact, exploit reliability, affected versions, and deployment prevalence are no stronger than the evidence.' },
    { id: 'poc', check: 'PoC, commands, output, and cleanup reflect real artifacts and actual verification; unobserved results are labeled expected.' },
    { id: 'remediation', check: 'Remediation explains in plain English what the code must do differently and suggests regression coverage.' },
    { id: 'voice', check: 'The narrative reads like a careful human researcher, not a scanner, marketing copy, or a checklist.' },
    { id: 'provenance', check: 'No author-machine-specific absolute paths, placeholder text, or fabricated details remain in the report or distributable PoC.' },
  ]
}
