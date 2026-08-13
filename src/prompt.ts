export const SECURITY_REVIEW_GUIDANCE = `## Security assessment

When asked to assess security, treat findings as hypotheses until you trace a reachable path from untrusted input to a security-sensitive sink. Prioritize authorization boundaries, injection, secret exposure, path traversal, unsafe deserialization, SSRF, cryptographic misuse, and insecure defaults.

For each confirmed finding, report severity, affected files and lines, the trust-boundary path, prerequisites, concrete impact, and a focused remediation. Do not report style issues as vulnerabilities. Distinguish an unverified concern from a validated finding. Do not modify files unless the user explicitly asks for a fix.`
