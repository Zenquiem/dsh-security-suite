import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { existsSync } from 'node:fs'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'
import test from 'node:test'
import { Context } from '@deepseek-ai/cordis'
import { SystemPrompt } from '@deepseek-ai/dsh-system-prompt'
import { ToolRegistry } from '@deepseek-ai/dsh-tools'
import { apply, inject, name } from '../src/index.ts'

const execFileAsync = promisify(execFile)

test('the suite composes with DSH registries and cleans up its native tool surface on unload', async () => {
  const ctx = new Context()
  new SystemPrompt(ctx, {})
  new ToolRegistry(ctx, {})
  const fiber = await ctx.plugin({ name, inject, apply }, { enabled: true, maxFiles: 10, maxFileBytes: 4096, stateDir: '' })
  const names = ctx.tools.schemas().map(tool => tool.name)
  assert.equal(names.includes('security_scan'), true)
  assert.equal(names.includes('security_review_diff'), true)
  assert.equal(names.includes('security_deep_discovery_capability'), true)
  assert.equal(names.includes('security_resume_deep_discovery'), true)
  assert.equal(names.includes('security_deep_get_worklist'), true)
  assert.equal(names.includes('security_plan_candidate_validation'), true)
  assert.equal(names.includes('security_run_candidate_validation_plan'), true)
  assert.equal(names.includes('security_rollback_remediation'), true)
  assert.equal(names.includes('security_tracking_advisory_preview'), true)
  assert.equal(names.includes('security_create_github_security_advisory'), true)
  assert.equal(names.includes('security_import_github_findings'), true)
  assert.equal(names.includes('security_triage_finding_backlog'), true)
  assert.equal(names.includes('security_start_deep_closure'), true)
  assert.equal(names.includes('security_resume_deep_closure'), true)
  assert.equal(names.includes('security_read_scan_source'), true)
  assert.equal(names.includes('security_deep_read_source'), true)
  assert.equal(ctx.tools.get('security_scan')?.output.schema.type, 'object')
  assert.match(ctx.tools.get('security_review_diff')?.description ?? '', /GitHub Actions pull_request_target shell interpolation/)
  assert.deepEqual(ctx.tools.get('security_scan')?.output.schema.required, ['scanId', 'findings', 'reviewedFiles', 'complete'])
  const assembled = await ctx.systemPrompt.assemble()
  assert.equal(assembled.sections.some(section => section.name === 'dsh-security-suite:workflow'), true)
  await fiber.dispose()
  assert.equal(ctx.tools.get('security_scan'), undefined)
  assert.equal(ctx.tools.get('security_import_github_findings'), undefined)
  assert.equal(ctx.tools.get('security_start_deep_closure'), undefined)
  const afterUnload = await ctx.systemPrompt.assemble()
  assert.equal(afterUnload.sections.some(section => section.name === 'dsh-security-suite:workflow'), false)
})

test('the built npm entrypoint registers and executes through the real DSH tool pipeline', async () => {
  const packageRoot = fileURLToPath(new URL('..', import.meta.url))
  if (!existsSync(new URL('../dist/index.js', import.meta.url))) await execFileAsync('npm', ['run', 'build'], { cwd: packageRoot })
  const built = await import('../dist/index.js') as typeof import('../src/index.ts')
  assert.equal('default' in built, false)
  const ctx = new Context()
  new SystemPrompt(ctx, {})
  new ToolRegistry(ctx, {})
  const fiber = await ctx.plugin({ name: built.name, inject: built.inject, apply: built.apply }, { enabled: true, maxFiles: 10, maxFileBytes: 4096, stateDir: '' })
  try {
    const result = await ctx.tools.execute({ signal: new AbortController().signal, callId: 'built-entrypoint' as never, name: 'security_deep_discovery_capability', arguments: {} })
    assert.equal(result.isError, false, result.isError ? result.error.message : '')
    assert.equal(typeof result.value, 'object')
    assert.equal(ctx.tools.get('security_resume_deep_discovery') !== undefined, true)
  } finally {
    await fiber.dispose()
  }
  assert.equal(ctx.tools.get('security_deep_discovery_capability'), undefined)
})

test('write tools require DSH user approval in addition to approved: true', async () => {
  const workspace = await mkdtemp(join(tmpdir(), 'dsh-security-suite-approval-'))
  const previousDirectory = process.cwd()
  const ctx = new Context()
  new SystemPrompt(ctx, {})
  new ToolRegistry(ctx, {})
  let approvalRequests = 0
  ctx.provide('approval', {
    async request() {
      approvalRequests += 1
      return 'allowed-once'
    },
  })
  const fiber = await ctx.plugin({ name, inject, apply }, { enabled: true, maxFiles: 10, maxFileBytes: 4096, stateDir: '' })
  try {
    process.chdir(workspace)
    const missingAcknowledgement = await ctx.tools.execute({ signal: new AbortController().signal, callId: 'approval-false' as never, name: 'security_install_precommit_hook', arguments: { approved: false }, agent: {} as never })
    assert.equal(missingAcknowledgement.isError, true)
    assert.match(missingAcknowledgement.isError ? missingAcknowledgement.error.message : '', /requires approved: true/)
    assert.equal(approvalRequests, 0)
    assert.equal(existsSync(join(workspace, '.git', 'hooks', 'pre-commit')), false)

    const approved = await ctx.tools.execute({ signal: new AbortController().signal, callId: 'approval-allowed' as never, name: 'security_install_precommit_hook', arguments: { approved: true }, agent: {} as never })
    assert.equal(approved.isError, false, approved.isError ? approved.error.message : '')
    assert.equal(approvalRequests, 1)
    assert.match(await readFile(join(workspace, '.git', 'hooks', 'pre-commit'), 'utf8'), /dsh run/)
  } finally {
    process.chdir(previousDirectory)
    await fiber.dispose()
    await rm(workspace, { recursive: true, force: true })
  }
})

test('write tools fail closed when their DSH approval route is unavailable', async () => {
  const workspace = await mkdtemp(join(tmpdir(), 'dsh-security-suite-no-approval-'))
  const previousDirectory = process.cwd()
  const ctx = new Context()
  new SystemPrompt(ctx, {})
  new ToolRegistry(ctx, {})
  const fiber = await ctx.plugin({ name, inject, apply }, { enabled: true, maxFiles: 10, maxFileBytes: 4096, stateDir: '' })
  try {
    process.chdir(workspace)
    const denied = await ctx.tools.execute({ signal: new AbortController().signal, callId: 'approval-unavailable' as never, name: 'security_install_precommit_hook', arguments: { approved: true }, agent: {} as never })
    assert.equal(denied.isError, true)
    assert.match(denied.isError ? denied.error.message : '', /Install the suite pre-commit hook/)
    assert.equal(existsSync(join(workspace, '.git', 'hooks', 'pre-commit')), false)
  } finally {
    process.chdir(previousDirectory)
    await fiber.dispose()
    await rm(workspace, { recursive: true, force: true })
  }
})

test('GitHub advisory creation is an approval-gated DSH write tool', async () => {
  const ctx = new Context()
  new SystemPrompt(ctx, {})
  new ToolRegistry(ctx, {})
  let approvalRequests = 0
  ctx.provide('approval', { async request() { approvalRequests++; return 'allowed-once' } })
  const fiber = await ctx.plugin({ name, inject, apply }, { enabled: true, maxFiles: 10, maxFileBytes: 4096, stateDir: '' })
  try {
    const result = await ctx.tools.execute({ signal: new AbortController().signal, callId: 'advisory-approval' as never, name: 'security_create_github_security_advisory', arguments: { scan_id: 'missing', finding_id: 'missing', token: 'test-token', approved: false }, agent: {} as never })
    assert.equal(result.isError, true)
    assert.match(result.isError ? result.error.message : '', /requires approved: true/)
    assert.equal(approvalRequests, 0)
    const approved = await ctx.tools.execute({ signal: new AbortController().signal, callId: 'advisory-approved' as never, name: 'security_create_github_security_advisory', arguments: { scan_id: 'missing', finding_id: 'missing', token: 'test-token', approved: true }, agent: {} as never })
    assert.equal(approved.isError, true)
    assert.equal(approvalRequests, 1)
  } finally { await fiber.dispose() }
})
