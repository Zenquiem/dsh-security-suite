import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { existsSync } from 'node:fs'
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
  assert.equal(names.includes('security_deep_read_source'), true)
  assert.equal(ctx.tools.get('security_scan')?.output.schema.type, 'object')
  assert.match(ctx.tools.get('security_review_diff')?.description ?? '', /GitHub Actions pull_request_target shell interpolation/)
  assert.deepEqual(ctx.tools.get('security_scan')?.output.schema.required, ['scanId', 'findings', 'reviewedFiles', 'complete'])
  const assembled = await ctx.systemPrompt.assemble()
  assert.equal(assembled.sections.some(section => section.name === 'dsh-security-suite:workflow'), true)
  await fiber.dispose()
  assert.equal(ctx.tools.get('security_scan'), undefined)
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
