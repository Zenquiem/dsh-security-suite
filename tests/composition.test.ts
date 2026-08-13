import assert from 'node:assert/strict'
import test from 'node:test'
import { Context } from '@deepseek-ai/cordis'
import { SystemPrompt } from '@deepseek-ai/dsh-system-prompt'
import { ToolRegistry } from '@deepseek-ai/dsh-tools'
import { apply } from '../src/index.ts'

test('the suite composes with DSH registries and exposes its native tool surface', async () => {
  const ctx = new Context()
  new SystemPrompt(ctx, {})
  new ToolRegistry(ctx, {})
  apply(ctx, { enabled: true, maxFiles: 10, maxFileBytes: 4096, stateDir: '' })
  const names = ctx.tools.schemas().map(tool => tool.name)
  assert.equal(names.includes('security_scan'), true)
  assert.equal(names.includes('security_deep_discovery_capability'), true)
  assert.equal(names.includes('security_deep_get_worklist'), true)
  assert.equal(names.includes('security_deep_read_source'), true)
  assert.equal(ctx.tools.get('security_scan')?.output.schema.type, 'object')
  assert.deepEqual(ctx.tools.get('security_scan')?.output.schema.required, ['scanId', 'findings', 'reviewedFiles', 'complete'])
  const assembled = await ctx.systemPrompt.assemble()
  assert.equal(assembled.sections.some(section => section.name === 'dsh-security-suite:workflow'), true)
})
