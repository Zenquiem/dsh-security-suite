import type { Context } from '@deepseek-ai/cordis'
import type {} from '@deepseek-ai/dsh-system-prompt'
import { defineTool } from '@deepseek-ai/dsh-tools'
import { Config, type Config as PluginConfig } from './config.js'
import { SECURITY_REVIEW_GUIDANCE } from './prompt.js'
import { assessDirectory, reviewGitDiff, resolveSafeTarget } from './scanner.js'

export const name = 'dsh-security-suite'
export const inject = ['tools', 'systemPrompt']
export { Config }

export function apply(ctx: Context, config: PluginConfig): void {
  if (!config.enabled) return

  ctx.systemPrompt.section({
    name: 'dsh-security-suite:review-guidance',
    order: 160,
    text: SECURITY_REVIEW_GUIDANCE,
  })

  ctx.tools.register(defineTool({
    name: 'security_assess',
    description: 'Perform a read-only security candidate scan of a directory inside the current workspace.',
    parameters: {
      path: { type: 'string', description: 'Optional workspace-relative directory. Defaults to the current workspace root.' },
    },
    output: {
      schema: {
        type: 'object',
        properties: {
          filesScanned: { type: 'number' },
          filesSkipped: { type: 'number' },
          candidates: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                rule: { type: 'string' },
                severity: { type: 'string' },
                file: { type: 'string' },
                line: { type: 'number' },
                excerpt: { type: 'string' },
                rationale: { type: 'string' },
              },
              required: ['rule', 'severity', 'file', 'line', 'excerpt', 'rationale'],
              additionalProperties: false,
            },
          },
        },
        required: ['filesScanned', 'filesSkipped', 'candidates'],
        additionalProperties: false,
      },
      render: (_args, value) => [{ type: 'text', text: JSON.stringify(value) }],
    },
    async execute(args) {
      const workspace = process.cwd()
      const target = resolveSafeTarget(workspace, args.path)
      const result = await assessDirectory(target, config)
      return {
        filesScanned: result.filesScanned,
        filesSkipped: result.filesSkipped,
        candidates: result.candidates.map(candidate => ({ ...candidate })),
      }
    },
  }))

  ctx.tools.register(defineTool({
    name: 'security_review_diff',
    description: 'Read a Git diff in the current workspace and return it with security-review instructions. This is read-only.',
    parameters: {
      base: { type: 'string', description: 'Optional Git base ref. Defaults to the working tree diff.' },
    },
    output: {
      schema: {
        type: 'object',
        properties: {
          mode: { type: 'string' },
          diff: { type: 'string' },
          truncated: { type: 'boolean' },
        },
        required: ['mode', 'diff', 'truncated'],
        additionalProperties: false,
      },
      render: (_args, value) => [{ type: 'text', text: value.diff ?? '' }],
    },
    async execute(args) {
      return reviewGitDiff(process.cwd(), args.base)
    },
  }))
}
