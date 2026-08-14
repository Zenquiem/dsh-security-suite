import Schema from '@deepseek-ai/schemastery'

/** Mirrors codex-security `[deep_scan]` configuration (Apache-2.0, adapted). */
export interface DeepScanConfig {
  /** Concurrent discovery workers: positive integer, or 'auto' for half of available parallelism capped at six. */
  workers: number | 'auto'
  /** Subagents each deep discovery worker may spawn for file review. */
  subagents: number
  /** Stop discovery after this many complete rounds with no new findings. */
  stopAfterNoNew: number
  /** Stop discovery after this many consecutive failing worker rounds. */
  stopAfterConsecutiveErrors: number
  /** Hard cap on complete discovery rounds. */
  maxDiscoveryRuns: number
  /** Maximum discovery wall-clock hours (fractional allowed, capped at 96). */
  maxTimeHours: number
}

export interface Config {
  enabled: boolean
  maxFiles: number
  maxFileBytes: number
  stateDir: string
  /** Deep-scan engine settings, aligned with codex-security deep_scan. Optional for backward compatibility. */
  deepScan?: DeepScanConfig
  /** Read-only security knowledge base: files or directories of Markdown/text/PDF/DOCX. Optional. */
  knowledgeBase?: string[]
  /** Extra shared scan instructions (equivalent of --scan-prompt-file content). Optional. */
  scanPrompt?: string
}

export const DEFAULT_DEEP_SCAN: DeepScanConfig = {
  workers: 'auto',
  subagents: 3,
  stopAfterNoNew: 6,
  stopAfterConsecutiveErrors: 3,
  maxDiscoveryRuns: 60,
  maxTimeHours: 96,
}

/** Fill codex-security-aligned defaults for optional suite settings. */
export function normalizeConfig(config: Config): Config {
  return {
    ...config,
    deepScan: { ...DEFAULT_DEEP_SCAN, ...(config.deepScan ?? {}) },
    knowledgeBase: config.knowledgeBase ?? [],
    scanPrompt: config.scanPrompt ?? '',
  }
}

export const Config: Schema<Config> = Schema.object({
  enabled: Schema.boolean().default(true),
  maxFiles: Schema.number().min(1).max(10_000).default(500),
  maxFileBytes: Schema.number().min(1_024).max(10_485_760).default(262_144),
  stateDir: Schema.string().default(''),
  deepScan: Schema.object({
    workers: Schema.union([
      Schema.const('auto' as const),
      Schema.number().min(1).max(6),
    ]).default('auto'),
    subagents: Schema.number().min(0).max(8).default(3),
    stopAfterNoNew: Schema.number().min(1).max(100).default(6),
    stopAfterConsecutiveErrors: Schema.number().min(1).max(100).default(3),
    maxDiscoveryRuns: Schema.number().min(1).max(1_000).default(60),
    maxTimeHours: Schema.number().min(0.1).max(96).default(96),
  }).default({ ...DEFAULT_DEEP_SCAN }),
  knowledgeBase: Schema.array(Schema.string()).default([]),
  scanPrompt: Schema.string().default(''),
})
