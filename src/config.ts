import Schema from '@deepseek-ai/schemastery'

export interface Config {
  enabled: boolean
  maxFiles: number
  maxFileBytes: number
  stateDir: string
}

export const Config: Schema<Config> = Schema.object({
  enabled: Schema.boolean().default(true),
  maxFiles: Schema.number().min(1).max(10_000).default(500),
  maxFileBytes: Schema.number().min(1_024).max(10_485_760).default(262_144),
  stateDir: Schema.string().default(''),
})
