import { readFile } from 'node:fs/promises'
import { resolve } from 'node:path'

const root = process.cwd()
const files = ['package.json', 'package-lock.json', 'cordis.patch.yml']
const source = await readFile(resolve(root, 'src/index.ts'), 'utf8')
for (const path of files) {
  const content = await readFile(resolve(root, path), 'utf8')
  if (/@openai\/|\bopenai\b|\bcodex\b/i.test(content)) throw new Error(`Forbidden second-assistant runtime reference in ${path}.`)
}
if (/@openai\/|\bopenai\b|\bcodex\b/i.test(source)) throw new Error('Forbidden second-assistant runtime reference in src/index.ts.')
