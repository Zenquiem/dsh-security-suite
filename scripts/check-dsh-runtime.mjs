import { readFile, readdir } from 'node:fs/promises'
import { extname, join, relative } from 'node:path'

const root = process.cwd()
const allowedPackages = new Set([
  '@deepseek-ai/cordis',
  '@deepseek-ai/dsh-agent',
  '@deepseek-ai/dsh-llm',
  '@deepseek-ai/dsh-session',
  '@deepseek-ai/dsh-system-prompt',
  '@deepseek-ai/dsh-tools',
  '@deepseek-ai/schemastery',
  '@typescript-eslint/typescript-estree',
])

async function sourceFiles(directory) {
  const entries = await readdir(directory, { withFileTypes: true })
  const files = []
  for (const entry of entries) {
    const path = join(directory, entry.name)
    if (entry.isDirectory()) files.push(...await sourceFiles(path))
    else if (extname(entry.name) === '.ts') files.push(path)
  }
  return files
}

const manifest = JSON.parse(await readFile(join(root, 'package.json'), 'utf8'))
const declaredPackages = new Set([
  ...Object.keys(manifest.dependencies ?? {}),
  ...Object.keys(manifest.peerDependencies ?? {}),
])
for (const packageName of declaredPackages) {
  if (!allowedPackages.has(packageName)) throw new Error(`Non-DSH runtime dependency declared: ${packageName}`)
}

for (const path of await sourceFiles(join(root, 'src'))) {
  const source = await readFile(path, 'utf8')
  const imports = source.matchAll(/(?:import|export)\s+(?:type\s+)?(?:[^'\"]*?\s+from\s+)?['\"]([^'\"]+)['\"]/g)
  for (const match of imports) {
    const specifier = match[1]
    if (specifier.startsWith('.') || specifier.startsWith('node:')) continue
    if (!allowedPackages.has(specifier)) {
      throw new Error(`Non-DSH source import in ${relative(root, path)}: ${specifier}`)
    }
  }
}
