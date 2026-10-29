// Generated runtime: dist/shared/uap-glob.mjs in nitropack@2.13.4.patch.
// Regenerate with the pinned TypeScript compiler; nitro-glob.test.ts checks bytes.
import { glob, type GlobOptions } from 'tinyglobby'

type NitroGlobOptions = Pick<GlobOptions, 'cwd' | 'absolute' | 'dot' | 'ignore'>

// fast-glob treats negated options.ignore as exclusions too, except extglobs.
const exclusion = (pattern: string) => pattern.startsWith('!') && !pattern.startsWith('!(') ? pattern.slice(1) : pattern

// Nitro uses ordered globby patterns: negatives exclude earlier positives only.
export async function globby(input: string | readonly string[], options: NitroGlobOptions = {}): Promise<string[]> {
  const patterns = [...new Set(typeof input === 'string' ? [input] : input)]
  if (patterns.length && patterns.every(pattern => pattern.startsWith('!'))) patterns.unshift('**/*')
  const ignore = typeof options.ignore === 'string' ? [options.ignore] : [...(options.ignore ?? [])]
  const tasks: Promise<string[]>[] = []
  let positives: string[] = []
  for (let index = 0; index <= patterns.length; index++) {
    const pattern = patterns[index]
    if (pattern !== undefined && !pattern.startsWith('!')) {
      positives.push(pattern)
      continue
    }
    if (positives.length) {
      // Nitro's public include groups and negation-only fallback are cwd-relative.
      const subsequentExcludes = patterns.slice(index).filter(pattern => pattern.startsWith('!')).map(pattern => pattern.slice(1).replace(/^\//, ''))
      tasks.push(glob(positives, { ...options, ignore: [...ignore, ...subsequentExcludes].map(exclusion) }))
      positives = []
    }
  }
  return [...new Set((await Promise.all(tasks)).flat())]
}
