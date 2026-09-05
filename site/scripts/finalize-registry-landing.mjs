import { lstat, readFile, writeFile } from 'node:fs/promises'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

export const destination = 'https://777genius.github.io/universal-agent-plugins/plugins/'
// Exact human entry points only. Never use a wildcard or a 404 redirect:
// signed feeds, schemas, package assets and unknown machine paths stay intact.
export const landingPaths = Object.freeze(['index.html', 'plugins/index.html'])
export const redirectHtml = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; base-uri 'none'; form-action 'none'">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="0; url=${destination}">
<link rel="canonical" href="${destination}">
<title>Universal Agent Plugins Directory has moved</title>
</head>
<body>
<h1>The plugin directory has moved</h1>
<p><a href="${destination}">Continue to Universal Agent Plugins</a>.</p>
<p>This registry host continues to serve public discovery, security, registry and schema data.</p>
</body>
</html>
`

export async function finalizeRegistryLanding(directory) {
  const root = resolve(directory)
  // Validate every target and ancestor before writing anything. A symlink must
  // never turn this bounded replacement into a write outside the artifact.
  for (const relative of landingPaths) {
    const segments = relative.split('/')
    for (let count = 0; count <= segments.length; count += 1) {
      const path = resolve(root, ...segments.slice(0, count))
      const stat = await lstat(path)
      const valid = count === segments.length ? stat.isFile() : stat.isDirectory()
      if (!valid || stat.isSymbolicLink() || (stat.isFile() && stat.nlink !== 1)) {
        throw new Error(`unsafe registry landing path: ${path}`)
      }
    }
  }
  for (const relative of landingPaths) {
    const path = resolve(root, relative)
    if (await readFile(path, 'utf8') !== redirectHtml) await writeFile(path, redirectHtml)
  }
  return [...landingPaths]
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const paths = await finalizeRegistryLanding(process.argv[2] ?? '.output/public')
  console.log(`finalized registry landing redirects: ${paths.join(', ')}`)
}
