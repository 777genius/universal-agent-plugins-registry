import { resolve } from 'node:path'
import { loadRegistryIndex } from './build/load-registry'

const signedSnapshotPath = process.env.UAP_SIGNED_SNAPSHOT_PATH
const previewPath = process.env.UAP_DIRECTORY_PREVIEW_PATH
const defaultRegistryPath = resolve(process.cwd(), '../registry/directory.json')
const implicitPreview = !signedSnapshotPath && !previewPath && !process.env.UAP_REGISTRY_PATH
const registryPath = signedSnapshotPath
  ? resolve(process.cwd(), signedSnapshotPath)
  : previewPath
    ? resolve(process.cwd(), previewPath)
    : process.env.UAP_REGISTRY_PATH
      ? resolve(process.cwd(), process.env.UAP_REGISTRY_PATH)
      : defaultRegistryPath
const registryIndex = loadRegistryIndex(registryPath, signedSnapshotPath ? 'published_snapshot' : (previewPath || implicitPreview) ? 'review_preview' : undefined)
if (!signedSnapshotPath && process.env.CI && process.env.GITHUB_EVENT_NAME !== 'pull_request') {
  throw new Error('Production builds require UAP_SIGNED_SNAPSHOT_PATH; unsigned data is allowed only for pull-request previews')
}

const siteUrl = (process.env.NUXT_PUBLIC_SITE_URL
  ?? 'https://777genius.github.io/universal-agent-plugins-registry').replace(/\/$/, '')
const baseURL = process.env.NUXT_APP_BASE_URL ?? '/'
const repositoryUrl = process.env.NUXT_PUBLIC_REPOSITORY_URL
  ?? 'https://github.com/777genius/universal-agent-plugins-registry'
const discoveryKeyID = process.env.NUXT_PUBLIC_DISCOVERY_KEY_ID ?? 'uap-discovery-2026-01'
const discoveryPublicKey = process.env.NUXT_PUBLIC_DISCOVERY_PUBLIC_KEY ?? 'IxWvGuscXR9crlCrGyBQZNqroYNVPbBA1B3pnjSffhc='
// server/plugins/csp.ts emits the production policy outside reactive app.head.
// The static finalizer adds exact inline hashes before Pages publication.

export default defineNuxtConfig({
  compatibilityDate: '2026-08-10',
  // Keep the established root-level app structure when upgrading Nuxt.
  srcDir: '.',
  ssr: true,
  devtools: { enabled: false },
  modules: ['@nuxt/eslint'],
  css: ['~/assets/css/main.css'],
  app: {
    baseURL,
    head: {
      htmlAttrs: { lang: 'en' },
      titleTemplate: '%s · Universal Agent Plugins',
      meta: [
        { name: 'referrer', content: 'strict-origin-when-cross-origin' },
      ],
      link: [
        { rel: 'icon', type: 'image/svg+xml', href: `${baseURL}logo.svg` },
      ],
      script: [{
        innerHTML: "try{document.documentElement.dataset.theme=localStorage.getItem('uap-theme')||((matchMedia('(prefers-color-scheme:light)').matches)?'light':'dark')}catch(e){}",
      }],
    },
  },
  runtimeConfig: {
    public: {
      registryIndex,
      siteUrl,
      baseURL,
      repositoryUrl,
      discoveryKeyID,
      discoveryPublicKey,
    },
  },
  nitro: {
    compressPublicAssets: true,
    prerender: {
      crawlLinks: false,
      routes: [
        '/',
        '/404.html',
        '/plugins',
        '/discovery-scan',
        '/robots.txt',
        '/sitemap.xml',
        ...registryIndex.plugins.map(plugin => `/plugins/${plugin.name}`),
      ],
    },
  },
  routeRules: {
    '/**': {
      prerender: true,
      headers: {
        'referrer-policy': 'strict-origin-when-cross-origin',
        'x-content-type-options': 'nosniff',
      },
    },
    '/_nuxt/**': { headers: { 'cache-control': 'public, max-age=31536000, immutable' } },
  },
  typescript: {
    strict: true,
    typeCheck: true,
  },
})
