<script setup lang="ts">
import savedScan from '~/data/discovery-scan.json'
import type { DiscoveryScan } from '~/types/discoveryScan'
import { discoveryScanManifestUrl, discoveryScanPage } from '~/utils/discoveryScan'

const scan = savedScan as DiscoveryScan
const query = ref('')
const page = ref(1)
const results = computed(() => discoveryScanPage(scan.records, query.value, page.value))
watch(query, () => { page.value = 1 })
const description = 'Browse package validation evidence saved from an incomplete discovery scan.'
useSeoMeta({ title: 'Saved scan preview', description, ogTitle: 'Saved scan preview · Universal Agent Plugins', ogDescription: description })
useHead({ link: [{ rel: 'canonical', href: `${useRuntimeConfig().public.siteUrl}/discovery-scan` }] })
</script>

<template>
  <div class="directory-page container saved-scan">
    <div class="page-intro">
      <p class="eyebrow">Browse-only · Incomplete scan</p>
      <h1>Saved scan preview</h1>
      <p>This historical observation contains {{ scan.records.length }} packages with package validation evidence from completed repository checks in an incomplete scan. This is not a signed catalog or a runtime or security review. No install commands are provided.</p>
      <p class="scan-observation">Originally observed <time :datetime="scan.observed_at">{{ scan.observed_at.replace('T', ' ').replace('Z', ' UTC') }}</time>. <a :href="`https://github.com/777genius/universal-agent-plugins-registry/actions/runs/${scan.source_run}`" target="_blank" rel="noreferrer">View source run</a>.</p>
      <NuxtLink to="/plugins">Back to plugin directory</NuxtLink>
    </div>
    <section class="catalog" aria-labelledby="scan-results-title">
      <h2 id="scan-results-title" class="sr-only">Saved package results</h2>
      <label class="search-field scan-search">
        <span class="sr-only">Search saved packages</span>
        <input v-model="query" type="search" placeholder="Search by name, description, or repository" />
      </label>
      <div class="catalog-meta">
        <p class="catalog-count" aria-live="polite">Showing {{ results.records.length }} of {{ results.total }} matching packages · {{ scan.records.length }} saved</p>
      </div>
      <div v-if="results.records.length" class="plugin-grid">
        <article v-for="record in results.records" :key="`${record.repository}/${record.package_path}`" class="plugin-card">
          <h3>{{ record.name }}</h3>
          <p class="plugin-card__source-label">{{ record.repository }}<template v-if="record.version"> · {{ record.version }}</template></p>
          <p class="plugin-card__description">{{ record.description }}</p>
          <p class="plugin-card__source-label">{{ Object.entries(record.components).filter(([, count]) => count > 0).map(([name, count]) => `${count} ${name}`).join(' · ') }}</p>
          <p class="scan-path">{{ record.package_path || '(repository root)' }}</p>
          <div class="plugin-card__bottom">
            <a v-if="discoveryScanManifestUrl(record)" :href="discoveryScanManifestUrl(record)!" target="_blank" rel="noreferrer">View manifest at saved revision ↗</a>
            <span v-else>Source link unavailable</span>
          </div>
        </article>
      </div>
      <div v-else class="empty-state"><h3>No matching packages</h3><p>Try a broader search.</p></div>
      <nav v-if="results.pageCount > 1" class="catalog-more" aria-label="Saved package pages">
        <button class="button button--secondary" type="button" :disabled="results.page === 1" @click="page = results.page - 1">Previous</button>
        <span aria-live="polite">Page {{ results.page }} of {{ results.pageCount }}</span>
        <button class="button button--secondary" type="button" :disabled="results.page === results.pageCount" @click="page = results.page + 1">Next</button>
      </nav>
    </section>
  </div>
</template>

<style scoped>
.scan-observation { font-size: .9rem; }
.scan-search { display: block; max-width: 680px; }
.scan-search input { width: 100%; min-height: 48px; padding: 12px; border: 1px solid var(--line); border-radius: 9px; color: var(--text); background: var(--surface); }
.scan-path { overflow-wrap: anywhere; color: var(--subtle); font-size: .75rem; }
.saved-scan .plugin-card h3 { white-space: normal; overflow-wrap: anywhere; }
.saved-scan .plugin-card__source-label { overflow-wrap: anywhere; }
.saved-scan .plugin-card__bottom { font-size: .8rem; }
.saved-scan button:disabled { opacity: .5; cursor: default; transform: none; }
</style>
