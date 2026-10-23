<script setup lang="ts">
import { catalogVisiblePlugins } from '~/utils/filter'

const registry = useRegistry()
const visiblePlugins = computed(() => catalogVisiblePlugins(registry.plugins))
const reviewedCount = computed(() => visiblePlugins.value.filter(plugin => plugin.trust_state !== 'conformant_unreviewed').length)
const discoveryCount = computed(() => visiblePlugins.value.length - reviewedCount.value)
const description = 'Browse Agent Plugins 1.0 by capability, agent support, component, and source.'
useSeoMeta({ title: 'Plugin directory', description, ogTitle: 'Plugin directory · Universal Agent Plugins', ogDescription: description })
useHead({ link: [{ rel: 'canonical', href: `${useRuntimeConfig().public.siteUrl}/plugins` }] })
</script>

<template>
  <div class="directory-page container">
    <div class="page-intro">
      <p class="eyebrow">{{ reviewedCount }} reviewed<template v-if="discoveryCount"> · {{ discoveryCount }} discovered</template> · Open submissions</p>
      <h1>Find the right ability for your agent.</h1>
      <p>Browse by capability, agent support, and validation status. Community packages stay linked to reviewable GitHub source.</p>
      <p><NuxtLink to="/discovery-scan">Browse the saved scan preview</NuxtLink> · Incomplete scan, package validation evidence only.</p>
    </div>
    <PluginCatalog :plugins="visiblePlugins" />
  </div>
</template>
