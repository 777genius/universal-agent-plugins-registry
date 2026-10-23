<script setup lang="ts">
import { PopoverContent, PopoverPortal, PopoverRoot, PopoverTrigger } from 'reka-ui'
import type { AuthenticationIndicator } from '~/utils/authentication'

defineProps<{ indicator: AuthenticationIndicator }>()
const open = ref(false)
const pinned = ref(false)
let leaveTimer: ReturnType<typeof setTimeout> | undefined
function enter() {
  clearTimeout(leaveTimer)
  open.value = true
}
function leave() {
  leaveTimer = setTimeout(() => { if (!pinned.value) open.value = false }, 120)
}
function pin() {
  clearTimeout(leaveTimer)
  pinned.value = true
  open.value = true
}
watch(open, value => { if (!value) pinned.value = false })
onBeforeUnmount(() => clearTimeout(leaveTimer))
</script>

<template>
  <PopoverRoot v-model:open="open">
    <PopoverTrigger
      class="authentication-indicator"
      type="button"
      :aria-label="indicator.label"
      :data-authentication="indicator.state"
      @pointerenter="event => { if (event.pointerType === 'mouse') enter() }"
      @pointerleave="leave"
      @click.prevent="pin"
    >
      <svg aria-hidden="true" width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
        <template v-if="indicator.state === 'required'"><circle cx="8" cy="8" r="5" /><path d="m11.5 11.5 9 9M17 17l3-3M14 14l3-3" /></template>
        <template v-else-if="indicator.state === 'not_required'"><rect x="4" y="10" width="16" height="11" rx="2" /><path d="M8 10V6a4 4 0 0 1 7.5-2M12 15v2" /></template>
        <template v-else><circle cx="12" cy="12" r="9" /><path d="M9.5 8.5a2.5 2.5 0 1 1 4 2c-1 .7-1.5 1-1.5 2.5M12 17h.01" /></template>
      </svg>
      <span class="sr-only">{{ indicator.label }}</span>
    </PopoverTrigger>
    <PopoverPortal>
      <PopoverContent class="authentication-indicator__content" :side-offset="6" :collision-padding="14" align="start" @open-auto-focus.prevent @pointerenter="enter" @pointerleave="leave">
        <strong>{{ indicator.label }}</strong>
        <p>{{ indicator.detail }}</p>
      </PopoverContent>
    </PopoverPortal>
  </PopoverRoot>
</template>
