<template>
  <span
    :class="['ds-span-chip', `ds-span-chip--${stateClass}`]"
    :title="tooltip || defaultTooltip"
  >
    <span class="span-orig-text">{{ displayText ?? span.text }}</span>
    <span v-if="span.exempted" class="ds-span-chip__meta">
      豁免保留 · {{ span.allowlist_group || 'allowlist' }}
    </span>
    <span v-else class="ds-span-chip__meta">
      {{ span.replacement }} · {{ span.detector }} {{ span.score.toFixed(2) }}
    </span>
  </span>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { ENTITY_LABEL_ZH_MAP } from '@/constants/domain'
import type { SandboxSpan } from '@/types/api'

const props = defineProps<{
  span: SandboxSpan
  displayText?: string
  tooltip?: string
}>()

const stateClass = computed(() =>
  props.span.exempted ? 'allowlist' : props.span.state || props.span.detector,
)

const defaultTooltip = computed(() => {
  const zh = ENTITY_LABEL_ZH_MAP[props.span.label] ?? props.span.label
  if (props.span.exempted) {
    return `${zh} (${props.span.label}) · 白名单豁免：${props.span.allowlist_group ?? ''} / ${props.span.allowlist_rule ?? ''}`
  }
  return `${zh} (${props.span.label}) · 检测器：${props.span.detector} · 置信度：${props.span.score.toFixed(2)} · 替换：${props.span.replacement ?? ''}`
})
</script>

<style scoped>
.span-orig-text {
  font-weight: 500;
}
</style>
