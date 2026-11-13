<template>
  <div class="span-highlight-root">
    <template v-for="(seg, idx) in segments" :key="idx">
      <span v-if="!seg.span" class="span-plain-text">{{ seg.text }}</span>
      <span
        v-else
        :class="chipClass(seg.span)"
        :title="chipTooltip(seg.span)"
      >
        <span class="span-orig-text">{{ seg.text }}</span>
        <span v-if="seg.span.exempted" class="ds-span-chip__meta">
          豁免保留 · {{ seg.span.allowlist_group || 'allowlist' }}
        </span>
        <span v-else class="ds-span-chip__meta">
          {{ seg.span.replacement }} · {{ seg.span.detector }} {{ seg.span.score.toFixed(2) }}
        </span>
      </span>
    </template>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { ENTITY_LABEL_ZH_MAP } from '@/constants/domain'
import type { SandboxSpan } from '@/types/api'

const props = defineProps<{
  text: string
  spans: readonly SandboxSpan[]
}>()

interface TextSegment {
  text: string
  span: SandboxSpan | null
}

const segments = computed<TextSegment[]>(() => {
  const source = props.text ?? ''
  if (!source) return []
  if (!props.spans.length) {
    return [{ text: source, span: null }]
  }

  // Match Python Unicode code-point indexing cleanly even for non-BMP characters
  const chars = Array.from(source)
  const ordered = [...props.spans].sort((a, b) => a.orig_start - b.orig_start || a.orig_end - b.orig_end)

  const out: TextSegment[] = []
  let cursor = 0
  for (const sp of ordered) {
    const start = Math.max(0, Math.min(sp.orig_start, chars.length))
    const end = Math.max(start, Math.min(sp.orig_end, chars.length))
    if (start < cursor) continue
    if (start > cursor) {
      out.push({ text: chars.slice(cursor, start).join(''), span: null })
    }
    out.push({ text: chars.slice(start, end).join('') || sp.text, span: sp })
    cursor = end
  }
  if (cursor < chars.length) {
    out.push({ text: chars.slice(cursor).join(''), span: null })
  }
  return out
})

function chipClass(span: SandboxSpan): string[] {
  const state = span.exempted ? 'allowlist' : span.state || span.detector
  return ['ds-span-chip', `ds-span-chip--${state}`]
}

function chipTooltip(span: SandboxSpan): string {
  const zh = ENTITY_LABEL_ZH_MAP[span.label] ?? span.label
  if (span.exempted) {
    return `${zh} (${span.label}) · 白名单豁免：${span.allowlist_group ?? ''} / ${span.allowlist_rule ?? ''}`
  }
  return `${zh} (${span.label}) · 检测器：${span.detector} · 置信度：${span.score.toFixed(2)} · 替换：${span.replacement ?? ''}`
}
</script>

<style scoped>
.span-highlight-root {
  white-space: pre-wrap;
  word-break: break-word;
  line-height: 1.85;
  color: var(--ds-text-primary);
}

.span-orig-text {
  font-weight: 500;
}
</style>
