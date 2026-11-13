<template>
  <div class="span-highlight-root">
    <template v-for="(seg, idx) in segments" :key="idx">
      <span v-if="!seg.span" class="span-plain-text">{{ seg.text }}</span>
      <SpanChip v-else :span="seg.span" :display-text="seg.text" />
    </template>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import SpanChip from '@/components/SpanChip.vue'
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
</script>

<style scoped>
.span-highlight-root {
  white-space: pre-wrap;
  word-break: break-word;
  line-height: 1.85;
  color: var(--ds-text-primary);
}
</style>
