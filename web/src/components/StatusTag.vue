<template>
  <el-tag :type="tagType" effect="light" size="small" class="ds-status-tag">
    {{ label }}
  </el-tag>
</template>

<script setup lang="ts">
defineProps<{
  label: string
  tagType: 'primary' | 'success' | 'warning' | 'danger' | 'info'
}>()
</script>

<style scoped>
.ds-status-tag {
  font-weight: 500;
}
</style>
