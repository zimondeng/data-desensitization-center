<script setup lang="ts">
import { ref } from 'vue'
import ApiKeysTab from '@/views/settings/ApiKeysTab.vue'
import DatasourcesTab from '@/views/settings/DatasourcesTab.vue'
import TelemetryTab from '@/views/settings/TelemetryTab.vue'

type SettingsTabKey = 'telemetry' | 'api-keys' | 'datasources'
const activeTab = ref<SettingsTabKey>('telemetry')
</script>

<template>
  <div class="settings-page">
    <div class="ds-page-header">
      <div>
        <h1 class="ds-page-title">系统设置与统计遥测</h1>
        <p class="ds-secondary-text" style="margin: 4px 0 0">
          汇总脱敏服务调用用量与性能分布、外部系统 API Key 生命周期及 MySQL 只读数据源接入。
        </p>
      </div>
    </div>

    <div class="settings-tablist" role="tablist" aria-label="系统设置子模块">
      <button
        type="button"
        role="tab"
        data-testid="tab-telemetry"
        class="settings-tab-btn"
        :class="{ 'is-active': activeTab === 'telemetry' }"
        :aria-selected="activeTab === 'telemetry'"
        @click="activeTab = 'telemetry'"
      >
        用量与性能遥测
      </button>

      <button
        type="button"
        role="tab"
        data-testid="tab-api-keys"
        class="settings-tab-btn"
        :class="{ 'is-active': activeTab === 'api-keys' }"
        :aria-selected="activeTab === 'api-keys'"
        @click="activeTab = 'api-keys'"
      >
        API Key 管理
      </button>

      <button
        type="button"
        role="tab"
        data-testid="tab-datasources"
        class="settings-tab-btn"
        :class="{ 'is-active': activeTab === 'datasources' }"
        :aria-selected="activeTab === 'datasources'"
        @click="activeTab = 'datasources'"
      >
        MySQL 只读数据源
      </button>
    </div>

    <div class="settings-tab-panel">
      <TelemetryTab v-if="activeTab === 'telemetry'" />
      <ApiKeysTab v-else-if="activeTab === 'api-keys'" />
      <DatasourcesTab v-else-if="activeTab === 'datasources'" />
    </div>
  </div>
</template>

<style scoped>
.settings-tablist {
  display: inline-flex;
  flex-wrap: wrap;
  gap: 6px;
  padding: 4px;
  margin-bottom: 16px;
  border-radius: var(--ds-radius-lg);
  border: 1px solid var(--ds-border-subtle);
  background: var(--ds-bg-card);
}

.settings-tab-btn {
  padding: 8px 16px;
  border: none;
  border-radius: var(--ds-radius-md);
  background: transparent;
  color: var(--ds-text-secondary);
  font-size: 0.875rem;
  font-weight: 500;
  cursor: pointer;
  transition: background-color var(--ds-motion-duration) var(--ds-motion-ease),
    color var(--ds-motion-duration) var(--ds-motion-ease);
}

.settings-tab-btn:hover {
  color: var(--ds-text-primary);
  background: var(--ds-bg-panel);
}

.settings-tab-btn.is-active {
  background: var(--ds-bg-active);
  color: var(--ds-color-primary);
  font-weight: 600;
}
</style>
