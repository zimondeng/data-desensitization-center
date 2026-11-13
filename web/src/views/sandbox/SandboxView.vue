<template>
  <div class="sandbox-page">
    <header class="ds-page-header">
      <div>
        <h1 class="ds-page-title">在线脱敏沙盒</h1>
        <p class="ds-muted-text sandbox-security-note">
          <el-icon aria-hidden="true"><Lock /></el-icon>
          <span>当前沙盒仅在内存执行脱敏推理与区间分析，原始输入与输出结果均不写入数据库或系统日志。</span>
        </p>
      </div>
    </header>

    <section class="ds-card sandbox-toolbar" aria-label="沙盒调试工具栏">
      <div class="sandbox-toolbar__controls">
        <div class="toolbar-field">
          <label for="sandbox-policy-select" class="toolbar-label">脱敏策略模板</label>
          <el-select
            id="sandbox-policy-select"
            v-model="store.policyCode"
            style="width: 240px"
            placeholder="选择策略编码"
            :loading="loadingPolicies"
            @change="store.policyVersion = 0"
          >
            <el-option
              v-for="grp in policyGroups"
              :key="grp.policy_code"
              :label="`${grp.policy_code} (v${grp.default_version ?? grp.latest_version})`"
              :value="grp.policy_code"
            />
          </el-select>
        </div>

        <div class="toolbar-field">
          <label for="sandbox-version-select" class="toolbar-label">策略版本</label>
          <el-select
            id="sandbox-version-select"
            v-model="store.policyVersion"
            style="width: 150px"
            placeholder="默认版本"
          >
            <el-option :value="0" label="当前默认版本" />
            <el-option
              v-for="ver in selectedPolicyVersions"
              :key="ver.version"
              :label="`v${ver.version}${ver.is_default ? ' (默认)' : ''}`"
              :value="ver.version"
            />
          </el-select>
        </div>

        <div class="toolbar-field">
          <span class="toolbar-label">输入模式</span>
          <el-radio-group v-model="store.mode" @change="handleModeSwitch">
            <el-radio-button value="TEXT">纯文本 TEXT</el-radio-button>
            <el-radio-button value="STRUCTURED">结构化多轮会话 JSON</el-radio-button>
          </el-radio-group>
        </div>
      </div>

      <div class="sandbox-toolbar__actions">
        <el-button data-testid="fill-golden-sample" @click="handleFillGoldenSample">
          填充政务问答示例
        </el-button>
        <el-button
          type="primary"
          data-testid="run-sandbox-btn"
          :loading="store.running"
          :disabled="store.running"
          @click="handleRunPreview"
        >
          执行脱敏测试
        </el-button>
      </div>
    </section>

    <el-alert
      v-if="store.errorMessage"
      type="error"
      show-icon
      :closable="false"
      class="sandbox-alert"
      :title="store.errorMessage"
      role="alert"
    />

    <section class="sandbox-grid">
      <!-- Left Pane: Input -->
      <div class="ds-card sandbox-pane">
        <div class="pane-header">
          <label for="sandbox-input-area" class="ds-section-title">
            {{ store.mode === 'TEXT' ? '待脱敏原文输入' : '结构化多轮会话 JSON 载荷' }}
          </label>
          <div class="pane-header__meta">
            <span class="ds-muted-text ds-tabular-nums">
              {{ activeCharCount.toLocaleString() }} 字符
            </span>
            <el-button size="small" @click="handleClear">清空输入</el-button>
          </div>
        </div>

        <el-input
          v-if="store.mode === 'TEXT'"
          id="sandbox-input-area"
          v-model="store.inputText"
          type="textarea"
          :rows="14"
          resize="vertical"
          placeholder="请输入待检测的政务问答或业务文本（支持中英姓名、18位身份证、手机号、地址、银行卡及公共热线对比）"
          @input="inputValidationError = ''"
        />

        <el-input
          v-else
          id="sandbox-input-area"
          v-model="store.structuredJsonText"
          type="textarea"
          :rows="14"
          resize="vertical"
          class="ds-mono"
          placeholder='请输入 JSON 对象，如 {"input_text": "...", "turns": [{"role": "user", "content": "..."}]}'
          @input="inputValidationError = ''"
        />

        <p v-if="inputValidationError" class="inline-field-error" role="alert">
          {{ inputValidationError }}
        </p>

        <div class="pane-legend ds-panel-slot">
          <span class="ds-muted-text">三态检测来源语义：</span>
          <span class="ds-span-chip ds-span-chip--onnx">ONNX 语义识别 · onnx</span>
          <span class="ds-span-chip ds-span-chip--regex">大陆强校验正则 · regex</span>
          <span class="ds-span-chip ds-span-chip--allowlist">白名单豁免保留 · allowlist</span>
        </div>
      </div>

      <!-- Right Pane: Output & Highlight Contrast -->
      <div class="ds-card sandbox-pane">
        <div class="pane-header">
          <h2 class="ds-section-title">脱敏对照与检测证据</h2>
          <div class="pane-header__meta">
            <el-radio-group v-model="outputTab" size="small">
              <el-radio-button value="HIGHLIGHT">命中与豁免对照</el-radio-button>
              <el-radio-button value="MASKED">脱敏后产物</el-radio-button>
            </el-radio-group>
            <el-button
              size="small"
              :disabled="!copyableOutput"
              @click="handleCopyResult"
            >
              {{ copied ? '已复制' : '复制脱敏结果' }}
            </el-button>
          </div>
        </div>

        <div class="sandbox-output-body ds-panel-slot">
          <el-skeleton v-if="store.running" :rows="7" animated />

          <el-empty
            v-else-if="!store.result"
            description="在左侧输入文本或点击「填充政务问答示例」，再点击「执行脱敏测试」查看三态检测与白名单豁免结果。"
          />

          <template v-else-if="outputTab === 'HIGHLIGHT'">
            <div v-if="isInputStaleAfterRun" class="stale-edit-notice" role="status">
              输入内容已修改，当前高亮仍对应上次测试文本，请重新点击「执行脱敏测试」刷新高亮结果。
            </div>
            <SpanHighlightText
              v-if="store.result.mode === 'TEXT'"
              :text="store.analyzedText"
              :spans="store.result.spans"
            />
            <div v-else class="structured-traces">
              <div
                v-for="(spans, fieldPath) in store.result.field_traces"
                :key="fieldPath"
                class="trace-row"
              >
                <div class="trace-row__path ds-mono">{{ fieldPath }}</div>
                <div v-if="spans.length === 0" class="ds-muted-text">
                  未触发实体命中（或按 PASSTHROUGH / 豁免保留）
                </div>
                <div v-else class="trace-row__chips">
                  <SpanChip
                    v-for="(sp, sIdx) in spans"
                    :key="sIdx"
                    :span="sp"
                  />
                </div>
              </div>
              <div
                v-if="Object.keys(store.result.field_traces).length === 0"
                class="ds-muted-text"
              >
                本次结构化载荷未命中任何敏感实体或白名单豁免项。
              </div>
            </div>
          </template>

          <template v-else>
            <pre v-if="store.result.mode === 'TEXT'" class="masked-output-pre">{{ store.result.masked_text }}</pre>
            <pre v-else class="masked-output-pre ds-mono">{{ formattedMaskedPayload }}</pre>
          </template>
        </div>

        <footer v-if="store.result" class="sandbox-stats-bar">
          <div class="stats-metrics ds-tabular-nums">
            <span class="stat-pill">
              策略快照：<strong class="ds-mono">{{ store.result.policy_code }}@v{{ store.result.policy_version }}</strong>
            </span>
            <span class="stat-pill">
              作用域：<strong>{{ store.result.scope_mode }}</strong>
            </span>
            <span class="stat-pill">
              推理耗时：<strong>{{ store.result.elapsed_ms }} ms</strong>
            </span>
            <span class="stat-pill">
              白名单豁免：<strong>{{ store.result.exempted_count }} 处</strong>
            </span>
          </div>
          <div class="stats-hits">
            <span v-if="hitEntries.length === 0" class="ds-muted-text">无敏感实体命中</span>
            <el-tag
              v-for="[label, count] in hitEntries"
              :key="label"
              effect="light"
              size="small"
              class="ds-tabular-nums"
            >
              {{ labelZh(label) }} ({{ label }}) × {{ count }}
            </el-tag>
          </div>
        </footer>
      </div>
    </section>
  </div>
</template>

<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { Lock } from '@element-plus/icons-vue'
import { listPolicies } from '@/api/policies'
import { extractErrorMessage } from '@/api/client'
import SpanChip from '@/components/SpanChip.vue'
import SpanHighlightText from '@/components/SpanHighlightText.vue'
import { ENTITY_LABEL_ZH_MAP } from '@/constants/domain'
import { useSandboxStore } from '@/stores/sandbox'
import type { PolicyGroupItem, PolicyVersionItem } from '@/types/api'

const store = useSandboxStore()

const policyGroups = ref<PolicyGroupItem[]>([])
const loadingPolicies = ref(false)
const outputTab = ref<'HIGHLIGHT' | 'MASKED'>('HIGHLIGHT')
const inputValidationError = ref('')
const copied = ref(false)
let copyTimer: ReturnType<typeof setTimeout> | null = null

const selectedPolicyVersions = computed<PolicyVersionItem[]>(() => {
  const grp = policyGroups.value.find((g) => g.policy_code === store.policyCode)
  return grp?.versions ?? []
})

const activeCharCount = computed(() =>
  store.mode === 'TEXT' ? store.inputText.length : store.structuredJsonText.length,
)

const formattedMaskedPayload = computed(() => {
  if (!store.result?.masked_payload) return ''
  return JSON.stringify(store.result.masked_payload, null, 2)
})

const copyableOutput = computed(() => {
  if (!store.result) return ''
  return store.result.mode === 'TEXT'
    ? store.result.masked_text ?? ''
    : formattedMaskedPayload.value
})

const hitEntries = computed<[string, number][]>(() => {
  if (!store.result?.hit_counts) return []
  return Object.entries(store.result.hit_counts).filter(([, count]) => count > 0)
})

const isInputStaleAfterRun = computed(
  () =>
    store.mode === 'TEXT' &&
    store.result?.mode === 'TEXT' &&
    store.inputText !== store.analyzedText,
)

function labelZh(code: string): string {
  return ENTITY_LABEL_ZH_MAP[code] ?? code
}

function handleModeSwitch(): void {
  inputValidationError.value = ''
  store.errorMessage = ''
  store.analyzedText = ''
  store.result = null
}

function handleFillGoldenSample(): void {
  inputValidationError.value = ''
  store.fillGoldenSample()
}

function handleClear(): void {
  inputValidationError.value = ''
  store.clearInputs()
}

async function handleRunPreview(): Promise<void> {
  if (store.running) return
  inputValidationError.value = ''
  store.errorMessage = ''

  let parsedPayload: Record<string, unknown> | undefined
  if (store.mode === 'TEXT') {
    if (!store.inputText.trim()) {
      inputValidationError.value = '请输入待脱敏文本或点击「填充政务问答示例」'
      return
    }
  } else {
    if (!store.structuredJsonText.trim()) {
      inputValidationError.value = '请输入 JSON 对象或点击「填充政务问答示例」'
      return
    }
    try {
      const parsed = JSON.parse(store.structuredJsonText)
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        inputValidationError.value = '结构化载荷必须是 JSON 对象（以 { ... } 包裹）'
        return
      }
      parsedPayload = parsed as Record<string, unknown>
    } catch {
      inputValidationError.value = 'JSON 语法格式错误，请检查引号、逗号或括号匹配'
      return
    }
  }

  try {
    await store.runPreview(parsedPayload)
  } catch (err) {
    store.errorMessage = extractErrorMessage(err, '沙盒脱敏预览请求失败，请检查后端服务连接')
  }
}

async function handleCopyResult(): Promise<void> {
  if (!copyableOutput.value) return
  try {
    await navigator.clipboard?.writeText(copyableOutput.value)
    copied.value = true
    if (copyTimer) clearTimeout(copyTimer)
    copyTimer = setTimeout(() => {
      copied.value = false
    }, 2000)
  } catch {
    copied.value = false
  }
}

onMounted(async () => {
  loadingPolicies.value = true
  try {
    const res = await listPolicies()
    policyGroups.value = res.policies
    if (
      res.policies.length > 0 &&
      !res.policies.some((g) => g.policy_code === store.policyCode)
    ) {
      store.policyCode = res.policies[0].policy_code
    }
  } catch (err) {
    store.errorMessage = extractErrorMessage(err, '加载脱敏策略列表失败')
  } finally {
    loadingPolicies.value = false
  }
})

onBeforeUnmount(() => {
  if (copyTimer) {
    clearTimeout(copyTimer)
    copyTimer = null
  }
  store.clearSensitiveState()
})
</script>

<style scoped>
.sandbox-page {
  display: flex;
  flex-direction: column;
  gap: var(--ds-space-lg);
}

.sandbox-security-note {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  margin: 6px 0 0;
  color: var(--ds-color-success);
}

.sandbox-toolbar {
  display: flex;
  flex-wrap: wrap;
  align-items: flex-end;
  justify-content: space-between;
  gap: var(--ds-space-md);
}

.sandbox-toolbar__controls {
  display: flex;
  flex-wrap: wrap;
  align-items: flex-end;
  gap: var(--ds-space-lg);
}

.toolbar-field {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.toolbar-label {
  font-size: 0.75rem;
  font-weight: 500;
  color: var(--ds-text-secondary);
}

.sandbox-toolbar__actions {
  display: flex;
  flex-wrap: wrap;
  gap: var(--ds-space-sm);
}

.sandbox-alert {
  margin: 0;
}

.sandbox-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: var(--ds-space-lg);
  align-items: stretch;
}

.sandbox-pane {
  display: flex;
  flex-direction: column;
  gap: var(--ds-space-md);
  min-width: 0;
}

.pane-header {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: var(--ds-space-sm);
}

.pane-header__meta {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: var(--ds-space-sm);
}

.inline-field-error {
  margin: 0;
  font-size: 0.75rem;
  color: var(--ds-color-danger-text);
}

.pane-legend {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: var(--ds-space-sm);
  padding: var(--ds-space-sm) var(--ds-space-md);
}

.sandbox-output-body {
  min-height: 290px;
  padding: var(--ds-space-md);
  overflow-x: auto;
}

.masked-output-pre {
  margin: 0;
  white-space: pre-wrap;
  word-break: break-word;
  line-height: 1.7;
  color: var(--ds-text-primary);
}

.structured-traces {
  display: flex;
  flex-direction: column;
  gap: var(--ds-space-md);
}

.stale-edit-notice {
  margin-bottom: 10px;
  padding: 6px 10px;
  border-radius: var(--ds-radius-sm);
  border: 1px solid var(--ds-border-warning);
  background: var(--ds-bg-warning);
  color: var(--ds-color-warning);
  font-size: 0.8125rem;
}

.trace-row {
  padding-bottom: var(--ds-space-sm);
  border-bottom: 1px solid var(--ds-border-subtle);
}

.trace-row:last-child {
  border-bottom: none;
  padding-bottom: 0;
}

.trace-row__path {
  font-weight: 600;
  color: var(--ds-text-secondary);
  margin-bottom: 6px;
}

.trace-row__chips {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}

.sandbox-stats-bar {
  display: flex;
  flex-direction: column;
  gap: var(--ds-space-sm);
  padding-top: var(--ds-space-md);
  border-top: 1px solid var(--ds-border-subtle);
}

.stats-metrics {
  display: flex;
  flex-wrap: wrap;
  gap: var(--ds-space-md);
  font-size: 0.8125rem;
  color: var(--ds-text-secondary);
}

.stats-hits {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}

@media (max-width: 1023px) {
  .sandbox-grid {
    grid-template-columns: 1fr;
  }
}
</style>
