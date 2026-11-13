<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import StatusTag from '@/components/StatusTag.vue'
import { extractErrorMessage } from '@/api/client'
import {
  createAllowlistItem,
  deleteAllowlistItem,
  listAllowlists,
  testAllowlistMatch,
  updateAllowlistItem,
} from '@/api/allowlists'
import { useAuthStore } from '@/stores/auth'
import {
  ENTITY_LABEL_META,
  ENTITY_LABEL_ZH_MAP,
  MATCH_MODE_OPTIONS,
} from '@/constants/domain'
import type {
  AllowlistGroupSummary,
  AllowlistItem,
  AllowlistMatchMode,
  AllowlistTestResponseData,
} from '@/types/api'

const auth = useAuthStore()

const loading = ref(false)
const loadError = ref('')
const items = ref<AllowlistItem[]>([])
const groups = ref<AllowlistGroupSummary[]>([])

const selectedGroup = ref('')
const filterEnabled = ref<'all' | 'enabled' | 'disabled'>('all')
const keyword = ref('')

const canEdit = computed(() => auth.canEditAllowlists)
const readonlyReason = computed(() =>
  canEdit.value
    ? ''
    : `当前角色为 ${auth.role ?? 'GUEST'}（仅审核/只读），不可新增、修改或删除白名单规则`,
)

const filteredItems = computed(() => {
  const kw = keyword.value.trim().toLowerCase()
  return items.value.filter((item) => {
    if (selectedGroup.value && item.group_code !== selectedGroup.value) return false
    if (filterEnabled.value === 'enabled' && !item.is_enabled) return false
    if (filterEnabled.value === 'disabled' && item.is_enabled) return false
    if (
      kw &&
      !item.item_name.toLowerCase().includes(kw) &&
      !item.pattern_text.toLowerCase().includes(kw) &&
      !item.group_code.toLowerCase().includes(kw)
    ) {
      return false
    }
    return true
  })
})

function getMatchModeMeta(mode: AllowlistMatchMode) {
  return (
    MATCH_MODE_OPTIONS.find((m) => m.value === mode) ?? {
      value: mode,
      label: mode,
      tagType: 'info' as const,
    }
  )
}

function formatApplyLabels(labels: string[]): string {
  if (!labels || labels.length === 0) return '未指定实体（请至少选择 1 类）'
  return labels.map((l) => `${ENTITY_LABEL_ZH_MAP[l] ?? l} (${l})`).join('、')
}

async function loadData() {
  loading.value = true
  loadError.value = ''
  try {
    const res = await listAllowlists()
    items.value = res.items ?? []
    groups.value = res.groups ?? []
  } catch (err) {
    loadError.value = extractErrorMessage(err, '加载白名单列表失败')
  } finally {
    loading.value = false
  }
}

// Inline Match Tester (Zero-Client-Persistence: cleared onBeforeUnmount)
const tester = reactive({
  text: '',
  label: 'phone',
  include_saved: true,
})
const testRunning = ref(false)
const testError = ref('')
const testResult = ref<AllowlistTestResponseData | null>(null)

async function runInlineTest() {
  testError.value = ''
  testResult.value = null
  if (!tester.text.trim()) {
    testError.value = '请输入待验证的样本文本。'
    return
  }
  testRunning.value = true
  try {
    const groupCodes = selectedGroup.value ? [selectedGroup.value] : undefined
    testResult.value = await testAllowlistMatch({
      text: tester.text,
      label: tester.label,
      group_codes: groupCodes,
      include_saved: tester.include_saved,
    })
  } catch (err) {
    testError.value = extractErrorMessage(err, '白名单测试请求失败')
  } finally {
    testRunning.value = false
  }
}

function clearTesterSensitiveState() {
  tester.text = ''
  testResult.value = null
  testError.value = ''
}

// Toggle & Delete
async function handleToggleEnabled(item: AllowlistItem, nextVal: boolean) {
  if (!canEdit.value) return
  try {
    await updateAllowlistItem(item.id, { is_enabled: nextVal })
    item.is_enabled = nextVal
    ElMessage.success(nextVal ? '规则已启用' : '规则已停用')
    await loadData()
  } catch (err) {
    ElMessage.error(extractErrorMessage(err, '更新状态失败'))
  }
}

async function handleDelete(item: AllowlistItem) {
  if (!canEdit.value) return
  try {
    await ElMessageBox.confirm(
      `确认永久删除白名单规则「${item.item_name}」(${item.group_code})？删除后相关实体将不再被此规则豁免。`,
      '高风险操作确认',
      {
        confirmButtonText: '确认删除',
        cancelButtonText: '取消',
        type: 'warning',
      },
    )
    await deleteAllowlistItem(item.id)
    ElMessage.success('白名单规则已删除')
    await loadData()
  } catch {
    // cancelled or error handled
  }
}

// Create / Edit Drawer
const drawerOpen = ref(false)
const drawerSubmitting = ref(false)
const editingId = ref<number | null>(null)
const drawerForm = reactive({
  group_code: 'gov_public_hotline',
  item_name: '',
  match_mode: 'EXACT' as AllowlistMatchMode,
  pattern_text: '',
  apply_labels: [] as string[],
  is_enabled: true,
  remark: '',
})
const drawerErrors = reactive({
  group_code: '',
  item_name: '',
  pattern_text: '',
  apply_labels: '',
  general: '',
})

function resetDrawerErrors() {
  drawerErrors.group_code = ''
  drawerErrors.item_name = ''
  drawerErrors.pattern_text = ''
  drawerErrors.apply_labels = ''
  drawerErrors.general = ''
}

function openCreateDrawer() {
  if (!canEdit.value) return
  editingId.value = null
  drawerForm.group_code = selectedGroup.value || 'gov_public_hotline'
  drawerForm.item_name = ''
  drawerForm.match_mode = 'EXACT'
  drawerForm.pattern_text = ''
  drawerForm.apply_labels = ['phone']
  drawerForm.is_enabled = true
  drawerForm.remark = ''
  resetDrawerErrors()
  drawerOpen.value = true
}

function openEditDrawer(item: AllowlistItem) {
  if (!canEdit.value) return
  editingId.value = item.id
  drawerForm.group_code = item.group_code
  drawerForm.item_name = item.item_name
  drawerForm.match_mode = item.match_mode
  drawerForm.pattern_text = item.pattern_text
  drawerForm.apply_labels = [...(item.apply_labels ?? [])]
  drawerForm.is_enabled = item.is_enabled
  drawerForm.remark = item.remark ?? ''
  resetDrawerErrors()
  drawerOpen.value = true
}

async function handleDrawerSubmit() {
  resetDrawerErrors()
  if (!drawerForm.group_code.trim()) {
    drawerErrors.group_code = '请填写规则分组编码'
  }
  if (!drawerForm.item_name.trim()) {
    drawerErrors.item_name = '请填写规则名称'
  }
  if (!drawerForm.pattern_text.trim()) {
    drawerErrors.pattern_text = '请填写匹配表达式或固定串'
  }
  if (!drawerForm.apply_labels || drawerForm.apply_labels.length === 0) {
    drawerErrors.apply_labels = '请至少选择 1 类作用实体'
  }
  if (
    drawerErrors.group_code ||
    drawerErrors.item_name ||
    drawerErrors.pattern_text ||
    drawerErrors.apply_labels
  ) {
    return
  }

  drawerSubmitting.value = true
  try {
    const payload = {
      group_code: drawerForm.group_code.trim(),
      item_name: drawerForm.item_name.trim(),
      match_mode: drawerForm.match_mode,
      pattern_text: drawerForm.pattern_text,
      apply_labels: [...drawerForm.apply_labels],
      is_enabled: drawerForm.is_enabled,
      remark: drawerForm.remark.trim() || null,
    }
    if (editingId.value !== null) {
      await updateAllowlistItem(editingId.value, payload)
      ElMessage.success('白名单规则已更新')
    } else {
      await createAllowlistItem(payload)
      ElMessage.success('白名单规则已创建')
    }
    drawerOpen.value = false
    await loadData()
  } catch (err) {
    drawerErrors.general = extractErrorMessage(err, '保存白名单规则失败')
  } finally {
    drawerSubmitting.value = false
  }
}

onBeforeUnmount(() => {
  clearTesterSensitiveState()
})

onMounted(() => {
  void loadData()
})
</script>

<template>
  <div class="allowlists-page">
    <div class="ds-page-header">
      <div>
        <h1 class="ds-page-title">白名单豁免与规则测试中心</h1>
        <p class="ds-secondary-text" style="margin: 4px 0 0">
          配置 12345 政务热线、官方政务大厅地址、*.gov.cn 域名等公共信息豁免规则，支持实时试算验证。
        </p>
      </div>
      <el-tooltip :disabled="canEdit" :content="readonlyReason" placement="bottom">
        <el-button
          data-testid="add-allowlist-btn"
          type="primary"
          :disabled="!canEdit"
          @click="openCreateDrawer"
        >
          + 新增规则
        </el-button>
      </el-tooltip>
    </div>

    <el-alert
      v-if="!canEdit"
      type="warning"
      :closable="false"
      show-icon
      style="margin-bottom: 16px"
      :title="readonlyReason"
    />

    <el-alert
      v-if="loadError"
      type="error"
      :closable="false"
      show-icon
      style="margin-bottom: 16px"
      :title="loadError"
    />

    <!-- Inline Rule Match Tester -->
    <section class="ds-card tester-card" aria-label="规则在线试算">
      <div class="tester-header">
        <div>
          <h2 class="ds-section-title">在线匹配测试器（仅内存试算，不写库不留痕）</h2>
          <p class="ds-muted-text" style="margin: 2px 0 0">
            所有角色（含 AUDITOR）均可安全验证某段候选文本是否命中当前启用的白名单规则。
          </p>
        </div>
        <StatusTag
          v-if="testResult"
          :label="
            testResult.matched
              ? `命中豁免（共 ${testResult.matched_count} 条规则）`
              : '未命中豁免规则'
          "
          :tag-type="testResult.matched ? 'success' : 'info'"
        />
      </div>

      <div class="tester-controls">
        <div class="tester-field tester-field--wide">
          <label class="form-label" for="allowlist-test-text">测试文本</label>
          <input
            id="allowlist-test-text"
            v-model="tester.text"
            name="allowlist-test-text"
            type="text"
            class="ds-native-input"
            placeholder="例如：12345 或 https://www.changzhou.gov.cn"
          />
        </div>

        <div class="tester-field">
          <label class="form-label" for="allowlist-test-label">候选实体标签</label>
          <select id="allowlist-test-label" v-model="tester.label" class="ds-native-input">
            <option v-for="meta in ENTITY_LABEL_META" :key="meta.label" :value="meta.label">
              {{ meta.labelZh }} ({{ meta.label }})
            </option>
          </select>
        </div>

        <div class="tester-field tester-field--action">
          <el-button
            data-testid="allowlist-test-btn"
            :loading="testRunning"
            @click="runInlineTest"
          >
            测试命中
          </el-button>
          <el-button v-if="tester.text || testResult" @click="clearTesterSensitiveState">
            清空样本
          </el-button>
        </div>
      </div>

      <div v-if="testError" class="field-error-text" style="margin-top: 8px">{{ testError }}</div>

      <div v-if="testResult && testResult.matched_rules.length > 0" class="matched-rules-strip">
        <span class="ds-muted-text">命中明细：</span>
        <span
          v-for="(rule, idx) in testResult.matched_rules"
          :key="idx"
          class="ds-span-chip ds-span-chip--allowlist"
        >
          <span>[豁免] {{ rule.item_name }}</span>
          <span class="ds-span-chip__meta">{{ rule.group_code }} · {{ rule.match_mode }}</span>
        </span>
      </div>
    </section>

    <!-- Main Master-Detail List -->
    <div v-loading="loading" class="allowlists-workspace">
      <!-- Group Filter Rail -->
      <aside class="ds-card group-rail" aria-label="白名单分组">
        <div class="group-rail__title">规则分组</div>
        <button
          type="button"
          class="group-pill"
          :class="{ 'is-selected': selectedGroup === '' }"
          @click="selectedGroup = ''"
        >
          <span>全部分组</span>
          <span class="ds-mono ds-tabular-nums">{{ items.length }}</span>
        </button>

        <button
          v-for="grp in groups"
          :key="grp.group_code"
          type="button"
          class="group-pill"
          :class="{ 'is-selected': selectedGroup === grp.group_code }"
          @click="selectedGroup = grp.group_code"
        >
          <span class="ds-mono group-pill__code">{{ grp.group_code }}</span>
          <span class="ds-mono ds-tabular-nums">{{ grp.enabled_count }}/{{ grp.total_count }}</span>
        </button>
      </aside>

      <!-- Rules Table -->
      <section class="ds-card rules-card">
        <div class="rules-toolbar">
          <el-input
            v-model="keyword"
            placeholder="按规则名称、分组或匹配表达式搜索"
            clearable
            style="max-width: 300px"
          />
          <el-select v-model="filterEnabled" style="width: 148px">
            <el-option label="全部状态" value="all" />
            <el-option label="仅已启用" value="enabled" />
            <el-option label="仅已停用" value="disabled" />
          </el-select>
        </div>

        <el-empty v-if="!loading && filteredItems.length === 0" description="暂无匹配的白名单规则" />

        <div v-else class="table-scroll-wrap">
          <table class="ds-data-table">
            <thead>
              <tr>
                <th>分组与规则名称</th>
                <th style="width: 120px">匹配模式</th>
                <th>匹配表达式</th>
                <th>作用实体标签</th>
                <th style="width: 112px">启用状态</th>
                <th style="width: 136px">操作</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="row in filteredItems" :key="row.id">
                <td>
                  <div class="rule-name-cell">{{ row.item_name }}</div>
                  <div class="ds-mono ds-muted-text">{{ row.group_code }}</div>
                </td>
                <td>
                  <StatusTag
                    :label="getMatchModeMeta(row.match_mode).label"
                    :tag-type="getMatchModeMeta(row.match_mode).tagType"
                  />
                </td>
                <td>
                  <code class="ds-mono pattern-code">{{ row.pattern_text }}</code>
                </td>
                <td>
                  <span class="ds-secondary-text" style="font-size: 0.8125rem">
                    {{ formatApplyLabels(row.apply_labels) }}
                  </span>
                </td>
                <td>
                  <div class="switch-status-cell">
                    <el-switch
                      :model-value="row.is_enabled"
                      :disabled="!canEdit"
                      :aria-label="`切换 ${row.item_name} 状态`"
                      @change="(val: string | number | boolean) => handleToggleEnabled(row, Boolean(val))"
                    />
                    <span class="ds-muted-text">{{ row.is_enabled ? '已启用' : '已停用' }}</span>
                  </div>
                </td>
                <td>
                  <div class="row-actions">
                    <el-tooltip :disabled="canEdit" :content="readonlyReason" placement="top">
                      <el-button
                        size="small"
                        :disabled="!canEdit"
                        @click="openEditDrawer(row)"
                      >
                        编辑
                      </el-button>
                    </el-tooltip>
                    <el-tooltip :disabled="canEdit" :content="readonlyReason" placement="top">
                      <el-button
                        :data-testid="`delete-allowlist-${row.id}`"
                        size="small"
                        type="danger"
                        plain
                        :disabled="!canEdit"
                        @click="handleDelete(row)"
                      >
                        删除
                      </el-button>
                    </el-tooltip>
                  </div>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>
    </div>

    <!-- Create / Edit Drawer -->
    <el-drawer
      v-model="drawerOpen"
      :title="editingId !== null ? '编辑白名单豁免规则' : '新增白名单豁免规则'"
      size="460px"
      :close-on-click-modal="false"
    >
      <template v-if="drawerOpen">
        <div class="dialog-form-stack">
          <el-alert
            v-if="drawerErrors.general"
            type="error"
            :closable="false"
            show-icon
            :title="drawerErrors.general"
          />

          <div class="form-field">
            <label class="form-label" for="drawer-group-code">分组编码 (group_code)</label>
            <el-input
              id="drawer-group-code"
              v-model="drawerForm.group_code"
              placeholder="例如 gov_public_hotline"
            />
            <div v-if="drawerErrors.group_code" class="field-error-text">{{ drawerErrors.group_code }}</div>
          </div>

          <div class="form-field">
            <label class="form-label" for="drawer-item-name">规则名称</label>
            <el-input
              id="drawer-item-name"
              v-model="drawerForm.item_name"
              placeholder="例如 政务便民服务热线 12345"
            />
            <div v-if="drawerErrors.item_name" class="field-error-text">{{ drawerErrors.item_name }}</div>
          </div>

          <div class="form-field">
            <label class="form-label" for="drawer-match-mode">匹配模式</label>
            <el-select id="drawer-match-mode" v-model="drawerForm.match_mode" style="width: 100%">
              <el-option
                v-for="opt in MATCH_MODE_OPTIONS"
                :key="opt.value"
                :label="opt.label"
                :value="opt.value"
              />
            </el-select>
          </div>

          <div class="form-field">
            <label class="form-label" for="drawer-pattern-text">匹配表达式 / 固定值</label>
            <el-input
              id="drawer-pattern-text"
              v-model="drawerForm.pattern_text"
              type="textarea"
              :rows="2"
              placeholder="精确文本或正则表达式"
            />
            <div v-if="drawerErrors.pattern_text" class="field-error-text">
              {{ drawerErrors.pattern_text }}
            </div>
          </div>

          <div class="form-field">
            <label class="form-label" for="drawer-apply-labels">作用实体类别（必填，至少选择 1 类）</label>
            <el-select
              id="drawer-apply-labels"
              v-model="drawerForm.apply_labels"
              multiple
              filterable
              style="width: 100%"
              @change="drawerErrors.apply_labels = ''"
            >
              <el-option
                v-for="meta in ENTITY_LABEL_META"
                :key="meta.label"
                :label="`${meta.labelZh} (${meta.label})`"
                :value="meta.label"
              />
            </el-select>
            <div v-if="drawerErrors.apply_labels" class="field-error-text">
              {{ drawerErrors.apply_labels }}
            </div>
          </div>

          <div class="form-field">
            <el-checkbox v-model="drawerForm.is_enabled">立即启用该规则</el-checkbox>
          </div>

          <div class="form-field">
            <label class="form-label" for="drawer-remark">备注</label>
            <el-input id="drawer-remark" v-model="drawerForm.remark" type="textarea" :rows="2" />
          </div>
        </div>
      </template>

      <template #footer>
        <template v-if="drawerOpen">
          <el-button @click="drawerOpen = false">取消</el-button>
          <el-button type="primary" :loading="drawerSubmitting" @click="handleDrawerSubmit">
            {{ editingId !== null ? '保存修改' : '创建规则' }}
          </el-button>
        </template>
      </template>
    </el-drawer>
  </div>
</template>

<style scoped>
.tester-card {
  margin-bottom: 16px;
}

.tester-header {
  display: flex;
  flex-wrap: wrap;
  justify-content: space-between;
  align-items: center;
  gap: 10px;
  margin-bottom: 12px;
}

.tester-controls {
  display: flex;
  flex-wrap: wrap;
  align-items: flex-end;
  gap: 12px;
}

.tester-field {
  display: flex;
  flex-direction: column;
  gap: 6px;
  min-width: 220px;
}

.tester-field--wide {
  flex: 1 1 320px;
}

.tester-field--action {
  flex-direction: row;
  align-items: center;
  min-width: auto;
}

.ds-native-input {
  height: 32px;
  padding: 4px 10px;
  border: 1px solid var(--ds-border-strong);
  border-radius: var(--ds-radius-md);
  background: var(--ds-bg-card);
  color: var(--ds-text-primary);
  font-size: 0.875rem;
}

.matched-rules-strip {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
  margin-top: 12px;
  padding-top: 10px;
  border-top: 1px solid var(--ds-border-subtle);
}

.allowlists-workspace {
  display: grid;
  grid-template-columns: 240px minmax(0, 1fr);
  gap: 16px;
  align-items: start;
}

.group-rail {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.group-rail__title {
  font-size: 0.9375rem;
  font-weight: 600;
  margin-bottom: 6px;
}

.group-pill {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  padding: 8px 10px;
  border: 1px solid var(--ds-border-subtle);
  border-radius: var(--ds-radius-md);
  background: var(--ds-bg-panel);
  cursor: pointer;
  text-align: left;
  font-size: 0.8125rem;
}

.group-pill.is-selected {
  background: var(--ds-bg-active);
  border-color: var(--ds-color-primary);
  color: var(--ds-color-primary);
}

.group-pill__code {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.rules-toolbar {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  margin-bottom: 14px;
}

.table-scroll-wrap {
  overflow-x: auto;
}

.rule-name-cell {
  font-weight: 500;
}

.pattern-code {
  display: inline-block;
  max-width: 280px;
  word-break: break-all;
}

.switch-status-cell {
  display: inline-flex;
  align-items: center;
  gap: 6px;
}

.row-actions {
  display: flex;
  gap: 6px;
}

.dialog-form-stack,
.form-field {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.form-label {
  font-size: 0.8125rem;
  font-weight: 500;
  color: var(--ds-text-secondary);
}

.field-error-text {
  font-size: 0.75rem;
  color: var(--ds-color-danger-text);
}

@media (max-width: 1023px) {
  .allowlists-workspace {
    grid-template-columns: 1fr;
  }
}
</style>
