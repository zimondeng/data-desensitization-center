<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import StatusTag from '@/components/StatusTag.vue'
import { listAllowlists } from '@/api/allowlists'
import {
  createOrBumpPolicyVersion,
  listPolicies,
  setDefaultPolicyVersion,
} from '@/api/policies'
import { useAuthStore } from '@/stores/auth'
import {
  createDefaultEntityRules,
  ENTITY_LABEL_META,
  FIELD_ROLE_META,
  HIGH_RISK_DEFAULT_LABELS,
  MASK_ACTION_OPTIONS,
  ONNX_VARIANT_OPTIONS,
  POLICY_STATUS_META,
  SCOPE_MODE_OPTIONS,
} from '@/constants/domain'
import type {
  AllowlistGroupSummary,
  EntityRuleConfig,
  FieldRole,
  FieldRoleRule,
  OnnxVariant,
  PolicyGroupItem,
  PolicyStatus,
  PolicyVersionItem,
  ScopeMode,
} from '@/types/api'

const POLICY_CODE_REGEX = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/

const auth = useAuthStore()
const router = useRouter()

const loading = ref(false)
const loadError = ref('')
const saving = ref(false)
const settingDefault = ref(false)
const submitError = ref('')

const policyGroups = ref<PolicyGroupItem[]>([])
const allowlistGroups = ref<AllowlistGroupSummary[]>([])
const selectedPolicyCode = ref('')
const selectedVersionNumber = ref<number | null>(null)

interface PolicyFormState {
  policy_code: string
  policy_name: string
  scope_mode: ScopeMode
  onnx_variant: OnnxVariant
  status: PolicyStatus
  set_as_default: boolean
  allowlist_groups: string[]
  description: string
  entity_rules: Record<string, EntityRuleConfig>
  default_role: FieldRole
  high_risk_only_labels: string[]
  field_rules: FieldRoleRule[]
}

function buildEmptyForm(): PolicyFormState {
  return {
    policy_code: '',
    policy_name: '',
    scope_mode: 'CONVERSATION',
    onnx_variant: 'int8',
    status: 'ACTIVE',
    set_as_default: false,
    allowlist_groups: [],
    description: '',
    entity_rules: createDefaultEntityRules(),
    default_role: 'FULL_MASK_WRITE_SCOPE',
    high_risk_only_labels: [...HIGH_RISK_DEFAULT_LABELS],
    field_rules: [],
  }
}

const form = reactive<PolicyFormState>(buildEmptyForm())
const savedSnapshot = ref('')

function cloneEntityRules(source: Record<string, EntityRuleConfig>): Record<string, EntityRuleConfig> {
  const defaults = createDefaultEntityRules()
  const merged: Record<string, EntityRuleConfig> = {}
  for (const meta of ENTITY_LABEL_META) {
    const incoming = source[meta.label] ?? defaults[meta.label]
    merged[meta.label] = {
      enabled: Boolean(incoming.enabled),
      min_score: Number(incoming.min_score ?? 0.8),
      action: incoming.action ?? 'PLACEHOLDER',
      prefix: incoming.prefix ?? meta.defaultPrefix,
      keep_head: incoming.keep_head ?? 4,
      keep_tail: incoming.keep_tail ?? 4,
      mask_char: incoming.mask_char ?? '*',
      replacement: incoming.replacement ?? '[REDACTED]',
      hash_len: incoming.hash_len ?? 12,
    }
  }
  return merged
}

function serializeFormSnapshot(): string {
  return JSON.stringify({
    policy_code: form.policy_code,
    policy_name: form.policy_name,
    scope_mode: form.scope_mode,
    onnx_variant: form.onnx_variant,
    status: form.status,
    set_as_default: form.set_as_default,
    allowlist_groups: [...form.allowlist_groups].sort(),
    description: form.description,
    entity_rules: form.entity_rules,
    default_role: form.default_role,
    high_risk_only_labels: [...form.high_risk_only_labels].sort(),
    field_rules: form.field_rules,
  })
}

const isDirty = computed(() => {
  if (!savedSnapshot.value) return false
  return serializeFormSnapshot() !== savedSnapshot.value
})

const currentGroup = computed(() =>
  policyGroups.value.find((g) => g.policy_code === selectedPolicyCode.value) ?? null,
)

const currentVersionItem = computed<PolicyVersionItem | null>(() => {
  if (!currentGroup.value || selectedVersionNumber.value === null) return null
  return (
    currentGroup.value.versions.find((v) => v.version === selectedVersionNumber.value) ?? null
  )
})

const nextVersionNumber = computed(() => (currentGroup.value ? currentGroup.value.latest_version + 1 : 1))

const canEdit = computed(() => auth.canEditPolicies)
const readonlyReason = computed(() =>
  canEdit.value
    ? ''
    : `当前角色为 ${auth.role ?? 'GUEST'}（仅审核/只读），不可发布策略或修改默认版本`,
)

const allowlistOptions = computed(() => {
  const seen = new Set<string>(allowlistGroups.value.map((g) => g.group_code))
  for (const code of form.allowlist_groups) {
    seen.add(code)
  }
  return Array.from(seen).map((code) => {
    const found = allowlistGroups.value.find((g) => g.group_code === code)
    return {
      value: code,
      label: found ? `${code}（启用 ${found.enabled_count}/${found.total_count}）` : code,
    }
  })
})

function applyVersionToForm(item: PolicyVersionItem) {
  form.policy_code = item.policy_code
  form.policy_name = item.policy_name
  form.scope_mode = item.scope_mode
  form.onnx_variant = item.onnx_variant
  form.status = item.status
  form.set_as_default = false
  form.allowlist_groups = [...(item.allowlist_groups ?? [])]
  form.description = item.description ?? ''
  form.entity_rules = cloneEntityRules(item.entity_rules ?? {})
  form.default_role = item.field_role_rules?.default_role ?? 'FULL_MASK_WRITE_SCOPE'
  form.high_risk_only_labels = [...(item.field_role_rules?.high_risk_only_labels ?? HIGH_RISK_DEFAULT_LABELS)]
  form.field_rules = (item.field_role_rules?.rules ?? []).map((rule) => ({
    jsonpath: rule.jsonpath,
    role: rule.role,
  }))
  submitError.value = ''
  savedSnapshot.value = serializeFormSnapshot()
}

async function confirmDiscardIfDirty(): Promise<boolean> {
  if (!isDirty.value) return true
  try {
    await ElMessageBox.confirm(
      '当前策略配置有未发布的修改，切换或离开将丢失草稿，确认继续？',
      '未保存修改提醒',
      {
        confirmButtonText: '确认放弃修改',
        cancelButtonText: '继续编辑',
        type: 'warning',
      },
    )
    return true
  } catch {
    return false
  }
}

async function selectPolicyVersion(policyCode: string, version: number) {
  if (policyCode === selectedPolicyCode.value && version === selectedVersionNumber.value) {
    return
  }
  const ok = await confirmDiscardIfDirty()
  if (!ok) return
  const group = policyGroups.value.find((g) => g.policy_code === policyCode)
  const ver = group?.versions.find((v) => v.version === version)
  if (!ver) return
  selectedPolicyCode.value = policyCode
  selectedVersionNumber.value = version
  applyVersionToForm(ver)
}

async function loadData(preferCode?: string, preferVersion?: number) {
  loading.value = true
  loadError.value = ''
  try {
    const [policyRes, allowlistRes] = await Promise.all([
      listPolicies(),
      listAllowlists(),
    ])
    policyGroups.value = policyRes.policies ?? []
    allowlistGroups.value = allowlistRes.groups ?? []

    if (policyGroups.value.length > 0) {
      const targetGroup =
        (preferCode && policyGroups.value.find((g) => g.policy_code === preferCode)) ||
        policyGroups.value.find((g) => g.policy_code === selectedPolicyCode.value) ||
        policyGroups.value[0]
      const targetVersion =
        (preferVersion && targetGroup.versions.find((v) => v.version === preferVersion)) ||
        targetGroup.versions.find((v) => v.version === targetGroup.default_version) ||
        targetGroup.versions[0]

      if (targetVersion) {
        selectedPolicyCode.value = targetGroup.policy_code
        selectedVersionNumber.value = targetVersion.version
        applyVersionToForm(targetVersion)
      }
    }
  } catch (err) {
    loadError.value = err instanceof Error ? err.message : '加载策略列表失败'
  } finally {
    loading.value = false
  }
}

function addFieldRoleRule() {
  form.field_rules.push({
    jsonpath: '$.',
    role: 'REPLAY_SCOPE_AND_HIGH_RISK',
  })
}

function removeFieldRoleRule(index: number) {
  form.field_rules.splice(index, 1)
}

function resetDraft() {
  if (currentVersionItem.value) {
    applyVersionToForm(currentVersionItem.value)
  }
}

function buildPayloadEntityRules(): Record<string, EntityRuleConfig> {
  const payload: Record<string, EntityRuleConfig> = {}
  for (const meta of ENTITY_LABEL_META) {
    const r = form.entity_rules[meta.label]
    if (!r) continue
    const clean: EntityRuleConfig = {
      enabled: Boolean(r.enabled),
      min_score: Number(r.min_score),
      action: r.action,
    }
    if (r.action === 'PLACEHOLDER') {
      clean.prefix = (r.prefix ?? meta.defaultPrefix).trim() || meta.defaultPrefix
    } else if (r.action === 'PARTIAL') {
      clean.keep_head = Number(r.keep_head ?? 2)
      clean.keep_tail = Number(r.keep_tail ?? 2)
      clean.mask_char = (r.mask_char ?? '*').slice(0, 1) || '*'
    } else if (r.action === 'FIXED') {
      clean.replacement = r.replacement ?? '[REDACTED]'
    } else if (r.action === 'HASH') {
      clean.hash_len = Number(r.hash_len ?? 12)
    }
    payload[meta.label] = clean
  }
  return payload
}

async function handlePublishNewVersion() {
  if (!canEdit.value) return
  submitError.value = ''

  if (!form.policy_name.trim()) {
    submitError.value = '请填写策略名称。'
    return
  }
  const invalidPath = form.field_rules.find((item) => !item.jsonpath.trim().startsWith('$'))
  if (invalidPath) {
    submitError.value = `JSONPath 规则必须以 $ 开头：${invalidPath.jsonpath || '(空)'}`
    return
  }

  saving.value = true
  try {
    const created = await createOrBumpPolicyVersion({
      policy_code: form.policy_code,
      policy_name: form.policy_name.trim(),
      scope_mode: form.scope_mode,
      onnx_variant: form.onnx_variant,
      entity_rules: buildPayloadEntityRules(),
      field_role_rules: {
        default_role: form.default_role,
        high_risk_only_labels: [...form.high_risk_only_labels],
        rules: form.field_rules.map((r) => ({
          jsonpath: r.jsonpath.trim(),
          role: r.role,
        })),
      },
      allowlist_groups: [...form.allowlist_groups],
      set_as_default: form.set_as_default,
      status: form.status,
      description: form.description.trim() || null,
    })
    ElMessage.success(`已发布不可变新版本 ${created.policy_code} v${created.version}`)
    await loadData(created.policy_code, created.version)
  } catch (err) {
    submitError.value = err instanceof Error ? err.message : '发布策略版本失败'
  } finally {
    saving.value = false
  }
}

async function handleSetDefaultVersion() {
  if (!canEdit.value || !currentVersionItem.value || currentVersionItem.value.is_default) return
  settingDefault.value = true
  submitError.value = ''
  try {
    const updated = await setDefaultPolicyVersion(
      currentVersionItem.value.policy_code,
      currentVersionItem.value.version,
    )
    ElMessage.success(`已将 ${updated.policy_code} v${updated.version} 设为默认策略版本`)
    await loadData(updated.policy_code, updated.version)
  } catch (err) {
    submitError.value = err instanceof Error ? err.message : '设置默认版本失败'
  } finally {
    settingDefault.value = false
  }
}

// Create New Policy Code Dialog
const createDialogOpen = ref(false)
const createSubmitting = ref(false)
const createForm = reactive({
  policy_code: '',
  policy_name: '',
  scope_mode: 'CONVERSATION' as ScopeMode,
  description: '',
})
const createFormErrors = reactive({
  policy_code: '',
  policy_name: '',
  general: '',
})

async function openCreatePolicyDialog() {
  if (!canEdit.value) return
  const ok = await confirmDiscardIfDirty()
  if (!ok) return
  createForm.policy_code = ''
  createForm.policy_name = ''
  createForm.scope_mode = 'CONVERSATION'
  createForm.description = ''
  createFormErrors.policy_code = ''
  createFormErrors.policy_name = ''
  createFormErrors.general = ''
  createDialogOpen.value = true
}

async function handleCreateNewPolicyCode() {
  createFormErrors.policy_code = ''
  createFormErrors.policy_name = ''
  createFormErrors.general = ''

  const code = createForm.policy_code.trim()
  const name = createForm.policy_name.trim()
  if (!POLICY_CODE_REGEX.test(code)) {
    createFormErrors.policy_code = '仅允许字母、数字、下划线或连字符，且须以字母/数字开头（最多64位）'
    return
  }
  if (!name) {
    createFormErrors.policy_name = '请输入策略名称'
    return
  }
  if (policyGroups.value.some((g) => g.policy_code === code)) {
    createFormErrors.policy_code = `策略编码 ${code} 已存在，请在右侧直接发布新版本`
    return
  }

  createSubmitting.value = true
  try {
    const created = await createOrBumpPolicyVersion({
      policy_code: code,
      policy_name: name,
      scope_mode: createForm.scope_mode,
      onnx_variant: 'int8',
      entity_rules: createDefaultEntityRules(),
      field_role_rules: {
        default_role: 'FULL_MASK_WRITE_SCOPE',
        high_risk_only_labels: [...HIGH_RISK_DEFAULT_LABELS],
        rules: [],
      },
      allowlist_groups: [],
      set_as_default: false,
      status: 'ACTIVE',
      description: createForm.description.trim() || null,
    })
    createDialogOpen.value = false
    ElMessage.success(`已创建策略 ${created.policy_code} v1`)
    await loadData(created.policy_code, created.version)
  } catch (err) {
    createFormErrors.general = err instanceof Error ? err.message : '创建策略失败'
  } finally {
    createSubmitting.value = false
  }
}

function handleBeforeUnload(event: BeforeUnloadEvent) {
  if (isDirty.value) {
    event.preventDefault()
    event.returnValue = ''
  }
}

const removeRouteGuard = router.beforeEach(async (to, from) => {
  if (to.fullPath === from.fullPath) return true
  return await confirmDiscardIfDirty()
})

onBeforeUnmount(() => {
  removeRouteGuard()
  window.removeEventListener('beforeunload', handleBeforeUnload)
})

onMounted(() => {
  window.addEventListener('beforeunload', handleBeforeUnload)
  void loadData()
})
</script>

<template>
  <div class="policies-page">
    <div class="ds-page-header">
      <div>
        <h1 class="ds-page-title">策略中心 · 不可变版本治理</h1>
        <p class="ds-secondary-text" style="margin: 4px 0 0">
          每次保存都会生成不可变新版本 v{N+1}，保障审计溯源与回滚能力。
        </p>
      </div>
      <div class="policies-header-actions">
        <el-tooltip :disabled="canEdit" :content="readonlyReason" placement="bottom">
          <el-button
            data-testid="new-policy-code-btn"
            :disabled="!canEdit"
            @click="openCreatePolicyDialog"
          >
            + 新建策略编码
          </el-button>
        </el-tooltip>
      </div>
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

    <div v-loading="loading" class="policies-workspace">
      <!-- Left Master List -->
      <aside class="ds-card policies-sidebar" aria-label="策略与版本列表">
        <div class="policies-sidebar__title">策略编码与版本时间线</div>
        <el-empty v-if="!loading && policyGroups.length === 0" description="暂无策略配置" />

        <div v-for="group in policyGroups" :key="group.policy_code" class="policy-group-block">
          <div class="policy-group-header">
            <span class="ds-mono policy-group-code">{{ group.policy_code }}</span>
            <span class="ds-muted-text ds-tabular-nums">共 {{ group.versions.length }} 版</span>
          </div>
          <div class="policy-group-name">{{ group.policy_name }}</div>

          <ul class="policy-version-list">
            <li v-for="ver in group.versions" :key="ver.uuid">
              <button
                type="button"
                class="policy-version-item"
                :class="{
                  'is-selected':
                    selectedPolicyCode === group.policy_code &&
                    selectedVersionNumber === ver.version,
                }"
                @click="selectPolicyVersion(group.policy_code, ver.version)"
              >
                <div class="policy-version-item__top">
                  <span class="ds-mono ds-tabular-nums">v{{ ver.version }}</span>
                  <div class="policy-version-item__tags">
                    <StatusTag
                      v-if="ver.is_default"
                      label="默认"
                      tag-type="primary"
                    />
                    <StatusTag
                      :label="POLICY_STATUS_META[ver.status]?.label ?? ver.status"
                      :tag-type="POLICY_STATUS_META[ver.status]?.tagType ?? 'info'"
                    />
                  </div>
                </div>
                <div class="policy-version-item__meta">
                  <span>{{ ver.scope_mode }} · {{ ver.onnx_variant }}</span>
                </div>
              </button>
            </li>
          </ul>
        </div>
      </aside>

      <!-- Right Detail Editor -->
      <section class="policies-editor">
        <div v-if="!currentVersionItem" class="ds-card">
          <el-empty description="请选择左侧策略版本查看或派发新版本" />
        </div>

        <template v-else>
          <!-- Version Banner & Default Button -->
          <div class="ds-card editor-summary-card">
            <div class="editor-summary-row">
              <div>
                <div class="editor-summary-badges">
                  <span class="ds-mono editor-code">{{ currentVersionItem.policy_code }}</span>
                  <StatusTag
                    :label="`正在查看 v${currentVersionItem.version}`"
                    tag-type="info"
                  />
                  <StatusTag
                    v-if="currentVersionItem.is_default"
                    label="当前默认版本"
                    tag-type="primary"
                  />
                  <StatusTag
                    :label="POLICY_STATUS_META[currentVersionItem.status]?.label ?? currentVersionItem.status"
                    :tag-type="POLICY_STATUS_META[currentVersionItem.status]?.tagType ?? 'info'"
                  />
                  <StatusTag
                    v-if="isDirty"
                    label="有未发布草稿修改"
                    tag-type="warning"
                  />
                </div>
                <p class="ds-muted-text" style="margin: 6px 0 0">
                  只读快照不可原地覆写；所有改动将发布为不可变版本
                  <span class="ds-mono ds-tabular-nums">v{{ nextVersionNumber }}</span>
                </p>
              </div>

              <el-tooltip
                :disabled="canEdit && !currentVersionItem.is_default"
                :content="
                  !canEdit
                    ? readonlyReason
                    : '当前版本已是该策略默认版本'
                "
                placement="top"
              >
                <el-button
                  :disabled="!canEdit || currentVersionItem.is_default || settingDefault"
                  :loading="settingDefault"
                  @click="handleSetDefaultVersion"
                >
                  设为默认版本
                </el-button>
              </el-tooltip>
            </div>
          </div>

          <!-- Section 1: Basic Config -->
          <div class="ds-card">
            <h2 class="ds-section-title" style="margin-bottom: 14px">1. 基础配置</h2>
            <div class="form-grid-2col">
              <div class="form-field">
                <label class="form-label" for="policy-name-input">策略名称</label>
                <el-input
                  id="policy-name-input"
                  v-model="form.policy_name"
                  name="policy_name"
                  :disabled="!canEdit"
                  placeholder="请输入策略名称"
                />
              </div>

              <div class="form-field">
                <label class="form-label" for="policy-scope-select">一致性作用域 (Scope Mode)</label>
                <el-select
                  id="policy-scope-select"
                  v-model="form.scope_mode"
                  :disabled="!canEdit"
                  style="width: 100%"
                >
                  <el-option
                    v-for="opt in SCOPE_MODE_OPTIONS"
                    :key="opt.value"
                    :label="opt.label"
                    :value="opt.value"
                  />
                </el-select>
              </div>

              <div class="form-field">
                <label class="form-label" for="policy-onnx-select">ONNX 推理模型变体</label>
                <el-select
                  id="policy-onnx-select"
                  v-model="form.onnx_variant"
                  :disabled="!canEdit"
                  style="width: 100%"
                >
                  <el-option
                    v-for="opt in ONNX_VARIANT_OPTIONS"
                    :key="opt.value"
                    :label="opt.label"
                    :value="opt.value"
                  />
                </el-select>
              </div>

              <div class="form-field">
                <label class="form-label" for="policy-status-select">新版本状态</label>
                <el-select
                  id="policy-status-select"
                  v-model="form.status"
                  :disabled="!canEdit"
                  style="width: 100%"
                >
                  <el-option label="已激活 ACTIVE" value="ACTIVE" />
                  <el-option label="草稿 DRAFT" value="DRAFT" />
                  <el-option label="已归档 ARCHIVED" value="ARCHIVED" />
                </el-select>
              </div>

              <div class="form-field form-field--full">
                <label class="form-label" for="policy-allowlists-select">绑定白名单分组</label>
                <el-select
                  id="policy-allowlists-select"
                  v-model="form.allowlist_groups"
                  multiple
                  filterable
                  :disabled="!canEdit"
                  placeholder="选择豁免白名单分组"
                  style="width: 100%"
                >
                  <el-option
                    v-for="opt in allowlistOptions"
                    :key="opt.value"
                    :label="opt.label"
                    :value="opt.value"
                  />
                </el-select>
              </div>

              <div class="form-field form-field--full">
                <label class="form-label" for="policy-desc-input">版本说明</label>
                <el-input
                  id="policy-desc-input"
                  v-model="form.description"
                  type="textarea"
                  :rows="2"
                  :disabled="!canEdit"
                  placeholder="描述该版本策略的变更点或适用业务场景"
                />
              </div>

              <div class="form-field form-field--full">
                <el-checkbox v-model="form.set_as_default" :disabled="!canEdit">
                  发布新版本 v{{ nextVersionNumber }} 后自动设为默认版本
                </el-checkbox>
              </div>
            </div>
          </div>

          <!-- Section 2: 14 Entity Matrix -->
          <div class="ds-card">
            <h2 class="ds-section-title" style="margin-bottom: 12px">
              2. 14 类实体检测与掩码规则矩阵
            </h2>
            <div class="entity-table-wrap">
              <table class="ds-matrix-table">
                <thead>
                  <tr>
                    <th>实体类别</th>
                    <th style="width: 72px; text-align: center">启用</th>
                    <th style="width: 120px">置信度阈值</th>
                    <th style="width: 196px">掩码动作</th>
                    <th>动作参数</th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="row in ENTITY_LABEL_META" :key="row.label">
                    <td>
                      <div class="entity-cell">
                        <div class="entity-cell__title">
                          <span>{{ row.labelZh }}</span>
                          <span
                            class="ds-span-chip"
                            :class="
                              row.detector === 'onnx'
                                ? 'ds-span-chip--onnx'
                                : 'ds-span-chip--regex'
                            "
                          >
                            {{ row.detector === 'onnx' ? 'ONNX 语义' : '正则校验' }}
                          </span>
                        </div>
                        <div class="ds-mono ds-muted-text">{{ row.label }}</div>
                      </div>
                    </td>
                    <td style="text-align: center">
                      <el-switch
                        v-if="form.entity_rules[row.label]"
                        v-model="form.entity_rules[row.label].enabled"
                        :disabled="!canEdit"
                        :aria-label="`启用 ${row.labelZh}`"
                      />
                    </td>
                    <td>
                      <input
                        v-if="form.entity_rules[row.label]"
                        v-model.number="form.entity_rules[row.label].min_score"
                        type="number"
                        min="0"
                        max="1"
                        step="0.05"
                        class="ds-native-input ds-tabular-nums"
                        :disabled="!canEdit || !form.entity_rules[row.label].enabled"
                        :aria-label="`${row.labelZh} 阈值`"
                        style="width: 88px"
                      />
                    </td>
                    <td>
                      <select
                        v-if="form.entity_rules[row.label]"
                        v-model="form.entity_rules[row.label].action"
                        class="ds-native-input"
                        :disabled="!canEdit || !form.entity_rules[row.label].enabled"
                        :aria-label="`${row.labelZh} 掩码动作`"
                        style="width: 184px"
                      >
                        <option
                          v-for="opt in MASK_ACTION_OPTIONS"
                          :key="opt.value"
                          :value="opt.value"
                        >
                          {{ opt.label }}
                        </option>
                      </select>
                    </td>
                    <td>
                      <div v-if="form.entity_rules[row.label]" class="action-params-cell">
                        <template v-if="form.entity_rules[row.label].action === 'PLACEHOLDER'">
                          <span class="ds-muted-text">前缀</span>
                          <input
                            v-model="form.entity_rules[row.label].prefix"
                            type="text"
                            class="ds-native-input ds-mono"
                            :disabled="!canEdit || !form.entity_rules[row.label].enabled"
                            style="width: 112px"
                          />
                        </template>

                        <template v-else-if="form.entity_rules[row.label].action === 'PARTIAL'">
                          <span class="ds-muted-text">前</span>
                          <input
                            v-model.number="form.entity_rules[row.label].keep_head"
                            type="number"
                            min="0"
                            max="16"
                            class="ds-native-input ds-tabular-nums"
                            :disabled="!canEdit || !form.entity_rules[row.label].enabled"
                            style="width: 58px"
                          />
                          <span class="ds-muted-text">后</span>
                          <input
                            v-model.number="form.entity_rules[row.label].keep_tail"
                            type="number"
                            min="0"
                            max="16"
                            class="ds-native-input ds-tabular-nums"
                            :disabled="!canEdit || !form.entity_rules[row.label].enabled"
                            style="width: 58px"
                          />
                        </template>

                        <template v-else-if="form.entity_rules[row.label].action === 'FIXED'">
                          <span class="ds-muted-text">替换为</span>
                          <input
                            v-model="form.entity_rules[row.label].replacement"
                            type="text"
                            class="ds-native-input ds-mono"
                            :disabled="!canEdit || !form.entity_rules[row.label].enabled"
                            style="width: 150px"
                          />
                        </template>

                        <template v-else-if="form.entity_rules[row.label].action === 'HASH'">
                          <span class="ds-muted-text">截断长度</span>
                          <input
                            v-model.number="form.entity_rules[row.label].hash_len"
                            type="number"
                            min="4"
                            max="64"
                            class="ds-native-input ds-tabular-nums"
                            :disabled="!canEdit || !form.entity_rules[row.label].enabled"
                            style="width: 72px"
                          />
                        </template>
                      </div>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>

          <!-- Section 3: Field Role & JSONPath Routing -->
          <div class="ds-card">
            <div class="section-header-inline">
              <h2 class="ds-section-title">3. 结构化字段角色与 JSONPath 路由</h2>
              <el-button size="small" :disabled="!canEdit" @click="addFieldRoleRule">
                + 添加 JSONPath 规则
              </el-button>
            </div>

            <div class="form-grid-2col" style="margin-bottom: 14px">
              <div class="form-field">
                <label class="form-label" for="policy-default-role-select">默认字段角色</label>
                <el-select
                  id="policy-default-role-select"
                  v-model="form.default_role"
                  :disabled="!canEdit"
                  style="width: 100%"
                >
                  <el-option
                    v-for="(meta, roleKey) in FIELD_ROLE_META"
                    :key="roleKey"
                    :label="`${roleKey} · ${meta.label}`"
                    :value="roleKey"
                  />
                </el-select>
              </div>

              <div class="form-field">
                <label class="form-label" for="policy-highrisk-select">高危补扫实体 (REPLAY_SCOPE_AND_HIGH_RISK)</label>
                <el-select
                  id="policy-highrisk-select"
                  v-model="form.high_risk_only_labels"
                  multiple
                  filterable
                  :disabled="!canEdit"
                  style="width: 100%"
                >
                  <el-option
                    v-for="meta in ENTITY_LABEL_META"
                    :key="meta.label"
                    :label="`${meta.labelZh} (${meta.label})`"
                    :value="meta.label"
                  />
                </el-select>
              </div>
            </div>

            <div v-if="form.field_rules.length === 0" class="ds-panel-slot empty-rules-box">
              暂未配置特定 JSONPath 路由，所有字段将遵循上方「默认字段角色」。
            </div>

            <div v-else class="field-rules-list">
              <div v-for="(rule, idx) in form.field_rules" :key="idx" class="field-rule-row">
                <el-input
                  v-model="rule.jsonpath"
                  class="ds-mono"
                  placeholder="例如 $.turns[?(@.role=='user')].content"
                  :disabled="!canEdit"
                />
                <el-select v-model="rule.role" :disabled="!canEdit" style="width: 280px">
                  <el-option
                    v-for="(meta, roleKey) in FIELD_ROLE_META"
                    :key="roleKey"
                    :label="`${roleKey} · ${meta.label}`"
                    :value="roleKey"
                  />
                </el-select>
                <el-button
                  type="danger"
                  plain
                  size="small"
                  :disabled="!canEdit"
                  @click="removeFieldRoleRule(idx)"
                >
                  移除
                </el-button>
              </div>
            </div>
          </div>

          <!-- Sticky Bottom Publish Action Bar -->
          <div class="ds-card publish-bar">
            <div class="publish-bar__info">
              <el-alert
                v-if="submitError"
                type="error"
                :closable="false"
                show-icon
                :title="submitError"
              />
              <span v-else class="ds-secondary-text">
                {{
                  canEdit
                    ? `将基于当前编辑器配置创建不可变新版本 v${nextVersionNumber}（原 v${currentVersionItem.version} 保持只读）。`
                    : readonlyReason
                }}
              </span>
            </div>

            <div class="publish-bar__actions">
              <el-button :disabled="!canEdit || !isDirty || saving" @click="resetDraft">
                重置修改
              </el-button>
              <el-tooltip :disabled="canEdit" :content="readonlyReason" placement="top">
                <el-button
                  data-testid="publish-new-version-btn"
                  type="primary"
                  :disabled="!canEdit || saving"
                  :loading="saving"
                  @click="handlePublishNewVersion"
                >
                  发布为新版本 v{{ nextVersionNumber }}
                </el-button>
              </el-tooltip>
            </div>
          </div>
        </template>
      </section>
    </div>

    <!-- Create New Policy Code Modal -->
    <el-dialog
      v-model="createDialogOpen"
      title="新建策略编码 (创建 v1)"
      width="500px"
      :close-on-click-modal="false"
    >
      <div class="dialog-form-stack">
        <el-alert
          v-if="createFormErrors.general"
          type="error"
          :closable="false"
          show-icon
          :title="createFormErrors.general"
        />

        <div class="form-field">
          <label class="form-label" for="new-policy-code">策略编码 (policy_code)</label>
          <el-input
            id="new-policy-code"
            v-model="createForm.policy_code"
            placeholder="例如 finance_audit_v1"
          />
          <div v-if="createFormErrors.policy_code" class="field-error-text">
            {{ createFormErrors.policy_code }}
          </div>
        </div>

        <div class="form-field">
          <label class="form-label" for="new-policy-name">策略名称</label>
          <el-input
            id="new-policy-name"
            v-model="createForm.policy_name"
            placeholder="例如 金融合规审计脱敏策略"
          />
          <div v-if="createFormErrors.policy_name" class="field-error-text">
            {{ createFormErrors.policy_name }}
          </div>
        </div>

        <div class="form-field">
          <label class="form-label" for="new-policy-scope">默认一致性作用域</label>
          <el-select id="new-policy-scope" v-model="createForm.scope_mode" style="width: 100%">
            <el-option
              v-for="opt in SCOPE_MODE_OPTIONS"
              :key="opt.value"
              :label="opt.label"
              :value="opt.value"
            />
          </el-select>
        </div>

        <div class="form-field">
          <label class="form-label" for="new-policy-desc">策略描述</label>
          <el-input
            id="new-policy-desc"
            v-model="createForm.description"
            type="textarea"
            :rows="2"
            placeholder="可选，说明业务场景"
          />
        </div>
      </div>

      <template #footer>
        <el-button @click="createDialogOpen = false">取消</el-button>
        <el-button type="primary" :loading="createSubmitting" @click="handleCreateNewPolicyCode">
          创建 v1
        </el-button>
      </template>
    </el-dialog>
  </div>
</template>

<style scoped>
.policies-workspace {
  display: grid;
  grid-template-columns: 290px minmax(0, 1fr);
  gap: 16px;
  align-items: start;
}

.policies-sidebar {
  position: sticky;
  top: 68px;
  max-height: calc(100vh - 96px);
  overflow-y: auto;
}

.policies-sidebar__title {
  font-size: 0.9375rem;
  font-weight: 600;
  margin-bottom: 12px;
}

.policy-group-block {
  padding-top: 12px;
  margin-top: 12px;
  border-top: 1px solid var(--ds-border-subtle);
}

.policy-group-block:first-of-type {
  padding-top: 0;
  margin-top: 0;
  border-top: none;
}

.policy-group-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.policy-group-code {
  font-weight: 600;
  color: var(--ds-text-primary);
}

.policy-group-name {
  font-size: 0.8125rem;
  color: var(--ds-text-secondary);
  margin: 4px 0 8px;
}

.policy-version-list {
  list-style: none;
  padding: 0;
  margin: 0;
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.policy-version-item {
  width: 100%;
  text-align: left;
  padding: 8px 10px;
  border-radius: var(--ds-radius-md);
  border: 1px solid var(--ds-border-subtle);
  background: var(--ds-bg-panel);
  cursor: pointer;
  transition: border-color var(--ds-motion-duration) var(--ds-motion-ease),
    background-color var(--ds-motion-duration) var(--ds-motion-ease);
}

.policy-version-item:hover {
  border-color: var(--ds-color-primary);
}

.policy-version-item.is-selected {
  background: var(--ds-bg-active);
  border-color: var(--ds-color-primary);
}

.policy-version-item__top {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 6px;
}

.policy-version-item__tags {
  display: inline-flex;
  gap: 4px;
  flex-wrap: wrap;
}

.policy-version-item__meta {
  font-size: 0.75rem;
  color: var(--ds-text-muted);
  margin-top: 4px;
}

.policies-editor {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.editor-summary-row {
  display: flex;
  flex-wrap: wrap;
  justify-content: space-between;
  align-items: center;
  gap: 12px;
}

.editor-summary-badges {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
}

.editor-code {
  font-size: 1rem;
  font-weight: 600;
}

.form-grid-2col {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 14px;
}

.form-field {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.form-field--full {
  grid-column: 1 / -1;
}

.form-label {
  font-size: 0.8125rem;
  font-weight: 500;
  color: var(--ds-text-secondary);
}

.entity-table-wrap {
  overflow-x: auto;
}

.ds-matrix-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.875rem;
}

.ds-matrix-table th,
.ds-matrix-table td {
  padding: 8px 10px;
  border-bottom: 1px solid var(--ds-border-subtle);
  text-align: left;
  vertical-align: middle;
}

.ds-matrix-table th {
  background: var(--ds-bg-panel);
  color: var(--ds-text-secondary);
  font-weight: 600;
  font-size: 0.8125rem;
}

.ds-native-input {
  height: 30px;
  padding: 2px 8px;
  border: 1px solid var(--ds-border-strong);
  border-radius: var(--ds-radius-sm);
  background: var(--ds-bg-card);
  color: var(--ds-text-primary);
  font-size: 0.8125rem;
}

.ds-native-input:disabled {
  background: var(--ds-bg-panel);
  color: var(--ds-text-disabled);
  cursor: not-allowed;
}

.entity-cell__title {
  display: flex;
  align-items: center;
  gap: 6px;
  font-weight: 500;
}

.action-params-cell {
  display: flex;
  align-items: center;
  gap: 6px;
  flex-wrap: wrap;
}

.section-header-inline {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 14px;
}

.empty-rules-box {
  padding: 14px 16px;
  font-size: 0.8125rem;
  color: var(--ds-text-muted);
}

.field-rules-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.field-rule-row {
  display: flex;
  gap: 8px;
  align-items: center;
}

.publish-bar {
  position: sticky;
  bottom: 12px;
  z-index: 5;
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  box-shadow: var(--ds-shadow-popover);
}

.publish-bar__info {
  flex: 1 1 320px;
}

.publish-bar__actions {
  display: flex;
  align-items: center;
  gap: 10px;
}

.dialog-form-stack {
  display: flex;
  flex-direction: column;
  gap: 14px;
}

.field-error-text {
  font-size: 0.75rem;
  color: var(--ds-color-danger-text);
}

@media (max-width: 1023px) {
  .policies-workspace {
    grid-template-columns: 1fr;
  }

  .policies-sidebar {
    position: static;
    max-height: none;
  }

  .form-grid-2col {
    grid-template-columns: 1fr;
  }
}
</style>
