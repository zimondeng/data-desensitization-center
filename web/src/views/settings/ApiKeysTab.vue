<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import StatusTag from '@/components/StatusTag.vue'
import { createApiKey, listApiKeys, revokeApiKey } from '@/api/apiKeys'
import { listPolicies } from '@/api/policies'
import { useAuthStore } from '@/stores/auth'
import type { ApiKeyItem, PolicyGroupItem } from '@/types/api'

const auth = useAuthStore()

const loading = ref(false)
const loadError = ref('')
const items = ref<ApiKeyItem[]>([])
const policies = ref<PolicyGroupItem[]>([])

const canManage = computed(() => auth.canManageApiKeys)
const readonlyReason = computed(() =>
  canManage.value
    ? ''
    : `当前角色为 ${auth.role ?? 'GUEST'}，仅系统管理员 (ADMIN) 可创建或吊销 API Key`,
)

function statusMeta(status: ApiKeyItem['status']) {
  if (status === 'ACTIVE') return { label: '有效 ACTIVE', tagType: 'success' as const }
  if (status === 'REVOKED') return { label: '已吊销 REVOKED', tagType: 'danger' as const }
  return { label: '已过期 EXPIRED', tagType: 'info' as const }
}

async function loadData() {
  loading.value = true
  loadError.value = ''
  try {
    const [keyRes, polRes] = await Promise.all([listApiKeys(), listPolicies()])
    items.value = keyRes.items ?? []
    policies.value = polRes.policies ?? []
  } catch (err) {
    loadError.value = err instanceof Error ? err.message : '加载 API Key 列表失败'
  } finally {
    loading.value = false
  }
}

// Create Modal
const createOpen = ref(false)
const createSubmitting = ref(false)
const createError = ref('')
const createForm = reactive({
  key_name: '',
  default_policy_code: 'gov_eval_corpus',
  rate_limit_rpm: 120,
  allowed_ips_text: '',
  env_tag: 'live' as 'live' | 'test',
})

// Show-Once Secret Confirmation Modal (Zero-Client-Persistence)
const onceDialogOpen = ref(false)
const oncePlainKey = ref('')
const onceKeyName = ref('')
const copiedOnceKey = ref(false)

function clearOnceSecretState() {
  oncePlainKey.value = ''
  onceKeyName.value = ''
  copiedOnceKey.value = false
  onceDialogOpen.value = false
}

function openCreateDialog() {
  if (!canManage.value) return
  createError.value = ''
  createForm.key_name = ''
  createForm.default_policy_code = policies.value[0]?.policy_code ?? 'gov_eval_corpus'
  createForm.rate_limit_rpm = 120
  createForm.allowed_ips_text = ''
  createForm.env_tag = 'live'
  createOpen.value = true
}

async function handleCreateSubmit() {
  createError.value = ''
  if (!createForm.key_name.trim()) {
    createError.value = '请填写密钥名称'
    return
  }

  const ips = createForm.allowed_ips_text
    .split(/[\n,]/)
    .map((s) => s.trim())
    .filter(Boolean)

  createSubmitting.value = true
  try {
    const created = await createApiKey({
      key_name: createForm.key_name.trim(),
      default_policy_code: createForm.default_policy_code,
      rate_limit_rpm: createForm.rate_limit_rpm,
      allowed_ips: ips.length > 0 ? ips : null,
      env_tag: createForm.env_tag,
    })
    createOpen.value = false
    onceKeyName.value = created.key_name
    oncePlainKey.value = created.plain_key
    copiedOnceKey.value = false
    onceDialogOpen.value = true
    await loadData()
  } catch (err) {
    createError.value = err instanceof Error ? err.message : '创建 API Key 失败'
  } finally {
    createSubmitting.value = false
  }
}

async function copyPlainKey() {
  if (!oncePlainKey.value) return
  try {
    await navigator.clipboard.writeText(oncePlainKey.value)
    copiedOnceKey.value = true
    ElMessage.success('完整 API Key 已复制到剪贴板')
  } catch {
    ElMessage.warning('请手动选中完整密钥并复制')
  }
}

async function handleRevoke(item: ApiKeyItem) {
  if (!canManage.value || item.status !== 'ACTIVE') return
  try {
    await ElMessageBox.confirm(
      `确认吊销 API Key「${item.key_name}」(${item.key_prefix}***)？吊销后所有使用该密钥的 /api/v1/* 调用将立即返回 401。`,
      '高风险操作确认',
      {
        confirmButtonText: '确认吊销',
        cancelButtonText: '取消',
        type: 'warning',
      },
    )
    await revokeApiKey(item.uuid)
    ElMessage.success('API Key 已吊销')
    await loadData()
  } catch {
    // cancelled
  }
}

onBeforeUnmount(() => {
  clearOnceSecretState()
})

onMounted(() => {
  void loadData()
})
</script>

<template>
  <div class="api-keys-tab">
    <div class="tab-header-bar">
      <div>
        <h3 class="ds-section-title">外部系统 API Key 管理</h3>
        <p class="ds-muted-text" style="margin: 2px 0 0">
          列表与数据库仅保留 HMAC-SHA256 摘要及脱敏前缀 <span class="ds-mono">dsk_*</span>；完整密钥仅创建时一次性显示。
        </p>
      </div>
      <el-tooltip :disabled="canManage" :content="readonlyReason" placement="bottom">
        <el-button
          data-testid="open-create-key-btn"
          type="primary"
          :disabled="!canManage"
          @click="openCreateDialog"
        >
          + 创建 API Key
        </el-button>
      </el-tooltip>
    </div>

    <el-alert
      v-if="!canManage"
      type="warning"
      :closable="false"
      show-icon
      style="margin-bottom: 14px"
      :title="readonlyReason"
    />

    <el-alert
      v-if="loadError"
      type="error"
      :closable="false"
      show-icon
      style="margin-bottom: 14px"
      :title="loadError"
    />

    <div v-loading="loading" class="ds-card">
      <el-empty v-if="!loading && items.length === 0" description="暂无 API Key" />

      <div v-else class="table-scroll-wrap">
        <table class="ds-data-table">
          <thead>
            <tr>
              <th>密钥名称</th>
              <th>脱敏前缀</th>
              <th>默认策略</th>
              <th>限流 (RPM)</th>
              <th>IP 白名单</th>
              <th>状态</th>
              <th>最近使用</th>
              <th>操作</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="item in items" :key="item.uuid">
              <td>{{ item.key_name }}</td>
              <td>
                <code class="ds-mono">{{ item.key_prefix }}***</code>
              </td>
              <td>
                <span class="ds-mono">{{ item.default_policy_code }}</span>
              </td>
              <td class="ds-mono ds-tabular-nums">{{ item.rate_limit_rpm }}</td>
              <td>
                <span class="ds-mono ds-muted-text">
                  {{ item.allowed_ips && item.allowed_ips.length > 0 ? item.allowed_ips.join(', ') : '不限制' }}
                </span>
              </td>
              <td>
                <StatusTag
                  :label="statusMeta(item.status).label"
                  :tag-type="statusMeta(item.status).tagType"
                />
              </td>
              <td class="ds-mono ds-muted-text">
                {{ item.last_used_at ? item.last_used_at.replace('T', ' ').slice(0, 16) : '--' }}
              </td>
              <td>
                <el-tooltip :disabled="canManage" :content="readonlyReason" placement="top">
                  <el-button
                    :data-testid="`revoke-key-${item.uuid}`"
                    size="small"
                    type="danger"
                    plain
                    :disabled="!canManage || item.status !== 'ACTIVE'"
                    @click="handleRevoke(item)"
                  >
                    吊销
                  </el-button>
                </el-tooltip>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- Create API Key Dialog -->
    <el-dialog
      v-model="createOpen"
      title="创建外部 API Key"
      width="480px"
      :close-on-click-modal="false"
    >
      <template v-if="createOpen">
        <div class="dialog-form-stack">
          <el-alert
            v-if="createError"
            type="error"
            :closable="false"
            show-icon
            :title="createError"
          />

          <div class="form-field">
            <label class="form-label" for="api-key-name-input">密钥名称</label>
            <el-input
              id="api-key-name-input"
              v-model="createForm.key_name"
              name="key_name"
              placeholder="例如 政务语料清洗网关"
            />
          </div>

          <div class="form-field">
            <label class="form-label" for="api-key-policy-select">默认策略编码</label>
            <el-select
              id="api-key-policy-select"
              v-model="createForm.default_policy_code"
              style="width: 100%"
            >
              <el-option
                v-for="p in policies"
                :key="p.policy_code"
                :label="`${p.policy_name} (${p.policy_code})`"
                :value="p.policy_code"
              />
            </el-select>
          </div>

          <div class="form-grid-2col">
            <div class="form-field">
              <label class="form-label" for="api-key-rpm">每分钟限流 (RPM)</label>
              <el-input-number
                id="api-key-rpm"
                v-model="createForm.rate_limit_rpm"
                :min="1"
                :max="10000"
                class="ds-tabular-nums"
                style="width: 100%"
              />
            </div>

            <div class="form-field">
              <label class="form-label" for="api-key-env">环境标识</label>
              <el-select id="api-key-env" v-model="createForm.env_tag" style="width: 100%">
                <el-option label="live · 生产密钥" value="live" />
                <el-option label="test · 测试密钥" value="test" />
              </el-select>
            </div>
          </div>

          <div class="form-field">
            <label class="form-label" for="api-key-ips">IP 白名单（逗号或换行分隔，留空不限制）</label>
            <el-input
              id="api-key-ips"
              v-model="createForm.allowed_ips_text"
              type="textarea"
              :rows="2"
              placeholder="127.0.0.1, 10.0.0.0/24"
            />
          </div>
        </div>
      </template>

      <template #footer>
        <template v-if="createOpen">
          <el-button @click="createOpen = false">取消</el-button>
          <el-button
            data-testid="submit-create-key-btn"
            type="primary"
            :loading="createSubmitting"
            @click="handleCreateSubmit"
          >
            生成密钥
          </el-button>
        </template>
      </template>
    </el-dialog>

    <!-- Show-Once Mandatory Confirmation Dialog -->
    <el-dialog
      v-model="onceDialogOpen"
      title="请立即保存您的新 API Key（仅显示一次）"
      width="540px"
      :close-on-click-modal="false"
      :close-on-press-escape="false"
      :show-close="false"
    >
      <template v-if="onceDialogOpen">
        <div class="dialog-form-stack">
          <el-alert
            type="warning"
            :closable="false"
            show-icon
            title="密钥仅在创建时明文展示一次，系统仅存储 HMAC-SHA256 哈希。关闭本窗口后将无法再次查看！"
          />

          <div class="ds-muted-text">密钥名称：{{ onceKeyName }}</div>

          <div class="once-secret-box">
            <code class="ds-mono once-secret-code">{{ oncePlainKey }}</code>
            <el-button data-testid="copy-plain-key-btn" size="small" @click="copyPlainKey">
              {{ copiedOnceKey ? '已复制' : '复制密钥' }}
            </el-button>
          </div>
        </div>
      </template>

      <template #footer>
        <template v-if="onceDialogOpen">
          <el-button
            data-testid="confirm-saved-key-btn"
            type="primary"
            @click="clearOnceSecretState"
          >
            我已妥善保存，关闭窗口
          </el-button>
        </template>
      </template>
    </el-dialog>
  </div>
</template>

<style scoped>
.api-keys-tab {
  display: flex;
  flex-direction: column;
  gap: 14px;
}

.tab-header-bar {
  display: flex;
  flex-wrap: wrap;
  justify-content: space-between;
  align-items: center;
  gap: 12px;
}

.table-scroll-wrap {
  overflow-x: auto;
}

.ds-data-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.875rem;
}

.ds-data-table th,
.ds-data-table td {
  padding: 10px 12px;
  border-bottom: 1px solid var(--ds-border-subtle);
  text-align: left;
  vertical-align: middle;
}

.ds-data-table th {
  background: var(--ds-bg-panel);
  color: var(--ds-text-secondary);
  font-weight: 600;
  font-size: 0.8125rem;
}

.dialog-form-stack,
.form-field {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.form-grid-2col {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 12px;
}

.form-label {
  font-size: 0.8125rem;
  font-weight: 500;
  color: var(--ds-text-secondary);
}

.once-secret-box {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 12px 14px;
  border: 1px solid var(--ds-border-warning);
  border-radius: var(--ds-radius-md);
  background: var(--ds-bg-warning);
}

.once-secret-code {
  word-break: break-all;
  color: var(--ds-text-primary);
  font-weight: 600;
}
</style>
