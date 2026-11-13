<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import StatusTag from '@/components/StatusTag.vue'
import {
  createDatasource,
  deleteDatasource,
  listDatasources,
  testDatasourceConnection,
  updateDatasource,
} from '@/api/datasources'
import { useAuthStore } from '@/stores/auth'
import type { DatasourceItem } from '@/types/api'

const auth = useAuthStore()

const loading = ref(false)
const loadError = ref('')
const items = ref<DatasourceItem[]>([])
const testingCode = ref('')

const canManage = computed(() => auth.canManageDatasources)
const readonlyReason = computed(() =>
  canManage.value
    ? ''
    : `当前角色为 ${auth.role ?? 'GUEST'}，仅系统管理员 (ADMIN) 可配置、测试或删除只读数据源`,
)

async function loadData() {
  loading.value = true
  loadError.value = ''
  try {
    const res = await listDatasources()
    items.value = res.items ?? []
  } catch (err) {
    loadError.value = err instanceof Error ? err.message : '加载数据源列表失败'
  } finally {
    loading.value = false
  }
}

// Create / Edit Dialog (Zero-Client-Persistence: password always wiped)
const formOpen = ref(false)
const editingCode = ref<string | null>(null)
const formSubmitting = ref(false)
const formError = ref('')
const dsForm = reactive({
  conn_code: '',
  conn_name: '',
  db_host: '127.0.0.1',
  db_port: 3306,
  db_name: '',
  db_user: '',
  password: '',
  allowed_tables_text: '',
  status: 'ACTIVE' as 'ACTIVE' | 'DISABLED',
})

function clearSensitiveFormState() {
  dsForm.password = ''
  formError.value = ''
}

function openCreateDialog() {
  if (!canManage.value) return
  editingCode.value = null
  dsForm.conn_code = ''
  dsForm.conn_name = ''
  dsForm.db_host = '127.0.0.1'
  dsForm.db_port = 3306
  dsForm.db_name = ''
  dsForm.db_user = ''
  dsForm.password = ''
  dsForm.allowed_tables_text = ''
  dsForm.status = 'ACTIVE'
  formError.value = ''
  formOpen.value = true
}

function openEditDialog(item: DatasourceItem) {
  if (!canManage.value) return
  editingCode.value = item.conn_code
  dsForm.conn_code = item.conn_code
  dsForm.conn_name = item.conn_name
  dsForm.db_host = item.db_host
  dsForm.db_port = item.db_port
  dsForm.db_name = item.db_name
  dsForm.db_user = item.db_user
  dsForm.password = ''
  dsForm.allowed_tables_text = item.allowed_tables.join(', ')
  dsForm.status = item.status
  formError.value = ''
  formOpen.value = true
}

async function handleSubmit() {
  formError.value = ''
  if (!dsForm.conn_name.trim() || !dsForm.db_name.trim() || !dsForm.db_user.trim()) {
    formError.value = '请完整填写连接名称、数据库名与只读用户名'
    return
  }
  const tables = dsForm.allowed_tables_text
    .split(/[\n,]/)
    .map((t) => t.trim())
    .filter(Boolean)
  if (tables.length === 0) {
    formError.value = '请至少指定一张允许抽样的只读白名单表'
    return
  }
  if (!editingCode.value) {
    if (!dsForm.conn_code.trim()) {
      formError.value = '请填写连接编码'
      return
    }
    if (!dsForm.password) {
      formError.value = '新增数据源必须填写只读账户密码'
      return
    }
  }

  formSubmitting.value = true
  try {
    if (editingCode.value) {
      await updateDatasource(editingCode.value, {
        conn_name: dsForm.conn_name.trim(),
        db_host: dsForm.db_host.trim(),
        db_port: dsForm.db_port,
        db_name: dsForm.db_name.trim(),
        db_user: dsForm.db_user.trim(),
        password: dsForm.password ? dsForm.password : undefined,
        allowed_tables: tables,
        status: dsForm.status,
      })
      ElMessage.success('只读数据源配置已更新')
    } else {
      await createDatasource({
        conn_code: dsForm.conn_code.trim(),
        conn_name: dsForm.conn_name.trim(),
        db_type: 'MYSQL',
        db_host: dsForm.db_host.trim(),
        db_port: dsForm.db_port,
        db_name: dsForm.db_name.trim(),
        db_user: dsForm.db_user.trim(),
        password: dsForm.password,
        allowed_tables: tables,
        status: dsForm.status,
      })
      ElMessage.success('只读数据源已创建（密码已加密托管）')
    }
    clearSensitiveFormState()
    formOpen.value = false
    await loadData()
  } catch (err) {
    formError.value = err instanceof Error ? err.message : '保存数据源失败'
  } finally {
    dsForm.password = ''
    formSubmitting.value = false
  }
}

async function handleTestConnection(item: DatasourceItem) {
  if (!canManage.value) return
  testingCode.value = item.conn_code
  try {
    const res = await testDatasourceConnection(item.conn_code)
    if (res.ok && res.read_only_verified) {
      ElMessage.success(`${item.conn_code} 只读连通测试通过 (${res.latency_ms.toFixed(1)} ms)`)
    } else {
      ElMessage.warning(res.message || '只读连通验证未通过')
    }
    await loadData()
  } catch (err) {
    ElMessage.error(err instanceof Error ? err.message : '连通性测试失败')
  } finally {
    testingCode.value = ''
  }
}

async function handleDelete(item: DatasourceItem) {
  if (!canManage.value) return
  try {
    await ElMessageBox.confirm(
      `确认删除只读数据源「${item.conn_name}」(${item.conn_code})？`,
      '高风险操作确认',
      {
        confirmButtonText: '确认删除',
        cancelButtonText: '取消',
        type: 'warning',
      },
    )
    await deleteDatasource(item.conn_code)
    ElMessage.success('数据源已删除')
    await loadData()
  } catch {
    // cancelled
  }
}

onBeforeUnmount(() => {
  clearSensitiveFormState()
})

onMounted(() => {
  void loadData()
})
</script>

<template>
  <div class="datasources-tab">
    <div class="tab-header-bar">
      <div>
        <h3 class="ds-section-title">MySQL 只读数据源管理</h3>
        <p class="ds-muted-text" style="margin: 2px 0 0">
          仅允许配置具备 READ ONLY / SELECT 权限的只读从库账户；密码在服务端加密存储，永不回显明文。
        </p>
      </div>
      <el-tooltip :disabled="canManage" :content="readonlyReason" placement="bottom">
        <el-button
          data-testid="open-create-ds-btn"
          type="primary"
          :disabled="!canManage"
          @click="openCreateDialog"
        >
          + 新增只读数据源
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
      <el-empty v-if="!loading && items.length === 0" description="暂无 MySQL 只读数据源" />

      <div v-else class="table-scroll-wrap">
        <table class="ds-data-table">
          <thead>
            <tr>
              <th>连接编码与名称</th>
              <th>只读地址 / 库名 / 账户</th>
              <th>密码托管</th>
              <th>允许抽样白名单表</th>
              <th>状态</th>
              <th>最近连通校验</th>
              <th>操作</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="item in items" :key="item.conn_code">
              <td>
                <div class="ds-mono" style="font-weight: 600">{{ item.conn_code }}</div>
                <div>{{ item.conn_name }}</div>
              </td>
              <td>
                <div class="ds-mono ds-tabular-nums">
                  {{ item.db_host }}:{{ item.db_port }} / {{ item.db_name }}
                </div>
                <div class="ds-mono ds-muted-text">只读用户：{{ item.db_user }}</div>
              </td>
              <td>
                <StatusTag
                  :label="item.has_password ? '已加密托管（只写不可读）' : '未配置密码'"
                  tag-type="info"
                />
              </td>
              <td>
                <span class="ds-mono">{{ item.allowed_tables.join(', ') }}</span>
              </td>
              <td>
                <StatusTag
                  :label="item.status === 'ACTIVE' ? '启用 ACTIVE' : '停用 DISABLED'"
                  :tag-type="item.status === 'ACTIVE' ? 'success' : 'info'"
                />
              </td>
              <td>
                <StatusTag
                  :label="
                    item.last_test_ok === true
                      ? '只读校验通过'
                      : item.last_test_ok === false
                        ? '校验失败'
                        : '未测试'
                  "
                  :tag-type="
                    item.last_test_ok === true
                      ? 'success'
                      : item.last_test_ok === false
                        ? 'danger'
                        : 'info'
                  "
                />
              </td>
              <td>
                <div class="row-actions">
                  <el-tooltip :disabled="canManage" :content="readonlyReason" placement="top">
                    <el-button
                      size="small"
                      :disabled="!canManage"
                      :loading="testingCode === item.conn_code"
                      @click="handleTestConnection(item)"
                    >
                      测试只读
                    </el-button>
                  </el-tooltip>
                  <el-tooltip :disabled="canManage" :content="readonlyReason" placement="top">
                    <el-button
                      size="small"
                      :disabled="!canManage"
                      @click="openEditDialog(item)"
                    >
                      编辑
                    </el-button>
                  </el-tooltip>
                  <el-tooltip :disabled="canManage" :content="readonlyReason" placement="top">
                    <el-button
                      size="small"
                      type="danger"
                      plain
                      :disabled="!canManage"
                      @click="handleDelete(item)"
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
    </div>

    <!-- Create / Edit Datasource Dialog -->
    <el-dialog
      v-model="formOpen"
      :title="editingCode ? `编辑只读数据源 (${editingCode})` : '新增 MySQL 只读数据源'"
      width="540px"
      :close-on-click-modal="false"
      @close="clearSensitiveFormState"
    >
      <template v-if="formOpen">
        <div class="dialog-form-stack">
          <el-alert
            v-if="formError"
            type="error"
            :closable="false"
            show-icon
            :title="formError"
          />

          <div class="form-grid-2col">
            <div class="form-field">
              <label class="form-label" for="ds-conn-code">连接编码</label>
              <el-input
                id="ds-conn-code"
                v-model="dsForm.conn_code"
                :disabled="Boolean(editingCode)"
                placeholder="例如 mysql_gov_ro"
              />
            </div>

            <div class="form-field">
              <label class="form-label" for="ds-conn-name">连接名称</label>
              <el-input id="ds-conn-name" v-model="dsForm.conn_name" placeholder="政务问答只读从库" />
            </div>
          </div>

          <div class="form-grid-2col">
            <div class="form-field">
              <label class="form-label" for="ds-host">MySQL 主机</label>
              <el-input id="ds-host" v-model="dsForm.db_host" />
            </div>

            <div class="form-field">
              <label class="form-label" for="ds-port">端口</label>
              <el-input-number
                id="ds-port"
                v-model="dsForm.db_port"
                :min="1"
                :max="65535"
                class="ds-tabular-nums"
                style="width: 100%"
              />
            </div>
          </div>

          <div class="form-grid-2col">
            <div class="form-field">
              <label class="form-label" for="ds-dbname">数据库名</label>
              <el-input id="ds-dbname" v-model="dsForm.db_name" />
            </div>

            <div class="form-field">
              <label class="form-label" for="ds-user">只读用户名</label>
              <el-input id="ds-user" v-model="dsForm.db_user" />
            </div>
          </div>

          <div class="form-field">
            <label class="form-label" for="ds-password">
              {{ editingCode ? '更新密码（留空保持已加密原密码，提交即清空输入）' : '只读账户密码（提交后即刻内存销毁）' }}
            </label>
            <el-input
              id="ds-password"
              v-model="dsForm.password"
              type="password"
              show-password
              autocomplete="new-password"
            />
          </div>

          <div class="form-field">
            <label class="form-label" for="ds-tables">允许抽样白名单表（逗号或换行分隔）</label>
            <el-input
              id="ds-tables"
              v-model="dsForm.allowed_tables_text"
              type="textarea"
              :rows="2"
              placeholder="qa_records, service_tickets"
            />
          </div>

          <div class="form-field">
            <label class="form-label" for="ds-status">数据源状态</label>
            <el-select id="ds-status" v-model="dsForm.status" style="width: 180px">
              <el-option label="启用 ACTIVE" value="ACTIVE" />
              <el-option label="停用 DISABLED" value="DISABLED" />
            </el-select>
          </div>
        </div>
      </template>

      <template #footer>
        <template v-if="formOpen">
          <el-button @click="formOpen = false">取消</el-button>
          <el-button type="primary" :loading="formSubmitting" @click="handleSubmit">
            保存配置
          </el-button>
        </template>
      </template>
    </el-dialog>
  </div>
</template>

<style scoped>
.datasources-tab {
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

.row-actions {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
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
</style>
