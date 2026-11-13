<script setup lang="ts">
import { computed, onBeforeUnmount, reactive, ref, watch } from 'vue'
import { ElMessage } from 'element-plus'
import StatusTag from '@/components/StatusTag.vue'
import { createFileJob, createMysqlSampleJob } from '@/api/jobs'
import { FIELD_ROLE_META } from '@/constants/domain'
import type { DatasourceItem, FieldRole, PolicyGroupItem } from '@/types/api'

const MAX_UPLOAD_BYTES = 200 * 1024 * 1024
const ALLOWED_EXTENSIONS = ['.jsonl', '.csv', '.xlsx', '.md', '.txt']
const OUTPUT_FORMATS = ['JSONL', 'CSV', 'MD', 'TXT', 'XLSX'] as const

const props = defineProps<{
  mode: 'file' | 'mysql' | null
  policies: PolicyGroupItem[]
  datasources: DatasourceItem[]
}>()

const emit = defineEmits<{
  'update:mode': [value: 'file' | 'mysql' | null]
  created: []
}>()

const visible = computed({
  get: () => props.mode !== null,
  set: (v: boolean) => {
    if (!v) emit('update:mode', null)
  },
})

const submitting = ref(false)
const submitError = ref('')

// File upload state (Zero-Client-Persistence: cleared on close & unmount)
const selectedFile = ref<File | null>(null)
const fileForm = reactive({
  job_name: '',
  policy_code: '',
  policy_version: 0,
  output_format: 'JSONL' as string,
  ttl_hours: 72,
  column_role_mapping_json: '',
})

// MySQL sample state
const mysqlForm = reactive({
  job_name: '',
  datasource_code: '',
  table_name: '',
  select_columns_text: '*',
  where_clause: '',
  limit_rows: 500,
  column_role_mapping_json: '',
  policy_code: '',
  policy_version: 0,
  output_format: 'JSONL' as string,
  ttl_hours: 72,
})

const activeDatasources = computed(() =>
  props.datasources.filter((ds) => ds.status === 'ACTIVE'),
)

const selectedDatasource = computed(() =>
  activeDatasources.value.find((ds) => ds.conn_code === mysqlForm.datasource_code) ?? null,
)

const availableTables = computed(() => selectedDatasource.value?.allowed_tables ?? [])

function formatTtlExpiryPreview(hours: number): string {
  const clamped = Math.min(8760, Math.max(1, Number(hours) || 72))
  const dt = new Date(Date.now() + clamped * 3600 * 1000)
  return dt.toLocaleString('zh-CN', { hour12: false })
}

function getDefaultPolicyCode(): string {
  return props.policies[0]?.policy_code ?? 'gov_eval_corpus'
}

watch(
  () => props.mode,
  (nextMode) => {
    submitError.value = ''
    if (nextMode === 'file') {
      selectedFile.value = null
      fileForm.job_name = ''
      fileForm.policy_code = getDefaultPolicyCode()
      fileForm.policy_version = 0
      fileForm.output_format = 'JSONL'
      fileForm.ttl_hours = 72
      fileForm.column_role_mapping_json = ''
    } else if (nextMode === 'mysql') {
      const firstDs = activeDatasources.value[0]
      mysqlForm.job_name = ''
      mysqlForm.datasource_code = firstDs?.conn_code ?? ''
      mysqlForm.table_name = firstDs?.allowed_tables[0] ?? ''
      mysqlForm.select_columns_text = '*'
      mysqlForm.where_clause = ''
      mysqlForm.limit_rows = 500
      mysqlForm.column_role_mapping_json = ''
      mysqlForm.policy_code = getDefaultPolicyCode()
      mysqlForm.policy_version = 0
      mysqlForm.output_format = 'JSONL'
      mysqlForm.ttl_hours = 72
    }
  },
)

watch(
  () => mysqlForm.datasource_code,
  () => {
    const tables = availableTables.value
    if (!tables.includes(mysqlForm.table_name)) {
      mysqlForm.table_name = tables[0] ?? ''
    }
  },
)

function handleFileInputChange(event: Event) {
  submitError.value = ''
  const target = event.target as HTMLInputElement
  const file = target.files?.[0] ?? null
  if (!file) {
    selectedFile.value = null
    return
  }
  const lower = file.name.toLowerCase()
  if (!ALLOWED_EXTENSIONS.some((ext) => lower.endsWith(ext))) {
    submitError.value = `仅支持 ${ALLOWED_EXTENSIONS.join('、')} 格式文件`
    selectedFile.value = null
    target.value = ''
    return
  }
  if (file.size > MAX_UPLOAD_BYTES) {
    submitError.value = '上传文件体积不能超过 200 MB'
    selectedFile.value = null
    target.value = ''
    return
  }
  selectedFile.value = file
  if (!fileForm.job_name.trim()) {
    fileForm.job_name = file.name.replace(/\.[^.]+$/, '')
  }
}

function parseColumnRoleMapping(raw: string): Record<string, FieldRole> | null {
  const trimmed = raw.trim()
  if (!trimmed) return {}
  const parsed = JSON.parse(trimmed) as Record<string, unknown>
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('字段角色映射必须是 JSON 对象，例如 {"user_msg":"FULL_MASK_WRITE_SCOPE"}')
  }
  const validRoles = Object.keys(FIELD_ROLE_META)
  const out: Record<string, FieldRole> = {}
  for (const [k, v] of Object.entries(parsed)) {
    if (typeof v !== 'string' || !validRoles.includes(v)) {
      throw new Error(`列 ${k} 的字段角色无效：${String(v)}`)
    }
    out[k] = v as FieldRole
  }
  return out
}

async function handleSubmit() {
  submitError.value = ''

  if (props.mode === 'file') {
    if (!selectedFile.value) {
      submitError.value = '请先选择要脱敏的本地文件'
      return
    }
    try {
      if (fileForm.column_role_mapping_json.trim()) {
        parseColumnRoleMapping(fileForm.column_role_mapping_json)
      }
    } catch (err) {
      submitError.value = err instanceof Error ? err.message : '字段角色映射 JSON 格式无效'
      return
    }

    const fd = new FormData()
    fd.append('file', selectedFile.value)
    if (fileForm.job_name.trim()) fd.append('job_name', fileForm.job_name.trim())
    if (fileForm.policy_code) fd.append('policy_code', fileForm.policy_code)
    if (fileForm.policy_version > 0) fd.append('policy_version', String(fileForm.policy_version))
    fd.append('output_format', fileForm.output_format)
    fd.append('ttl_hours', String(fileForm.ttl_hours))
    if (fileForm.column_role_mapping_json.trim()) {
      fd.append('column_role_mapping', fileForm.column_role_mapping_json.trim())
    }

    submitting.value = true
    try {
      await createFileJob(fd)
      ElMessage.success('文件脱敏任务已提交，正在后台异步处理')
      clearSensitiveInputs()
      emit('update:mode', null)
      emit('created')
    } catch (err) {
      submitError.value = err instanceof Error ? err.message : '提交文件脱敏任务失败'
    } finally {
      submitting.value = false
    }
    return
  }

  if (props.mode === 'mysql') {
    if (!mysqlForm.job_name.trim()) {
      submitError.value = '请填写任务名称'
      return
    }
    if (!mysqlForm.datasource_code) {
      submitError.value = '请选择已配置的只读数据源'
      return
    }
    if (!mysqlForm.table_name) {
      submitError.value = '请从该数据源允许抽样表白名单中选择目标表'
      return
    }
    const cols = mysqlForm.select_columns_text
      .split(/[\n,]/)
      .map((c) => c.trim())
      .filter(Boolean)
    if (cols.length === 0) {
      submitError.value = '请填写抽样列名（或 * 表示全部列）'
      return
    }

    let roleMapping: Record<string, FieldRole> = {}
    try {
      roleMapping = parseColumnRoleMapping(mysqlForm.column_role_mapping_json) ?? {}
    } catch (err) {
      submitError.value = err instanceof Error ? err.message : '字段角色映射 JSON 格式无效'
      return
    }

    submitting.value = true
    try {
      await createMysqlSampleJob({
        job_name: mysqlForm.job_name.trim(),
        datasource_code: mysqlForm.datasource_code,
        table_name: mysqlForm.table_name,
        select_columns: cols,
        where_clause: mysqlForm.where_clause.trim() || undefined,
        limit_rows: mysqlForm.limit_rows,
        column_role_mapping: roleMapping,
        policy_code: mysqlForm.policy_code || getDefaultPolicyCode(),
        policy_version: mysqlForm.policy_version > 0 ? mysqlForm.policy_version : null,
        output_format: mysqlForm.output_format,
        ttl_hours: mysqlForm.ttl_hours,
      })
      ElMessage.success('MySQL 只读抽样脱敏任务已创建')
      clearSensitiveInputs()
      emit('update:mode', null)
      emit('created')
    } catch (err) {
      submitError.value = err instanceof Error ? err.message : '提交 MySQL 抽样任务失败'
    } finally {
      submitting.value = false
    }
  }
}

function clearSensitiveInputs() {
  selectedFile.value = null
  fileForm.column_role_mapping_json = ''
  mysqlForm.where_clause = ''
  mysqlForm.column_role_mapping_json = ''
}

function handleClose() {
  clearSensitiveInputs()
  emit('update:mode', null)
}

onBeforeUnmount(() => {
  clearSensitiveInputs()
})
</script>

<template>
  <el-dialog
    v-model="visible"
    :title="mode === 'mysql' ? '创建 MySQL 只读抽样脱敏任务' : '上传文件批量脱敏'"
    width="580px"
    :close-on-click-modal="false"
    @close="handleClose"
  >
    <div v-if="mode === 'file'" class="dialog-form-stack">
      <el-alert
        v-if="submitError"
        type="error"
        :closable="false"
        show-icon
        :title="submitError"
      />

      <div class="form-field">
        <label class="form-label" for="file-job-upload">
          选择待脱敏文件（支持 .jsonl / .csv / .xlsx / .md / .txt，最大 200 MB）
        </label>
        <input
          id="file-job-upload"
          type="file"
          accept=".jsonl,.csv,.xlsx,.md,.txt"
          @change="handleFileInputChange"
        />
        <span v-if="selectedFile" class="ds-muted-text ds-tabular-nums">
          已选：{{ selectedFile.name }}（{{ (selectedFile.size / 1024).toFixed(1) }} KB）
        </span>
      </div>

      <div class="form-field">
        <label class="form-label" for="file-job-name">任务名称（可选）</label>
        <el-input id="file-job-name" v-model="fileForm.job_name" placeholder="默认采用脱敏处理后文件名" />
      </div>

      <div class="form-grid-2col">
        <div class="form-field">
          <label class="form-label" for="file-policy-select">绑定策略</label>
          <el-select id="file-policy-select" v-model="fileForm.policy_code" style="width: 100%">
            <el-option
              v-for="p in policies"
              :key="p.policy_code"
              :label="`${p.policy_name} (${p.policy_code})`"
              :value="p.policy_code"
            />
          </el-select>
        </div>

        <div class="form-field">
          <label class="form-label" for="file-format-select">输出格式</label>
          <el-select id="file-format-select" v-model="fileForm.output_format" style="width: 100%">
            <el-option v-for="fmt in OUTPUT_FORMATS" :key="fmt" :label="fmt" :value="fmt" />
          </el-select>
        </div>
      </div>

      <div class="form-field">
        <label class="form-label" for="file-ttl-hours">产物本地保留期限 TTL（小时，1–8760）</label>
        <el-input-number
          id="file-ttl-hours"
          v-model="fileForm.ttl_hours"
          :min="1"
          :max="8760"
          class="ds-tabular-nums"
          style="width: 180px"
        />
        <span class="ds-muted-text">
          预计物理清理时间：{{ formatTtlExpiryPreview(fileForm.ttl_hours) }}
        </span>
      </div>

      <div class="form-field">
        <label class="form-label" for="file-role-mapping">
          列字段角色映射 JSON（可选，针对 CSV / XLSX / JSONL）
        </label>
        <el-input
          id="file-role-mapping"
          v-model="fileForm.column_role_mapping_json"
          type="textarea"
          :rows="2"
          placeholder='{"user_text":"FULL_MASK_WRITE_SCOPE","bot_reply":"REPLAY_SCOPE_AND_HIGH_RISK"}'
        />
      </div>
    </div>

    <div v-else-if="mode === 'mysql'" class="dialog-form-stack">
      <div class="mysql-ro-banner">
        <StatusTag label="READ ONLY · 仅允许 SELECT 抽样" tag-type="info" />
        <span class="ds-muted-text">禁止写操作、禁止 DDL，仅允许抽样连接器白名单表</span>
      </div>

      <el-alert
        v-if="submitError"
        type="error"
        :closable="false"
        show-icon
        :title="submitError"
      />

      <div class="form-field">
        <label class="form-label" for="mysql-job-name">任务名称</label>
        <el-input id="mysql-job-name" v-model="mysqlForm.job_name" placeholder="例如 工单库抽样脱敏" />
      </div>

      <div class="form-grid-2col">
        <div class="form-field">
          <label class="form-label" for="mysql-ds-select">只读数据源</label>
          <el-select id="mysql-ds-select" v-model="mysqlForm.datasource_code" style="width: 100%">
            <el-option
              v-for="ds in activeDatasources"
              :key="ds.conn_code"
              :label="`${ds.conn_name} (${ds.conn_code})`"
              :value="ds.conn_code"
            />
          </el-select>
        </div>

        <div class="form-field">
          <label class="form-label" for="mysql-table-select">允许抽样表（受白名单限制）</label>
          <el-select
            id="mysql-table-select"
            v-model="mysqlForm.table_name"
            placeholder="请先选择数据源"
            style="width: 100%"
          >
            <el-option v-for="tbl in availableTables" :key="tbl" :label="tbl" :value="tbl" />
          </el-select>
        </div>
      </div>

      <div class="form-grid-2col">
        <div class="form-field">
          <label class="form-label" for="mysql-select-cols">抽样列（逗号分隔或 *）</label>
          <el-input id="mysql-select-cols" v-model="mysqlForm.select_columns_text" />
        </div>

        <div class="form-field">
          <label class="form-label" for="mysql-limit-rows">最大抽样行数（1–100000）</label>
          <el-input-number
            id="mysql-limit-rows"
            v-model="mysqlForm.limit_rows"
            :min="1"
            :max="100000"
            class="ds-tabular-nums"
            style="width: 100%"
          />
        </div>
      </div>

      <div class="form-field">
        <label class="form-label" for="mysql-where">只读 WHERE 条件（可选，不含 WHERE 关键字）</label>
        <el-input id="mysql-where" v-model="mysqlForm.where_clause" placeholder="例如 status = 'CLOSED'" />
      </div>

      <div class="form-grid-2col">
        <div class="form-field">
          <label class="form-label" for="mysql-policy-select">绑定策略</label>
          <el-select id="mysql-policy-select" v-model="mysqlForm.policy_code" style="width: 100%">
            <el-option
              v-for="p in policies"
              :key="p.policy_code"
              :label="`${p.policy_name} (${p.policy_code})`"
              :value="p.policy_code"
            />
          </el-select>
        </div>

        <div class="form-field">
          <label class="form-label" for="mysql-format-select">输出格式</label>
          <el-select id="mysql-format-select" v-model="mysqlForm.output_format" style="width: 100%">
            <el-option v-for="fmt in OUTPUT_FORMATS" :key="fmt" :label="fmt" :value="fmt" />
          </el-select>
        </div>
      </div>

      <div class="form-field">
        <label class="form-label" for="mysql-ttl-hours">产物本地保留期限 TTL（小时，1–8760）</label>
        <el-input-number
          id="mysql-ttl-hours"
          v-model="mysqlForm.ttl_hours"
          :min="1"
          :max="8760"
          class="ds-tabular-nums"
          style="width: 180px"
        />
        <span class="ds-muted-text">
          预计物理清理时间：{{ formatTtlExpiryPreview(mysqlForm.ttl_hours) }}
        </span>
      </div>

      <div class="form-field">
        <label class="form-label" for="mysql-role-mapping">列字段角色映射 JSON（可选）</label>
        <el-input
          id="mysql-role-mapping"
          v-model="mysqlForm.column_role_mapping_json"
          type="textarea"
          :rows="2"
          placeholder='{"question":"FULL_MASK_WRITE_SCOPE","answer":"REPLAY_SCOPE_AND_HIGH_RISK"}'
        />
      </div>
    </div>

    <template #footer>
      <el-button @click="handleClose">取消</el-button>
      <el-button type="primary" :loading="submitting" @click="handleSubmit">
        提交脱敏任务
      </el-button>
    </template>
  </el-dialog>
</template>

<style scoped>
.dialog-form-stack {
  display: flex;
  flex-direction: column;
  gap: 14px;
}

.form-grid-2col {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 12px;
}

.form-field {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.form-label {
  font-size: 0.8125rem;
  font-weight: 500;
  color: var(--ds-text-secondary);
}

.mysql-ro-banner {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
}
</style>
