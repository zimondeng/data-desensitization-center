<script setup lang="ts">
import { computed, onBeforeUnmount, reactive, ref, watch } from 'vue'
import { ElMessage } from 'element-plus'
import StatusTag from '@/components/StatusTag.vue'
import { extractErrorMessage } from '@/api/client'
import { createFileJob, createMysqlSampleJob } from '@/api/jobs'
import { FIELD_ROLE_META } from '@/constants/domain'
import type { DatasourceItem, FieldRole, PolicyGroupItem } from '@/types/api'

const MAX_UPLOAD_BYTES = 200 * 1024 * 1024
const ALLOWED_EXTENSIONS = ['.jsonl', '.csv', '.xlsx', '.md', '.txt']
const OUTPUT_FORMATS = ['JSONL', 'CSV', 'MD', 'TXT', 'XLSX'] as const
const EXT_TO_FORMAT: Record<string, (typeof OUTPUT_FORMATS)[number]> = {
  '.jsonl': 'JSONL',
  '.csv': 'CSV',
  '.xlsx': 'XLSX',
  '.md': 'MD',
  '.txt': 'TXT',
}
const SQL_COL_IDENT_RE = /^[A-Za-z_][A-Za-z0-9_]*$/

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
const uploadProgress = ref(0)
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
const fileErrors = reactive({
  file: '',
  column_role_mapping: '',
})

// MySQL sample state
const mysqlForm = reactive({
  job_name: '',
  datasource_code: '',
  table_name: '',
  select_columns_text: '',
  where_clause: '',
  limit_rows: 500,
  column_role_mapping_json: '',
  policy_code: '',
  policy_version: 0,
  output_format: 'JSONL' as string,
  ttl_hours: 72,
})
const mysqlColumnRoles = reactive<Record<string, FieldRole>>({})
const mysqlErrors = reactive({
  job_name: '',
  datasource_code: '',
  table_name: '',
  select_columns: '',
  column_role_mapping: '',
})

const verifiedDatasources = computed(() =>
  props.datasources.filter((ds) => ds.status === 'ACTIVE' && ds.last_test_ok === true),
)

const selectedDatasource = computed(() =>
  verifiedDatasources.value.find((ds) => ds.conn_code === mysqlForm.datasource_code) ?? null,
)

const availableTables = computed(() => selectedDatasource.value?.allowed_tables ?? [])

function getPolicyVersions(policyCode: string) {
  return props.policies.find((p) => p.policy_code === policyCode)?.versions ?? []
}

const filePolicyVersions = computed(() => getPolicyVersions(fileForm.policy_code))
const mysqlPolicyVersions = computed(() => getPolicyVersions(mysqlForm.policy_code))

function parseSelectColumnList(raw: string): string[] {
  const seen = new Set<string>()
  const out: string[] = []
  for (const part of raw.split(/[\n,]+/)) {
    const col = part.trim()
    if (col && !seen.has(col)) {
      seen.add(col)
      out.push(col)
    }
  }
  return out
}

const validMysqlColumns = computed(() =>
  parseSelectColumnList(mysqlForm.select_columns_text).filter((col) => SQL_COL_IDENT_RE.test(col)),
)

function clearValidationErrors() {
  submitError.value = ''
  fileErrors.file = ''
  fileErrors.column_role_mapping = ''
  mysqlErrors.job_name = ''
  mysqlErrors.datasource_code = ''
  mysqlErrors.table_name = ''
  mysqlErrors.select_columns = ''
  mysqlErrors.column_role_mapping = ''
}

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
    clearValidationErrors()
    uploadProgress.value = 0
    if (nextMode === 'file') {
      selectedFile.value = null
      fileForm.job_name = ''
      fileForm.policy_code = getDefaultPolicyCode()
      fileForm.policy_version = 0
      fileForm.output_format = 'JSONL'
      fileForm.ttl_hours = 72
      fileForm.column_role_mapping_json = ''
    } else if (nextMode === 'mysql') {
      const firstDs = verifiedDatasources.value[0]
      mysqlForm.job_name = ''
      mysqlForm.datasource_code = firstDs?.conn_code ?? ''
      mysqlForm.table_name = firstDs?.allowed_tables[0] ?? ''
      mysqlForm.select_columns_text = ''
      mysqlForm.where_clause = ''
      mysqlForm.limit_rows = 500
      mysqlForm.column_role_mapping_json = ''
      for (const k of Object.keys(mysqlColumnRoles)) {
        delete mysqlColumnRoles[k]
      }
      mysqlForm.policy_code = getDefaultPolicyCode()
      mysqlForm.policy_version = 0
      mysqlForm.output_format = 'JSONL'
      mysqlForm.ttl_hours = 72
    }
  },
)

watch(
  () => fileForm.policy_code,
  () => {
    fileForm.policy_version = 0
  },
)

watch(
  () => mysqlForm.policy_code,
  () => {
    mysqlForm.policy_version = 0
  },
)

watch(
  () => mysqlForm.datasource_code,
  () => {
    mysqlErrors.datasource_code = ''
    const tables = availableTables.value
    if (!tables.includes(mysqlForm.table_name)) {
      mysqlForm.table_name = tables[0] ?? ''
    }
  },
)

function buildCleanMysqlRoleMap(allowedCols: string[]): Record<string, FieldRole> {
  const allowedSet = new Set(allowedCols)
  const out: Record<string, FieldRole> = {}
  for (const col of allowedCols) {
    const role = mysqlColumnRoles[col]
    if (role && allowedSet.has(col)) {
      out[col] = role
    }
  }
  return out
}

function handleMysqlTableRoleChange(col: string, nextValue: string) {
  mysqlErrors.column_role_mapping = ''
  if (!nextValue) {
    delete mysqlColumnRoles[col]
  } else {
    mysqlColumnRoles[col] = nextValue as FieldRole
  }
  const cleanMap = buildCleanMysqlRoleMap(validMysqlColumns.value)
  mysqlForm.column_role_mapping_json =
    Object.keys(cleanMap).length > 0 ? JSON.stringify(cleanMap) : ''
}

function handleMysqlRoleJsonInput() {
  mysqlErrors.column_role_mapping = ''
  const raw = mysqlForm.column_role_mapping_json.trim()
  if (!raw) {
    for (const k of Object.keys(mysqlColumnRoles)) {
      delete mysqlColumnRoles[k]
    }
    return
  }
  try {
    const parsed = parseColumnRoleMapping(raw) ?? {}
    for (const k of Object.keys(mysqlColumnRoles)) {
      delete mysqlColumnRoles[k]
    }
    for (const [k, v] of Object.entries(parsed)) {
      mysqlColumnRoles[k] = v
    }
  } catch {
    // Allow incomplete JSON while user is typing; validated strictly on submit
  }
}

function handleFileInputChange(event: Event) {
  submitError.value = ''
  fileErrors.file = ''
  const target = event.target as HTMLInputElement
  const file = target.files?.[0] ?? null
  if (!file) {
    selectedFile.value = null
    return
  }
  const lower = file.name.toLowerCase()
  const matchedExt = ALLOWED_EXTENSIONS.find((ext) => lower.endsWith(ext))
  if (!matchedExt) {
    const msg = `仅支持 ${ALLOWED_EXTENSIONS.join('、')} 格式文件`
    fileErrors.file = msg
    submitError.value = msg
    selectedFile.value = null
    target.value = ''
    return
  }
  if (file.size > MAX_UPLOAD_BYTES) {
    const msg = '上传文件体积不能超过 200 MB'
    fileErrors.file = msg
    submitError.value = msg
    selectedFile.value = null
    target.value = ''
    return
  }
  selectedFile.value = file
  fileForm.output_format = EXT_TO_FORMAT[matchedExt] ?? 'JSONL'
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
  clearValidationErrors()

  if (props.mode === 'file') {
    if (!selectedFile.value) {
      fileErrors.file = '请先选择要脱敏的本地文件'
      submitError.value = fileErrors.file
      return
    }
    try {
      if (fileForm.column_role_mapping_json.trim()) {
        parseColumnRoleMapping(fileForm.column_role_mapping_json)
      }
    } catch (err) {
      const msg = extractErrorMessage(err, '字段角色映射 JSON 格式无效')
      fileErrors.column_role_mapping = msg
      submitError.value = msg
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
    uploadProgress.value = 0
    try {
      await createFileJob(fd, (pct) => {
        uploadProgress.value = pct
      })
      ElMessage.success('文件脱敏任务已提交，正在后台异步处理')
      clearSensitiveInputs()
      emit('update:mode', null)
      emit('created')
    } catch (err) {
      submitError.value = extractErrorMessage(err, '提交文件脱敏任务失败')
    } finally {
      submitting.value = false
      uploadProgress.value = 0
    }
    return
  }

  if (props.mode === 'mysql') {
    let hasError = false
    if (!mysqlForm.job_name.trim()) {
      mysqlErrors.job_name = '请填写任务名称'
      hasError = true
    }
    if (!mysqlForm.datasource_code) {
      mysqlErrors.datasource_code = '请选择状态 ACTIVE 且已通过连通校验的只读数据源'
      hasError = true
    }
    if (!mysqlForm.table_name) {
      mysqlErrors.table_name = '请从允许抽样表白名单中选择目标表'
      hasError = true
    }
    const cols = parseSelectColumnList(mysqlForm.select_columns_text)
    if (cols.length === 0) {
      mysqlErrors.select_columns = '请显式填写至少 1 个抽样列名（逗号或换行分隔，禁止使用 *）'
      hasError = true
    } else if (cols.includes('*')) {
      mysqlErrors.select_columns = '基于最小权限与字段角色隔离要求，严禁使用 * 通配符，请显式指定抽样列名'
      hasError = true
    } else {
      const invalidCol = cols.find((c) => !SQL_COL_IDENT_RE.test(c))
      if (invalidCol) {
        mysqlErrors.select_columns = `抽样列名格式非法（仅允许字母、数字、下划线且不以数字开头）：${invalidCol}`
        hasError = true
      }
    }

    let roleMapping: Record<string, FieldRole> = {}
    if (!hasError) {
      try {
        if (mysqlForm.column_role_mapping_json.trim()) {
          const parsed = parseColumnRoleMapping(mysqlForm.column_role_mapping_json) ?? {}
          const outside = Object.keys(parsed).find((k) => !cols.includes(k))
          if (outside) {
            mysqlErrors.column_role_mapping = `字段角色映射中的列名 "${outside}" 不在抽样列清单内`
            hasError = true
          } else {
            roleMapping = parsed
          }
        } else {
          roleMapping = buildCleanMysqlRoleMap(cols)
        }
      } catch (err) {
        mysqlErrors.column_role_mapping = extractErrorMessage(err, '字段角色映射 JSON 格式无效')
        hasError = true
      }
    }

    if (hasError) {
      submitError.value =
        mysqlErrors.job_name ||
        mysqlErrors.datasource_code ||
        mysqlErrors.table_name ||
        mysqlErrors.select_columns ||
        mysqlErrors.column_role_mapping
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
      submitError.value = extractErrorMessage(err, '提交 MySQL 抽样任务失败')
    } finally {
      submitting.value = false
    }
  }
}

function clearSensitiveInputs() {
  selectedFile.value = null
  uploadProgress.value = 0
  fileForm.column_role_mapping_json = ''
  mysqlForm.where_clause = ''
  mysqlForm.column_role_mapping_json = ''
  for (const k of Object.keys(mysqlColumnRoles)) {
    delete mysqlColumnRoles[k]
  }
  clearValidationErrors()
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
    width="640px"
    :close-on-click-modal="false"
    @close="handleClose"
  >
    <div v-if="mode === 'file'" class="dialog-form-stack">
      <div class="notice-banner">
        <StatusTag label="即读即焚" tag-type="info" />
        <span class="ds-muted-text">源临时文件读取完毕后立即物理删除（即读即焚），仅保留受 TTL 管控的脱敏产物</span>
      </div>

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
          data-testid="file-job-upload"
          type="file"
          accept=".jsonl,.csv,.xlsx,.md,.txt"
          @change="handleFileInputChange"
        />
        <span v-if="selectedFile" class="ds-muted-text ds-tabular-nums">
          已选：{{ selectedFile.name }}（{{ (selectedFile.size / 1024).toFixed(1) }} KB）
        </span>
        <el-progress
          v-if="submitting && mode === 'file'"
          data-testid="file-upload-progress"
          :percentage="uploadProgress"
          :stroke-width="6"
          style="margin-top: 4px"
        />
        <div v-if="fileErrors.file" class="ds-field-error">{{ fileErrors.file }}</div>
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
          <label class="form-label" for="file-policy-version-select">策略版本</label>
          <el-select
            id="file-policy-version-select"
            data-testid="file-policy-version-select"
            v-model="fileForm.policy_version"
            style="width: 100%"
          >
            <el-option :value="0" label="自动使用当前默认版本" />
            <el-option
              v-for="ver in filePolicyVersions"
              :key="ver.version"
              :value="ver.version"
              :label="`v${ver.version}${ver.is_default ? '（当前默认）' : ''}`"
            />
          </el-select>
        </div>
      </div>

      <div class="form-grid-2col">
        <div class="form-field">
          <label class="form-label" for="file-format-select">输出格式（选定文件时默认同构）</label>
          <el-select
            id="file-format-select"
            data-testid="file-format-select"
            v-model="fileForm.output_format"
            style="width: 100%"
          >
            <el-option v-for="fmt in OUTPUT_FORMATS" :key="fmt" :label="fmt" :value="fmt" />
          </el-select>
        </div>

        <div class="form-field">
          <label class="form-label" for="file-ttl-hours">产物本地保留期限 TTL（小时，1–8760）</label>
          <el-input-number
            id="file-ttl-hours"
            v-model="fileForm.ttl_hours"
            :min="1"
            :max="8760"
            class="ds-tabular-nums"
            style="width: 100%"
          />
          <span class="ds-muted-text">
            预计物理清理时间：{{ formatTtlExpiryPreview(fileForm.ttl_hours) }}
          </span>
        </div>
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
          @input="fileErrors.column_role_mapping = ''"
        />
        <div v-if="fileErrors.column_role_mapping" class="ds-field-error">
          {{ fileErrors.column_role_mapping }}
        </div>
      </div>
    </div>

    <div v-else-if="mode === 'mysql'" class="dialog-form-stack">
      <div class="notice-banner">
        <StatusTag label="READ ONLY · 仅允许 SELECT 抽样" tag-type="info" />
        <span class="ds-muted-text">禁止写操作、禁止 DDL，仅允许已通过只读连通校验的数据源与白名单表</span>
      </div>

      <el-alert
        v-if="verifiedDatasources.length === 0"
        data-testid="mysql-no-verified-ds-alert"
        type="warning"
        :closable="false"
        show-icon
        title="暂无状态为 ACTIVE 且已通过只读连通校验的数据源，请先前往「系统设置 -> 只读数据源」完成测试验证。"
      />

      <el-alert
        v-if="submitError"
        type="error"
        :closable="false"
        show-icon
        :title="submitError"
      />

      <div class="form-field">
        <label class="form-label" for="mysql-job-name">任务名称</label>
        <el-input
          id="mysql-job-name"
          v-model="mysqlForm.job_name"
          placeholder="例如 工单库抽样脱敏"
          @input="mysqlErrors.job_name = ''"
        />
        <div v-if="mysqlErrors.job_name" class="ds-field-error">{{ mysqlErrors.job_name }}</div>
      </div>

      <div class="form-grid-2col">
        <div class="form-field">
          <label class="form-label" for="mysql-ds-select">只读数据源（仅限 ACTIVE 且校验通过）</label>
          <el-select
            id="mysql-ds-select"
            data-testid="mysql-ds-select"
            v-model="mysqlForm.datasource_code"
            style="width: 100%"
            placeholder="请先配置并校验只读数据源"
          >
            <el-option
              v-for="ds in verifiedDatasources"
              :key="ds.conn_code"
              :label="`${ds.conn_name} (${ds.conn_code})`"
              :value="ds.conn_code"
            />
          </el-select>
          <div v-if="mysqlErrors.datasource_code" class="ds-field-error">
            {{ mysqlErrors.datasource_code }}
          </div>
        </div>

        <div class="form-field">
          <label class="form-label" for="mysql-table-select">允许抽样表（受白名单限制）</label>
          <el-select
            id="mysql-table-select"
            v-model="mysqlForm.table_name"
            placeholder="请先选择数据源"
            style="width: 100%"
            @change="mysqlErrors.table_name = ''"
          >
            <el-option v-for="tbl in availableTables" :key="tbl" :label="tbl" :value="tbl" />
          </el-select>
          <div v-if="mysqlErrors.table_name" class="ds-field-error">{{ mysqlErrors.table_name }}</div>
        </div>
      </div>

      <div class="form-grid-2col">
        <div class="form-field">
          <label class="form-label" for="mysql-select-cols">抽样列（逗号或换行分隔，严禁使用 *）</label>
          <el-input
            id="mysql-select-cols"
            v-model="mysqlForm.select_columns_text"
            name="mysql_select_columns"
            placeholder="例如 id, question, answer"
            @input="mysqlErrors.select_columns = ''"
          />
          <div v-if="mysqlErrors.select_columns" data-testid="mysql-select-columns-error" class="ds-field-error">
            {{ mysqlErrors.select_columns }}
          </div>
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

      <div v-if="validMysqlColumns.length > 0" class="form-field" data-testid="mysql-column-role-table">
        <span class="form-label">抽样列与字段角色映射表（同步至列字段角色 JSON）</span>
        <div class="col-role-table-wrap">
          <table class="ds-data-table col-role-table">
            <thead>
              <tr>
                <th>抽样列名</th>
                <th>字段角色作用域</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="col in validMysqlColumns" :key="col">
                <td class="ds-mono">{{ col }}</td>
                <td>
                  <select
                    class="ds-native-input"
                    :data-testid="`mysql-col-role-${col}`"
                    :aria-label="`${col} 字段角色`"
                    :value="mysqlColumnRoles[col] ?? ''"
                    style="width: 100%"
                    @change="handleMysqlTableRoleChange(col, ($event.target as HTMLSelectElement).value)"
                  >
                    <option value="">跟随策略默认角色</option>
                    <option
                      v-for="(meta, roleKey) in FIELD_ROLE_META"
                      :key="roleKey"
                      :value="roleKey"
                    >
                      {{ roleKey }} · {{ meta.label }}
                    </option>
                  </select>
                </td>
              </tr>
            </tbody>
          </table>
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
          <label class="form-label" for="mysql-policy-version-select">策略版本</label>
          <el-select
            id="mysql-policy-version-select"
            data-testid="mysql-policy-version-select"
            v-model="mysqlForm.policy_version"
            style="width: 100%"
          >
            <el-option :value="0" label="自动使用当前默认版本" />
            <el-option
              v-for="ver in mysqlPolicyVersions"
              :key="ver.version"
              :value="ver.version"
              :label="`v${ver.version}${ver.is_default ? '（当前默认）' : ''}`"
            />
          </el-select>
        </div>
      </div>

      <div class="form-grid-2col">
        <div class="form-field">
          <label class="form-label" for="mysql-format-select">输出格式</label>
          <el-select id="mysql-format-select" v-model="mysqlForm.output_format" style="width: 100%">
            <el-option v-for="fmt in OUTPUT_FORMATS" :key="fmt" :label="fmt" :value="fmt" />
          </el-select>
        </div>

        <div class="form-field">
          <label class="form-label" for="mysql-ttl-hours">产物本地保留期限 TTL（小时，1–8760）</label>
          <el-input-number
            id="mysql-ttl-hours"
            v-model="mysqlForm.ttl_hours"
            :min="1"
            :max="8760"
            class="ds-tabular-nums"
            style="width: 100%"
          />
          <span class="ds-muted-text">
            预计物理清理时间：{{ formatTtlExpiryPreview(mysqlForm.ttl_hours) }}
          </span>
        </div>
      </div>

      <div class="form-field">
        <label class="form-label" for="mysql-role-mapping">列字段角色映射 JSON（可选，与上方映射表联动）</label>
        <el-input
          id="mysql-role-mapping"
          v-model="mysqlForm.column_role_mapping_json"
          type="textarea"
          :rows="2"
          placeholder='{"question":"FULL_MASK_WRITE_SCOPE","answer":"REPLAY_SCOPE_AND_HIGH_RISK"}'
          @input="handleMysqlRoleJsonInput"
        />
        <div v-if="mysqlErrors.column_role_mapping" class="ds-field-error">
          {{ mysqlErrors.column_role_mapping }}
        </div>
      </div>
    </div>

    <template #footer>
      <el-button @click="handleClose">取消</el-button>
      <el-button
        data-testid="submit-create-job-btn"
        type="primary"
        :loading="submitting"
        @click="handleSubmit"
      >
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

.notice-banner {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
}

.col-role-table-wrap {
  border: 1px solid var(--ds-border-subtle);
  border-radius: var(--ds-radius-sm);
  overflow: hidden;
}

.col-role-table th,
.col-role-table td {
  padding: 6px 10px;
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
</style>
