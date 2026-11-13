<script setup lang="ts">
import { computed, defineAsyncComponent, onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import StatusTag from '@/components/StatusTag.vue'
import JobCreateModals from '@/views/jobs/JobCreateModals.vue'
import { extractErrorMessage } from '@/api/client'
import { listDatasources } from '@/api/datasources'
import { cancelJob, downloadJobArtifact, listJobs } from '@/api/jobs'
import { listPolicies } from '@/api/policies'
import { useAuthStore } from '@/stores/auth'
import { JOB_STATUS_META, SPOT_CHECK_STATUS_META } from '@/constants/domain'
import type { BatchJobItem, DatasourceItem, PolicyGroupItem } from '@/types/api'

const SpotCheckDrawer = defineAsyncComponent(() => import('@/views/jobs/SpotCheckDrawer.vue'))

const POLL_INTERVAL_MS = 4000

const auth = useAuthStore()

const loading = ref(false)
const loadError = ref('')
const jobs = ref<BatchJobItem[]>([])
const total = ref(0)
const policies = ref<PolicyGroupItem[]>([])
const datasources = ref<DatasourceItem[]>([])

const filters = reactive({
  page: 1,
  page_size: 20,
  keyword: '',
  status: '',
  source_type: '',
  spot_check_status: '',
})

const createModalMode = ref<'file' | 'mysql' | null>(null)
const spotCheckDrawerOpen = ref(false)
const activeSpotJob = ref<BatchJobItem | null>(null)
const downloadingJobNo = ref('')

const canCreateCancel = computed(() => auth.canCreateCancelJobs)
const createCancelDisabledReason = computed(() =>
  canCreateCancel.value
    ? ''
    : `当前角色为 ${auth.role ?? 'GUEST'}，仅可审核或下载允许产物，不可创建或取消批处理任务`,
)

const hasRunningJobs = computed(() =>
  jobs.value.some((j) => j.status === 'PENDING' || j.status === 'RUNNING'),
)

function getDownloadDisabledReason(job: BatchJobItem): string {
  if (job.spot_check_status === 'FLAGGED_LEAK') {
    return '抽检标记为疑似漏脱敏，系统已强制阻断下载'
  }
  if (job.status === 'ARTIFACT_EXPIRED' || !job.has_artifact) {
    return '脱敏产物已超过保留期限并自动物理清理，仅保留审计记录'
  }
  if (job.status !== 'COMPLETED') {
    return '仅 COMPLETED 状态任务支持下载脱敏产物'
  }
  return ''
}

function canOpenSpotCheck(job: BatchJobItem): boolean {
  return job.status === 'COMPLETED' || job.status === 'ARTIFACT_EXPIRED'
}

let pollTimer: number | null = null

function clearPollTimer() {
  if (pollTimer !== null) {
    window.clearTimeout(pollTimer)
    pollTimer = null
  }
}

function scheduleNextPoll() {
  clearPollTimer()
  if (document.hidden || !hasRunningJobs.value) return
  pollTimer = window.setTimeout(() => {
    void loadJobs(true)
  }, POLL_INTERVAL_MS)
}

function handleVisibilityChange() {
  if (document.hidden) {
    clearPollTimer()
  } else if (hasRunningJobs.value) {
    void loadJobs(true)
  }
}

async function loadJobs(silent = false) {
  if (!silent) {
    loading.value = true
  }
  loadError.value = ''
  try {
    const res = await listJobs({
      page: filters.page,
      page_size: filters.page_size,
      keyword: filters.keyword.trim() || undefined,
      status: filters.status || undefined,
      source_type: filters.source_type || undefined,
      spot_check_status: filters.spot_check_status || undefined,
    })
    jobs.value = res.items ?? []
    total.value = res.total ?? 0
  } catch (err) {
    if (!silent) {
      loadError.value = extractErrorMessage(err, '加载批处理任务列表失败')
    }
  } finally {
    if (!silent) {
      loading.value = false
    }
    scheduleNextPoll()
  }
}

function handleSearch() {
  filters.page = 1
  void loadJobs()
}

function resetFilters() {
  filters.keyword = ''
  filters.status = ''
  filters.source_type = ''
  filters.spot_check_status = ''
  filters.page = 1
  void loadJobs()
}

async function loadReferenceOptions() {
  try {
    const [policyRes, dsRes] = await Promise.all([
      listPolicies(),
      listDatasources(),
    ])
    policies.value = policyRes.policies ?? []
    datasources.value = dsRes.items ?? []
  } catch {
    // Non-fatal reference loading error handled lazily in modals
  }
}

async function handleDownload(job: BatchJobItem) {
  if (getDownloadDisabledReason(job)) return
  downloadingJobNo.value = job.job_no
  try {
    await downloadJobArtifact(job.job_no, job.output_format)
    ElMessage.success(`已开始下载 ${job.job_no} 脱敏产物`)
  } catch (err) {
    ElMessage.error(extractErrorMessage(err, '下载脱敏产物失败'))
    await loadJobs(true)
  } finally {
    downloadingJobNo.value = ''
  }
}

async function handleCancel(job: BatchJobItem) {
  if (!canCreateCancel.value) return
  try {
    await ElMessageBox.confirm(
      `确认取消正在运行的任务「${job.job_name}」(${job.job_no})？`,
      '取消任务确认',
      {
        confirmButtonText: '确认取消任务',
        cancelButtonText: '保持运行',
        type: 'warning',
      },
    )
    await cancelJob(job.job_no)
    ElMessage.success(`任务 ${job.job_no} 已请求取消`)
    await loadJobs()
  } catch {
    // cancelled
  }
}

function openSpotCheck(job: BatchJobItem) {
  activeSpotJob.value = job
  spotCheckDrawerOpen.value = true
}

function formatExpiry(expiresAt: string | null): string {
  if (!expiresAt) return '--'
  return expiresAt.replace('T', ' ').slice(0, 16)
}

onMounted(() => {
  document.addEventListener('visibilitychange', handleVisibilityChange)
  void loadJobs()
  void loadReferenceOptions()
})

onBeforeUnmount(() => {
  clearPollTimer()
  document.removeEventListener('visibilitychange', handleVisibilityChange)
})
</script>

<template>
  <div class="jobs-page">
    <div class="ds-page-header">
      <div>
        <h1 class="ds-page-title">批处理任务与合规抽检中心</h1>
        <p class="ds-secondary-text" style="margin: 4px 0 0">
          支持文件上传批量脱敏、MySQL 只读抽样脱敏、产物保留期 (TTL) 倒计时与人工合规抽检阻断。
        </p>
      </div>
      <div class="jobs-header-actions">
        <el-tooltip :disabled="canCreateCancel" :content="createCancelDisabledReason" placement="bottom">
          <el-button
            data-testid="open-mysql-job-btn"
            :disabled="!canCreateCancel"
            @click="createModalMode = 'mysql'"
          >
            + MySQL 只读抽样
          </el-button>
        </el-tooltip>

        <el-tooltip :disabled="canCreateCancel" :content="createCancelDisabledReason" placement="bottom">
          <el-button
            data-testid="open-file-job-btn"
            type="primary"
            :disabled="!canCreateCancel"
            @click="createModalMode = 'file'"
          >
            + 上传文件脱敏
          </el-button>
        </el-tooltip>
      </div>
    </div>

    <el-alert
      v-if="!canCreateCancel"
      type="info"
      :closable="false"
      show-icon
      style="margin-bottom: 16px"
      :title="createCancelDisabledReason"
    />

    <el-alert
      v-if="loadError"
      type="error"
      :closable="false"
      show-icon
      style="margin-bottom: 16px"
      :title="loadError"
    />

    <section class="ds-card">
      <div class="jobs-toolbar">
        <el-input
          v-model="filters.keyword"
          placeholder="搜索任务编号或任务名称"
          clearable
          style="width: 220px"
          @keyup.enter="handleSearch()"
        />
        <el-select v-model="filters.status" clearable placeholder="任务状态" style="width: 156px">
          <el-option
            v-for="(meta, key) in JOB_STATUS_META"
            :key="key"
            :label="meta.label"
            :value="key"
          />
        </el-select>
        <el-select v-model="filters.source_type" clearable placeholder="数据来源" style="width: 152px">
          <el-option label="文件上传 FILE_UPLOAD" value="FILE_UPLOAD" />
          <el-option label="MySQL 只读 MYSQL_READONLY" value="MYSQL_READONLY" />
        </el-select>
        <el-select
          v-model="filters.spot_check_status"
          clearable
          placeholder="抽检结论"
          style="width: 184px"
        >
          <el-option
            v-for="(meta, key) in SPOT_CHECK_STATUS_META"
            :key="key"
            :label="meta.label"
            :value="key"
          />
        </el-select>
        <el-button data-testid="jobs-search-btn" @click="handleSearch()">查询刷新</el-button>
        <el-button data-testid="jobs-reset-btn" @click="resetFilters()">重置</el-button>
        <span v-if="hasRunningJobs" class="ds-muted-text" style="margin-left: auto">
          检测到进行中任务，每 4 秒自动刷新（切至后台标签页自动暂停）
        </span>
      </div>

      <el-empty v-if="!loading && jobs.length === 0" description="暂无脱敏批处理任务" />

      <div v-else v-loading="loading" class="table-scroll-wrap">
        <table class="ds-data-table">
          <thead>
            <tr>
              <th>任务编号与名称</th>
              <th>来源 / 策略</th>
              <th>执行状态</th>
              <th>处理进度</th>
              <th>人工抽检结论</th>
              <th>产物 TTL 截止</th>
              <th>操作</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="job in jobs" :key="job.job_no">
              <td>
                <div class="ds-mono job-no-cell">{{ job.job_no }}</div>
                <div class="job-name-cell">{{ job.job_name }}</div>
                <div v-if="job.source_filename_masked" class="ds-muted-text">
                  源文件：{{ job.source_filename_masked }}
                </div>
              </td>
              <td>
                <div>{{ job.source_type === 'FILE_UPLOAD' ? '文件上传' : 'MySQL 只读抽样' }} · {{ job.output_format }}</div>
                <div class="ds-mono ds-muted-text">{{ job.policy_code }} v{{ job.policy_version }}</div>
              </td>
              <td>
                <StatusTag
                  :label="JOB_STATUS_META[job.status]?.label ?? job.status"
                  :tag-type="JOB_STATUS_META[job.status]?.tagType ?? 'info'"
                />
              </td>
              <td>
                <div class="ds-mono ds-tabular-nums">
                  {{ job.progress_pct }}% ({{ job.processed_records }}/{{ job.total_records }})
                </div>
                <div class="ds-muted-text ds-tabular-nums">
                  {{ job.total_chars.toLocaleString() }} 字符
                </div>
              </td>
              <td>
                <StatusTag
                  :label="SPOT_CHECK_STATUS_META[job.spot_check_status]?.label ?? job.spot_check_status"
                  :tag-type="SPOT_CHECK_STATUS_META[job.spot_check_status]?.tagType ?? 'info'"
                />
              </td>
              <td>
                <div class="ds-mono ds-tabular-nums">{{ formatExpiry(job.expires_at) }}</div>
                <div v-if="!job.has_artifact && job.status === 'ARTIFACT_EXPIRED'" class="ds-muted-text">
                  产物已物理清理
                </div>
              </td>
              <td>
                <div class="row-actions">
                  <el-button
                    v-if="canOpenSpotCheck(job)"
                    :data-testid="`spot-check-job-${job.job_no}`"
                    size="small"
                    @click="openSpotCheck(job)"
                  >
                    {{ auth.canSpotCheck ? '抽检复核' : '查看预览' }}
                  </el-button>

                  <el-tooltip
                    :disabled="!getDownloadDisabledReason(job)"
                    :content="getDownloadDisabledReason(job)"
                    placement="top"
                  >
                    <el-button
                      :data-testid="`download-job-${job.job_no}`"
                      size="small"
                      :disabled="Boolean(getDownloadDisabledReason(job))"
                      :loading="downloadingJobNo === job.job_no"
                      @click="handleDownload(job)"
                    >
                      下载
                    </el-button>
                  </el-tooltip>

                  <el-button
                    v-if="job.status === 'PENDING' || job.status === 'RUNNING'"
                    :data-testid="`cancel-job-${job.job_no}`"
                    size="small"
                    type="danger"
                    plain
                    :disabled="!canCreateCancel"
                    @click="handleCancel(job)"
                  >
                    取消
                  </el-button>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <div v-if="total > 0" class="jobs-pagination">
        <el-pagination
          v-model:current-page="filters.page"
          v-model:page-size="filters.page_size"
          :total="total"
          :page-sizes="[10, 20, 50, 100]"
          layout="total, sizes, prev, pager, next"
          @current-change="loadJobs()"
          @size-change="handleSearch()"
        />
      </div>
    </section>

    <JobCreateModals
      v-model:mode="createModalMode"
      :policies="policies"
      :datasources="datasources"
      @created="handleSearch()"
    />

    <SpotCheckDrawer
      v-model="spotCheckDrawerOpen"
      :job="activeSpotJob"
      @updated="loadJobs()"
    />
  </div>
</template>

<style scoped>
.jobs-header-actions {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
}

.jobs-toolbar {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 10px;
  margin-bottom: 14px;
}

.table-scroll-wrap {
  overflow-x: auto;
}

.jobs-pagination {
  display: flex;
  justify-content: flex-end;
  margin-top: 14px;
}

.job-no-cell {
  font-weight: 600;
}

.job-name-cell {
  font-size: 0.875rem;
  color: var(--ds-text-primary);
}

.row-actions {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}
</style>
