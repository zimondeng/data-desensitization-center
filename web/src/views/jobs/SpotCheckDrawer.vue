<script setup lang="ts">
import { computed, onBeforeUnmount, reactive, ref, watch } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import StatusTag from '@/components/StatusTag.vue'
import { previewJobMasked, submitSpotCheck } from '@/api/jobs'
import { useAuthStore } from '@/stores/auth'
import { SPOT_CHECK_STATUS_META } from '@/constants/domain'
import type { BatchJobItem, JobPreviewMaskedData } from '@/types/api'

const props = defineProps<{
  modelValue: boolean
  job: BatchJobItem | null
}>()

const emit = defineEmits<{
  'update:modelValue': [value: boolean]
  updated: []
}>()

const auth = useAuthStore()

const open = computed({
  get: () => props.modelValue,
  set: (v: boolean) => emit('update:modelValue', v),
})

const loading = ref(false)
const loadError = ref('')
const previewData = ref<JobPreviewMaskedData | null>(null)
const submitting = ref(false)
const submitError = ref('')

const spotForm = reactive({
  status: 'PASSED' as 'PASSED' | 'FLAGGED_LEAK' | 'FLAGGED_OVERMASK',
  note: '',
})

const canSubmitSpotCheck = computed(() => auth.canSpotCheck)

function clearSensitivePreviewState() {
  previewData.value = null
  spotForm.note = ''
  loadError.value = ''
  submitError.value = ''
}

async function loadPreview() {
  if (!props.job) return
  loading.value = true
  loadError.value = ''
  submitError.value = ''
  try {
    previewData.value = await previewJobMasked(props.job.job_no, 20)
    if (
      props.job.spot_check_status === 'PASSED' ||
      props.job.spot_check_status === 'FLAGGED_LEAK' ||
      props.job.spot_check_status === 'FLAGGED_OVERMASK'
    ) {
      spotForm.status = props.job.spot_check_status
    } else {
      spotForm.status = 'PASSED'
    }
    spotForm.note = props.job.spot_check_note ?? ''
  } catch (err) {
    loadError.value = err instanceof Error ? err.message : '加载脱敏抽检预览失败'
  } finally {
    loading.value = false
  }
}

watch(
  () => [props.modelValue, props.job?.job_no] as const,
  ([isOpen, jobNo]) => {
    if (isOpen && jobNo) {
      void loadPreview()
    } else if (!isOpen) {
      clearSensitivePreviewState()
    }
  },
)

async function handleSubmit() {
  if (!props.job || !canSubmitSpotCheck.value) return
  submitError.value = ''

  if (spotForm.status === 'FLAGGED_LEAK') {
    try {
      await ElMessageBox.confirm(
        '标记为「疑似漏脱敏」将立即阻断该批次产物下载，且不可通过下载接口绕过。确认提交该抽检结论？',
        '高风险阻断确认',
        {
          confirmButtonText: '确认标记并阻断下载',
          cancelButtonText: '返回复核',
          type: 'warning',
        },
      )
    } catch {
      return
    }
  }

  submitting.value = true
  try {
    await submitSpotCheck(props.job.job_no, {
      spot_check_status: spotForm.status,
      spot_check_note: spotForm.note.trim() || undefined,
    })
    ElMessage.success('人工抽检结论已记录')
    clearSensitivePreviewState()
    emit('update:modelValue', false)
    emit('updated')
  } catch (err) {
    submitError.value = err instanceof Error ? err.message : '提交抽检结论失败'
  } finally {
    submitting.value = false
  }
}

onBeforeUnmount(() => {
  clearSensitivePreviewState()
})
</script>

<template>
  <el-drawer
    v-model="open"
    title="合规抽检 · 脱敏产物样本复核"
    size="620px"
    @close="clearSensitivePreviewState"
  >
    <template v-if="open && job">
      <div class="drawer-stack">
        <div class="ds-panel-slot job-meta-banner">
          <div class="job-meta-row">
            <span class="ds-mono">{{ job.job_no }}</span>
            <StatusTag
              :label="SPOT_CHECK_STATUS_META[job.spot_check_status]?.label ?? job.spot_check_status"
              :tag-type="SPOT_CHECK_STATUS_META[job.spot_check_status]?.tagType ?? 'info'"
            />
          </div>
          <div class="ds-muted-text" style="margin-top: 6px">
            策略：<span class="ds-mono">{{ job.policy_code }} v{{ job.policy_version }}</span>
            · SHA-256：<span class="ds-mono">{{ (previewData?.output_sha256 ?? job.output_sha256 ?? '--').slice(0, 16) }}</span>
          </div>
        </div>

        <el-alert
          v-if="loadError"
          type="error"
          :closable="false"
          show-icon
          :title="loadError"
        />

        <div v-loading="loading" class="preview-block">
          <div class="preview-block__header">
            <span class="form-label">脱敏产物前 20 条样本预览（实时流式读取，关闭即焚）</span>
            <span v-if="previewData" class="ds-muted-text ds-tabular-nums">
              已展示 {{ previewData.returned_count }} 条
            </span>
          </div>
          <pre v-if="previewData && previewData.lines.length > 0" class="ds-mono preview-pre">{{ previewData.lines.join('\n') }}</pre>
          <el-empty v-else-if="!loading && !loadError" description="产物暂无预览行" />
        </div>

        <div class="spot-check-form">
          <el-alert
            v-if="!canSubmitSpotCheck"
            type="warning"
            :closable="false"
            show-icon
            title="当前角色为 OPERATOR，无权提交合规抽检结论（需 ADMIN 或 AUDITOR 权限）"
          />

          <div class="form-field">
            <span class="form-label">抽检合规判定</span>
            <div class="radio-group-stack">
              <label class="radio-option">
                <input
                  v-model="spotForm.status"
                  type="radio"
                  value="PASSED"
                  data-testid="spot-check-radio-PASSED"
                  :disabled="!canSubmitSpotCheck"
                />
                <span>抽检通过 (PASSED) — 允许正常下载</span>
              </label>
              <label class="radio-option radio-option--danger">
                <input
                  v-model="spotForm.status"
                  type="radio"
                  value="FLAGGED_LEAK"
                  data-testid="spot-check-radio-FLAGGED_LEAK"
                  :disabled="!canSubmitSpotCheck"
                />
                <span>疑似漏脱敏 (FLAGGED_LEAK) — 立即阻断下载并需二次确认</span>
              </label>
              <label class="radio-option">
                <input
                  v-model="spotForm.status"
                  type="radio"
                  value="FLAGGED_OVERMASK"
                  data-testid="spot-check-radio-FLAGGED_OVERMASK"
                  :disabled="!canSubmitSpotCheck"
                />
                <span>疑似误伤公共信息 (FLAGGED_OVERMASK) — 建议核查白名单</span>
              </label>
            </div>
          </div>

          <el-alert
            type="warning"
            :closable="false"
            show-icon
            title="严禁将原始敏感明文写入备注；请仅记录行号、字段路径或占位符位置。"
          />

          <div class="form-field">
            <label class="form-label" for="spot-check-note-input">抽检备注（仅限脱敏后审计信息）</label>
            <el-input
              id="spot-check-note-input"
              v-model="spotForm.note"
              type="textarea"
              :rows="3"
              :disabled="!canSubmitSpotCheck"
              placeholder="例如：第 12 行 turns[1].content 仍有未命中实体特征，已建议调整策略阈值"
            />
          </div>

          <el-alert
            v-if="submitError"
            type="error"
            :closable="false"
            show-icon
            :title="submitError"
          />
        </div>
      </div>
    </template>

    <template #footer>
      <template v-if="open && job">
        <el-button @click="open = false">关闭</el-button>
        <el-button
          data-testid="submit-spot-check-btn"
          type="primary"
          :disabled="!canSubmitSpotCheck || submitting"
          :loading="submitting"
          @click="handleSubmit"
        >
          提交抽检结论
        </el-button>
      </template>
    </template>
  </el-drawer>
</template>

<style scoped>
.drawer-stack {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.job-meta-banner {
  padding: 12px 14px;
}

.job-meta-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
}

.preview-block__header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 6px;
}

.preview-pre {
  margin: 0;
  padding: 12px;
  max-height: 240px;
  overflow: auto;
  border-radius: var(--ds-radius-md);
  border: 1px solid var(--ds-border-subtle);
  background: var(--ds-bg-panel);
  white-space: pre-wrap;
  word-break: break-all;
}

.spot-check-form {
  display: flex;
  flex-direction: column;
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

.radio-group-stack {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.radio-option {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 10px;
  border: 1px solid var(--ds-border-subtle);
  border-radius: var(--ds-radius-md);
  font-size: 0.875rem;
  cursor: pointer;
}

.radio-option--danger {
  border-color: var(--ds-border-danger);
  background: var(--ds-bg-danger);
  color: var(--ds-color-danger-text);
}
</style>
