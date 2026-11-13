import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { mount } from '@vue/test-utils'
import { ElMessageBox } from 'element-plus'
import { http } from '@/api/client'
import { useAuthStore } from '@/stores/auth'
import JobsView from '@/views/jobs/JobsView.vue'

function makeJobsResponse(overrides?: Array<Record<string, unknown>>) {
  return {
    items: overrides ?? [
      {
        id: 10,
        uuid: 'job-10',
        job_no: 'JOB-20261113-001',
        job_name: '政务热线对话脱敏批次',
        source_type: 'FILE_UPLOAD',
        input_format: 'JSONL',
        source_filename_masked: 'gov_qa_sample.jsonl',
        datasource_id: null,
        sampling_config: null,
        policy_id: 2,
        policy_code: 'gov_eval_corpus',
        policy_version: 1,
        status: 'COMPLETED',
        total_records: 100,
        processed_records: 100,
        failed_records: 0,
        total_chars: 12000,
        progress_pct: 100,
        entity_hit_stats: { cn_id_card: 20, cn_mobile: 35 },
        output_format: 'JSONL',
        output_size_bytes: 8192,
        output_sha256: 'abc123def456',
        has_artifact: true,
        expires_at: '2026-11-16T00:00:00Z',
        spot_check_status: 'FLAGGED_LEAK',
        spot_checked_by: 'auditor',
        spot_checked_at: '2026-11-13T01:00:00Z',
        spot_check_note: '第 12 行字段 turns[1].content 仍有疑似漏脱敏占位符异常',
        elapsed_ms: 420,
        error_summary: null,
        started_at: '2026-11-13T00:00:00Z',
        finished_at: '2026-11-13T00:00:01Z',
        triggered_by: 'operator',
        create_time: '2026-11-13T00:00:00Z',
        update_time: '2026-11-13T00:00:01Z',
      },
      {
        id: 11,
        uuid: 'job-11',
        job_no: 'JOB-20261113-002',
        job_name: '过期批次验证',
        source_type: 'MYSQL_READONLY',
        input_format: 'MYSQL_TABLE',
        source_filename_masked: null,
        datasource_id: 1,
        sampling_config: { table_name: 'qa_records', limit_rows: 200 },
        policy_id: 2,
        policy_code: 'gov_eval_corpus',
        policy_version: 1,
        status: 'ARTIFACT_EXPIRED',
        total_records: 200,
        processed_records: 200,
        failed_records: 0,
        total_chars: 24000,
        progress_pct: 100,
        entity_hit_stats: { private_person: 40 },
        output_format: 'CSV',
        output_size_bytes: 0,
        output_sha256: 'deadbeef0011',
        has_artifact: false,
        expires_at: '2026-11-12T00:00:00Z',
        spot_check_status: 'PASSED',
        spot_checked_by: 'auditor',
        spot_checked_at: '2026-11-11T00:00:00Z',
        spot_check_note: null,
        elapsed_ms: 600,
        error_summary: null,
        started_at: '2026-11-11T00:00:00Z',
        finished_at: '2026-11-11T00:00:02Z',
        triggered_by: 'operator',
        create_time: '2026-11-11T00:00:00Z',
        update_time: '2026-11-11T00:00:02Z',
      },
      {
        id: 12,
        uuid: 'job-12',
        job_no: 'JOB-20261113-003',
        job_name: '运行中抽样任务',
        source_type: 'MYSQL_READONLY',
        input_format: 'MYSQL_TABLE',
        source_filename_masked: null,
        datasource_id: 1,
        sampling_config: { table_name: 'qa_records', limit_rows: 100 },
        policy_id: 2,
        policy_code: 'gov_eval_corpus',
        policy_version: 1,
        status: 'RUNNING',
        total_records: 100,
        processed_records: 40,
        failed_records: 0,
        total_chars: 4000,
        progress_pct: 40,
        entity_hit_stats: {},
        output_format: 'JSONL',
        output_size_bytes: null,
        output_sha256: null,
        has_artifact: false,
        expires_at: '2026-11-16T00:00:00Z',
        spot_check_status: 'UNCHECKED',
        spot_checked_by: null,
        spot_checked_at: null,
        spot_check_note: null,
        elapsed_ms: null,
        error_summary: null,
        started_at: '2026-11-13T00:10:00Z',
        finished_at: null,
        triggered_by: 'operator',
        create_time: '2026-11-13T00:10:00Z',
        update_time: '2026-11-13T00:10:00Z',
      },
    ],
    total: 3,
    page: 1,
    page_size: 20,
  }
}

describe('Slice 5: JobsView download guards, spot-check confirmation, polling & RBAC', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    localStorage.clear()
    sessionStorage.clear()
    vi.useFakeTimers()
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it('blocks download on FLAGGED_LEAK & ARTIFACT_EXPIRED, pauses polling when hidden, enforces FLAGGED_LEAK confirm and RBAC', async () => {
    const auth = useAuthStore()
    auth.setSession('jwt-aud', {
      uuid: 'u-aud',
      username: 'aud1',
      display_name: '合规审核员',
      role: 'AUDITOR',
    })

    const getSpy = vi.spyOn(http, 'get').mockImplementation(async (url: string) => {
      if (url === '/api/admin/jobs') {
        return { data: { code: 200, message: 'ok', request_id: 'r1', data: makeJobsResponse() } } as never
      }
      if (url === '/api/admin/policies') {
        return { data: { code: 200, message: 'ok', request_id: 'r2', data: { items: [], total: 0, policies: [] } } } as never
      }
      if (url === '/api/admin/datasources') {
        return { data: { code: 200, message: 'ok', request_id: 'r3', data: { items: [], total: 0 } } } as never
      }
      if (url === '/api/admin/jobs/JOB-20261113-001/preview-masked') {
        return {
          data: {
            code: 200,
            message: 'ok',
            request_id: 'r4',
            data: {
              job_no: 'JOB-20261113-001',
              policy_code: 'gov_eval_corpus',
              policy_version: 1,
              spot_check_status: 'UNCHECKED',
              spot_check_note: null,
              output_sha256: 'abc123def456',
              expires_at: '2026-11-16T00:00:00Z',
              output_format: 'JSONL',
              limit: 20,
              returned_count: 1,
              has_more: false,
              lines: ['{"case_code":"CASE_01","text":"我是<PERSON_1>"}'],
              records: [{ case_code: 'CASE_01', text: '我是<PERSON_1>' }],
            },
          },
        } as never
      }
      throw new Error(`Unexpected GET ${url}`)
    })

    const postSpy = vi.spyOn(http, 'post').mockResolvedValue({
      data: {
        code: 200,
        message: 'ok',
        request_id: 'r5',
        data: { job_no: 'JOB-20261113-001', spot_check_status: 'FLAGGED_LEAK' },
      },
    } as never)

    const wrapper = mount(JobsView)
    await vi.advanceTimersByTimeAsync(50)

    // AUDITOR cannot create jobs
    expect(wrapper.find('[data-testid="open-file-job-btn"]').attributes('disabled')).toBeDefined()
    expect(wrapper.find('[data-testid="open-mysql-job-btn"]').attributes('disabled')).toBeDefined()

    // Download disabled for FLAGGED_LEAK & ARTIFACT_EXPIRED
    expect(wrapper.find('[data-testid="download-job-JOB-20261113-001"]').attributes('disabled')).toBeDefined()
    expect(wrapper.find('[data-testid="download-job-JOB-20261113-002"]').attributes('disabled')).toBeDefined()
    expect(wrapper.text()).toContain('疑似漏脱敏')
    expect(wrapper.text()).toContain('产物已过期')

    // Polling runs while visible because JOB-20261113-003 is RUNNING
    const callsBeforePoll = getSpy.mock.calls.filter((c) => c[0] === '/api/admin/jobs').length
    await vi.advanceTimersByTimeAsync(4500)
    const callsAfterPoll = getSpy.mock.calls.filter((c) => c[0] === '/api/admin/jobs').length
    expect(callsAfterPoll).toBeGreaterThan(callsBeforePoll)

    // Polling pauses when document.hidden becomes true
    Object.defineProperty(document, 'hidden', { configurable: true, get: () => true })
    document.dispatchEvent(new Event('visibilitychange'))
    const callsWhenHidden = getSpy.mock.calls.filter((c) => c[0] === '/api/admin/jobs').length
    await vi.advanceTimersByTimeAsync(9000)
    expect(getSpy.mock.calls.filter((c) => c[0] === '/api/admin/jobs').length).toBe(callsWhenHidden)
    Object.defineProperty(document, 'hidden', { configurable: true, get: () => false })
    document.dispatchEvent(new Event('visibilitychange'))

    // Open spot-check drawer for AUDITOR and verify FLAGGED_LEAK confirmation
    await wrapper.find('[data-testid="spot-check-job-JOB-20261113-001"]').trigger('click')
    await vi.advanceTimersByTimeAsync(50)
    expect(wrapper.text()).toContain('严禁将原始敏感明文写入备注')
    expect(wrapper.text()).toContain('<PERSON_1>')

    const confirmSpy = vi.spyOn(ElMessageBox, 'confirm').mockResolvedValueOnce('confirm' as never)
    await wrapper.find('[data-testid="spot-check-radio-FLAGGED_LEAK"]').trigger('click')
    await wrapper.find('[data-testid="submit-spot-check-btn"]').trigger('click')
    await vi.advanceTimersByTimeAsync(50)
    expect(confirmSpy).toHaveBeenCalled()
    expect(postSpy).toHaveBeenCalledWith(
      '/api/admin/jobs/JOB-20261113-001/spot-check',
      expect.objectContaining({ spot_check_status: 'FLAGGED_LEAK' }),
    )
    confirmSpy.mockRestore()

    wrapper.unmount()
    getSpy.mockRestore()
    postSpy.mockRestore()
  })
})
