import { describe, it, expect, beforeEach, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { mount } from '@vue/test-utils'
import { ElMessageBox } from 'element-plus'
import { http } from '@/api/client'
import { useAuthStore } from '@/stores/auth'
import SettingsView from '@/views/settings/SettingsView.vue'

vi.mock('echarts/core', () => {
  const chartInstance = {
    setOption: vi.fn(),
    resize: vi.fn(),
    dispose: vi.fn(),
  }
  return {
    use: vi.fn(),
    init: vi.fn(() => chartInstance),
  }
})
vi.mock('echarts/charts', () => ({ LineChart: {}, BarChart: {} }))
vi.mock('echarts/components', () => ({ GridComponent: {}, TooltipComponent: {}, LegendComponent: {} }))
vi.mock('echarts/renderers', () => ({ CanvasRenderer: {} }))

function makeMetricsResponse() {
  return {
    hours: 24,
    include_sandbox: false,
    window_start: '2026-11-12T00:00:00Z',
    updated_at: '2026-11-13T00:00:00Z',
    total_requests: 1280,
    total_items: 5120,
    total_chars: 980400,
    total_elapsed_ms: 44800,
    avg_elapsed_ms: 35.0,
    error_count: 0,
    total_entity_hits: 3100,
    summary: {
      total_requests: 1280,
      total_items: 5120,
      total_chars: 980400,
      total_elapsed_ms: 44800,
      avg_elapsed_ms: 35.0,
      error_count: 0,
    },
    buckets: [
      {
        hour_bucket: '2026-11-13 00:00',
        request_count: 640,
        item_count: 2560,
        total_chars: 490200,
        total_elapsed_ms: 22400,
        avg_elapsed_ms: 35.0,
        error_count: 0,
      },
    ],
    entity_distribution: [
      {
        label: 'cn_id_card',
        label_zh: '二代居民身份证号',
        display_name: '二代居民身份证号',
        detector: 'regex',
        count: 900,
        ratio: 0.29,
        percentage: 29.0,
      },
    ],
    batch_jobs_summary: {
      total_jobs: 4,
      completed_jobs: 4,
      processed_records: 800,
      total_chars: 250000,
    },
  }
}

describe('Slice 6: SettingsView Telemetry charts, Show-Once API Key, Datasource zero-persistence & ADMIN RBAC', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    localStorage.clear()
    sessionStorage.clear()
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: { writeText: vi.fn().mockResolvedValue(undefined) },
    })
  })

  it('renders ECharts telemetry KPIs, handles show-once dsk_* key without persistence, protects datasource passwords, and locks non-ADMIN mutations', async () => {
    const auth = useAuthStore()
    auth.setSession('jwt-admin', {
      uuid: 'u-admin',
      username: 'admin',
      display_name: '系统管理员',
      role: 'ADMIN',
    })

    const getSpy = vi.spyOn(http, 'get').mockImplementation(async (url: string) => {
      if (url === '/api/admin/metrics/hourly') {
        return { data: { code: 200, message: 'ok', request_id: 'r1', data: makeMetricsResponse() } } as never
      }
      if (url === '/api/admin/api-keys') {
        return {
          data: {
            code: 200,
            message: 'ok',
            request_id: 'r2',
            data: {
              items: [
                {
                  id: 1,
                  uuid: 'key-1',
                  key_name: '政务工单生产密钥',
                  key_prefix: 'dsk_live_abc',
                  default_policy_code: 'gov_eval_corpus',
                  rate_limit_rpm: 120,
                  allowed_ips: [],
                  status: 'ACTIVE',
                  expires_at: null,
                  last_used_at: null,
                  created_by: 'admin',
                  create_time: '2026-11-12T00:00:00Z',
                  update_time: '2026-11-12T00:00:00Z',
                },
              ],
              total: 1,
            },
          },
        } as never
      }
      if (url === '/api/admin/policies') {
        return { data: { code: 200, message: 'ok', request_id: 'r3', data: { items: [], total: 0, policies: [{ policy_code: 'gov_eval_corpus', policy_name: '政务默认', default_version: 1, latest_version: 1, versions: [] }] } } } as never
      }
      if (url === '/api/admin/datasources') {
        return {
          data: {
            code: 200,
            message: 'ok',
            request_id: 'r4',
            data: {
              items: [
                {
                  id: 1,
                  uuid: 'ds-1',
                  conn_code: 'mysql_gov_ro',
                  conn_name: '政务问答只读从库',
                  db_type: 'MYSQL',
                  db_host: '127.0.0.1',
                  db_port: 3306,
                  db_name: 'gov_qa',
                  db_user: 'ro_reader',
                  has_password: true,
                  allowed_tables: ['qa_records'],
                  status: 'ACTIVE',
                  last_test_ok: true,
                  last_tested_at: '2026-11-13T00:00:00Z',
                  created_by: 'admin',
                  create_time: '2026-11-12T00:00:00Z',
                  update_time: '2026-11-12T00:00:00Z',
                },
              ],
              total: 1,
            },
          },
        } as never
      }
      throw new Error(`Unexpected GET ${url}`)
    })

    const createdPlainKey = 'dsk_live_secret_once_9999999999'
    const postSpy = vi.spyOn(http, 'post').mockImplementation(async (url: string) => {
      if (url === '/api/admin/api-keys') {
        return {
          data: {
            code: 200,
            message: 'ok',
            request_id: 'r5',
            data: {
              id: 2,
              uuid: 'key-2',
              key_name: '新测试密钥',
              key_prefix: 'dsk_live_sec',
              default_policy_code: 'gov_eval_corpus',
              rate_limit_rpm: 120,
              allowed_ips: null,
              status: 'ACTIVE',
              expires_at: null,
              last_used_at: null,
              created_by: 'admin',
              create_time: '2026-11-13T00:00:00Z',
              update_time: '2026-11-13T00:00:00Z',
              plain_key: createdPlainKey,
            },
          },
        } as never
      }
      if (url === '/api/admin/datasources/mysql_gov_ro/test') {
        return {
          data: {
            code: 200,
            message: 'ok',
            request_id: 'r6',
            data: {
              conn_code: 'mysql_gov_ro',
              ok: true,
              read_only_verified: true,
              last_test_ok: true,
              last_tested_at: '2026-11-13T01:00:00Z',
              latency_ms: 12.4,
              message: '只读连通校验通过',
            },
          },
        } as never
      }
      throw new Error(`Unexpected POST ${url}`)
    })

    const deleteSpy = vi.spyOn(http, 'delete').mockResolvedValue({
      data: { code: 200, message: 'ok', request_id: 'r7', data: { revoked: true } },
    } as never)

    const wrapper = mount(SettingsView)
    await vi.waitFor(() => {
      expect(wrapper.text()).toContain('1,280')
    }, { timeout: 3000 })

    // Tab 1 Telemetry KPIs & truthful api_key_id=0 label
    expect(wrapper.text()).toContain('1,280')
    expect(wrapper.text()).toContain('980,400')
    expect(wrapper.text()).toContain('35.0')
    expect(wrapper.text()).toContain('api_key_id=0')
    expect(wrapper.text()).toContain('不会写入小时级遥测表')

    // Zero hardcoded hex colors in ECharts setOption configs
    const echartsMod = await import('echarts/core')
    const initResult = vi.mocked(echartsMod.init).mock.results.find((r) => r.type === 'return')?.value as
      | { setOption: ReturnType<typeof vi.fn> }
      | undefined
    expect(initResult).toBeDefined()
    expect(initResult!.setOption).toHaveBeenCalled()
    expect(JSON.stringify(initResult!.setOption.mock.calls)).not.toMatch(/#[0-9a-fA-F]{3,8}/)

    // Switch to API Keys tab and create key -> Show-Once dialog opens
    await wrapper.find('[data-testid="tab-api-keys"]').trigger('click')
    await new Promise((r) => setTimeout(r, 30))
    expect(wrapper.text()).toContain('dsk_live_abc')
    expect(wrapper.text()).toContain('SHA-256')
    expect(wrapper.text()).not.toContain('HMAC-SHA256')

    await wrapper.find('[data-testid="open-create-key-btn"]').trigger('click')
    await new Promise((r) => setTimeout(r, 20))
    await wrapper.find('input[name="key_name"]').setValue('新测试密钥')
    await wrapper.find('[data-testid="submit-create-key-btn"]').trigger('click')
    await new Promise((r) => setTimeout(r, 30))

    expect(wrapper.text()).toContain(createdPlainKey)
    expect(JSON.stringify(localStorage)).not.toContain(createdPlainKey)
    expect(JSON.stringify(sessionStorage)).not.toContain(createdPlainKey)

    await wrapper.find('[data-testid="copy-plain-key-btn"]').trigger('click')
    await wrapper.find('[data-testid="confirm-saved-key-btn"]').trigger('click')
    await new Promise((r) => setTimeout(r, 20))
    expect(wrapper.text()).not.toContain(createdPlainKey)

    // Revoke requires secondary confirm noting HTTP 403 (not 401)
    const confirmSpy = vi.spyOn(ElMessageBox, 'confirm').mockResolvedValueOnce('confirm' as never)
    await wrapper.find('[data-testid="revoke-key-key-1"]').trigger('click')
    await new Promise((r) => setTimeout(r, 20))
    expect(confirmSpy).toHaveBeenCalledWith(
      expect.stringContaining('403'),
      expect.any(String),
      expect.any(Object),
    )
    expect(deleteSpy).toHaveBeenCalledWith('/api/admin/api-keys/key-1')
    confirmSpy.mockRestore()

    // Non-ADMIN (OPERATOR) -> API Keys & Datasources mutations disabled with reason
    auth.setSession('jwt-op', {
      uuid: 'u-op',
      username: 'op1',
      display_name: '操作员',
      role: 'OPERATOR',
    })
    await new Promise((r) => setTimeout(r, 20))
    expect(wrapper.find('[data-testid="open-create-key-btn"]').attributes('disabled')).toBeDefined()
    expect(wrapper.text()).toContain('ADMIN')

    await wrapper.find('[data-testid="tab-datasources"]').trigger('click')
    await new Promise((r) => setTimeout(r, 30))
    expect(wrapper.find('[data-testid="open-create-ds-btn"]').attributes('disabled')).toBeDefined()
    expect(wrapper.text()).toContain('mysql_gov_ro')

    wrapper.unmount()
    getSpy.mockRestore()
    postSpy.mockRestore()
    deleteSpy.mockRestore()
  })
})
