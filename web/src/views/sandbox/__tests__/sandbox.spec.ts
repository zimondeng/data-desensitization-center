import { describe, it, expect, beforeEach, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { mount } from '@vue/test-utils'
import { http } from '@/api/client'
import { useSandboxStore } from '@/stores/sandbox'
import SandboxView from '@/views/sandbox/SandboxView.vue'

describe('Slice 2: SandboxView 3-state capsules & Zero-Client-Persistence', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    localStorage.clear()
    sessionStorage.clear()
    window.history.replaceState({}, '', '/sandbox')
  })

  it('fills valid mod-11 Golden QA sample, renders onnx/regex/allowlist capsules, and clears state on unmount', async () => {
    const consoleLogSpy = vi.spyOn(console, 'log').mockImplementation(() => {})
    const consoleErrSpy = vi.spyOn(console, 'error').mockImplementation(() => {})

    const getSpy = vi.spyOn(http, 'get').mockResolvedValueOnce({
      data: {
        code: 200,
        message: 'ok',
        request_id: 'req_pol',
        data: {
          items: [
            {
              id: 1,
              uuid: 'p1',
              policy_code: 'gov_eval_corpus',
              version: 1,
              policy_name: '政务问答与评测语料差异化脱敏策略 v1',
              scope_mode: 'CONVERSATION',
              onnx_variant: 'int8',
              entity_rules: {},
              field_role_rules: { default_role: 'FULL_MASK_WRITE_SCOPE', high_risk_only_labels: [], rules: [] },
              allowlist_groups: ['gov_public_hotline', 'gov_public_domain', 'gov_public_hall'],
              is_default: true,
              status: 'ACTIVE',
              description: null,
              created_by: 'system',
              create_time: '2026-11-12T00:00:00.000Z',
              update_time: '2026-11-12T00:00:00.000Z',
            },
          ],
          total: 1,
          policies: [
            {
              policy_code: 'gov_eval_corpus',
              policy_name: '政务问答与评测语料差异化脱敏策略 v1',
              default_version: 1,
              latest_version: 1,
              versions: [],
            },
          ],
        },
      },
    } as never)

    const sampleText = '我是张三，身份证 32040219900307118X，拨打 12345。'
    const postSpy = vi.spyOn(http, 'post').mockResolvedValueOnce({
      data: {
        code: 200,
        message: 'ok',
        request_id: 'req_sb',
        data: {
          mode: 'TEXT',
          policy_code: 'gov_eval_corpus',
          policy_version: 1,
          scope_mode: 'CONVERSATION',
          onnx_variant: 'int8',
          masked_text: '我是<PERSON_1>，身份证 <IDCARD_1>，拨打 12345。',
          masked_payload: null,
          spans: [
            {
              kind: 'masked',
              state: 'onnx',
              source: 'onnx',
              detector: 'onnx',
              label: 'private_person',
              start: 2,
              end: 4,
              orig_start: 2,
              orig_end: 4,
              text: '张三',
              replacement: '<PERSON_1>',
              score: 0.96,
              exempted: false,
              allowlist_group: null,
              allowlist_rule: null,
            },
            {
              kind: 'masked',
              state: 'regex',
              source: 'regex',
              detector: 'regex',
              label: 'cn_id_card',
              start: 9,
              end: 27,
              orig_start: 9,
              orig_end: 27,
              text: '32040219900307118X',
              replacement: '<IDCARD_1>',
              score: 1.0,
              exempted: false,
              allowlist_group: null,
              allowlist_rule: null,
            },
            {
              kind: 'exempted',
              state: 'allowlist',
              source: 'allowlist',
              detector: 'onnx',
              label: 'phone',
              start: 31,
              end: 36,
              orig_start: 31,
              orig_end: 36,
              text: '12345',
              replacement: null,
              score: 0.92,
              exempted: true,
              allowlist_group: 'gov_public_hotline',
              allowlist_rule: '全国政务与公共服务5位短号',
            },
          ],
          masked_spans: [],
          exempted_spans: [],
          exempted_count: 1,
          field_traces: {},
          hit_counts: { private_person: 1, cn_id_card: 1 },
          elapsed_ms: 14,
        },
      },
    } as never)

    const wrapper = mount(SandboxView)
    await new Promise((r) => setTimeout(r, 20))

    // Enforce Single Primary Action Rule
    expect(wrapper.findAll('.el-button--primary').length).toBe(1)

    // Fill Golden QA sample and confirm valid mod-11 ID (never 32040219900307123X)
    await wrapper.find('[data-testid="fill-golden-sample"]').trigger('click')
    const store = useSandboxStore()
    expect(store.inputText).toContain('32040219900307118X')
    expect(store.inputText).not.toContain('32040219900307123X')

    // Overwrite with test sample matching mocked offsets for exact span rendering check
    store.inputText = sampleText
    await wrapper.find('[data-testid="run-sandbox-btn"]').trigger('click')
    await new Promise((r) => setTimeout(r, 20))

    expect(postSpy).toHaveBeenCalledWith(
      '/api/admin/sandbox/preview',
      expect.objectContaining({
        mode: 'TEXT',
        text: sampleText,
      }),
    )

    // Switch to highlight contrast tab if needed and verify all 3 semantic capsules inside output body
    const outputBody = wrapper.find('.sandbox-output-body')
    const onnxChip = outputBody.find('.ds-span-chip--onnx')
    const regexChip = outputBody.find('.ds-span-chip--regex')
    const allowlistChip = outputBody.find('.ds-span-chip--allowlist')
    expect(onnxChip.exists()).toBe(true)
    expect(regexChip.exists()).toBe(true)
    expect(allowlistChip.exists()).toBe(true)
    expect(onnxChip.text()).toContain('onnx')
    expect(regexChip.text()).toContain('regex')
    expect(allowlistChip.text()).toContain('豁免保留')
    expect(allowlistChip.text()).toContain('gov_public_hotline')

    // Verify Zero-Client-Persistence
    expect(localStorage.length).toBe(0)
    expect(sessionStorage.length).toBe(0)
    expect(window.location.search).toBe('')
    expect(consoleLogSpy).not.toHaveBeenCalled()
    expect(consoleErrSpy).not.toHaveBeenCalled()

    // Unmount clears sensitive reactive state in memory
    wrapper.unmount()
    expect(store.inputText).toBe('')
    expect(store.structuredJsonText).toBe('')
    expect(store.result).toBeNull()

    getSpy.mockRestore()
    postSpy.mockRestore()
    consoleLogSpy.mockRestore()
    consoleErrSpy.mockRestore()
  })
})
