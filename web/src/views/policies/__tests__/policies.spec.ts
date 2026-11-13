import { describe, it, expect, beforeEach, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { mount } from '@vue/test-utils'
import { createMemoryHistory, createRouter } from 'vue-router'
import { ElMessageBox } from 'element-plus'
import { http } from '@/api/client'
import { useAuthStore } from '@/stores/auth'
import { createDefaultEntityRules } from '@/constants/domain'
import PoliciesView from '@/views/policies/PoliciesView.vue'

function makeMockPolicyResponse() {
  const rules = createDefaultEntityRules()
  return {
    items: [
      {
        id: 2,
        uuid: 'pol-gov-v1',
        policy_code: 'gov_eval_corpus',
        version: 1,
        policy_name: '政务问答与评测语料差异化脱敏策略 v1',
        scope_mode: 'CONVERSATION',
        onnx_variant: 'int8',
        entity_rules: rules,
        field_role_rules: {
          default_role: 'FULL_MASK_WRITE_SCOPE',
          high_risk_only_labels: ['cn_id_card', 'cn_mobile', 'bank_card_luhn', 'payment_card', 'common_secret'],
          rules: [{ jsonpath: '$.turns[?(@.role==\'user\')].content', role: 'FULL_MASK_WRITE_SCOPE' }],
        },
        allowlist_groups: ['gov_public_hotline', 'gov_public_domain', 'gov_public_hall'],
        is_default: true,
        status: 'ACTIVE',
        description: '政务默认策略',
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
        versions: [
          {
            id: 2,
            uuid: 'pol-gov-v1',
            policy_code: 'gov_eval_corpus',
            version: 1,
            policy_name: '政务问答与评测语料差异化脱敏策略 v1',
            scope_mode: 'CONVERSATION',
            onnx_variant: 'int8',
            entity_rules: rules,
            field_role_rules: {
              default_role: 'FULL_MASK_WRITE_SCOPE',
              high_risk_only_labels: ['cn_id_card', 'cn_mobile', 'bank_card_luhn', 'payment_card', 'common_secret'],
              rules: [{ jsonpath: '$.turns[?(@.role==\'user\')].content', role: 'FULL_MASK_WRITE_SCOPE' }],
            },
            allowlist_groups: ['gov_public_hotline', 'gov_public_domain', 'gov_public_hall'],
            is_default: true,
            status: 'ACTIVE',
            description: '政务默认策略',
            created_by: 'system',
            create_time: '2026-11-12T00:00:00.000Z',
            update_time: '2026-11-12T00:00:00.000Z',
          },
        ],
      },
    ],
  }
}

describe('Slice 3: PoliciesView immutable versioning, dirty guard & RBAC', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    localStorage.clear()
    sessionStorage.clear()
  })

  it('publishes edits as immutable version v{N+1}, blocks unsaved leave, and disables mutations for AUDITOR', async () => {
    const auth = useAuthStore()
    auth.setSession('jwt-op', {
      uuid: 'u-op',
      username: 'op1',
      display_name: '操作员',
      role: 'OPERATOR',
    })

    const getSpy = vi.spyOn(http, 'get').mockImplementation(async (url: string) => {
      if (url === '/api/admin/policies') {
        return { data: { code: 200, message: 'ok', request_id: 'r1', data: makeMockPolicyResponse() } } as never
      }
      if (url === '/api/admin/allowlists') {
        return {
          data: {
            code: 200,
            message: 'ok',
            request_id: 'r2',
            data: {
              items: [],
              total: 0,
              groups: [
                { group_code: 'gov_public_hotline', total_count: 2, enabled_count: 2 },
                { group_code: 'gov_public_domain', total_count: 1, enabled_count: 1 },
                { group_code: 'gov_public_hall', total_count: 1, enabled_count: 1 },
              ],
            },
          },
        } as never
      }
      throw new Error(`Unexpected GET ${url}`)
    })

    const postSpy = vi.spyOn(http, 'post').mockResolvedValueOnce({
      data: {
        code: 200,
        message: 'ok',
        request_id: 'r3',
        data: {
          ...makeMockPolicyResponse().items[0],
          id: 3,
          version: 2,
          policy_name: '政务问答策略 v2',
          is_default: false,
        },
      },
    } as never)

    const router = createRouter({
      history: createMemoryHistory(),
      routes: [
        { path: '/policies', component: PoliciesView },
        { path: '/sandbox', component: { template: '<div>Sandbox</div>' } },
      ],
    })
    await router.push('/policies')
    await router.isReady()

    const wrapper = mount(PoliciesView, {
      global: { plugins: [router] },
    })
    await new Promise((r) => setTimeout(r, 30))

    // Single primary button displays "发布为新版本 v2"
    expect(wrapper.findAll('.el-button--primary').length).toBe(1)
    const publishBtn = wrapper.find('[data-testid="publish-new-version-btn"]')
    expect(publishBtn.text()).toContain('发布为新版本 v2')

    // Modify policy_name to become dirty
    const nameInput = wrapper.find('input[name="policy_name"]')
    await nameInput.setValue('政务问答策略 v2')
    await new Promise((r) => setTimeout(r, 10))

    // Unsaved changes guard prompts when navigating away
    const confirmSpy = vi.spyOn(ElMessageBox, 'confirm').mockRejectedValueOnce('cancel')
    await router.push('/sandbox')
    expect(confirmSpy).toHaveBeenCalled()
    expect(router.currentRoute.value.path).toBe('/policies')
    confirmSpy.mockRestore()

    // Submit immutable version bump via POST /api/admin/policies
    await publishBtn.trigger('click')
    await new Promise((r) => setTimeout(r, 20))
    expect(postSpy).toHaveBeenCalledWith(
      '/api/admin/policies',
      expect.objectContaining({
        policy_code: 'gov_eval_corpus',
        policy_name: '政务问答策略 v2',
      }),
    )

    // Switch to AUDITOR role -> publish button must be disabled with reason visible
    auth.setSession('jwt-aud', {
      uuid: 'u-aud',
      username: 'aud1',
      display_name: '审核员',
      role: 'AUDITOR',
    })
    await new Promise((r) => setTimeout(r, 10))
    expect(wrapper.find('[data-testid="publish-new-version-btn"]').attributes('disabled')).toBeDefined()
    expect(wrapper.text()).toContain('AUDITOR')

    wrapper.unmount()
    getSpy.mockRestore()
    postSpy.mockRestore()
  })

  it('sets set_as_default=true when creating v1 policy and enforces hash_len >= 6 & policy_name inline errors', async () => {
    const auth = useAuthStore()
    auth.setSession('jwt-op', {
      uuid: 'u-op',
      username: 'op1',
      display_name: '操作员',
      role: 'OPERATOR',
    })

    const createdItem = {
      ...makeMockPolicyResponse().items[0],
      id: 9,
      uuid: 'pol-new-v1',
      policy_code: 'finance_v1',
      version: 1,
      policy_name: '金融测试策略 v1',
      is_default: true,
    }

    const getSpy = vi.spyOn(http, 'get').mockImplementation(async (url: string) => {
      if (url === '/api/admin/policies') {
        return { data: { code: 200, message: 'ok', request_id: 'r1', data: makeMockPolicyResponse() } } as never
      }
      if (url === '/api/admin/allowlists') {
        return { data: { code: 200, message: 'ok', request_id: 'r2', data: { items: [], total: 0, groups: [] } } } as never
      }
      throw new Error(`Unexpected GET ${url}`)
    })

    const postSpy = vi.spyOn(http, 'post').mockResolvedValueOnce({
      data: { code: 200, message: 'ok', request_id: 'r3', data: createdItem },
    } as never)

    const router = createRouter({
      history: createMemoryHistory(),
      routes: [{ path: '/policies', component: PoliciesView }],
    })
    await router.push('/policies')
    await router.isReady()

    const wrapper = mount(PoliciesView, {
      global: { plugins: [router] },
    })
    await new Promise((r) => setTimeout(r, 30))

    // Open New Policy v1 modal and verify set_as_default: true
    await wrapper.find('[data-testid="new-policy-code-btn"]').trigger('click')
    await new Promise((r) => setTimeout(r, 20))
    await wrapper.find('#new-policy-code').setValue('finance_v1')
    await wrapper.find('#new-policy-name').setValue('金融测试策略 v1')
    const createBtn = wrapper.findAll('button').find((b) => b.text().includes('创建 v1'))
    expect(createBtn).toBeDefined()
    await createBtn!.trigger('click')
    await new Promise((r) => setTimeout(r, 30))

    expect(postSpy).toHaveBeenCalledWith(
      '/api/admin/policies',
      expect.objectContaining({
        policy_code: 'finance_v1',
        set_as_default: true,
      }),
    )

    // Switch an enabled entity rule to HASH with hash_len=4 -> inline error blocks submit
    postSpy.mockClear()
    const actionSelect = wrapper.find('select[aria-label="个人姓名 掩码动作"]')
    await actionSelect.setValue('HASH')
    const hashLenInput = wrapper.find('[data-testid="hash-len-input-private_person"]')
    await hashLenInput.setValue('4')
    await wrapper.find('[data-testid="publish-new-version-btn"]').trigger('click')
    await new Promise((r) => setTimeout(r, 20))

    expect(wrapper.find('[data-testid="entity-error-private_person"]').text()).toContain('6 至 64')
    expect(postSpy).not.toHaveBeenCalled()

    // Empty policy_name -> inline error blocks submit
    await hashLenInput.setValue('8')
    await wrapper.find('input[name="policy_name"]').setValue('   ')
    await wrapper.find('[data-testid="publish-new-version-btn"]').trigger('click')
    await new Promise((r) => setTimeout(r, 20))

    expect(wrapper.find('[data-testid="policy-name-error"]').exists()).toBe(true)
    expect(postSpy).not.toHaveBeenCalled()

    wrapper.unmount()
    getSpy.mockRestore()
    postSpy.mockRestore()
  })
})
