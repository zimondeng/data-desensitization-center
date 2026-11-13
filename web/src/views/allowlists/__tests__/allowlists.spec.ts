import { describe, it, expect, beforeEach, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { mount } from '@vue/test-utils'
import { ElMessageBox } from 'element-plus'
import { http } from '@/api/client'
import { useAuthStore } from '@/stores/auth'
import AllowlistsView from '@/views/allowlists/AllowlistsView.vue'

function makeAllowlistResponse() {
  return {
    items: [
      {
        id: 1,
        uuid: 'al-1',
        group_code: 'gov_public_hotline',
        item_name: '政务服务便民热线 12345',
        match_mode: 'EXACT',
        pattern_text: '12345',
        apply_labels: ['phone', 'cn_mobile'],
        is_enabled: true,
        remark: '全国政务热线',
        created_by: 'system',
        create_time: '2026-11-12T00:00:00Z',
        update_time: '2026-11-12T00:00:00Z',
      },
      {
        id: 2,
        uuid: 'al-2',
        group_code: 'gov_public_domain',
        item_name: '政府门户域名后缀',
        match_mode: 'REGEX',
        pattern_text: '^https?://([a-z0-9-]+\\.)*gov\\.cn(/.*)?$',
        apply_labels: ['url'],
        is_enabled: true,
        remark: null,
        created_by: 'system',
        create_time: '2026-11-12T00:00:00Z',
        update_time: '2026-11-12T00:00:00Z',
      },
    ],
    total: 2,
    groups: [
      { group_code: 'gov_public_hotline', total_count: 1, enabled_count: 1 },
      { group_code: 'gov_public_domain', total_count: 1, enabled_count: 1 },
    ],
  }
}

describe('Slice 4: AllowlistsView CRUD, inline match tester, zero persistence & RBAC', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    localStorage.clear()
    sessionStorage.clear()
    window.history.replaceState({}, '', '/allowlists')
  })

  it('runs inline tester without persisting sample text, supports delete confirm, and enforces AUDITOR read-only RBAC', async () => {
    const auth = useAuthStore()
    auth.setSession('jwt-op', {
      uuid: 'u-op',
      username: 'op1',
      display_name: '操作员',
      role: 'OPERATOR',
    })

    const getSpy = vi.spyOn(http, 'get').mockResolvedValue({
      data: { code: 200, message: 'ok', request_id: 'r1', data: makeAllowlistResponse() },
    } as never)

    const postSpy = vi.spyOn(http, 'post').mockResolvedValueOnce({
      data: {
        code: 200,
        message: 'ok',
        request_id: 'r2',
        data: {
          matched: true,
          matched_count: 1,
          matched_rules: [
            {
              id: 1,
              uuid: 'al-1',
              group_code: 'gov_public_hotline',
              item_name: '政务服务便民热线 12345',
              match_mode: 'EXACT',
              pattern_text: '12345',
              apply_labels: ['phone', 'cn_mobile'],
            },
          ],
        },
      },
    } as never)

    const deleteSpy = vi.spyOn(http, 'delete').mockResolvedValueOnce({
      data: { code: 200, message: 'ok', request_id: 'r3', data: { deleted_id: 1 } },
    } as never)

    const wrapper = mount(AllowlistsView)
    await new Promise((r) => setTimeout(r, 30))

    expect(wrapper.text()).toContain('gov_public_hotline')
    expect(wrapper.text()).toContain('12345')
    expect(wrapper.findAll('.el-button--primary').length).toBeLessThanOrEqual(1)

    // Inline match test
    const testInput = wrapper.find('input[name="allowlist-test-text"]')
    await testInput.setValue('12345')
    await wrapper.find('[data-testid="allowlist-test-btn"]').trigger('click')
    await new Promise((r) => setTimeout(r, 20))

    expect(postSpy).toHaveBeenCalledWith(
      '/api/admin/allowlists/test',
      expect.objectContaining({
        text: '12345',
        include_saved: true,
      }),
    )
    expect(wrapper.text()).toContain('命中豁免')
    expect(JSON.stringify(localStorage)).not.toContain('12345')
    expect(JSON.stringify(sessionStorage)).not.toContain('12345')

    // Delete with confirmation
    const confirmSpy = vi.spyOn(ElMessageBox, 'confirm').mockResolvedValueOnce('confirm' as never)
    await wrapper.find('[data-testid="delete-allowlist-1"]').trigger('click')
    await new Promise((r) => setTimeout(r, 20))
    expect(confirmSpy).toHaveBeenCalled()
    expect(deleteSpy).toHaveBeenCalledWith('/api/admin/allowlists/1')
    confirmSpy.mockRestore()

    // Switch to AUDITOR -> mutations disabled while inline tester remains usable
    auth.setSession('jwt-aud', {
      uuid: 'u-aud',
      username: 'aud1',
      display_name: '审核员',
      role: 'AUDITOR',
    })
    await new Promise((r) => setTimeout(r, 10))
    expect(wrapper.find('[data-testid="add-allowlist-btn"]').attributes('disabled')).toBeDefined()
    expect(wrapper.find('[data-testid="allowlist-test-btn"]').attributes('disabled')).toBeUndefined()
    expect(wrapper.text()).toContain('AUDITOR')

    wrapper.unmount()
    getSpy.mockRestore()
    postSpy.mockRestore()
    deleteSpy.mockRestore()
  })

  it('requires non-empty apply_labels with inline validation error before submitting create', async () => {
    const auth = useAuthStore()
    auth.setSession('jwt-op', {
      uuid: 'u-op',
      username: 'op1',
      display_name: '操作员',
      role: 'OPERATOR',
    })

    const getSpy = vi.spyOn(http, 'get').mockResolvedValue({
      data: { code: 200, message: 'ok', request_id: 'r1', data: makeAllowlistResponse() },
    } as never)
    const postSpy = vi.spyOn(http, 'post')

    const wrapper = mount(AllowlistsView)
    await new Promise((r) => setTimeout(r, 30))

    await wrapper.find('[data-testid="add-allowlist-btn"]').trigger('click')
    await new Promise((r) => setTimeout(r, 20))

    expect(wrapper.text()).toContain('作用实体类别（必填，至少选择 1 类）')
    await wrapper.find('#drawer-group-code').setValue('gov_custom')
    await wrapper.find('#drawer-item-name').setValue('测试豁免规则')
    await wrapper.find('#drawer-pattern-text').setValue('10086')
    for (const closeBtn of wrapper.findAll('.el-drawer .el-tag__close')) {
      await closeBtn.trigger('click')
    }

    const submitBtn = wrapper.findAll('button').find((b) => b.text().includes('创建规则'))
    expect(submitBtn).toBeDefined()
    await submitBtn!.trigger('click')
    await new Promise((r) => setTimeout(r, 20))

    expect(wrapper.text()).toContain('请至少选择 1 类作用实体')
    expect(postSpy).not.toHaveBeenCalled()

    wrapper.unmount()
    getSpy.mockRestore()
    postSpy.mockRestore()
  })
})
