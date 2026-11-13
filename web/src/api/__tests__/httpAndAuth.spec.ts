import { describe, it, expect, beforeEach, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { mount } from '@vue/test-utils'
import { createMemoryHistory, createRouter } from 'vue-router'
import { http, ApiRequestError, sanitizeErrorMessage } from '@/api/client'
import { useAuthStore } from '@/stores/auth'
import LoginView from '@/views/login/LoginView.vue'

describe('Slice 1: HTTP sanitization, Auth store RBAC & LoginView', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    localStorage.clear()
    sessionStorage.clear()
  })

  it('sanitizes errors and never echoes sensitive plaintext payload in thrown errors or console', async () => {
    const consoleErrSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    const consoleLogSpy = vi.spyOn(console, 'log').mockImplementation(() => {})

    const sensitiveInput = '我是张三，身份证 32040219900307118X，密码 SecretPwd@999，密钥 dsk_live_abcdef1234567890'
    const adapterSpy = vi.fn().mockRejectedValue({
      isAxiosError: true,
      config: {
        url: '/api/admin/sandbox/preview',
        data: JSON.stringify({ text: sensitiveInput }),
      },
      response: {
        status: 503,
        data: {
          code: 50301,
          message: 'Local AstrLink Guard ONNX model is not ready',
          request_id: 'req_test_503',
        },
      },
    })

    const origAdapter = http.defaults.adapter
    http.defaults.adapter = adapterSpy
    try {
      await expect(
        http.post('/api/admin/sandbox/preview', { text: sensitiveInput }),
      ).rejects.toMatchObject({
        name: 'ApiRequestError',
        code: 50301,
        httpStatus: 503,
      })
    } catch (e) {
      expect(e).toBeInstanceOf(ApiRequestError)
    } finally {
      http.defaults.adapter = origAdapter
    }

    const sanitized = sanitizeErrorMessage(
      `Request failed with payload ${sensitiveInput} dsk_live_abcdef1234567890`,
    )
    expect(sanitized).not.toContain('32040219900307118X')
    expect(sanitized).not.toContain('dsk_live_abcdef1234567890')
    expect(consoleErrSpy).not.toHaveBeenCalled()
    expect(consoleLogSpy).not.toHaveBeenCalled()

    consoleErrSpy.mockRestore()
    consoleLogSpy.mockRestore()
  })

  it('enforces RBAC capability matrix across ADMIN, OPERATOR, AUDITOR without persisting secrets', () => {
    const auth = useAuthStore()

    auth.setSession('jwt-admin-token', {
      uuid: 'u1',
      username: 'admin',
      display_name: '系统管理员',
      role: 'ADMIN',
    })
    expect(auth.canEditPolicies).toBe(true)
    expect(auth.canEditAllowlists).toBe(true)
    expect(auth.canCreateCancelJobs).toBe(true)
    expect(auth.canSpotCheck).toBe(true)
    expect(auth.canManageApiKeys).toBe(true)
    expect(auth.canManageDatasources).toBe(true)

    auth.setSession('jwt-operator-token', {
      uuid: 'u2',
      username: 'op1',
      display_name: '操作员',
      role: 'OPERATOR',
    })
    expect(auth.canEditPolicies).toBe(true)
    expect(auth.canEditAllowlists).toBe(true)
    expect(auth.canCreateCancelJobs).toBe(true)
    expect(auth.canSpotCheck).toBe(false)
    expect(auth.canManageApiKeys).toBe(false)
    expect(auth.canManageDatasources).toBe(false)

    auth.setSession('jwt-auditor-token', {
      uuid: 'u3',
      username: 'aud1',
      display_name: '审计员',
      role: 'AUDITOR',
    })
    expect(auth.canEditPolicies).toBe(false)
    expect(auth.canEditAllowlists).toBe(false)
    expect(auth.canCreateCancelJobs).toBe(false)
    expect(auth.canSpotCheck).toBe(true)
    expect(auth.canManageApiKeys).toBe(false)
    expect(auth.canManageDatasources).toBe(false)

    expect(localStorage.length).toBe(0)
    auth.logout()
    expect(auth.isAuthenticated).toBe(false)
    expect(sessionStorage.length).toBe(0)
  })

  it('LoginView submits credentials, displays inline error on 40101, and never stores password', async () => {
    const router = createRouter({
      history: createMemoryHistory(),
      routes: [
        { path: '/login', component: LoginView },
        { path: '/sandbox', component: { template: '<div>Sandbox</div>' } },
      ],
    })
    await router.push('/login')
    await router.isReady()

    const postSpy = vi.spyOn(http, 'post').mockRejectedValueOnce(
      new ApiRequestError({
        httpStatus: 401,
        code: 40101,
        message: 'Invalid username or password',
        requestId: 'req_401',
      }),
    )

    const wrapper = mount(LoginView, {
      global: {
        plugins: [router],
      },
    })

    const primaryButtons = wrapper.findAll('.el-button--primary')
    expect(primaryButtons.length).toBe(1)

    await wrapper.find('input[name="username"]').setValue('admin')
    await wrapper.find('input[name="password"]').setValue('WrongPassword!')
    await wrapper.find('form').trigger('submit.prevent')

    await new Promise((r) => setTimeout(r, 20))
    expect(wrapper.text()).toContain('用户名或密码错误')
    expect(JSON.stringify({ ...localStorage, ...sessionStorage })).not.toContain('WrongPassword!')

    postSpy.mockResolvedValueOnce({
      data: {
        code: 200,
        message: 'ok',
        request_id: 'req_ok',
        data: {
          access_token: 'jwt-valid-token',
          token_type: 'Bearer',
          expires_in: 3600,
          user: {
            uuid: 'u1',
            username: 'admin',
            display_name: '系统管理员',
            role: 'ADMIN',
          },
          onnx_ready: true,
        },
      },
    } as never)

    await wrapper.find('input[name="password"]').setValue('Admin@123456')
    await wrapper.find('form').trigger('submit.prevent')
    await new Promise((r) => setTimeout(r, 20))

    expect(router.currentRoute.value.path).toBe('/sandbox')
    expect(JSON.stringify({ ...localStorage, ...sessionStorage })).not.toContain('Admin@123456')
    wrapper.unmount()
    postSpy.mockRestore()
  })
})
