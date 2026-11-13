import { computed, ref } from 'vue'
import { defineStore } from 'pinia'
import { fetchCurrentAdmin, loginAdmin } from '@/api/auth'
import { configureHttpAuth } from '@/api/client'
import type { AdminRole, AdminUserProfile } from '@/types/api'

const SESSION_TOKEN_KEY = 'ds_console_jwt'
const SESSION_USER_KEY = 'ds_console_user'

function safeReadSessionStorage(key: string): string {
  try {
    return typeof sessionStorage !== 'undefined' ? sessionStorage.getItem(key) ?? '' : ''
  } catch {
    return ''
  }
}

function safeWriteSessionStorage(key: string, value: string): void {
  try {
    if (typeof sessionStorage !== 'undefined') {
      sessionStorage.setItem(key, value)
    }
  } catch {
    // Ignore storage restriction
  }
}

function safeRemoveSessionStorage(key: string): void {
  try {
    if (typeof sessionStorage !== 'undefined') {
      sessionStorage.removeItem(key)
    }
  } catch {
    // Ignore
  }
}

function loadInitialUser(): AdminUserProfile | null {
  const raw = safeReadSessionStorage(SESSION_USER_KEY)
  if (!raw) return null
  try {
    const parsed = JSON.parse(raw) as Partial<AdminUserProfile>
    if (
      typeof parsed.uuid === 'string' &&
      typeof parsed.username === 'string' &&
      typeof parsed.display_name === 'string' &&
      (parsed.role === 'ADMIN' || parsed.role === 'OPERATOR' || parsed.role === 'AUDITOR')
    ) {
      return {
        uuid: parsed.uuid,
        username: parsed.username,
        display_name: parsed.display_name,
        role: parsed.role,
      }
    }
  } catch {
    // Ignore malformed data
  }
  return null
}

export const useAuthStore = defineStore('auth', () => {
  const token = ref<string>(safeReadSessionStorage(SESSION_TOKEN_KEY))
  const user = ref<AdminUserProfile | null>(loadInitialUser())
  const onnxReady = ref<boolean>(false)
  const onnxVariant = ref<string>('int8')
  const profileLoaded = ref<boolean>(false)

  const isAuthenticated = computed(() => Boolean(token.value && user.value))
  const role = computed<AdminRole | null>(() => user.value?.role ?? null)

  // Strict RBAC capability matrix (matches backend/app/auth/dependencies.py)
  const canEditPolicies = computed(
    () => role.value === 'ADMIN' || role.value === 'OPERATOR',
  )
  const canEditAllowlists = computed(
    () => role.value === 'ADMIN' || role.value === 'OPERATOR',
  )
  const canCreateCancelJobs = computed(
    () => role.value === 'ADMIN' || role.value === 'OPERATOR',
  )
  const canSpotCheck = computed(
    () => role.value === 'ADMIN' || role.value === 'AUDITOR',
  )
  const canManageApiKeys = computed(() => role.value === 'ADMIN')
  const canManageDatasources = computed(() => role.value === 'ADMIN')

  function setSession(
    accessToken: string,
    profile: AdminUserProfile,
    ready = false,
    variant = 'int8',
  ): void {
    const safeProfile: AdminUserProfile = {
      uuid: profile.uuid,
      username: profile.username,
      display_name: profile.display_name,
      role: profile.role,
    }
    token.value = accessToken
    user.value = safeProfile
    onnxReady.value = ready
    onnxVariant.value = variant
    profileLoaded.value = true

    safeWriteSessionStorage(SESSION_TOKEN_KEY, accessToken)
    safeWriteSessionStorage(SESSION_USER_KEY, JSON.stringify(safeProfile))
  }

  function logout(): void {
    token.value = ''
    user.value = null
    onnxReady.value = false
    profileLoaded.value = false
    safeRemoveSessionStorage(SESSION_TOKEN_KEY)
    safeRemoveSessionStorage(SESSION_USER_KEY)
  }

  async function login(username: string, password: string): Promise<void> {
    const res = await loginAdmin(username.trim(), password)
    setSession(res.access_token, res.user, Boolean(res.onnx_ready), 'int8')
  }

  async function refreshMe(): Promise<void> {
    if (!token.value) return
    const me = await fetchCurrentAdmin()
    const safeProfile: AdminUserProfile = {
      uuid: me.uuid,
      username: me.username,
      display_name: me.display_name,
      role: me.role,
    }
    user.value = safeProfile
    onnxReady.value = Boolean(me.onnx_ready)
    onnxVariant.value = me.onnx_variant || 'int8'
    profileLoaded.value = true
    safeWriteSessionStorage(SESSION_USER_KEY, JSON.stringify(safeProfile))
  }

  configureHttpAuth(
    () => token.value,
    () => {
      logout()
    },
  )

  return {
    token,
    user,
    onnxReady,
    onnxVariant,
    profileLoaded,
    isAuthenticated,
    role,
    canEditPolicies,
    canEditAllowlists,
    canCreateCancelJobs,
    canSpotCheck,
    canManageApiKeys,
    canManageDatasources,
    setSession,
    logout,
    login,
    refreshMe,
  }
})
