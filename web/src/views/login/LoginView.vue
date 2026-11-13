<template>
  <main class="login-page">
    <section class="ds-card login-card" aria-labelledby="login-heading">
      <header class="login-header">
        <div class="login-brand">
          <span class="login-brand__mark" aria-hidden="true">
            <el-icon :size="20"><Lock /></el-icon>
          </span>
          <div>
            <h1 id="login-heading" class="ds-page-title">数据脱敏中心</h1>
            <p class="ds-muted-text login-subtitle">
              零残留合规工作台 · 本地离线隐私识别与单向不可逆脱敏
            </p>
          </div>
        </div>
      </header>

      <el-alert
        v-if="authError"
        type="error"
        :closable="false"
        show-icon
        class="login-alert"
        :title="authError"
        role="alert"
      />

      <form class="login-form" novalidate @submit.prevent="handleSubmit">
        <div class="login-field">
          <label for="login-username" class="login-label">管理员账号</label>
          <el-input
            id="login-username"
            v-model="form.username"
            name="username"
            autocomplete="username"
            placeholder="请输入控制台用户名（如 admin）"
            :disabled="submitting"
            @input="fieldErrors.username = ''"
          />
          <p v-if="fieldErrors.username" class="login-field-error" role="alert">
            {{ fieldErrors.username }}
          </p>
        </div>

        <div class="login-field">
          <label for="login-password" class="login-label">登录密码</label>
          <el-input
            id="login-password"
            v-model="form.password"
            name="password"
            type="password"
            show-password
            autocomplete="current-password"
            placeholder="请输入登录密码"
            :disabled="submitting"
            @input="fieldErrors.password = ''"
          />
          <p v-if="fieldErrors.password" class="login-field-error" role="alert">
            {{ fieldErrors.password }}
          </p>
        </div>

        <el-button
          type="primary"
          native-type="submit"
          class="login-submit"
          :loading="submitting"
          :disabled="submitting"
        >
          {{ submitting ? '正在验证凭证...' : '登录控制台' }}
        </el-button>
      </form>

      <footer class="login-footer ds-muted-text">
        <span>支持角色：ADMIN / OPERATOR / AUDITOR</span>
        <span>本地单向脱敏 · 严禁留存原始明文</span>
      </footer>
    </section>
  </main>
</template>

<script setup lang="ts">
import { onBeforeUnmount, reactive, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { Lock } from '@element-plus/icons-vue'
import { ApiRequestError } from '@/api/client'
import { useAuthStore } from '@/stores/auth'

const router = useRouter()
const route = useRoute()
const authStore = useAuthStore()

const form = reactive({
  username: '',
  password: '',
})

const fieldErrors = reactive({
  username: '',
  password: '',
})

const authError = ref('')
const submitting = ref(false)

function validate(): boolean {
  let valid = true
  fieldErrors.username = ''
  fieldErrors.password = ''
  if (!form.username.trim()) {
    fieldErrors.username = '请输入管理员账号'
    valid = false
  }
  if (!form.password) {
    fieldErrors.password = '请输入登录密码'
    valid = false
  }
  return valid
}

async function handleSubmit(): Promise<void> {
  if (submitting.value) return
  authError.value = ''
  if (!validate()) return

  submitting.value = true
  const rawUsername = form.username
  const rawPassword = form.password
  try {
    await authStore.login(rawUsername, rawPassword)
    const target =
      typeof route.query.redirect === 'string' && route.query.redirect.startsWith('/')
        ? route.query.redirect
        : '/sandbox'
    await router.push(target)
  } catch (err) {
    if (err instanceof ApiRequestError) {
      if (err.code === 40101) {
        authError.value = '用户名或密码错误，请核对后重试（若账号已停用请联系 ADMIN）'
      } else {
        authError.value = err.userMessage
      }
    } else {
      authError.value = '登录请求失败，请检查后端服务（18100 端口）是否正常运行'
    }
  } finally {
    // Zero-Client-Persistence: wipe password immediately from memory
    form.password = ''
    submitting.value = false
  }
}

onBeforeUnmount(() => {
  form.username = ''
  form.password = ''
  authError.value = ''
})
</script>

<style scoped>
.login-page {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: var(--ds-space-xl);
  background-color: var(--ds-bg-page);
}

.login-card {
  width: 100%;
  max-width: 420px;
  padding: var(--ds-space-xl);
}

.login-header {
  margin-bottom: var(--ds-space-lg);
}

.login-brand {
  display: flex;
  align-items: flex-start;
  gap: var(--ds-space-md);
}

.login-brand__mark {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 38px;
  height: 38px;
  flex-shrink: 0;
  border-radius: var(--ds-radius-md);
  background-color: var(--ds-bg-active);
  color: var(--ds-color-primary);
  border: 1px solid var(--ds-border-subtle);
}

.login-subtitle {
  margin: 4px 0 0;
}

.login-alert {
  margin-bottom: var(--ds-space-lg);
}

.login-form {
  display: flex;
  flex-direction: column;
  gap: var(--ds-space-lg);
}

.login-field {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.login-label {
  font-size: 0.875rem;
  font-weight: 500;
  color: var(--ds-text-primary);
}

.login-field-error {
  margin: 0;
  font-size: 0.75rem;
  color: var(--ds-color-danger-text);
}

.login-submit {
  width: 100%;
  height: 40px;
  font-weight: 500;
}

.login-footer {
  margin-top: var(--ds-space-xl);
  padding-top: var(--ds-space-md);
  border-top: 1px solid var(--ds-border-subtle);
  display: flex;
  flex-wrap: wrap;
  justify-content: space-between;
  gap: var(--ds-space-sm);
}
</style>
