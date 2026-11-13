import { createApp } from 'vue'
import { createPinia } from 'pinia'
import ElementPlus from 'element-plus'
import 'element-plus/dist/index.css'
import '@/styles/tokens.css'

import App from '@/App.vue'
import router from '@/router'
import { sanitizeErrorMessage } from '@/api/client'
import { useAuthStore } from '@/stores/auth'

const app = createApp(App)
const pinia = createPinia()

app.use(pinia)
// Initialize store early so Axios interceptors bind token & 401 handler before first navigation
useAuthStore(pinia)

app.use(ElementPlus)
app.use(router)

// Zero-Client-Persistence: sanitize unexpected UI errors before console output
app.config.errorHandler = (err) => {
  const safeMsg = sanitizeErrorMessage(err instanceof Error ? err.message : String(err))
  console.error('[console-ui-error]', safeMsg)
}

app.mount('#app')
