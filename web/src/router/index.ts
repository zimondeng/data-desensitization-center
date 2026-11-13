import { createRouter, createWebHistory, type RouteRecordRaw } from 'vue-router'
import { useAuthStore } from '@/stores/auth'

const AppShell = () => import('@/components/AppShell.vue')
const LoginView = () => import('@/views/login/LoginView.vue')
const SandboxView = () => import('@/views/sandbox/SandboxView.vue')
const PoliciesView = () => import('@/views/policies/PoliciesView.vue')
const AllowlistsView = () => import('@/views/allowlists/AllowlistsView.vue')
const JobsView = () => import('@/views/jobs/JobsView.vue')
const SettingsView = () => import('@/views/settings/SettingsView.vue')

const routes: RouteRecordRaw[] = [
  {
    path: '/login',
    name: 'login',
    component: LoginView,
    meta: { public: true, title: '管理员登录' },
  },
  {
    path: '/',
    component: AppShell,
    redirect: '/sandbox',
    children: [
      {
        path: 'sandbox',
        name: 'sandbox',
        component: SandboxView,
        meta: { title: '在线脱敏沙盒' },
      },
      {
        path: 'policies',
        name: 'policies',
        component: PoliciesView,
        meta: { title: '策略版本工作台' },
      },
      {
        path: 'allowlists',
        name: 'allowlists',
        component: AllowlistsView,
        meta: { title: '白名单豁免字典' },
      },
      {
        path: 'jobs',
        name: 'jobs',
        component: JobsView,
        meta: { title: '批处理与抽检' },
      },
      {
        path: 'settings',
        name: 'settings',
        component: SettingsView,
        meta: { title: '治理台与统计看板' },
      },
    ],
  },
  {
    path: '/:pathMatch(.*)*',
    redirect: '/sandbox',
  },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
})

router.beforeEach((to) => {
  const authStore = useAuthStore()

  if (to.meta.public) {
    if (to.path === '/login' && authStore.isAuthenticated) {
      return '/sandbox'
    }
    document.title = `${String(to.meta.title ?? '登录')} · 数据脱敏中心`
    return true
  }

  if (!authStore.isAuthenticated) {
    const safeRedirect =
      to.fullPath && to.fullPath.startsWith('/') && !to.fullPath.startsWith('//') && to.fullPath !== '/login'
        ? to.fullPath
        : undefined
    return safeRedirect ? { path: '/login', query: { redirect: safeRedirect } } : { path: '/login' }
  }

  document.title = `${String(to.meta.title ?? '控制台')} · 数据脱敏中心`
  return true
})

export default router
