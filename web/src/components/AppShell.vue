<template>
  <div class="app-shell">
    <!-- Desktop Fixed Left Sidebar -->
    <aside
      class="app-sidebar"
      :class="{ 'is-collapsed': sidebarCollapsed }"
      aria-label="主导航栏"
    >
      <div class="sidebar-brand">
        <span class="sidebar-brand__logo" aria-hidden="true">
          <el-icon :size="18"><Lock /></el-icon>
        </span>
        <span v-if="!sidebarCollapsed" class="sidebar-brand__title">数据脱敏中心</span>
      </div>

      <nav class="sidebar-nav">
        <el-tooltip
          v-for="item in navItems"
          :key="item.path"
          :content="item.title"
          placement="right"
          :disabled="!sidebarCollapsed"
        >
          <router-link
            :to="item.path"
            class="sidebar-link"
            :class="{ 'is-active': route.path === item.path }"
          >
            <el-icon class="sidebar-link__icon" :size="18">
              <component :is="item.icon" />
            </el-icon>
            <span v-if="!sidebarCollapsed" class="sidebar-link__text">{{ item.title }}</span>
          </router-link>
        </el-tooltip>
      </nav>

      <div class="sidebar-footer">
        <el-tooltip
          :content="sidebarCollapsed ? '展开导航栏' : '收起导航栏'"
          placement="right"
        >
          <button
            type="button"
            class="collapse-btn"
            :aria-label="sidebarCollapsed ? '展开导航栏' : '收起导航栏'"
            @click="sidebarCollapsed = !sidebarCollapsed"
          >
            <el-icon :size="16">
              <Expand v-if="sidebarCollapsed" />
              <Fold v-else />
            </el-icon>
            <span v-if="!sidebarCollapsed">收起侧栏</span>
          </button>
        </el-tooltip>
      </div>
    </aside>

    <!-- Narrow Viewport Drawer Sidebar (< 1024px) -->
    <el-drawer
      v-model="mobileDrawerOpen"
      direction="ltr"
      size="240px"
      title="数据脱敏中心"
      class="mobile-nav-drawer"
    >
      <nav class="sidebar-nav" aria-label="移动端主导航">
        <router-link
          v-for="item in navItems"
          :key="item.path"
          :to="item.path"
          class="sidebar-link ds-touch-target"
          :class="{ 'is-active': route.path === item.path }"
          @click="mobileDrawerOpen = false"
        >
          <el-icon class="sidebar-link__icon" :size="18">
            <component :is="item.icon" />
          </el-icon>
          <span class="sidebar-link__text">{{ item.title }}</span>
        </router-link>
      </nav>
    </el-drawer>

    <div class="app-main-wrap">
      <!-- Top Status Bar (52px) -->
      <header class="app-topbar">
        <div class="topbar-left">
          <el-tooltip content="展开导航菜单" placement="bottom">
            <button
              type="button"
              class="mobile-menu-btn ds-touch-target"
              aria-label="展开导航菜单"
              @click="mobileDrawerOpen = true"
            >
              <el-icon :size="20"><Menu /></el-icon>
            </button>
          </el-tooltip>
          <span class="topbar-breadcrumb ds-secondary-text">
            控制台 / <strong class="topbar-current">{{ currentTitle }}</strong>
          </span>
        </div>

        <div class="topbar-right">
          <el-tag
            :type="authStore.onnxReady ? 'success' : 'warning'"
            effect="light"
            size="small"
            class="ds-tabular-nums"
          >
            {{
              authStore.onnxReady
                ? `ONNX 引擎就绪 (${authStore.onnxVariant})`
                : 'ONNX 模型未挂载（启用 NER 策略将返回 50301）'
            }}
          </el-tag>

          <div v-if="authStore.user" class="topbar-user">
            <span class="topbar-user__name">{{ authStore.user.display_name }}</span>
            <el-tag :type="roleMeta.tagType" effect="light" size="small">
              {{ roleMeta.label }}
            </el-tag>
          </div>

          <el-button size="small" @click="handleLogout">退出登录</el-button>
        </div>
      </header>

      <main class="app-content">
        <router-view />
      </main>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import {
  Collection,
  DataAnalysis,
  DocumentCopy,
  Expand,
  Fold,
  Lock,
  Menu,
  Monitor,
  Setting,
} from '@element-plus/icons-vue'
import { ROLE_META } from '@/constants/domain'
import { useAuthStore } from '@/stores/auth'

const route = useRoute()
const router = useRouter()
const authStore = useAuthStore()

const sidebarCollapsed = ref(false)
const mobileDrawerOpen = ref(false)

const navItems = [
  { path: '/sandbox', title: '在线脱敏沙盒', icon: Monitor },
  { path: '/policies', title: '策略版本工作台', icon: DocumentCopy },
  { path: '/allowlists', title: '白名单豁免字典', icon: Collection },
  { path: '/jobs', title: '批处理与抽检', icon: DataAnalysis },
  { path: '/settings', title: '治理台与统计看板', icon: Setting },
]

const currentTitle = computed(() => {
  const found = navItems.find((item) => item.path === route.path)
  return found?.title ?? '零残留合规工作台'
})

const roleMeta = computed(() => {
  const r = authStore.role ?? 'AUDITOR'
  return ROLE_META[r]
})

async function handleLogout(): Promise<void> {
  authStore.logout()
  await router.push('/login')
}

onMounted(() => {
  if (authStore.isAuthenticated) {
    authStore.refreshMe().catch(() => {
      // Handled safely by HTTP interceptor if 401
    })
  }
})
</script>

<style scoped>
.app-shell {
  display: flex;
  min-height: 100vh;
  background-color: var(--ds-bg-page);
}

.app-sidebar {
  width: 220px;
  flex-shrink: 0;
  display: flex;
  flex-direction: column;
  background-color: var(--ds-bg-card);
  border-right: 1px solid var(--ds-border-subtle);
  transition: width var(--ds-motion-duration) var(--ds-motion-ease);
}

.app-sidebar.is-collapsed {
  width: 64px;
}

.sidebar-brand {
  height: 52px;
  display: flex;
  align-items: center;
  gap: var(--ds-space-sm);
  padding: 0 var(--ds-space-lg);
  border-bottom: 1px solid var(--ds-border-subtle);
}

.app-sidebar.is-collapsed .sidebar-brand {
  justify-content: center;
  padding: 0;
}

.sidebar-brand__logo {
  width: 30px;
  height: 30px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  border-radius: var(--ds-radius-md);
  background-color: var(--ds-color-primary);
  color: var(--ds-bg-card);
  flex-shrink: 0;
}

.sidebar-brand__title {
  font-size: 0.9375rem;
  font-weight: 600;
  color: var(--ds-text-primary);
  white-space: nowrap;
}

.sidebar-nav {
  flex: 1;
  display: flex;
  flex-direction: column;
  gap: 4px;
  padding: var(--ds-space-md) var(--ds-space-sm);
}

.sidebar-link {
  display: flex;
  align-items: center;
  gap: var(--ds-space-sm);
  padding: 10px 12px;
  border-radius: var(--ds-radius-md);
  color: var(--ds-text-secondary);
  text-decoration: none;
  font-weight: 500;
  transition: background-color var(--ds-motion-duration) var(--ds-motion-ease),
    color var(--ds-motion-duration) var(--ds-motion-ease);
}

.app-sidebar.is-collapsed .sidebar-link {
  justify-content: center;
  padding: 10px;
}

.sidebar-link:hover {
  background-color: var(--ds-bg-panel);
  color: var(--ds-text-primary);
}

.sidebar-link.is-active {
  background-color: var(--ds-bg-active);
  color: var(--ds-color-primary);
}

.sidebar-link__text {
  white-space: nowrap;
}

.sidebar-footer {
  padding: var(--ds-space-sm);
  border-top: 1px solid var(--ds-border-subtle);
}

.collapse-btn {
  width: 100%;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 6px;
  padding: 8px;
  border: 1px solid var(--ds-border-subtle);
  border-radius: var(--ds-radius-md);
  background-color: var(--ds-bg-panel);
  color: var(--ds-text-secondary);
  cursor: pointer;
  font-size: 0.8125rem;
}

.collapse-btn:hover {
  border-color: var(--ds-border-strong);
  color: var(--ds-text-primary);
}

.app-main-wrap {
  flex: 1;
  min-width: 0;
  display: flex;
  flex-direction: column;
}

.app-topbar {
  min-height: 52px;
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: var(--ds-space-sm);
  padding: var(--ds-space-sm) var(--ds-space-xl);
  background-color: var(--ds-bg-card);
  border-bottom: 1px solid var(--ds-border-subtle);
}

.topbar-left {
  display: flex;
  align-items: center;
  gap: var(--ds-space-sm);
}

.topbar-current {
  color: var(--ds-text-primary);
  font-weight: 600;
}

.mobile-menu-btn {
  display: none;
  align-items: center;
  justify-content: center;
  border: 1px solid var(--ds-border-subtle);
  border-radius: var(--ds-radius-md);
  background-color: var(--ds-bg-card);
  color: var(--ds-text-primary);
  cursor: pointer;
}

.topbar-right {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: var(--ds-space-md);
}

.topbar-user {
  display: inline-flex;
  align-items: center;
  gap: 6px;
}

.topbar-user__name {
  font-weight: 500;
  color: var(--ds-text-primary);
}

.app-content {
  flex: 1;
  padding: var(--ds-space-xl);
  max-width: 1440px;
  width: 100%;
  margin: 0 auto;
}

@media (max-width: 1023px) {
  .app-sidebar {
    display: none;
  }

  .mobile-menu-btn {
    display: inline-flex;
  }

  .app-topbar {
    padding: var(--ds-space-sm) var(--ds-space-lg);
  }

  .app-content {
    padding: var(--ds-space-lg);
  }
}
</style>
