<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import * as echarts from 'echarts/core'
import { BarChart, LineChart } from 'echarts/charts'
import { GridComponent, LegendComponent, TooltipComponent } from 'echarts/components'
import { CanvasRenderer } from 'echarts/renderers'
import StatusTag from '@/components/StatusTag.vue'
import { extractErrorMessage } from '@/api/client'
import { fetchHourlyMetrics } from '@/api/metrics'
import { resolveChartPalette } from '@/styles/themeTokens'
import type { MetricsHourlyResponseData } from '@/types/api'

echarts.use([LineChart, BarChart, GridComponent, TooltipComponent, LegendComponent, CanvasRenderer])

const loading = ref(false)
const loadError = ref('')
const hours = ref(24)
const includeSandbox = ref(false)
const metrics = ref<MetricsHourlyResponseData | null>(null)

const lineChartRef = ref<HTMLElement | null>(null)
const barChartRef = ref<HTMLElement | null>(null)
let lineChart: echarts.ECharts | null = null
let barChart: echarts.ECharts | null = null

const hasBuckets = computed(() => (metrics.value?.buckets.length ?? 0) > 0)
const hasDistribution = computed(() => (metrics.value?.entity_distribution.length ?? 0) > 0)

const scopeBadgeLabel = computed(() =>
  includeSandbox.value
    ? '统计口径：含无 Key 内部调用桶 (api_key_id=0) 与 /api/v1/*'
    : '统计口径：仅 /api/v1/* API Key 调用（已排除 api_key_id=0 桶）',
)

function formatNumber(value: number | null | undefined, digits = 0): string {
  if (value === null || value === undefined || Number.isNaN(value)) return '--'
  if (digits > 0) return value.toFixed(digits)
  return Math.round(value).toLocaleString('en-US')
}

function renderCharts() {
  if (!metrics.value) return
  const palette = resolveChartPalette()

  if (lineChartRef.value && hasBuckets.value) {
    if (!lineChart) {
      lineChart = echarts.init(lineChartRef.value)
    }
    const buckets = metrics.value.buckets
    lineChart.setOption({
      tooltip: {
        trigger: 'axis',
      },
      legend: {
        data: ['请求数（次）', '平均耗时（ms）'],
        bottom: 0,
      },
      grid: {
        left: 52,
        right: 52,
        top: 28,
        bottom: 40,
      },
      xAxis: {
        type: 'category',
        data: buckets.map((b) => b.hour_bucket.slice(5, 16)),
        axisLabel: { color: palette.textMuted, fontSize: 11 },
      },
      yAxis: [
        {
          type: 'value',
          name: '次',
          nameTextStyle: { color: palette.textMuted },
          axisLabel: { color: palette.textMuted },
          splitLine: { lineStyle: { color: palette.borderSubtle } },
        },
        {
          type: 'value',
          name: 'ms',
          nameTextStyle: { color: palette.textMuted },
          axisLabel: { color: palette.textMuted },
          splitLine: { show: false },
        },
      ],
      series: [
        {
          name: '请求数（次）',
          type: 'line',
          yAxisIndex: 0,
          smooth: false,
          data: buckets.map((b) => b.request_count),
          lineStyle: { color: palette.primary, width: 2, type: 'solid' },
          itemStyle: { color: palette.primary },
        },
        {
          name: '平均耗时（ms）',
          type: 'line',
          yAxisIndex: 1,
          smooth: false,
          data: buckets.map((b) => Number(b.avg_elapsed_ms.toFixed(1))),
          lineStyle: { color: palette.warning, width: 2, type: 'dashed' },
          itemStyle: { color: palette.warning },
        },
      ],
    })
  }

  if (barChartRef.value && hasDistribution.value) {
    if (!barChart) {
      barChart = echarts.init(barChartRef.value)
    }
    const sorted = [...metrics.value.entity_distribution].sort((a, b) => a.count - b.count)
    barChart.setOption({
      tooltip: {
        trigger: 'axis',
        axisPointer: { type: 'shadow' },
      },
      legend: {
        data: ['实体命中数（处）'],
        bottom: 0,
      },
      grid: {
        left: 130,
        right: 36,
        top: 16,
        bottom: 40,
      },
      xAxis: {
        type: 'value',
        name: '处',
        axisLabel: { color: palette.textMuted },
        splitLine: { lineStyle: { color: palette.borderSubtle } },
      },
      yAxis: {
        type: 'category',
        data: sorted.map((d) => d.display_name || d.label_zh || d.label),
        axisLabel: { color: palette.textPrimary, fontSize: 12 },
      },
      series: [
        {
          name: '实体命中数（处）',
          type: 'bar',
          barMaxWidth: 18,
          data: sorted.map((d) => ({
            value: d.count,
            itemStyle: {
              color: d.detector === 'regex' ? palette.warning : palette.primary,
            },
          })),
        },
      ],
    })
  }
}

async function loadMetrics() {
  loading.value = true
  loadError.value = ''
  try {
    metrics.value = await fetchHourlyMetrics({
      hours: hours.value,
      include_sandbox: includeSandbox.value,
    })
    await nextTick()
    renderCharts()
  } catch (err) {
    loadError.value = extractErrorMessage(err, '加载用量遥测统计失败')
  } finally {
    loading.value = false
  }
}

function handleResize() {
  lineChart?.resize()
  barChart?.resize()
}

watch([hours, includeSandbox], () => {
  void loadMetrics()
})

onMounted(() => {
  window.addEventListener('resize', handleResize)
  void loadMetrics()
})

onBeforeUnmount(() => {
  window.removeEventListener('resize', handleResize)
  lineChart?.dispose()
  barChart?.dispose()
  lineChart = null
  barChart = null
})
</script>

<template>
  <div v-loading="loading" class="telemetry-tab">
    <div class="telemetry-toolbar">
      <div class="telemetry-toolbar__filters">
        <el-select v-model="hours" style="width: 156px" aria-label="统计时间窗口">
          <el-option label="最近 24 小时" :value="24" />
          <el-option label="最近 7 天 (168h)" :value="168" />
          <el-option label="最近 30 天 (720h)" :value="720" />
        </el-select>

        <el-tooltip
          content="在线沙盒遵循零写库边界（绝不落库或打日志），不会写入小时级遥测表"
          placement="top"
        >
          <el-checkbox v-model="includeSandbox">
            统计包含无 Key 内部调用桶 (api_key_id=0)
          </el-checkbox>
        </el-tooltip>

        <el-button @click="loadMetrics">刷新统计</el-button>
      </div>

      <div class="telemetry-toolbar__meta">
        <StatusTag :label="scopeBadgeLabel" tag-type="info" />
        <span class="ds-muted-text">
          在线沙盒遵循零写库边界（绝不落库或打日志），不会写入小时级遥测表
        </span>
        <span v-if="metrics?.updated_at" class="ds-muted-text ds-mono ds-tabular-nums">
          更新时间：{{ metrics.updated_at.replace('T', ' ').slice(0, 19) }}
        </span>
      </div>
    </div>

    <el-alert
      v-if="loadError"
      type="error"
      :closable="false"
      show-icon
      style="margin-bottom: 14px"
      :title="loadError"
    />

    <!-- 4 KPI Summary Cards -->
    <div class="kpi-grid">
      <div class="ds-card kpi-card">
        <div class="kpi-card__label">总脱敏请求数</div>
        <div class="kpi-card__value ds-tabular-nums">
          {{ formatNumber(metrics?.total_requests) }}
          <span class="kpi-card__unit">次</span>
        </div>
        <div class="ds-muted-text">窗口：最近 {{ hours }} 小时</div>
      </div>

      <div class="ds-card kpi-card">
        <div class="kpi-card__label">累计脱敏字符数</div>
        <div class="kpi-card__value ds-tabular-nums">
          {{ formatNumber(metrics?.total_chars) }}
          <span class="kpi-card__unit">字符</span>
        </div>
        <div class="ds-muted-text ds-tabular-nums">
          含批处理 {{ formatNumber(metrics?.batch_jobs_summary?.total_chars) }} 字符
        </div>
      </div>

      <div class="ds-card kpi-card">
        <div class="kpi-card__label">平均处理耗时</div>
        <div class="kpi-card__value ds-tabular-nums">
          {{ formatNumber(metrics?.avg_elapsed_ms, 1) }}
          <span class="kpi-card__unit">ms</span>
        </div>
        <div class="ds-muted-text ds-tabular-nums">
          异常次数：{{ formatNumber(metrics?.error_count) }} 次
        </div>
      </div>

      <div class="ds-card kpi-card">
        <div class="kpi-card__label">累计实体命中</div>
        <div class="kpi-card__value ds-tabular-nums">
          {{ formatNumber(metrics?.total_entity_hits) }}
          <span class="kpi-card__unit">处</span>
        </div>
        <div class="ds-muted-text ds-tabular-nums">
          批处理完成 {{ formatNumber(metrics?.batch_jobs_summary?.completed_jobs) }} 批
        </div>
      </div>
    </div>

    <!-- Charts Grid -->
    <div class="charts-grid">
      <div class="ds-card chart-card">
        <div class="chart-card__header">
          <div>
            <h3 class="ds-section-title">每小时请求量与平均耗时趋势</h3>
            <p class="ds-muted-text" style="margin: 2px 0 0">
              实线：请求数（次） · 虚线：平均耗时（ms） · {{ scopeBadgeLabel }}
            </p>
          </div>
        </div>

        <div v-if="hasBuckets" ref="lineChartRef" class="chart-canvas" />
        <el-empty v-else description="当前时间窗口暂无遥测样本" />
      </div>

      <div class="ds-card chart-card">
        <div class="chart-card__header">
          <div>
            <h3 class="ds-section-title">14 类敏感实体识别分布（横向排名）</h3>
            <p class="ds-muted-text" style="margin: 2px 0 0">
              蓝色：ONNX 语义模型 · 琥珀色：确定性正则引擎（单位：处）
            </p>
          </div>
        </div>

        <div v-if="hasDistribution" ref="barChartRef" class="chart-canvas" />
        <el-empty v-else description="当前时间窗口暂无实体命中统计" />
      </div>
    </div>
  </div>
</template>

<style scoped>
.telemetry-tab {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.telemetry-toolbar {
  display: flex;
  flex-wrap: wrap;
  justify-content: space-between;
  align-items: center;
  gap: 12px;
}

.telemetry-toolbar__filters,
.telemetry-toolbar__meta {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 12px;
}

.kpi-grid {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 16px;
}

.kpi-card {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.kpi-card__label {
  font-size: 0.8125rem;
  font-weight: 500;
  color: var(--ds-text-secondary);
}

.kpi-card__value {
  font-size: 1.5rem;
  font-weight: 700;
  color: var(--ds-text-primary);
}

.kpi-card__unit {
  font-size: 0.8125rem;
  font-weight: 500;
  color: var(--ds-text-muted);
  margin-left: 2px;
}

.charts-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 16px;
}

.chart-card__header {
  margin-bottom: 10px;
}

.chart-canvas {
  width: 100%;
  height: 300px;
}

@media (max-width: 1279px) {
  .kpi-grid {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }

  .charts-grid {
    grid-template-columns: 1fr;
  }
}

@media (max-width: 639px) {
  .kpi-grid {
    grid-template-columns: 1fr;
  }
}
</style>
