import { http, unwrapEnvelope } from '@/api/client'
import type { ApiEnvelope, MetricsHourlyResponseData } from '@/types/api'

export async function fetchHourlyMetrics(params?: {
  hours?: number
  include_sandbox?: boolean
  api_key_id?: number
  policy_id?: number
}): Promise<MetricsHourlyResponseData> {
  const resp = await http.get<ApiEnvelope<MetricsHourlyResponseData>>(
    '/api/admin/metrics/hourly',
    params ? { params } : undefined,
  )
  return unwrapEnvelope(resp)
}
