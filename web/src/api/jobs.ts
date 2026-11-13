import { http, parseBlobError, unwrapEnvelope } from '@/api/client'
import type {
  ApiEnvelope,
  BatchJobItem,
  BatchJobListResponseData,
  JobPreviewMaskedData,
  MysqlSampleJobPayload,
  SpotCheckPayload,
} from '@/types/api'

export async function listJobs(params?: {
  page?: number
  page_size?: number
  status?: string
  source_type?: string
  spot_check_status?: string
  keyword?: string
}): Promise<BatchJobListResponseData> {
  const resp = await http.get<ApiEnvelope<BatchJobListResponseData>>(
    '/api/admin/jobs',
    params ? { params } : undefined,
  )
  return unwrapEnvelope(resp)
}

export async function getJobDetail(jobNo: string): Promise<BatchJobItem> {
  const resp = await http.get<ApiEnvelope<BatchJobItem>>(
    `/api/admin/jobs/${encodeURIComponent(jobNo)}`,
  )
  return unwrapEnvelope(resp)
}

export async function createFileJob(formData: FormData): Promise<BatchJobItem> {
  const resp = await http.post<ApiEnvelope<BatchJobItem>>('/api/v1/jobs/file', formData)
  return unwrapEnvelope(resp)
}

export async function createMysqlSampleJob(
  payload: MysqlSampleJobPayload,
): Promise<BatchJobItem> {
  const resp = await http.post<ApiEnvelope<BatchJobItem>>(
    '/api/admin/jobs/mysql-sample',
    payload,
  )
  return unwrapEnvelope(resp)
}

export async function cancelJob(jobNo: string): Promise<BatchJobItem> {
  const resp = await http.post<ApiEnvelope<BatchJobItem>>(
    `/api/v1/jobs/${encodeURIComponent(jobNo)}/cancel`,
  )
  return unwrapEnvelope(resp)
}

export async function previewJobMasked(
  jobNo: string,
  limit = 20,
): Promise<JobPreviewMaskedData> {
  const resp = await http.get<ApiEnvelope<JobPreviewMaskedData>>(
    `/api/admin/jobs/${encodeURIComponent(jobNo)}/preview-masked`,
    { params: { limit } },
  )
  return unwrapEnvelope(resp)
}

export async function submitSpotCheck(
  jobNo: string,
  payload: SpotCheckPayload,
): Promise<BatchJobItem> {
  const resp = await http.post<ApiEnvelope<BatchJobItem>>(
    `/api/admin/jobs/${encodeURIComponent(jobNo)}/spot-check`,
    payload,
  )
  return unwrapEnvelope(resp)
}

export async function downloadJobArtifact(
  jobNo: string,
  outputFormat: string,
): Promise<void> {
  const resp = await http.get<Blob>(
    `/api/v1/jobs/${encodeURIComponent(jobNo)}/download`,
    {
      responseType: 'blob',
      validateStatus: () => true,
    },
  )

  if (resp.status >= 400) {
    if (resp.data instanceof Blob) {
      throw await parseBlobError(resp.data, resp.status)
    }
    throw new Error(`下载脱敏产物失败 (${resp.status})`)
  }

  const ext = outputFormat.toLowerCase()
  const filename = `${jobNo}_masked.${ext}`
  const blobUrl = URL.createObjectURL(resp.data)
  try {
    const link = document.createElement('a')
    link.href = blobUrl
    link.download = filename
    document.body.appendChild(link)
    link.click()
    link.remove()
  } finally {
    URL.revokeObjectURL(blobUrl)
  }
}
