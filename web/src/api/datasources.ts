import { http, unwrapEnvelope } from '@/api/client'
import type {
  ApiEnvelope,
  CreateDatasourcePayload,
  DatasourceItem,
  DatasourceTestResult,
  UpdateDatasourcePayload,
} from '@/types/api'

export async function listDatasources(params?: {
  status?: string
  keyword?: string
}): Promise<{ items: DatasourceItem[]; total: number }> {
  const resp = await http.get<ApiEnvelope<{ items: DatasourceItem[]; total: number }>>(
    '/api/admin/datasources',
    params ? { params } : undefined,
  )
  return unwrapEnvelope(resp)
}

export async function createDatasource(
  payload: CreateDatasourcePayload,
): Promise<DatasourceItem> {
  const resp = await http.post<ApiEnvelope<DatasourceItem>>('/api/admin/datasources', payload)
  return unwrapEnvelope(resp)
}

export async function updateDatasource(
  codeOrId: string | number,
  payload: UpdateDatasourcePayload,
): Promise<DatasourceItem> {
  const resp = await http.put<ApiEnvelope<DatasourceItem>>(
    `/api/admin/datasources/${encodeURIComponent(String(codeOrId))}`,
    payload,
  )
  return unwrapEnvelope(resp)
}

export async function deleteDatasource(codeOrId: string | number): Promise<{ deleted_id: number }> {
  const resp = await http.delete<ApiEnvelope<{ deleted_id: number }>>(
    `/api/admin/datasources/${encodeURIComponent(String(codeOrId))}`,
  )
  return unwrapEnvelope(resp)
}

export async function testDatasourceConnection(
  connCode: string,
): Promise<DatasourceTestResult> {
  const resp = await http.post<ApiEnvelope<DatasourceTestResult>>(
    `/api/admin/datasources/${encodeURIComponent(connCode)}/test`,
  )
  return unwrapEnvelope(resp)
}
