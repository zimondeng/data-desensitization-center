import { http, unwrapEnvelope } from '@/api/client'
import type {
  AllowlistItem,
  AllowlistListResponseData,
  AllowlistTestRequest,
  AllowlistTestResponseData,
  ApiEnvelope,
  CreateAllowlistPayload,
  UpdateAllowlistPayload,
} from '@/types/api'

export async function listAllowlists(params?: {
  group_code?: string
  is_enabled?: boolean
  keyword?: string
}): Promise<AllowlistListResponseData> {
  const resp = await http.get<ApiEnvelope<AllowlistListResponseData>>(
    '/api/admin/allowlists',
    params ? { params } : undefined,
  )
  return unwrapEnvelope(resp)
}

export async function createAllowlistItem(payload: CreateAllowlistPayload): Promise<AllowlistItem> {
  const resp = await http.post<ApiEnvelope<AllowlistItem>>('/api/admin/allowlists', payload)
  return unwrapEnvelope(resp)
}

export async function updateAllowlistItem(
  itemId: number,
  payload: UpdateAllowlistPayload,
): Promise<AllowlistItem> {
  const resp = await http.put<ApiEnvelope<AllowlistItem>>(
    `/api/admin/allowlists/${itemId}`,
    payload,
  )
  return unwrapEnvelope(resp)
}

export async function deleteAllowlistItem(itemId: number): Promise<{ deleted_id: number }> {
  const resp = await http.delete<ApiEnvelope<{ deleted_id: number }>>(
    `/api/admin/allowlists/${itemId}`,
  )
  return unwrapEnvelope(resp)
}

export async function testAllowlistMatch(
  payload: AllowlistTestRequest,
): Promise<AllowlistTestResponseData> {
  const resp = await http.post<ApiEnvelope<AllowlistTestResponseData>>(
    '/api/admin/allowlists/test',
    payload,
  )
  return unwrapEnvelope(resp)
}
