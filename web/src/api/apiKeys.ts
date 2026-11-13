import { http, unwrapEnvelope } from '@/api/client'
import type {
  ApiEnvelope,
  ApiKeyItem,
  CreateApiKeyPayload,
  CreateApiKeyResponseData,
} from '@/types/api'

export async function listApiKeys(): Promise<{ items: ApiKeyItem[]; total: number }> {
  const resp = await http.get<ApiEnvelope<{ items: ApiKeyItem[]; total: number }>>(
    '/api/admin/api-keys',
  )
  return unwrapEnvelope(resp)
}

export async function createApiKey(
  payload: CreateApiKeyPayload,
): Promise<CreateApiKeyResponseData> {
  const resp = await http.post<ApiEnvelope<CreateApiKeyResponseData>>(
    '/api/admin/api-keys',
    payload,
  )
  return unwrapEnvelope(resp)
}

export async function revokeApiKey(uuidOrId: string | number): Promise<{ revoked: boolean }> {
  const resp = await http.delete<ApiEnvelope<{ revoked: boolean }>>(
    `/api/admin/api-keys/${encodeURIComponent(String(uuidOrId))}`,
  )
  return unwrapEnvelope(resp)
}
