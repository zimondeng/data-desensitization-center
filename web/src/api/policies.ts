import { http, unwrapEnvelope } from '@/api/client'
import type {
  ApiEnvelope,
  CreatePolicyVersionPayload,
  PolicyListResponseData,
  PolicyVersionItem,
} from '@/types/api'

export async function listPolicies(params?: {
  policy_code?: string
  status?: string
}): Promise<PolicyListResponseData> {
  const resp = await http.get<ApiEnvelope<PolicyListResponseData>>('/api/admin/policies', {
    params,
  })
  return unwrapEnvelope(resp)
}

export async function getPolicyVersion(
  policyCode: string,
  version: number,
): Promise<PolicyVersionItem> {
  const resp = await http.get<ApiEnvelope<PolicyVersionItem>>(
    `/api/admin/policies/${encodeURIComponent(policyCode)}/versions/${version}`,
  )
  return unwrapEnvelope(resp)
}

export async function createOrBumpPolicyVersion(
  payload: CreatePolicyVersionPayload,
): Promise<PolicyVersionItem> {
  const resp = await http.post<ApiEnvelope<PolicyVersionItem>>('/api/admin/policies', payload)
  return unwrapEnvelope(resp)
}

export async function setDefaultPolicyVersion(
  policyCode: string,
  version: number,
): Promise<PolicyVersionItem> {
  const resp = await http.post<ApiEnvelope<PolicyVersionItem>>(
    `/api/admin/policies/${encodeURIComponent(policyCode)}/versions/${version}/set-default`,
  )
  return unwrapEnvelope(resp)
}
