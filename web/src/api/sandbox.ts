import { http, unwrapEnvelope } from '@/api/client'
import type {
  ApiEnvelope,
  SandboxPreviewRequest,
  SandboxPreviewResponseData,
} from '@/types/api'

export async function previewSandboxMask(
  payload: SandboxPreviewRequest,
): Promise<SandboxPreviewResponseData> {
  const resp = await http.post<ApiEnvelope<SandboxPreviewResponseData>>(
    '/api/admin/sandbox/preview',
    payload,
  )
  return unwrapEnvelope(resp)
}
