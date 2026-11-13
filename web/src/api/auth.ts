import { http, unwrapEnvelope } from '@/api/client'
import type { ApiEnvelope, LoginResponseData, MeResponseData } from '@/types/api'

export async function loginAdmin(
  username: string,
  password: string,
): Promise<LoginResponseData> {
  const resp = await http.post<ApiEnvelope<LoginResponseData>>('/api/admin/auth/login', {
    username,
    password,
  })
  return unwrapEnvelope(resp)
}

export async function fetchCurrentAdmin(): Promise<MeResponseData> {
  const resp = await http.get<ApiEnvelope<MeResponseData>>('/api/admin/auth/me')
  return unwrapEnvelope(resp)
}
