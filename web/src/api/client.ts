import axios, { type AxiosResponse } from 'axios'
import type { ApiEnvelope } from '@/types/api'

let accessTokenGetter: (() => string) | null = null
let unauthorizedHandler: (() => void) | null = null

export function configureHttpAuth(
  getToken: () => string,
  onUnauthorized: () => void,
): void {
  accessTokenGetter = getToken
  unauthorizedHandler = onUnauthorized
}

const API_KEY_PATTERN = /\bdsk_[a-zA-Z0-9_]{6,}\b/g
const LONG_DIGIT_PATTERN = /(?<!\d)\d{11,19}[Xx]?(?!\d)/g

export function sanitizeErrorMessage(raw: unknown): string {
  const base = typeof raw === 'string' && raw.trim() ? raw.trim() : '请求处理失败'
  return base
    .replace(API_KEY_PATTERN, 'dsk_***')
    .replace(LONG_DIGIT_PATTERN, '[已脱敏数字]')
    .slice(0, 260)
}

export function mapErrorCodeToZh(code: number, fallbackMessage: string): string {
  switch (code) {
    case 40001:
      return fallbackMessage || '请求参数或表达式格式不正确，请检查后重试'
    case 40101:
      return '登录状态已失效或凭证无效，请重新登录'
    case 40301:
      return '当前账号角色暂无执行该操作的权限，请联系系统管理员（ADMIN）'
    case 40401:
      return '请求的策略版本、任务或资源不存在'
    case 40901:
      return '该任务产物在人工抽检中被标记为「疑似漏脱敏」，已被禁止下载。请核查绑定策略或调整规则后重新发起脱敏任务。'
    case 41001:
      return '该任务的本地脱敏产物已超过保留期并由系统自动物理清理，当前仅保留零明文统计审计记录。'
    case 42901:
      return '请求频率超过限流阈值，请稍后再试'
    case 50301:
      return '本地 AstrLink Guard ONNX 模型权重未就绪或推理线程池繁忙，请检查服务端 models/astrlink-guard/int8/ 挂载状态后重试。'
    default:
      return fallbackMessage || '服务端返回异常，请稍后重试'
  }
}

export class ApiRequestError extends Error {
  readonly httpStatus: number
  readonly code: number
  readonly requestId: string
  readonly userMessage: string

  constructor(opts: {
    httpStatus: number
    code: number
    message: string
    requestId?: string
    userMessage?: string
  }) {
    const safeMsg = sanitizeErrorMessage(opts.message)
    super(safeMsg)
    this.name = 'ApiRequestError'
    this.httpStatus = opts.httpStatus
    this.code = opts.code
    this.requestId = opts.requestId ?? ''
    this.userMessage = opts.userMessage ?? mapErrorCodeToZh(opts.code, safeMsg)
  }
}

export const http = axios.create({
  baseURL: '',
  timeout: 30000,
})

http.interceptors.request.use((config) => {
  const token = accessTokenGetter?.() ?? ''
  if (token) {
    config.headers = config.headers ?? {}
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

http.interceptors.response.use(
  (response) => {
    const body = response.data as Partial<ApiEnvelope<unknown>> | undefined
    if (
      body &&
      typeof body === 'object' &&
      !(body instanceof Blob) &&
      typeof body.code === 'number' &&
      body.code !== 200
    ) {
      return Promise.reject(
        new ApiRequestError({
          httpStatus: response.status,
          code: body.code,
          message: sanitizeErrorMessage(body.message),
          requestId: typeof body.request_id === 'string' ? body.request_id : '',
        }),
      )
    }
    return response
  },
  (error: unknown) => {
    const errObj = error as {
      response?: { status?: number; data?: unknown }
      message?: string
    }
    const status = errObj?.response?.status ?? 0
    const respData = errObj?.response?.data as
      | { code?: number; message?: string; request_id?: string }
      | undefined

    const code =
      typeof respData?.code === 'number'
        ? respData.code
        : status > 0
          ? status * 100 + 1
          : 50001
    const rawMsg =
      typeof respData?.message === 'string' && respData.message
        ? respData.message
        : errObj?.message ?? '网络连接异常'
    const requestId =
      typeof respData?.request_id === 'string' ? respData.request_id : ''

    if (status === 401 || code === 40101) {
      unauthorizedHandler?.()
    }

    // Zero-Plaintext Rule: never forward error.config / request payload
    return Promise.reject(
      new ApiRequestError({
        httpStatus: status,
        code,
        message: sanitizeErrorMessage(rawMsg),
        requestId,
      }),
    )
  },
)

export function unwrapEnvelope<T>(response: AxiosResponse<ApiEnvelope<T>>): T {
  return response.data.data
}

export async function parseBlobError(blob: Blob, httpStatus: number): Promise<ApiRequestError> {
  try {
    const text = await blob.text()
    const parsed = JSON.parse(text) as {
      code?: number
      message?: string
      request_id?: string
    }
    const code = typeof parsed.code === 'number' ? parsed.code : httpStatus * 100 + 1
    return new ApiRequestError({
      httpStatus,
      code,
      message: sanitizeErrorMessage(parsed.message ?? '下载失败'),
      requestId: typeof parsed.request_id === 'string' ? parsed.request_id : '',
    })
  } catch {
    return new ApiRequestError({
      httpStatus,
      code: httpStatus * 100 + 1,
      message: '产物下载失败',
    })
  }
}
