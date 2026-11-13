import type {
  AdminRole,
  AllowlistMatchMode,
  DetectorSource,
  EntityRuleConfig,
  FieldRole,
  JobStatus,
  MaskAction,
  OnnxVariant,
  PolicyStatus,
  ScopeMode,
  SpotCheckStatus,
} from '@/types/api'

export interface EntityLabelMeta {
  label: string
  labelZh: string
  detector: DetectorSource
  defaultPrefix: string
  description: string
}

export const ENTITY_LABEL_META: readonly EntityLabelMeta[] = [
  {
    label: 'private_person',
    labelZh: '个人姓名',
    detector: 'onnx',
    defaultPrefix: 'PERSON',
    description: '自然人中文或英文姓名',
  },
  {
    label: 'cn_id_card',
    labelZh: '二代居民身份证号',
    detector: 'regex',
    defaultPrefix: 'IDCARD',
    description: '18 位大陆身份证（含出生日期与 Mod-11 校验位）',
  },
  {
    label: 'cn_mobile',
    labelZh: '中国大陆手机号',
    detector: 'regex',
    defaultPrefix: 'PHONE',
    description: '11 位中国大陆移动电话号码（与 phone 共享 PHONE 序号）',
  },
  {
    label: 'phone',
    labelZh: '电话/固话号码',
    detector: 'onnx',
    defaultPrefix: 'PHONE',
    description: '语义识别的联系电话与固话（受公共热线白名单豁免约束）',
  },
  {
    label: 'bank_card_luhn',
    labelZh: '银行卡号 (Luhn)',
    detector: 'regex',
    defaultPrefix: 'BANKCARD',
    description: '16–19 位银行卡号（通过 Luhn Mod-10 校验）',
  },
  {
    label: 'payment_card',
    labelZh: '支付卡号',
    detector: 'onnx',
    defaultPrefix: 'CARD',
    description: '语义识别的支付账号或银行卡片段',
  },
  {
    label: 'private_address',
    labelZh: '个人详细地址',
    detector: 'onnx',
    defaultPrefix: 'ADDR',
    description: '自然人住址或私人地址（受政务大厅白名单豁免约束）',
  },
  {
    label: 'email',
    labelZh: '电子邮箱',
    detector: 'onnx',
    defaultPrefix: 'EMAIL',
    description: '个人或内部电子邮箱地址',
  },
  {
    label: 'account',
    labelZh: '账号标识',
    detector: 'onnx',
    defaultPrefix: 'ACCOUNT',
    description: '业务登录账号、用户编号或社保账号',
  },
  {
    label: 'common_secret',
    labelZh: '敏感密钥与口令',
    detector: 'onnx',
    defaultPrefix: 'SECRET',
    description: 'API Token、密钥串或口令凭据',
  },
  {
    label: 'cn_uscc',
    labelZh: '统一社会信用代码',
    detector: 'regex',
    defaultPrefix: 'USCC',
    description: '18 位企业/机构统一社会信用代码（GB 32100 Mod-31）',
  },
  {
    label: 'private_date',
    labelZh: '个人关联日期',
    detector: 'onnx',
    defaultPrefix: 'DATE',
    description: '出生日期等个人关联时间节点',
  },
  {
    label: 'ip_address',
    labelZh: 'IP 地址',
    detector: 'onnx',
    defaultPrefix: 'IP',
    description: 'IPv4 / IPv6 网络地址',
  },
  {
    label: 'url',
    labelZh: '网址链接 (URL)',
    detector: 'onnx',
    defaultPrefix: 'URL',
    description: 'HTTP/HTTPS 链接（受 *.gov.cn 政务域名白名单豁免约束）',
  },
] as const

export const ENTITY_LABEL_ZH_MAP: Record<string, string> = Object.fromEntries(
  ENTITY_LABEL_META.map((item) => [item.label, item.labelZh]),
)

export function createDefaultEntityRules(): Record<string, EntityRuleConfig> {
  const rules: Record<string, EntityRuleConfig> = {}
  for (const meta of ENTITY_LABEL_META) {
    if (meta.label === 'payment_card' || meta.label === 'bank_card_luhn') {
      rules[meta.label] = {
        enabled: true,
        min_score: meta.detector === 'regex' ? 1.0 : 0.8,
        action: 'PARTIAL',
        keep_head: 4,
        keep_tail: 4,
      }
    } else if (meta.label === 'common_secret') {
      rules[meta.label] = {
        enabled: true,
        min_score: 0.8,
        action: 'FIXED',
        replacement: '[REDACTED_SECRET]',
      }
    } else {
      rules[meta.label] = {
        enabled: meta.label !== 'ip_address' && meta.label !== 'url',
        min_score: meta.detector === 'regex' ? 1.0 : 0.8,
        action: 'PLACEHOLDER',
        prefix: meta.defaultPrefix,
      }
    }
  }
  return rules
}

export const ROLE_META: Record<AdminRole, { label: string; tagType: 'primary' | 'success' | 'warning' }> = {
  ADMIN: { label: '系统管理员 (ADMIN)', tagType: 'primary' },
  OPERATOR: { label: '脱敏操作员 (OPERATOR)', tagType: 'success' },
  AUDITOR: { label: '合规审核员 (AUDITOR)', tagType: 'warning' },
}

export const SCOPE_MODE_OPTIONS: { value: ScopeMode; label: string; desc: string }[] = [
  { value: 'CONVERSATION', label: 'CONVERSATION · 会话级一致', desc: '单条请求或单轮多轮对话内保持指代一致，结束即焚' },
  { value: 'RECORD', label: 'RECORD · 记录级一致', desc: '每条记录独立维护占位符序号，跨记录重置为 1' },
  { value: 'NONE', label: 'NONE · 无作用域重放', desc: '不做同义指代重放，每次命中独立生成掩码' },
]

export const ONNX_VARIANT_OPTIONS: { value: OnnxVariant; label: string }[] = [
  { value: 'int8', label: 'int8（默认量化模型）' },
  { value: 'fp32', label: 'fp32（全精度模型）' },
  { value: 'fp16', label: 'fp16（静态 512 半精度）' },
]

export const MASK_ACTION_OPTIONS: { value: MaskAction; label: string }[] = [
  { value: 'PLACEHOLDER', label: 'PLACEHOLDER · 语义占位符' },
  { value: 'PARTIAL', label: 'PARTIAL · 保留首尾掩码' },
  { value: 'FIXED', label: 'FIXED · 固定字符串替换' },
  { value: 'HASH', label: 'HASH · 单向加盐摘要' },
]

export const FIELD_ROLE_META: Record<
  FieldRole,
  { label: string; tagType: 'primary' | 'warning' | 'info'; desc: string }
> = {
  FULL_MASK_WRITE_SCOPE: {
    label: '全量提取并写入作用域',
    tagType: 'primary',
    desc: '全量执行 ONNX+正则检测并登记到一致性脱敏作用域',
  },
  REPLAY_SCOPE_AND_HIGH_RISK: {
    label: '重放作用域+高危补扫',
    tagType: 'warning',
    desc: '重放用户侧已识别实体占位符，并对高危个人凭证补扫，保留政务热线/地址',
  },
  PASSTHROUGH: {
    label: '原样透传不脱敏',
    tagType: 'info',
    desc: '标识字段或结构字段原样保留',
  },
}

export const POLICY_STATUS_META: Record<
  PolicyStatus,
  { label: string; tagType: 'success' | 'warning' | 'info' }
> = {
  ACTIVE: { label: '已激活 ACTIVE', tagType: 'success' },
  DRAFT: { label: '草稿 DRAFT', tagType: 'warning' },
  ARCHIVED: { label: '已归档 ARCHIVED', tagType: 'info' },
}

export const MATCH_MODE_OPTIONS: { value: AllowlistMatchMode; label: string; tagType: 'primary' | 'success' | 'warning' | 'info' }[] = [
  { value: 'REGEX', label: 'REGEX 正则', tagType: 'warning' },
  { value: 'EXACT', label: 'EXACT 精确', tagType: 'primary' },
  { value: 'PREFIX', label: 'PREFIX 前缀', tagType: 'success' },
  { value: 'SUFFIX', label: 'SUFFIX 后缀', tagType: 'info' },
]

export const JOB_STATUS_META: Record<
  JobStatus,
  { label: string; tagType: 'info' | 'warning' | 'success' | 'danger' }
> = {
  PENDING: { label: '排队中 PENDING', tagType: 'info' },
  RUNNING: { label: '处理中 RUNNING', tagType: 'warning' },
  COMPLETED: { label: '已完成 COMPLETED', tagType: 'success' },
  FAILED: { label: '失败 FAILED', tagType: 'danger' },
  CANCELLED: { label: '已取消 CANCELLED', tagType: 'info' },
  ARTIFACT_EXPIRED: { label: '产物已过期 EXPIRED', tagType: 'info' },
}

export const SPOT_CHECK_STATUS_META: Record<
  SpotCheckStatus,
  { label: string; tagType: 'info' | 'success' | 'danger' | 'warning' }
> = {
  UNCHECKED: { label: '待抽检 UNCHECKED', tagType: 'info' },
  PASSED: { label: '抽检通过 PASSED', tagType: 'success' },
  FLAGGED_LEAK: { label: '疑似漏脱敏（已阻断下载）', tagType: 'danger' },
  FLAGGED_OVERMASK: { label: '疑似误伤公共信息', tagType: 'warning' },
}

export const HIGH_RISK_DEFAULT_LABELS: readonly string[] = [
  'cn_id_card',
  'cn_mobile',
  'bank_card_luhn',
  'payment_card',
  'common_secret',
]

// Valid Mod-11 Chinese Resident ID used across Golden Government QA sample data
export const GOLDEN_GOV_QA_TEXT =
  '我是张三，身份证 32040219900307118X，手机 13812345678。请问可否拨打 12345 或 0519-85681234，前往常州市政务服务中心（锦绣路2号）或登录 https://www.changzhou.gov.cn 办理？'

export const GOLDEN_GOV_QA_STRUCTURED = {
  case_code: 'CASE_GOV_001',
  turn_mode: 'MULTI_TURN',
  input_text: '我是张三，身份证 32040219900307118X，手机 13812345678，想查医保办理窗口。',
  turns: [
    {
      role: 'user',
      content: '你好，我是张三，身份证 32040219900307118X，手机 13812345678',
    },
    {
      role: 'assistant',
      content:
        '张三您好，可拨打 12345 或 0519-85681234，前往常州市政务服务中心（锦绣路2号）或登录 https://www.changzhou.gov.cn 办理。',
    },
  ],
  references: [
    {
      doc_name: '政务服务大厅办事指引.md',
      content: '常州市政务服务中心（锦绣路2号）服务热线 0519-85681234，官方门户 https://www.changzhou.gov.cn。',
    },
  ],
}
