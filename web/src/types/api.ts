export interface ApiEnvelope<T> {
  code: number
  message: string
  request_id: string
  data: T
}

export type AdminRole = 'ADMIN' | 'OPERATOR' | 'AUDITOR'

export interface AdminUserProfile {
  uuid: string
  username: string
  display_name: string
  role: AdminRole
}

export interface LoginResponseData {
  access_token: string
  token_type: string
  expires_in: number
  user: AdminUserProfile
  onnx_ready: boolean
}

export interface MeResponseData extends AdminUserProfile {
  onnx_ready: boolean
  onnx_variant: string
}

export type DetectorSource = 'onnx' | 'regex'
export type SpanState = 'onnx' | 'regex' | 'allowlist'

export type ScopeMode = 'CONVERSATION' | 'RECORD' | 'NONE'
export type OnnxVariant = 'int8' | 'fp32' | 'fp16'
export type MaskAction = 'PLACEHOLDER' | 'PARTIAL' | 'FIXED' | 'HASH'
export type FieldRole = 'FULL_MASK_WRITE_SCOPE' | 'REPLAY_SCOPE_AND_HIGH_RISK' | 'PASSTHROUGH'
export type PolicyStatus = 'DRAFT' | 'ACTIVE' | 'ARCHIVED'

export interface EntityRuleConfig {
  enabled: boolean
  min_score: number
  action: MaskAction
  prefix?: string
  keep_head?: number
  keep_tail?: number
  mask_char?: string
  replacement?: string
  hash_len?: number
}

export interface FieldRoleRule {
  jsonpath: string
  role: FieldRole
}

export interface FieldRoleRulesConfig {
  default_role: FieldRole
  high_risk_only_labels: string[]
  rules: FieldRoleRule[]
}

export interface PolicyVersionItem {
  id: number
  uuid: string
  policy_code: string
  version: number
  policy_name: string
  scope_mode: ScopeMode
  onnx_variant: OnnxVariant
  entity_rules: Record<string, EntityRuleConfig>
  field_role_rules: FieldRoleRulesConfig
  allowlist_groups: string[]
  is_default: boolean
  status: PolicyStatus
  description: string | null
  created_by: string | null
  create_time: string | null
  update_time: string | null
}

export interface PolicyGroupItem {
  policy_code: string
  policy_name: string
  default_version: number | null
  latest_version: number
  versions: PolicyVersionItem[]
}

export interface PolicyListResponseData {
  items: PolicyVersionItem[]
  total: number
  policies: PolicyGroupItem[]
}

export interface CreatePolicyVersionPayload {
  policy_code: string
  policy_name: string
  scope_mode: ScopeMode
  onnx_variant: OnnxVariant
  entity_rules: Record<string, EntityRuleConfig>
  field_role_rules: FieldRoleRulesConfig
  allowlist_groups: string[]
  set_as_default?: boolean
  status: PolicyStatus
  description?: string | null
}

export interface SandboxSpan {
  kind: 'masked' | 'exempted'
  state: SpanState
  source: SpanState
  detector: DetectorSource
  label: string
  start: number
  end: number
  orig_start: number
  orig_end: number
  text: string
  replacement: string | null
  score: number
  exempted: boolean
  allowlist_group: string | null
  allowlist_rule: string | null
  field_path?: string
}

export interface SandboxMaskedSpan {
  label: string
  start: number
  end: number
  masked_start: number
  masked_end: number
  placeholder: string
  detector: DetectorSource
  state: DetectorSource
  score: number
}

export interface SandboxPreviewRequest {
  mode: 'TEXT' | 'STRUCTURED'
  text?: string
  payload?: Record<string, unknown>
  policy_code?: string
  policy_version?: number | null
  scope_mode?: ScopeMode
  onnx_variant?: OnnxVariant
  entity_rules?: Record<string, EntityRuleConfig>
  field_role_rules?: FieldRoleRulesConfig
  allowlist_groups?: string[]
}

export interface SandboxPreviewResponseData {
  mode: 'TEXT' | 'STRUCTURED'
  policy_code: string
  policy_version: number
  scope_mode: ScopeMode
  onnx_variant: OnnxVariant
  masked_text: string | null
  masked_payload: Record<string, unknown> | null
  spans: SandboxSpan[]
  masked_spans: SandboxMaskedSpan[]
  exempted_spans: SandboxSpan[]
  exempted_count: number
  field_traces: Record<string, SandboxSpan[]>
  hit_counts: Record<string, number>
  elapsed_ms: number
}

export type AllowlistMatchMode = 'EXACT' | 'SUFFIX' | 'PREFIX' | 'REGEX'

export interface AllowlistItem {
  id: number
  uuid: string
  group_code: string
  item_name: string
  match_mode: AllowlistMatchMode
  pattern_text: string
  apply_labels: string[]
  is_enabled: boolean
  remark: string | null
  created_by: string | null
  create_time: string | null
  update_time: string | null
}

export interface AllowlistGroupSummary {
  group_code: string
  total_count: number
  enabled_count: number
}

export interface AllowlistListResponseData {
  items: AllowlistItem[]
  total: number
  groups: AllowlistGroupSummary[]
}

export interface CreateAllowlistPayload {
  group_code: string
  item_name: string
  match_mode: AllowlistMatchMode
  pattern_text: string
  apply_labels: string[]
  is_enabled: boolean
  remark?: string | null
}

export interface UpdateAllowlistPayload {
  group_code?: string
  item_name?: string
  match_mode?: AllowlistMatchMode
  pattern_text?: string
  apply_labels?: string[]
  is_enabled?: boolean
  remark?: string | null
}

export interface AllowlistTestRequest {
  text: string
  label: string
  group_codes?: string[]
  group_code?: string
  match_mode?: AllowlistMatchMode
  pattern_text?: string
  apply_labels?: string[]
  item_name?: string
  include_saved?: boolean
}

export interface AllowlistMatchedRule {
  id: number | null
  uuid: string | null
  group_code: string
  item_name: string
  match_mode: AllowlistMatchMode
  pattern_text: string
  apply_labels: string[]
}

export interface AllowlistTestResponseData {
  matched: boolean
  matched_count: number
  matched_rules: AllowlistMatchedRule[]
}

export type JobStatus =
  | 'PENDING'
  | 'RUNNING'
  | 'COMPLETED'
  | 'FAILED'
  | 'CANCELLED'
  | 'ARTIFACT_EXPIRED'

export type SpotCheckStatus =
  | 'UNCHECKED'
  | 'PASSED'
  | 'FLAGGED_LEAK'
  | 'FLAGGED_OVERMASK'

export interface BatchJobItem {
  id: number
  uuid: string
  job_no: string
  job_name: string
  source_type: 'FILE_UPLOAD' | 'MYSQL_READONLY'
  input_format: string
  source_filename_masked: string | null
  datasource_id: number | null
  sampling_config: Record<string, unknown> | null
  policy_id: number
  policy_code: string
  policy_version: number
  status: JobStatus
  total_records: number
  processed_records: number
  failed_records: number
  total_chars: number
  progress_pct: number
  entity_hit_stats: Record<string, number>
  output_format: string
  output_size_bytes: number | null
  output_sha256: string | null
  has_artifact: boolean
  expires_at: string | null
  spot_check_status: SpotCheckStatus
  spot_checked_by: string | null
  spot_checked_at: string | null
  spot_check_note: string | null
  elapsed_ms: number | null
  error_summary: string | null
  started_at: string | null
  finished_at: string | null
  triggered_by: string | null
  create_time: string | null
  update_time: string | null
}

export interface BatchJobListResponseData {
  items: BatchJobItem[]
  total: number
  page: number
  page_size: number
}

export interface MysqlSampleJobPayload {
  job_name: string
  datasource_code: string
  table_name: string
  select_columns: string[]
  where_clause?: string
  limit_rows: number
  column_role_mapping: Record<string, FieldRole>
  policy_code: string
  policy_version?: number | null
  output_format: string
  ttl_hours: number
}

export interface JobPreviewMaskedData {
  job_no: string
  policy_code: string
  policy_version: number
  spot_check_status: SpotCheckStatus
  spot_check_note: string | null
  output_sha256: string | null
  expires_at: string | null
  output_format: string
  limit: number
  returned_count: number
  has_more: boolean
  lines: string[]
  records: Record<string, unknown>[]
}

export interface SpotCheckPayload {
  spot_check_status: 'PASSED' | 'FLAGGED_LEAK' | 'FLAGGED_OVERMASK'
  spot_check_note?: string
}

export interface ApiKeyItem {
  id: number
  uuid: string
  key_name: string
  key_prefix: string
  default_policy_code: string
  rate_limit_rpm: number
  allowed_ips: string[] | null
  status: 'ACTIVE' | 'REVOKED' | 'EXPIRED'
  expires_at: string | null
  last_used_at: string | null
  created_by: string | null
  create_time: string | null
  update_time: string | null
}

export interface CreateApiKeyPayload {
  key_name: string
  default_policy_code: string
  rate_limit_rpm: number
  allowed_ips?: string[] | null
  expires_at?: string | null
  env_tag: 'live' | 'test'
}

export interface CreateApiKeyResponseData extends ApiKeyItem {
  plain_key: string
}

export interface DatasourceItem {
  id: number
  uuid: string
  conn_code: string
  conn_name: string
  db_type: string
  db_host: string
  db_port: number
  db_name: string
  db_user: string
  has_password: boolean
  allowed_tables: string[]
  status: 'ACTIVE' | 'DISABLED'
  last_test_ok: boolean | null
  last_tested_at: string | null
  created_by: string | null
  create_time: string | null
  update_time: string | null
}

export interface CreateDatasourcePayload {
  conn_code: string
  conn_name: string
  db_type: 'MYSQL'
  db_host: string
  db_port: number
  db_name: string
  db_user: string
  password: string
  allowed_tables: string[]
  status: 'ACTIVE' | 'DISABLED'
}

export interface UpdateDatasourcePayload {
  conn_name?: string
  db_host?: string
  db_port?: number
  db_name?: string
  db_user?: string
  password?: string
  allowed_tables?: string[]
  status?: 'ACTIVE' | 'DISABLED'
}

export interface DatasourceTestResult {
  conn_code: string
  ok: boolean
  read_only_verified: boolean
  last_test_ok: boolean
  last_tested_at: string | null
  latency_ms: number
  message: string
}

export interface MetricsHourlyBucket {
  hour_bucket: string
  request_count: number
  item_count: number
  total_chars: number
  total_elapsed_ms: number
  avg_elapsed_ms: number
  error_count: number
}

export interface EntityDistributionItem {
  label: string
  label_zh: string
  display_name: string
  detector: DetectorSource
  count: number
  ratio: number
  percentage: number
}

export interface MetricsHourlyResponseData {
  hours: number
  include_sandbox: boolean
  window_start: string
  updated_at: string
  total_requests: number
  total_items: number
  total_chars: number
  total_elapsed_ms: number
  avg_elapsed_ms: number
  error_count: number
  total_entity_hits: number
  summary: {
    total_requests: number
    total_items: number
    total_chars: number
    total_elapsed_ms: number
    avg_elapsed_ms: number
    error_count: number
  }
  buckets: MetricsHourlyBucket[]
  entity_distribution: EntityDistributionItem[]
  batch_jobs_summary: {
    total_jobs: number
    completed_jobs: number
    processed_records: number
    total_chars: number
  }
}
