-- ============================================================================
-- 数据脱敏中心 默认白名单豁免规则与预置策略模板初始化脚本
-- ============================================================================

USE `kd_desensitize`;

-- 1. 预置公共服务信息豁免白名单
INSERT INTO `ds_allowlist_dict` (`uuid`, `group_code`, `item_name`, `match_mode`, `pattern_text`, `apply_labels_json`, `remark`, `created_by`)
VALUES
  (REPLACE(UUID(), '-', ''), 'gov_public_hotline', '全国政务与公共服务5位短号', 'REGEX', '^(12345|12333|12329|12366|12315|12348|12123|110|119|120|122)$', JSON_ARRAY('phone'), '保留政务服务便民热线及应急短号', 'system'),
  (REPLACE(UUID(), '-', ''), 'gov_public_hotline', '400/800公共服务热线与带区号政务固话', 'REGEX', '^(0\\d{2,3}-?\\d{7,8}|[48]00-?\\d{3}-?\\d{4})$', JSON_ARRAY('phone'), '保留带区号公开办公固话，11位个人手机仍由cn_mobile严格拦截', 'system'),
  (REPLACE(UUID(), '-', ''), 'gov_public_domain', '中国政府网及各级政务域名', 'REGEX', '^https?://([a-zA-Z0-9-]+\\.)*gov\\.cn(/.*)?$', JSON_ARRAY('url'), '保留各级政府门户与在线办事大厅链接', 'system'),
  (REPLACE(UUID(), '-', ''), 'gov_public_hall', '政务服务中心与便民中心通用办公地址特征', 'REGEX', '(政务服务中心|行政审批局|市民中心|便民服务中心|公积金管理中心|社保中心|车管所|不动产登记交易中心)', JSON_ARRAY('private_address'), '保留公开办事窗口与大厅地址不被误标为私人住址', 'system');

-- 2. 预置策略模板 1：strict_general (v1) —— 通用全字段严格脱敏
INSERT INTO `ds_policy_profile` (
  `uuid`, `policy_code`, `version`, `policy_name`, `scope_mode`, `onnx_variant`,
  `entity_rules_json`, `field_role_rules_json`, `allowlist_groups_json`,
  `is_default`, `status`, `description`, `created_by`
) VALUES (
  REPLACE(UUID(), '-', ''),
  'strict_general',
  1,
  '通用全量严格脱敏策略 v1',
  'RECORD',
  'int8',
  JSON_OBJECT(
    'private_person', JSON_OBJECT('enabled', true, 'min_score', 0.80, 'action', 'PLACEHOLDER', 'prefix', 'PERSON'),
    'phone',          JSON_OBJECT('enabled', true, 'min_score', 0.80, 'action', 'PLACEHOLDER', 'prefix', 'PHONE'),
    'email',          JSON_OBJECT('enabled', true, 'min_score', 0.80, 'action', 'PLACEHOLDER', 'prefix', 'EMAIL'),
    'private_address',JSON_OBJECT('enabled', true, 'min_score', 0.80, 'action', 'PLACEHOLDER', 'prefix', 'ADDR'),
    'private_date',   JSON_OBJECT('enabled', true, 'min_score', 0.80, 'action', 'PLACEHOLDER', 'prefix', 'DATE'),
    'account',        JSON_OBJECT('enabled', true, 'min_score', 0.80, 'action', 'PLACEHOLDER', 'prefix', 'ACCOUNT'),
    'payment_card',   JSON_OBJECT('enabled', true, 'min_score', 0.80, 'action', 'PARTIAL', 'keep_head', 4, 'keep_tail', 4),
    'ip_address',     JSON_OBJECT('enabled', true, 'min_score', 0.80, 'action', 'PLACEHOLDER', 'prefix', 'IP'),
    'url',            JSON_OBJECT('enabled', true, 'min_score', 0.82, 'action', 'PLACEHOLDER', 'prefix', 'URL'),
    'common_secret',  JSON_OBJECT('enabled', true, 'min_score', 0.80, 'action', 'FIXED', 'replacement', '[REDACTED_SECRET]'),
    'cn_id_card',     JSON_OBJECT('enabled', true, 'min_score', 1.00, 'action', 'PLACEHOLDER', 'prefix', 'IDCARD'),
    'cn_uscc',        JSON_OBJECT('enabled', true, 'min_score', 1.00, 'action', 'PLACEHOLDER', 'prefix', 'USCC'),
    'cn_mobile',      JSON_OBJECT('enabled', true, 'min_score', 1.00, 'action', 'PLACEHOLDER', 'prefix', 'PHONE'),
    'bank_card_luhn', JSON_OBJECT('enabled', true, 'min_score', 1.00, 'action', 'PARTIAL', 'keep_head', 4, 'keep_tail', 4)
  ),
  JSON_OBJECT('default_role', 'FULL_MASK_WRITE_SCOPE', 'rules', JSON_ARRAY()),
  JSON_ARRAY(),
  1,
  'ACTIVE',
  '适用于普通日志导出、外部文本清洗与微调语料预处理，全标签严格遮蔽',
  'system'
);

-- 3. 预置策略模板 2：gov_eval_corpus (v1) —— 政务问答评测语料差异化防误伤策略
INSERT INTO `ds_policy_profile` (
  `uuid`, `policy_code`, `version`, `policy_name`, `scope_mode`, `onnx_variant`,
  `entity_rules_json`, `field_role_rules_json`, `allowlist_groups_json`,
  `is_default`, `status`, `description`, `created_by`
) VALUES (
  REPLACE(UUID(), '-', ''),
  'gov_eval_corpus',
  1,
  '政务问答与评测语料差异化脱敏策略 v1',
  'CONVERSATION',
  'int8',
  JSON_OBJECT(
    'private_person', JSON_OBJECT('enabled', true, 'min_score', 0.80, 'action', 'PLACEHOLDER', 'prefix', 'PERSON'),
    'phone',          JSON_OBJECT('enabled', true, 'min_score', 0.82, 'action', 'PLACEHOLDER', 'prefix', 'PHONE'),
    'email',          JSON_OBJECT('enabled', true, 'min_score', 0.80, 'action', 'PLACEHOLDER', 'prefix', 'EMAIL'),
    'private_address',JSON_OBJECT('enabled', true, 'min_score', 0.82, 'action', 'PLACEHOLDER', 'prefix', 'ADDR'),
    'private_date',   JSON_OBJECT('enabled', true, 'min_score', 0.82, 'action', 'PLACEHOLDER', 'prefix', 'DATE'),
    'account',        JSON_OBJECT('enabled', true, 'min_score', 0.82, 'action', 'PLACEHOLDER', 'prefix', 'ACCOUNT'),
    'payment_card',   JSON_OBJECT('enabled', true, 'min_score', 0.80, 'action', 'PARTIAL', 'keep_head', 4, 'keep_tail', 4),
    'ip_address',     JSON_OBJECT('enabled', false, 'min_score', 0.85, 'action', 'PLACEHOLDER', 'prefix', 'IP'),
    'url',            JSON_OBJECT('enabled', false, 'min_score', 0.85, 'action', 'PLACEHOLDER', 'prefix', 'URL'),
    'common_secret',  JSON_OBJECT('enabled', true, 'min_score', 0.80, 'action', 'FIXED', 'replacement', '[REDACTED_SECRET]'),
    'cn_id_card',     JSON_OBJECT('enabled', true, 'min_score', 1.00, 'action', 'PLACEHOLDER', 'prefix', 'IDCARD'),
    'cn_uscc',        JSON_OBJECT('enabled', true, 'min_score', 1.00, 'action', 'PLACEHOLDER', 'prefix', 'USCC'),
    'cn_mobile',      JSON_OBJECT('enabled', true, 'min_score', 1.00, 'action', 'PLACEHOLDER', 'prefix', 'PHONE'),
    'bank_card_luhn', JSON_OBJECT('enabled', true, 'min_score', 1.00, 'action', 'PARTIAL', 'keep_head', 4, 'keep_tail', 4)
  ),
  JSON_OBJECT(
    'default_role', 'FULL_MASK_WRITE_SCOPE',
    'high_risk_only_labels', JSON_ARRAY('cn_id_card', 'cn_mobile', 'bank_card_luhn', 'payment_card', 'common_secret'),
    'rules', JSON_ARRAY(
      JSON_OBJECT('jsonpath', '$.input_text', 'role', 'FULL_MASK_WRITE_SCOPE'),
      JSON_OBJECT('jsonpath', '$.turns[?(@.role==''user'')].content', 'role', 'FULL_MASK_WRITE_SCOPE'),
      JSON_OBJECT('jsonpath', '$.expected_output', 'role', 'REPLAY_SCOPE_AND_HIGH_RISK'),
      JSON_OBJECT('jsonpath', '$.actual_output', 'role', 'REPLAY_SCOPE_AND_HIGH_RISK'),
      JSON_OBJECT('jsonpath', '$.turns[?(@.role==''assistant'')].content', 'role', 'REPLAY_SCOPE_AND_HIGH_RISK'),
      JSON_OBJECT('jsonpath', '$.references[*].content', 'role', 'REPLAY_SCOPE_AND_HIGH_RISK'),
      JSON_OBJECT('jsonpath', '$.case_code', 'role', 'PASSTHROUGH'),
      JSON_OBJECT('jsonpath', '$.turn_mode', 'role', 'PASSTHROUGH')
    )
  ),
  JSON_ARRAY('gov_public_hotline', 'gov_public_domain', 'gov_public_hall'),
  1,
  'ACTIVE',
  '专为政务客服会话与知识库评测入库设计：用户侧全脱敏并建立临时指代映射，回答与引用侧重放映射并保留政务热线、公开大厅地址及.gov.cn链接',
  'system'
);
