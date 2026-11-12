-- ============================================================================
-- 数据脱敏中心 (Data Desensitization Center) MySQL 8.0 Schema
-- 数据库名: kd_desensitize
-- 安全红线: 全库严禁存储原始未脱敏明文或明文到占位符的可逆映射表
-- ============================================================================

CREATE DATABASE IF NOT EXISTS `kd_desensitize`
  DEFAULT CHARACTER SET utf8mb4
  DEFAULT COLLATE utf8mb4_0900_ai_ci;

USE `kd_desensitize`;

-- ----------------------------------------------------------------------------
-- 1. 控制台管理员本地账号表
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `ds_admin_user` (
  `id` bigint UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '主键ID',
  `uuid` char(32) NOT NULL COMMENT '业务UUID(无连字符)',
  `username` varchar(64) NOT NULL COMMENT '登录用户名',
  `display_name` varchar(64) NOT NULL COMMENT '显示名称',
  `password_hash` varchar(255) NOT NULL COMMENT '密码Bcrypt哈希',
  `role` varchar(32) NOT NULL DEFAULT 'ADMIN' COMMENT '角色: ADMIN / OPERATOR / AUDITOR',
  `is_enabled` tinyint(1) NOT NULL DEFAULT 1 COMMENT '启用状态(1启用 0禁用)',
  `last_login_at` datetime(3) DEFAULT NULL COMMENT '最后登录时间',
  `is_deleted` tinyint(1) NOT NULL DEFAULT 0 COMMENT '逻辑删除标志',
  `create_time` datetime(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) COMMENT '创建时间',
  `update_time` datetime(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) COMMENT '更新时间',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_ds_user_uuid` (`uuid`),
  UNIQUE KEY `uk_ds_username` (`username`)
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci ROW_FORMAT = Dynamic COMMENT = '脱敏中心-控制台用户表';

-- ----------------------------------------------------------------------------
-- 2. 服务间调用 API Key 令牌表（仅存前缀与 SHA-256 哈希）
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `ds_api_key` (
  `id` bigint UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '主键ID',
  `uuid` char(32) NOT NULL COMMENT '业务UUID',
  `key_name` varchar(128) NOT NULL COMMENT '令牌名称(如 ai-eval-center-prod)',
  `key_prefix` varchar(20) NOT NULL COMMENT '令牌可读前缀(如 dsk_live_8f3a)',
  `key_sha256` char(64) NOT NULL COMMENT '完整API Key的SHA-256十六进制摘要',
  `default_policy_code` varchar(64) NOT NULL DEFAULT 'strict_general' COMMENT '未传策略时默认使用的策略编码',
  `rate_limit_rpm` int NOT NULL DEFAULT 600 COMMENT '每分钟最大请求数限制',
  `allowed_ips_json` json DEFAULT NULL COMMENT '允许来源IP/CIDR列表，null表示不限',
  `status` varchar(16) NOT NULL DEFAULT 'ACTIVE' COMMENT '状态: ACTIVE / REVOKED',
  `expires_at` datetime(3) DEFAULT NULL COMMENT '过期时间，null表示永不过期',
  `last_used_at` datetime(3) DEFAULT NULL COMMENT '最近一次调用时间',
  `created_by` varchar(64) DEFAULT NULL COMMENT '创建人',
  `is_deleted` tinyint(1) NOT NULL DEFAULT 0 COMMENT '逻辑删除标志',
  `create_time` datetime(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) COMMENT '创建时间',
  `update_time` datetime(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) COMMENT '更新时间',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_ds_apikey_uuid` (`uuid`),
  UNIQUE KEY `uk_ds_apikey_sha256` (`key_sha256`),
  KEY `idx_ds_apikey_status` (`status`, `is_deleted`)
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci ROW_FORMAT = Dynamic COMMENT = '脱敏中心-外部服务API密钥表';

-- ----------------------------------------------------------------------------
-- 3. 公共信息豁免白名单字典表
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `ds_allowlist_dict` (
  `id` bigint UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '主键ID',
  `uuid` char(32) NOT NULL COMMENT '业务UUID',
  `group_code` varchar(64) NOT NULL COMMENT '白名单分组编码(如 gov_public_hotline / gov_domain / gov_hall_addr)',
  `item_name` varchar(128) NOT NULL COMMENT '规则说明名称',
  `match_mode` varchar(16) NOT NULL DEFAULT 'EXACT' COMMENT '匹配方式: EXACT(精确匹配) / SUFFIX(后缀/域名) / PREFIX(前缀) / REGEX(正则)',
  `pattern_text` varchar(500) NOT NULL COMMENT '豁免匹配表达式或字面值',
  `apply_labels_json` json NOT NULL COMMENT '生效豁免的实体标签数组，如 ["phone","url","private_address"]',
  `is_enabled` tinyint(1) NOT NULL DEFAULT 1 COMMENT '是否启用(1启用 0禁用)',
  `remark` varchar(255) DEFAULT NULL COMMENT '备注说明',
  `created_by` varchar(64) DEFAULT NULL COMMENT '创建人',
  `is_deleted` tinyint(1) NOT NULL DEFAULT 0 COMMENT '逻辑删除标志',
  `create_time` datetime(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) COMMENT '创建时间',
  `update_time` datetime(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) COMMENT '更新时间',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_ds_allowlist_uuid` (`uuid`),
  KEY `idx_ds_allowlist_group` (`group_code`, `is_enabled`, `is_deleted`)
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci ROW_FORMAT = Dynamic COMMENT = '脱敏中心-公共信息豁免白名单表';

-- ----------------------------------------------------------------------------
-- 4. 脱敏策略模板表（按 policy_code + version 不可变版本化）
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `ds_policy_profile` (
  `id` bigint UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '主键ID',
  `uuid` char(32) NOT NULL COMMENT '业务UUID',
  `policy_code` varchar(64) NOT NULL COMMENT '策略编码(如 strict_general / gov_eval_corpus)',
  `version` int NOT NULL DEFAULT 1 COMMENT '不可变版本号(修改检测/掩码语义须升版)',
  `policy_name` varchar(128) NOT NULL COMMENT '策略中文名称',
  `scope_mode` varchar(24) NOT NULL DEFAULT 'CONVERSATION' COMMENT '一致性脱敏作用域: CONVERSATION / RECORD / NONE',
  `onnx_variant` varchar(16) NOT NULL DEFAULT 'int8' COMMENT '使用的AstrLink权重规格: int8 / fp32 / fp16',
  `entity_rules_json` json NOT NULL COMMENT '14类实体检测开关、置信度阈值与掩码动作配置JSON',
  `field_role_rules_json` json DEFAULT NULL COMMENT '结构化JSON字段角色映射规则(FULL_MASK_WRITE_SCOPE / REPLAY_SCOPE_AND_HIGH_RISK)',
  `allowlist_groups_json` json DEFAULT NULL COMMENT '绑定的白名单分组编码数组',
  `is_default` tinyint(1) NOT NULL DEFAULT 0 COMMENT '是否为该policy_code的当前默认激活版本',
  `status` varchar(16) NOT NULL DEFAULT 'ACTIVE' COMMENT '状态: DRAFT / ACTIVE / ARCHIVED',
  `description` varchar(500) DEFAULT NULL COMMENT '适用场景说明',
  `created_by` varchar(64) DEFAULT NULL COMMENT '创建人',
  `is_deleted` tinyint(1) NOT NULL DEFAULT 0 COMMENT '逻辑删除标志',
  `create_time` datetime(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) COMMENT '创建时间',
  `update_time` datetime(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) COMMENT '更新时间',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_ds_policy_uuid` (`uuid`),
  UNIQUE KEY `uk_ds_policy_code_ver` (`policy_code`, `version`),
  KEY `idx_ds_policy_active` (`policy_code`, `is_default`, `status`, `is_deleted`)
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci ROW_FORMAT = Dynamic COMMENT = '脱敏中心-脱敏策略模板版本表';

-- ----------------------------------------------------------------------------
-- 5. 外部只读数据源连接表
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `ds_datasource_conn` (
  `id` bigint UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '主键ID',
  `uuid` char(32) NOT NULL COMMENT '业务UUID',
  `conn_code` varchar(64) NOT NULL COMMENT '数据源唯一编码',
  `conn_name` varchar(128) NOT NULL COMMENT '数据源名称',
  `db_type` varchar(16) NOT NULL DEFAULT 'MYSQL' COMMENT '数据库类型: MYSQL',
  `db_host` varchar(128) NOT NULL COMMENT '主机地址',
  `db_port` int NOT NULL DEFAULT 3306 COMMENT '端口',
  `db_name` varchar(64) NOT NULL COMMENT '数据库名',
  `db_user` varchar(64) NOT NULL COMMENT '只读数据库用户名',
  `password_cipher` text NOT NULL COMMENT 'AES-256-GCM加密后的密码密文',
  `allowed_tables_json` json NOT NULL COMMENT '允许抽样读取的表名白名单数组',
  `status` varchar(16) NOT NULL DEFAULT 'ACTIVE' COMMENT '状态: ACTIVE / DISABLED',
  `last_test_ok` tinyint(1) DEFAULT NULL COMMENT '最近连通性及只读权限校验结果',
  `last_tested_at` datetime(3) DEFAULT NULL COMMENT '最近测试时间',
  `created_by` varchar(64) DEFAULT NULL COMMENT '创建人',
  `is_deleted` tinyint(1) NOT NULL DEFAULT 0 COMMENT '逻辑删除标志',
  `create_time` datetime(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) COMMENT '创建时间',
  `update_time` datetime(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) COMMENT '更新时间',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_ds_conn_uuid` (`uuid`),
  UNIQUE KEY `uk_ds_conn_code` (`conn_code`)
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci ROW_FORMAT = Dynamic COMMENT = '脱敏中心-只读外部数据源连接配置表';

-- ----------------------------------------------------------------------------
-- 6. 异步批量脱敏任务与零明文统计审计表
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `ds_batch_job` (
  `id` bigint UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '主键ID',
  `uuid` char(32) NOT NULL COMMENT '业务UUID',
  `job_no` varchar(64) NOT NULL COMMENT '作业单号(如 DSJ_20261112_0001)',
  `job_name` varchar(128) NOT NULL COMMENT '任务名称',
  `source_type` varchar(24) NOT NULL COMMENT '输入源类型: FILE_UPLOAD / MYSQL_READONLY',
  `input_format` varchar(16) NOT NULL COMMENT '输入格式: JSONL / CSV / XLSX / MD / TXT / SQL_CURSOR',
  `source_filename_masked` varchar(255) DEFAULT NULL COMMENT '源文件名标识(源临时文件读完即物理删除)',
  `datasource_id` bigint UNSIGNED DEFAULT NULL COMMENT '关联只读数据源ID(MYSQL_READONLY时必填)',
  `sampling_config_json` json DEFAULT NULL COMMENT '抽样表名、筛选条件与列角色映射配置(不含敏感字面值)',
  `policy_id` bigint UNSIGNED NOT NULL COMMENT '锁定的策略版本ID(关联 ds_policy_profile.id)',
  `policy_code_snapshot` varchar(64) NOT NULL COMMENT '策略编码快照',
  `policy_version_snapshot` int NOT NULL COMMENT '策略版本快照',
  `status` varchar(20) NOT NULL DEFAULT 'PENDING' COMMENT '状态: PENDING / RUNNING / COMPLETED / FAILED / CANCELLED / ARTIFACT_EXPIRED',
  `total_records` bigint NOT NULL DEFAULT 0 COMMENT '总处理记录/行数',
  `processed_records` bigint NOT NULL DEFAULT 0 COMMENT '已完成记录数',
  `failed_records` bigint NOT NULL DEFAULT 0 COMMENT '格式异常跳过记录数',
  `total_chars` bigint NOT NULL DEFAULT 0 COMMENT '累计扫描字符数',
  `entity_hit_stats_json` json DEFAULT NULL COMMENT '各实体标签命中次数汇总JSON(严禁存明文样本)',
  `output_format` varchar(16) NOT NULL DEFAULT 'JSONL' COMMENT '导出产物格式: JSONL / CSV / MD / TXT',
  `output_artifact_relpath` varchar(255) DEFAULT NULL COMMENT '本地受控卷上的脱敏后产物相对路径',
  `output_size_bytes` bigint DEFAULT NULL COMMENT '脱敏产物字节大小',
  `output_sha256` char(64) DEFAULT NULL COMMENT '脱敏产物SHA-256校验和',
  `expires_at` datetime(3) DEFAULT NULL COMMENT '脱敏产物TTL到期自动清理时间',
  `spot_check_status` varchar(24) NOT NULL DEFAULT 'UNCHECKED' COMMENT '人工抽检状态: UNCHECKED / PASSED / FLAGGED_LEAK / FLAGGED_OVERMASK',
  `spot_checked_by` varchar(64) DEFAULT NULL COMMENT '抽检人',
  `spot_checked_at` datetime(3) DEFAULT NULL COMMENT '抽检时间',
  `spot_check_note` varchar(500) DEFAULT NULL COMMENT '抽检备注(严禁录入原始隐私明文)',
  `elapsed_ms` bigint DEFAULT NULL COMMENT '任务总执行耗时(ms)',
  `error_summary` varchar(500) DEFAULT NULL COMMENT '任务异常摘要(不含原始数据内容)',
  `started_at` datetime(3) DEFAULT NULL COMMENT '开始时间',
  `finished_at` datetime(3) DEFAULT NULL COMMENT '结束时间',
  `triggered_by` varchar(64) DEFAULT NULL COMMENT '发起账号或API Key前缀',
  `is_deleted` tinyint(1) NOT NULL DEFAULT 0 COMMENT '逻辑删除标志',
  `create_time` datetime(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) COMMENT '创建时间',
  `update_time` datetime(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) COMMENT '更新时间',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_ds_job_uuid` (`uuid`),
  UNIQUE KEY `uk_ds_job_no` (`job_no`),
  KEY `idx_ds_job_status_time` (`status`, `create_time`),
  KEY `idx_ds_job_expires` (`status`, `expires_at`)
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci ROW_FORMAT = Dynamic COMMENT = '脱敏中心-异步批量脱敏任务与统计审计表';

-- ----------------------------------------------------------------------------
-- 7. 同步脱敏 API 小时级聚合统计表（支撑监控大盘，避免逐请求落库）
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `ds_api_usage_hourly` (
  `id` bigint UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '主键ID',
  `hour_bucket` datetime NOT NULL COMMENT '整点小时时间桶(如 2026-11-12 13:00:00)',
  `api_key_id` bigint UNSIGNED NOT NULL DEFAULT 0 COMMENT '调用API Key ID(0表示控制台沙盒)',
  `policy_id` bigint UNSIGNED NOT NULL COMMENT '使用的策略版本ID',
  `request_count` bigint NOT NULL DEFAULT 0 COMMENT '请求总次数',
  `item_count` bigint NOT NULL DEFAULT 0 COMMENT '脱敏条目/会话总数',
  `total_chars` bigint NOT NULL DEFAULT 0 COMMENT '累计处理字符数',
  `total_elapsed_ms` bigint NOT NULL DEFAULT 0 COMMENT '累计处理耗时(ms)',
  `error_count` bigint NOT NULL DEFAULT 0 COMMENT '异常请求次数',
  `entity_hit_stats_json` json DEFAULT NULL COMMENT '本小时各标签累计命中次数JSON',
  `create_time` datetime(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) COMMENT '创建时间',
  `update_time` datetime(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) COMMENT '更新时间',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_ds_usage_bucket_key_pol` (`hour_bucket`, `api_key_id`, `policy_id`),
  KEY `idx_ds_usage_bucket` (`hour_bucket`)
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci ROW_FORMAT = Dynamic COMMENT = '脱敏中心-同步接口小时级统计遥测表';
