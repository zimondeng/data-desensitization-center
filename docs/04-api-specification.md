# API 规格文档：数据脱敏中心 (Data Desensitization Center)

- **默认服务监听**：`http://127.0.0.1:18100`
- **统一响应包络**：
```json
{
  "code": 200,
  "message": "ok",
  "request_id": "req_9f4b2c10e8a14d20",
  "data": {}
}
```
- **鉴权分域**：
  1. **数据面外部脱敏接口 (`/api/v1/mask/*`, `/api/v1/jobs/*` 外部提交)**：请求头携带 `X-API-Key: dsk_live_xxxxxxxx`（或 `Authorization: Bearer dsk_live_xxxxxxxx`）。
  2. **控制面管理与沙盒接口 (`/api/admin/*`)**：请求头携带控制台登录后签发的 `Authorization: Bearer <jwt_token>`。

---

## 1. 同步脱敏数据面 API（供 `ai-eval-center` 及各业务系统调用）

### 1.1 单条纯文本脱敏
`POST /api/v1/mask/text`

**请求体**：
```json
{
  "text": "我是张三，身份证 32040219900307123X，手机号 13812345678，请问天宁区政务服务中心电话是 0519-69661800 吗？",
  "policy_code": "gov_eval_corpus",
  "policy_version": null,
  "return_spans": false
}
```
> 说明：`policy_version` 为 `null` 时使用该 `policy_code` 当前 `is_default = 1` 的激活版本；`return_spans` 仅返回**掩码后的占位符区间与标签统计**，绝不在外部接口回显明文（控制台沙盒接口除外）。

**响应 `data`**：
```json
{
  "masked_text": "我是<PERSON_1>，身份证 <IDCARD_1>，手机号 <PHONE_1>，请问天宁区政务服务中心电话是 0519-69661800 吗？",
  "policy_code": "gov_eval_corpus",
  "policy_version": 1,
  "hit_counts": {
    "private_person": 1,
    "cn_id_card": 1,
    "cn_mobile": 1
  },
  "elapsed_ms": 14
}
```

---

### 1.2 结构化 JSON / 多轮会话批量内联脱敏（`ai-eval-center` 采集主入口）
`POST /api/v1/mask/batch-inline`

用于评测中心或上游服务一次提交 `1~100` 条结构化记录（每条记录内部独立维护**一致性脱敏作用域**，按策略的 `field_role_rules_json` 执行用户/助手差异化脱敏，内存即算即焚）。

**请求体**：
```json
{
  "policy_code": "gov_eval_corpus",
  "policy_version": 1,
  "items": [
    {
      "item_id": "src_rec_10086",
      "payload": {
        "case_code": "CASE_001",
        "turn_mode": "MULTI_TURN",
        "input_text": "我叫李四，想查一下我名下在钟楼区的公积金账户提取进度",
        "turns": [
          { "role": "user", "content": "你好，我是李四，手机 13900139000" },
          { "role": "assistant", "content": "李四您好，请拨打住房公积金热线 12329 或登录 https://gjj.changzhou.gov.cn 查询。" }
        ],
        "expected_output": "李四可通过 12329 热线或常州市住房公积金网厅查询提取进度。",
        "references": [
          { "doc_name": "公积金办事指南.md", "content": "办理地点：常州市政务服务中心（锦绣路2号）1楼公积金窗口，咨询电话 0519-12329。" }
        ]
      }
    }
  ]
}
```

**响应 `data`**：
```json
{
  "policy_code": "gov_eval_corpus",
  "policy_version": 1,
  "total_items": 1,
  "elapsed_ms": 29,
  "results": [
    {
      "item_id": "src_rec_10086",
      "masked_payload": {
        "case_code": "CASE_001",
        "turn_mode": "MULTI_TURN",
        "input_text": "我叫<PERSON_1>，想查一下我名下在钟楼区的公积金账户提取进度",
        "turns": [
          { "role": "user", "content": "你好，我是<PERSON_1>，手机 <PHONE_1>" },
          { "role": "assistant", "content": "<PERSON_1>您好，请拨打住房公积金热线 12329 或登录 https://gjj.changzhou.gov.cn 查询。" }
        ],
        "expected_output": "<PERSON_1>可通过 12329 热线或常州市住房公积金网厅查询提取进度。",
        "references": [
          { "doc_name": "公积金办事指南.md", "content": "办理地点：常州市政务服务中心（锦绣路2号）1楼公积金窗口，咨询电话 0519-12329。" }
        ]
      },
      "hit_counts": {
        "private_person": 4,
        "cn_mobile": 1
      }
    }
  ]
}
```

---

## 2. 异步批量脱敏任务 API

### 2.1 上传文件创建异步脱敏任务（源临时文件即读即焚）
`POST /api/v1/jobs/file`（`multipart/form-data`，支持 JWT 或 `X-API-Key`）

- **表单字段**：
  - `file`：上传文件（支持 `.jsonl`, `.csv`, `.xlsx`, `.md`, `.txt`，默认上限 200 MB）
  - `job_name`：任务名称
  - `policy_code`：策略编码（如 `strict_general` / `gov_eval_corpus`）
  - `policy_version`：可选锁定版本号
  - `output_format`：导出格式（默认与输入同构或 `JSONL`）
  - `ttl_hours`：产物保留小时数（默认 `72`，到期自动删除本地产物文件并置状态 `ARTIFACT_EXPIRED`）

**响应 `data`**：
```json
{
  "job_no": "DSJ_20261112_0001",
  "status": "PENDING",
  "policy_code": "gov_eval_corpus",
  "policy_version": 1,
  "expires_at": "2026-11-15T13:45:00.000Z"
}
```

### 2.2 基于只读外部数据库抽样创建脱敏任务
`POST /api/admin/jobs/mysql-sample`（仅控制台管理员 JWT）

**请求体**：
```json
{
  "job_name": "智能路由11月第2周线上对话导出脱敏",
  "datasource_code": "gov_prod_readonly",
  "table_name": "ai_routing_conversation_record",
  "select_columns": ["request_id", "session_id", "query_text", "answer_text", "selected_region"],
  "where_clause": "status = 'SUCCESS' AND is_deleted = 0 AND create_time >= '2026-11-05 00:00:00'",
  "limit_rows": 2000,
  "column_role_mapping": {
    "query_text": "FULL_MASK_WRITE_SCOPE",
    "answer_text": "REPLAY_SCOPE_AND_HIGH_RISK",
    "request_id": "PASSTHROUGH",
    "session_id": "PASSTHROUGH",
    "selected_region": "PASSTHROUGH"
  },
  "policy_code": "gov_eval_corpus",
  "output_format": "JSONL",
  "ttl_hours": 72
}
```

### 2.3 查询任务状态、预览脱敏后样本、人工抽检标记与下载产物
- `GET /api/v1/jobs/{job_no}`：返回进度（`processed_records / total_records`）、`entity_hit_stats_json`、`output_sha256`、`spot_check_status`。
- `GET /api/admin/jobs/{job_no}/preview-masked?limit=20`：仅从本地**脱敏后产物**流式读取前 N 行供审核员在页面抽检是否存在漏脱敏或误伤。
- `POST /api/admin/jobs/{job_no}/spot-check`：提交抽检结论 `{ "spot_check_status": "PASSED" | "FLAGGED_LEAK" | "FLAGGED_OVERMASK", "spot_check_note": "..." }`。
- `GET /api/v1/jobs/{job_no}/download`：流式下载脱敏后产物文件（若 `spot_check_status == "FLAGGED_LEAK"` 则拒绝外部下载并返回 `409 Conflict`）。
- `POST /api/v1/jobs/{job_no}/cancel`：取消运行中任务并清理半成品产物。

---

## 3. 控制面管理与在线沙盒 API（JWT 鉴权）

| 方法与路径 | 说明 |
| --- | --- |
| `POST /api/admin/auth/login` | 管理员本地登录，返回 JWT 访问令牌 |
| `POST /api/admin/sandbox/preview` | 在线交互式调试沙盒（仅内存计算，返回原文命中区间偏移、置信度、豁免原因与脱敏后对比，**绝不写库或打日志**） |
| `GET /api/admin/policies` | 查询策略模板列表与历史版本 |
| `POST /api/admin/policies` | 新建策略编码，或在既有 `policy_code` 下创建新版本 `version + 1` |
| `POST /api/admin/policies/{policy_code}/versions/{ver}/set-default` | 切换某策略编码的当前默认激活版本 |
| `GET / POST / PUT / DELETE /api/admin/allowlists` | 管理豁免白名单分组与规则（支持即时测试单条正则） |
| `GET / POST / PUT / DELETE /api/admin/datasources` | 管理只读 MySQL 数据源及 `POST /api/admin/datasources/{code}/test` 只读连通性校验 |
| `GET / POST / DELETE /api/admin/api-keys` | 签发与吊销外部服务 `X-API-Key`（创建响应一次性返回完整明文 Key） |
| `GET /api/admin/metrics/hourly?hours=24` | 查询同步接口与批处理任务的吞吐量、平均延迟及实体类型分布看板 |

---

## 4. 标准错误码表

| HTTP 状态码 | 业务 `code` | 含义与触发条件 |
| --- | --- | --- |
| `400` | `40001` | 请求参数或 JSONPath 表达式语法错误 |
| `401` | `40101` | 缺少或无效的 `X-API-Key` / JWT 令牌 |
| `403` | `40301` | API Key 已吊销、已过期或来源 IP 不在白名单 |
| `404` | `40401` | 指定的 `policy_code` 版本或 `job_no` 不存在 |
| `409` | `40901` | 任务产物被人工抽检标记为疑似漏脱敏（`FLAGGED_LEAK`），禁止下载 |
| `410` | `41001` | 任务脱敏产物已超过 TTL 保留期被自动清理（`ARTIFACT_EXPIRED`） |
| `429` | `42901` | 触发 API Key 每分钟请求速率限制（`rate_limit_rpm`） |
| `503` | `50301` | 本地 `AstrLink Guard` ONNX 权重文件缺失或推理池过载 |
