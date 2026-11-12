# 需求规格说明书与工程研发规范：数据脱敏中心

## 0. 模块能力地图 (Capability Map)

本产品包含多个可独立验证的能力模块，按无环依赖顺序逐层建设：

| Module id | 职责范围 | Depends on |
| --- | --- | --- |
| `core-detector` | 本地 `AstrLink Guard` v0.1.3 INT8 ONNX 滑窗推理、BIO 字符偏移解码、强校验正则（二代身份证/统一社会信用代码/大陆手机号/银行卡 Luhn）与白名单豁免过滤 | — |
| `policy-engine` | 脱敏策略模板不可变版本管理、JSONPath 字段角色映射、内存级一致性脱敏作用域与多掩码动作执行器 | `core-detector` |
| `auth-and-keys` | 控制台本地管理员账号（JWT）与外部服务调用令牌（`dsk_*` API Key SHA-256 鉴权与限流） | — |
| `sync-mask-api` | 面向外部系统与评测中心的低延迟同步文本/结构化 JSON/批量内联脱敏接口、在线调试沙盒与小时级统计遥测 | `policy-engine`, `auth-and-keys` |
| `batch-jobs` | 流式文件上传（即读即焚）与外部只读 MySQL 游标抽样异步批处理作业、本地 TTL 产物卷管理及脱敏后产物人工抽检标记 | `policy-engine`, `auth-and-keys` |
| `web-console` | Vue 3 独立控制台（在线调试高亮沙盒、策略与白名单工作台、异步任务监控与抽检台、API Key 与调用统计看板） | `sync-mask-api`, `batch-jobs` |

**构建顺序**：`core-detector`, `auth-and-keys` → `policy-engine` → `sync-mask-api`, `batch-jobs` → `web-console`

---

## 1. 显式前提与假设 (Explicit Assumptions)

1. 部署环境具备 Python 3.11+ 与 Node.js 20+（构建前端静态产物后由 FastAPI 单端口一体托管，生产运行无需独立 Nginx）。
2. `AstrLink Guard` v0.1.3 权重文件（`int8/model_int8.onnx` + `int8/model_int8.onnx_data` + `tokenizer.json` + `labels.json` + `config.json`）预先挂载或通过离线初始化脚本放置于本地 `models/astrlink-guard/int8/` 目录，运行时 100% 离线推理。
3. 数据库采用独立 MySQL 8.0 Schema `kd_desensitize`，不与任何业务系统共享表或跨库连表。
4. 外部只读数据源连接器一期仅支持 MySQL 8.0 只读账号游标查询，禁止执行任何非 `SELECT` 语句。

---

## 2. 产品目标与核心用户场景 (Objective)

构建一个跨项目可独立交付的通用隐私实体识别与单向脱敏中心，解决通用大模型语料清洗、日志外发与自动化评测入库中的两大核心痛点：
1. **高精度混合识别**：结合 `AstrLink Guard` 语义上下文识别能力（中英人名、私有地址、个人关联日期、密钥口令等 10 类标签）与中国大陆强校验规则（18 位身份证校验位、18 位统一社会信用代码、11 位手机号、Luhn 银行卡号）。
2. **上下文指代不断裂且不误伤公共服务信息**：通过**一致性脱敏作用域**保证同会话内“张三 → `<PERSON_1>`”前后一致；通过**字段角色映射 + 白名单豁免**保留政务服务热线（`12345`、`0519-*`）、公开办事大厅地址与 `.gov.cn` 网址，支撑下游评测模型准确核对业务事实。

---

## 3. 技术栈 (Tech Stack)

- **后端**：Python 3.11+, FastAPI, Uvicorn, Pydantic v2, SQLAlchemy 2.0 + PyMySQL / Cryptography (`AES-GCM`), `onnxruntime` (>=1.18, CPUExecutionProvider), `tokenizers`, `numpy`, `jsonpath-ng`, `openpyxl` (流式 Excel)。
- **前端**：Vue 3.4+, Vite 5+, TypeScript 5+, Pinia, Element Plus, Axios。
- **存储**：MySQL 8.0（独立库 `kd_desensitize`）+ 本地受控文件目录 `data/artifacts/`（TTL 自动过期清理）。

---

## 4. 标准可执行命令 (Commands)

```powershell
# 后端依赖安装与本地开发启动 (f:\work_space\data-desensitization-center\backend)
python -m venv .venv
.\.venv\Scripts\python -m pip install -r requirements.txt
.\.venv\Scripts\python -m uvicorn app.main:app --host 0.0.0.0 --port 18100 --reload

# 后端单元测试与覆盖率校验
.\.venv\Scripts\python -m pytest tests/ -v --tb=short

# 前端安装、开发联调与生产静态构建 (f:\work_space\data-desensitization-center\web)
npm install
npm run dev
npm run build
```

---

## 5. 项目目录结构 (Project Structure)

```text
f:\work_space\data-desensitization-center\
├── GLOSSARY.md                      # 领域词汇表
├── README.md                        # 项目入口说明
├── docs/                            # 需求、设计、数据库、API 规格与 SQL 脚本
├── models/
│   └── astrlink-guard/int8/         # 本地离线挂载的 ONNX 模型与词表 (纳入 .gitignore)
├── data/
│   ├── tmp_uploads/                 # 流式上传临时缓冲 (读取完毕立即 unlink 删除)
│   └── artifacts/                   # 脱敏后导出产物目录 (按 TTL 定时清理)
├── backend/
│   ├── app/
│   │   ├── main.py                  # FastAPI 入口与静态前端挂载
│   │   ├── config.py                # 环境变量配置 (Pydantic Settings)
│   │   ├── auth/                    # JWT 登录与 API Key SHA-256 鉴权中间件
│   │   ├── detectors/               # AstrLink ONNX 滑窗器、大陆强规则正则、白名单豁免器
│   │   ├── engine/                  # 一致性脱敏作用域、字段角色映射与掩码替换器
│   │   ├── jobs/                    # 进程内异步批处理调度器、流式文件/只读MySQL连接器、TTL清理器
│   │   ├── api/                     # 控制台管理路由与外部 v1 脱敏路由
│   │   └── db/                      # SQLAlchemy 模型与仓储层
│   ├── tests/                       # 单元与集成测试 (含假 ONNX 桩与真实规则闭环测试)
│   └── requirements.txt
└── web/
    ├── src/
    │   ├── api/                     # 接口封装
    │   ├── views/
    │   │   ├── sandbox/             # 在线交互式脱敏沙盒 (高亮命中标签与耗时)
    │   │   ├── policies/            # 策略模板版本与字段角色映射工作台
    │   │   ├── allowlists/          # 公共信息白名单豁免字典管理
    │   │   ├── jobs/                # 批量脱敏任务监控与脱敏后产物抽检台
    │   │   └── settings/            # 只读数据源、API Key 签发与调用统计看板
    │   └── router/
    ├── package.json
    └── vite.config.ts
```

---

## 6. 代码风格约定 (Code Style)

Python 侧使用显式类型注解、Pydantic 数据契约与纯函数式区间合并，禁止在日志或异常消息中打印原始待脱敏文本：

```python
from dataclasses import dataclass
from typing import Literal

MaskAction = Literal["PLACEHOLDER", "PARTIAL", "FIXED", "HASH"]

@dataclass(frozen=True, slots=True)
class DetectedSpan:
    label: str
    start: int          # Unicode 字符起始偏移 (含)
    end: int            # Unicode 字符结束偏移 (不含)
    score: float
    detector: Literal["onnx", "regex"]

def mask_text_safe_log(char_len: int, hit_counts: dict[str, int]) -> str:
    """日志只允许记录字符长度与标签命中计数，严禁记录原文片段。"""
    return f"masked_chars={char_len} hits={hit_counts}"
```

---

## 7. 测试策略 (Testing Strategy)

- **单元测试 (`backend/tests/unit/`)**：
  - 18 位二代身份证（含最后一位 `X` 与非法校验位拒绝）、统一社会信用代码（MOD 31 校验）、大陆手机号与银行卡 Luhn 校验全覆盖；
  - 重叠滑窗（512/128）跨窗口边界实体的区间合并与最长/最高分冲突消解测试；
  - 同会话 `user` 与 `assistant` 字段角色映射的一致性占位符（`<PERSON_1>`）与政务热线（`12345`、`0519-85680000`、`*.gov.cn`）豁免防误伤测试；
  - 临时文件即读即焚断言（包括解析抛错分支下 `tmp_uploads` 零残留验证）。
- **API 集成测试 (`backend/tests/integration/`)**：
  - 验证 API Key 鉴权、沙盒零落库、批量内联接口 `/api/v1/mask/batch-inline` 的结构化会话输入输出契约。

---

## 8. 行为边界 (Boundaries)

- **Always do（必须遵守）**：
  - 所有文件流式处理使用 `try...finally` 确保上传源临时文件处理完或异常时立即物理删除；
  - API Key 入库前仅存前缀与 `SHA-256` 摘要，明文仅在创建响应返回一次；
  - 只读数据源连接器强制设置会话 `SET SESSION TRANSACTION READ ONLY` 且 SQL 解析仅放行单条 `SELECT`。
- **Ask first（需先确认）**：
  - 修改 `kd_desensitize` 核心表结构或新增第三方重量级运行时依赖；
  - 更改默认预置策略 `gov_eval_corpus` 的豁免边界。
- **Never do（绝对禁止）**：
  - 在任何数据库列、日志文件、错误堆栈或监控指标中写入未脱敏原始文本或“明文 ↔ 占位符”映射表；
  - 将脱敏中心作为反向代理串入线上实时客服对话链路。

---

## 9. 可验证验收标准 (Success Criteria)

1. 单条 ≤ 1,000 字中文政务问答在 CPU（INT8 ONNX）下同步脱敏 P95 耗时 < 80ms。
2. 输入含“我是张三，身份证 32040219900307123X，手机 13812345678”及助手回复“张三您好，可拨打 12345 或 0519-85681234，前往常州市政务服务中心（锦绣路2号）或登录 https://www.changzhou.gov.cn 办理”时：
   - 用户与助手侧“张三”均一致替换为 `<PERSON_1>`；身份证与手机号被准确脱敏；
   - 助手侧 `12345`、`0519-85681234`、`常州市政务服务中心（锦绣路2号）` 与 `https://www.changzhou.gov.cn` 100% 完整保留。
3. 执行沙盒调试与批量脱敏任务后，查询 `kd_desensitize` 全库所有列与 `data/tmp_uploads/` 目录，原始敏感明文出现次数为 `0`。
