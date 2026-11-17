# 数据脱敏中心 (Data Desensitization Center)

基于本地轻量级 `AstrLink Guard`（v0.1.3 INT8 ONNX）+ 强规则校验位检测器 + 可版本化策略模板构建的独立全栈数据脱敏平台。提供毫秒级无状态同步脱敏 API、交互式调试沙盒以及文件/只读数据库异步批量脱敏能力，严格遵循**旁路不可逆掩码**与**零明文落库**原则。

## 文档索引

- [GLOSSARY.md](./GLOSSARY.md)：领域统一词汇表
- [docs/01-requirements-and-spec.md](./docs/01-requirements-and-spec.md)：产品需求、模块能力地图（Capability Map）与工程研发规格
- [docs/02-architecture-and-design.md](./docs/02-architecture-and-design.md)：系统架构与核心引擎详细设计（ONNX 滑窗解码、一致性脱敏作用域、字段角色映射）
- [docs/03-database-design.md](./docs/03-database-design.md)：`kd_desensitize` 数据库 ER 模型与表结构说明
- [docs/04-api-specification.md](./docs/04-api-specification.md)：RESTful API 完整接口规格文档（控制台 JWT 接口与外部服务 API Key 接口）
- [docs/sql/01_schema.sql](./docs/sql/01_schema.sql)：MySQL 8.0 建库与 7 张核心表完整 DDL
- [docs/sql/02_seed_defaults.sql](./docs/sql/02_seed_defaults.sql)：预置白名单豁免规则与默认策略模板（通用严格模式 & 政务语料防误伤模式）
- [docs/adr/](./docs/adr/)：关键架构决策记录（ADR）

## Docker Compose 启动

1. （可选）复制环境变量模板并按需修改端口、密钥与构建镜像源配置：

```bash
cp .env.example .env
```

2. （可选）如需启用 ONNX 语义实体识别，请将 `AstrLink Guard` 权重文件放入 `models/astrlink-guard/int8/` 目录（包含 `model_int8.onnx`、`model_int8.onnx_data`、`tokenizer.json`、`labels.json`、`config.json`）。未放置权重时服务仍可正常启动，仅 ONNX 检测规则在调用时会提示模型未就绪（`50301`），纯正则校验规则可直接运行。

3. 构建并启动服务（MySQL 8.0 + FastAPI 一体托管前端）：

```bash
docker compose up -d --build
```

- 控制台与 API 地址：`http://127.0.0.1:18100`（默认管理员：`admin` / `Admin@123456`，可在 `.env` 中覆盖）
- MySQL 宿主机映射端口：`127.0.0.1:13306`（容器内通过 `mysql:3306` 通信，避免与本机 `3306` 冲突）
- 停止服务：`docker compose down`（如需连同数据库卷一起清理：`docker compose down -v`）
