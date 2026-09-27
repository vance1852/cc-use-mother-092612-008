# 夜市跨专区现场事件指挥基础服务

本项目提供中医文化夜市的通用后台基础能力，负责活动机构、服务站点、操作者和结构化参考资料的登记，内置角色权限、请求幂等、SQLite 事务与哈希串联审计。新的业务模块可以在这些稳定边界之上增加领域状态、规则和接口。

目前已内置跨专区现场事件指挥模块：从聊天消息进入的每份现场报告都被独立保存，关联规则只提出合并候选，由值班指挥确认后才组成共同事件，并支持升级、调援、有期限的指挥权交接、结案复核与迟到报告处理。

## 目录

- `src/night_market_foundation/`：领域模型、SQLite 存储、权限服务、审计链、事件指挥模块、HTTP 路由和离线验收；
- `tests/`：基础规则、事务边界、接口路由、事件指挥规则和端到端验收测试。

## 环境

- Linux
- Python 3.11 或更高版本
- 运行时仅使用 Python 标准库和 SQLite

## 测试

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

## 构建检查

```bash
python3 -m compileall -q src tests
```

## 离线验收

```bash
PYTHONPATH=src python3 -m night_market_foundation.acceptance
```

验收命令会在临时 SQLite 数据库中登记活动机构、操作者、站点和参考资料，随后走完报告、合并、升级、调援、交接、结案与迟到报告的完整指挥链路，并模拟应用重启核对行动负责人、幂等回执与审计链。成功时输出一行 `status` 为 `ok` 的 JSON 并以退出码 `0` 结束。

## HTTP 服务

```bash
PYTHONPATH=src python3 -m night_market_foundation.api --database night_market.sqlite3 --host 127.0.0.1 --port 8080
```

健康检查使用 `GET /health`。写入接口通过 `X-Actor-Id` 标识操作者，服务重启后 SQLite 中的业务状态和审计链继续保留。

## 跨专区事件指挥模块

### 角色约定

- 值班指挥由 `operator` 或 `admin` 角色的操作者担任，开立事件的人即为现任指挥；
- 结案确认与复开审批由 `reviewer` 或 `admin` 角色完成，且结案确认人不能是结案提出人；
- `auditor` 角色只读，不能提交报告或推进任何流程。

### 主要接口

- `POST /incident-reports`：独立保存一份现场报告（发生时间、地点、可公开摘要、证据指纹，敏感信息单独存放）；保存后关联规则自动为同站点、同专区、同类别且发生时间相近的未结事件提出合并候选；
- `POST /incidents`：值班指挥把一份报告开立为共同事件；
- `GET /merge-candidates`、`POST /merge-decisions`：查看候选并由值班指挥确认或拒绝合并；原始报告始终可通过 `GET /incident-report` 单独追查；
- `POST /escalations`：提升事件等级，必须引用尚未使用过的新现场事实（已关联报告的编号或证据指纹）；
- `POST /qualifications`（管理员）、`POST /support-requests`、`POST /support-request-updates`：登记人员资格、发起调援（核验资格并冻结当时的责任清单快照）、推进调援状态；
- `POST /incident-actions`、`POST /incident-action-updates`、`GET /incident-actions`：登记与推进行动，行动从创建起就有负责人；
- `POST /handovers`、`POST /handover-acceptances`、`POST /handover-cancellations`：有期限的指挥权交接；接班人接受后原指挥不得继续作决定，其名下未决行动自动移交；
- `POST /closure-requests`、`POST /closure-decisions`：结案前必须清空未决行动、调援与交接，由另一名复核者确认；
- `POST /evidence-supplements`、`POST /reopen-requests`、`POST /reopen-decisions`：迟到报告只能作为补充证据挂到已结案事件，或发起复开申请；
- `GET /incident-status`：对外状态，只含等级、状态与公开摘要等必要字段；
- `GET /incident`、`GET /incident-reports`：内部视图；健康信息与联系方式只对 `admin`、`operator` 角色开放；
- `GET /incident-history`：按审计顺序还原合并、升级、调援、交接和结案的因果链，每条记录都带哈希链指纹。

所有写接口都通过 `request_id` 幂等：同一请求编号重放返回原回执，内容不同的重放会被拒绝。
