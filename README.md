# 夜市跨专区现场事件指挥基础服务

本项目提供中医文化夜市的通用后台基础能力，负责活动机构、服务站点、操作者和结构化参考资料的登记，内置角色权限、请求幂等、SQLite 事务与哈希串联审计。新的业务模块可以在这些稳定边界之上增加领域状态、规则和接口。

## 跨专区事件指挥模块

在基础层之上实现了跨专区支援的事件指挥生命周期：

- **独立报告存档**：每份报告按发生时间、地点、公开摘要和证据指纹（SHA-256）独立保存，原始报告始终可单独追查；
- **关联规则只提候选**：同证据指纹、近重复摘要、同地点时间窗三条规则只产生合并候选，是否组成共同事件必须由值班指挥确认，也可拒绝；
- **事实驱动升级**：升级必须引用事件建立后到达的新报告或已完成行动的现场结果，同一事实只能支撑一次升级；
- **资格核验调援**：调援前核验被调人员资格与有效期，创建时冻结当时的责任清单快照；
- **有期限交接**：指挥权以 0.5–24 小时的交接方式转移，完成后原指挥立即失权，超期后需管理员重新指派；
- **分级可见**：健康信息与联系方式只对报告人本人、指挥、复核员、管理员开放；对外状态接口只返回最小公开信息；
- **结案与复开**：结案前必须清空未决行动，由另一名复核者确认；迟到报告只能补充证据或对已结案事件申请复开；
- **因果链还原**：每个事件可经接口还原合并、升级、调援、交接、结案的完整审计链；行动项责任人非空持久化，重启后可检查悬空行动。

## 目录

- `src/night_market_foundation/`：领域模型、SQLite 存储、权限服务、审计链、HTTP 路由和离线验收；
- `src/night_market_foundation/incident_*.py`：事件指挥模块的领域常量、模型、存储、服务、HTTP 边界与验收；
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
PYTHONPATH=src python3 -m night_market_foundation.incident_acceptance
```

验收命令会在临时 SQLite 数据库中完成登记与事件指挥全链路，核对幂等回执与审计链，成功时输出一行 `status` 为 `ok` 的 JSON 并以退出码 `0` 结束。

## HTTP 服务

```bash
PYTHONPATH=src python3 -m night_market_foundation.api --database night_market.sqlite3 --host 127.0.0.1 --port 8080
PYTHONPATH=src python3 -m night_market_foundation.incident_api --database incident.sqlite3 --host 127.0.0.1 --port 8081
```

健康检查使用 `GET /health`。写入接口通过 `X-Actor-Id` 标识操作者，服务重启后 SQLite 中的业务状态和审计链继续保留。事件接口包括：`POST /reports`、`GET /merge-candidates`、`POST /merges/confirm|reject`、`POST /incidents/{id}/escalate|actions|support|handovers|closures|commander-assignment`、`GET /incidents/{id}/public|causal-chain|actions`、`POST /actions/{id}/transition|reassign`、`POST /support/{id}/fulfill|cancel`、`POST /handovers/{id}/complete`、`POST /closures/{id}/review`、`POST /reopen-applications/{id}/decision`、`POST /commanders`、`POST /qualifications`、`POST /recovery/startup`。
