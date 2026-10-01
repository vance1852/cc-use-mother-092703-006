# 产业园环境事件响应平台

本项目是一套可离线运行的 Python 服务端平台，用于管理数据中心、互联通道、加速卡资源批次、租户预约、容量分配、交付情景与硬件稳定性准入。业务状态、幂等结果和审计事件保存在 SQLite 中，适合调度、质量、风险和审计人员在单个 Linux 应用容器内协作。

## 目录

- `src/compute_fabric/`：站点、通道、资源库存、预约、容量分配和情景分析；
- `src/accelerator_lab/`：加速卡测点导入、排除复核、分析任务租约和准入决定；
- `src/silicon_qualification/`：AI 加速芯片批次、测量、分析与质量审批；
- `src/env_response/`：产业园环境事件响应——证据版本判断、区域变化理由、隔离与资源调度、修复任务、授权解除复核；
- `fixtures/`：离线验收使用的结构化协议与测点；
- `tests/`：核心规则、错误边界、事务、API 和命令行验收测试。

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
PYTHONPATH=src python3 -m compute_fabric.acceptance --workspace .
PYTHONPATH=src python3 -m accelerator_lab.acceptance --workspace .
PYTHONPATH=src python3 -m silicon_qualification.acceptance
PYTHONPATH=src python3 -m env_response.acceptance --workspace .
```

这些命令使用临时 SQLite 数据库完成站点、资源、预约、分配、测点分析和芯片准入流程，不访问外部网络。

## HTTP 服务

```bash
PYTHONPATH=src python3 -m compute_fabric.api --database compute.sqlite3 --host 127.0.0.1 --port 8080
PYTHONPATH=src python3 -m accelerator_lab.api --database lab.sqlite3 --host 127.0.0.1 --port 8081
PYTHONPATH=src python3 -m silicon_qualification.api --database silicon.sqlite3 --host 127.0.0.1 --port 8082
PYTHONPATH=src python3 -m env_response.api --database env.sqlite3 --host 127.0.0.1 --port 8083
```

### 环境事件响应服务规则

- 每份证据（监测告警、现场复测、第三方分析、设备校准）在事件内形成一个**带版本的判断**，
  重算影响区域并显式给出 `added_zones`、`removed_zones` 与 `change_reason`；
  新证据可通过 `finding=cleared` 收窄，或通过 `disputes_refs` 推翻旧证据（如校准证明探头漂移）。
- 并发提交的现场记录按 `(incident_id, source_ref)` 在数据库层去重，重复来源只保留首次提交，
  并累计 `deduped` 计数。
- 区域隔离与资源调度只能落在当前影响区域内；修复任务完成**不会**自动解除管控。
- 解除管控须先申请（要求每个影响区域均有完成的修复任务），再由复核员授权裁决；
  只有复核通过才会解除全部生效措施、关闭事件并恢复受影响业务；驳回后可整改再申请。
- 值班人员可通过 `GET /todos` 查询当前措施、责任人、待办时限与逾期标记，
  通过 `GET /incidents/{id}/history` 查询整条决策沿革。所有写操作进入 SHA-256 哈希链审计日志。

服务均提供 `GET /health`，其余接口使用 JSON。进程重启后可以继续查询 SQLite 中的业务状态和审计历史。
