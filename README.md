# 产业园环境事件响应平台

本项目是一套可离线运行的 Python 服务端平台，用于管理数据中心、互联通道、加速卡资源批次、租户预约、容量分配、交付情景与硬件稳定性准入。业务状态、幂等结果和审计事件保存在 SQLite 中，适合调度、质量、风险和审计人员在单个 Linux 应用容器内协作。

## 目录

- `src/compute_fabric/`：站点、通道、资源库存、预约、容量分配和情景分析；
- `src/accelerator_lab/`：加速卡测点导入、排除复核、分析任务租约和准入决定；
- `src/silicon_qualification/`：AI 加速芯片批次、测量、分析与质量审批；
- `src/env_response/`：产业园环境事件的证据版本判断、区域隔离、资源调度、修复任务与授权解除；
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

这些命令使用临时 SQLite 数据库完成站点、资源、预约、分配、测点分析、芯片准入以及环境事件
“异常信号→证据版本判断→隔离/调度/修复→授权解除”的完整流程，不访问外部网络。

## HTTP 服务

```bash
PYTHONPATH=src python3 -m compute_fabric.api --database compute.sqlite3 --host 127.0.0.1 --port 8080
PYTHONPATH=src python3 -m accelerator_lab.api --database lab.sqlite3 --host 127.0.0.1 --port 8081
PYTHONPATH=src python3 -m silicon_qualification.api --database silicon.sqlite3 --host 127.0.0.1 --port 8082
PYTHONPATH=src python3 -m env_response.api --database env.sqlite3 --host 127.0.0.1 --port 8083
```

环境事件响应服务（`env_response`）的核心规则：

- 每份证据（现场复测 `field_retest`、第三方分析 `third_party`、设备校准 `calibration` 等）都会生成
  一个带证据集合 SHA-256 的判断版本（`assessments`）；新版本相对上一版给出 `initial/expanded/
  narrowed/unchanged` 方向、新增与移出区域清单以及必填的变化理由。
- 证据可通过 `cleared_zone_ids` 排除被误报的区域；影响区域为全部指认区域与排除区域的并集差。
- 并发提交按 `(incident_id, source_id)` 去重：完全重复原样返回，相同编号不同内容报 409。
- 隔离、资源调度、修复是三类措施；生效中的隔离随判断版本自动扩缩并留下审计。修复完成只把事件推进到
  `recovering`，不会自动解除管控。
- 解除必须先申请、再由独立授权复核人（reviewer，不能是申请人）审批；仍有未完成任务时无法批准，
  批准后隔离解除、受影响区域业务恢复。
- 值班视图 `GET /board` 提供当前措施、责任人与待办时限（含逾期标记）；
  `GET /incidents/{id}/history` 返回整条决策沿革，`GET /audit/chain` 校验哈希审计链。

服务均提供 `GET /health`，其余接口使用 JSON。进程重启后可以继续查询 SQLite 中的业务状态和审计历史。
