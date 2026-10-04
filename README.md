# 星载姿控参数页 · ARIES 恢复审计服务

审计断电恢复：浏览器提交**至多 48 个崩溃页像**与**至多 128 条按 LSN 排列的受限 WAL
记录**（仅含 `begin/update/commit/abort/end/checkpoint`），服务严格执行 ARIES
三阶段——**分析**（自检查点建立脏页表 DPT 与事务表 ATT）、**重做**（自最小
recLSN，仅在 `pageLSN < LSN` 即确有缺失时重写）、**撤销**（失败事务沿
prevLSN 前驱链逆序，且只在页 LSN 条件满足时回写 before）——并冻结恢复裁决与
最终页摘要（恢复前后 pageLSN、SHA-256）。

断链、重复 LSN、错误前像、越界区间或已结束事务仍被引用时，一律 **HTTP 422
稳定拒绝**。

## 稳定审计标识的冻结语义

**每一次提交都会实际执行完整恢复校验**，不存在"看到旧标识就直接返回"的捷径；
校验之后再由存储在单个 SQLite 事务中裁决：

| 情形 | HTTP / outcome | 存储效果 |
| --- | --- | --- |
| 该标识第一次成功 | `200 frozen` | 冻结裁决与**恢复输入指纹**（规范化 pages+WAL 的 SHA-256） |
| 语义等价重传（JSON 字段顺序、十六进制大小写、`0x` 前缀、页像列出顺序不同） | `200 replayed` | 证据不变，稳定回放**最先冻结**的原裁决 |
| 同一标识提交**业务内容不同但本身合法**的另一份恢复历史 | **`409 conflict`** | 明确判为标识冲突；最先冻结的证据保持不变，本次输入不覆盖任何字段 |
| 请求形式完整但未通过恢复校验（如引用已结束事务、前驱链断裂） | **`422 rejected`** | 拒绝记录同样终局冻结；若该标识此前有成功裁决，则**旧成功证据在同一事务中被清除**，再按标识读取只剩拒绝记录、没有 verdict |

相同的损坏请求重放得到相同的 422（`outcome=replayed`）；记录持久化在卷中，
**服务重启后**冻结、回放、冲突与拒绝行为全部保持一致。两个并发的不同合法首提交
经同一事务竞争，**恰好一个** `frozen`、另一个 `409 conflict`，冻结记录始终唯一。

## 快速开始

```bash
# 默认宿主机端口 8080
docker compose up --build

# 自定义宿主机端口
HOST_PORT=9090 docker compose up --build
```

- 浏览器打开 <http://localhost:8080>
- 健康响应：<http://localhost:8080/healthz> → `{"status":"ok",...}`

`verify` 容器等待 `web` 健康后依次执行：构建检查（py_compile）→
恢复规则单元测试（提交事务补写 / 失败事务回滚 / 损坏前驱链 / 指纹规范化 /
存储冻结·冲突·拒绝终局·并发竞争 / 重启持久化）→
对 `web` 的 API/HTTP 验收（等价重传 200、标识冲突 409、成功后损坏链 422 且
verdict 被清除、并发首提交恰好一个冻结、HTTP 状态与冻结记录逐一核对），随后
**以退出码结束**（0 表示全部通过）：

```bash
# 查看一次性校验结果
docker compose up --build verify
docker compose logs verify

# 或只重跑校验
docker compose run --rm verify
```

## HTTP API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/healthz` | 健康响应 |
| GET | `/` | 浏览器审计页面 |
| GET | `/api/sample` | 内置演示场景 |
| POST | `/api/recover` | 始终先做恢复校验，再裁决：`200 frozen` / `200 replayed` / `409 conflict` / `422 rejected`（每次响应均带 `outcome`，成功裁决含 `inputFingerprint`） |
| GET | `/api/audit?auditId=...` | 读取该稳定审计标识的冻结裁决（accepted 含 verdict）或稳定拒绝（rejected，无 verdict） |

### 请求示例

```json
{
  "auditId": "AOC-AUDIT-20261004-01",
  "pages": [
    {"page": 7, "pageLSN": 30, "data": "<4096 字节的十六进制>"}
  ],
  "wal": [
    {"lsn": 10, "type": "begin", "xid": "T1"},
    {"lsn": 20, "type": "update", "xid": "T1", "prevLSN": 10,
     "page": 7, "offset": 0,
     "before": "0000000000000000", "after": "1111111111111111"},
    {"lsn": 30, "type": "checkpoint",
     "transactions": {"T1": 20}, "dirtyPages": {"7": 20}},
    {"lsn": 40, "type": "commit", "xid": "T1", "prevLSN": 20},
    {"lsn": 50, "type": "end", "xid": "T1", "prevLSN": 40}
  ]
}
```

裁决中逐条给出：分析归属、重做/撤销判据、恢复前后 pageLSN；每页给出恢复前后
SHA-256。已提交但未在崩溃页像中的更新被补写且保留；失败事务的更新先重做历史、
再逆序撤销，最终页中不会残留未提交字节。

## 无 Docker 时本地运行 / 测试

仅依赖 Python 3.11 标准库：

```bash
python app/server.py                         # 启动服务
python -m unittest discover -s tests -v      # 规则测试
python tests/smoke_http.py                   # 自启服务并跑 API/HTTP 冒烟
```

## 目录结构

```
app/
  recovery.py    # ARIES 分析/重做/撤销引擎与全部稳定拒绝规则
  storage.py     # SQLite 冻结存储：首次冻结 / 等价回放 / 标识冲突 / 拒绝终局（含旧成功清除），单事务并发安全
  server.py      # http.server：页面 / API / healthz
  static/        # 浏览器 UI
tests/
  test_recovery.py  # 规则单元测试
  smoke_http.py     # API/HTTP 冒烟
  verify.sh         # verify 容器入口（三阶段）
Dockerfile
docker-compose.yml
```
