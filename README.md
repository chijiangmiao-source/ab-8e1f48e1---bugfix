# 星载姿控参数页 · ARIES 恢复审计服务

审计断电恢复：浏览器提交**至多 48 个崩溃页像**与**至多 128 条按 LSN 排列的受限 WAL
记录**（仅含 `begin/update/commit/abort/end/checkpoint`），服务严格执行 ARIES
三阶段——**分析**（自检查点建立脏页表 DPT 与事务表 ATT）、**重做**（自最小
recLSN，仅在 `pageLSN < LSN` 即确有缺失时重写）、**撤销**（失败事务沿
prevLSN 前驱链逆序，且只在页 LSN 条件满足时回写 before）——并冻结恢复裁决与
最终页摘要（恢复前后 pageLSN、SHA-256）。

断链、重复 LSN、错误前像、越界区间或已结束事务仍被引用时，一律 **HTTP 422
稳定拒绝**，同一 `auditId` 的旧成功证据会在同一事务中被清除替换。

## 稳定标识冻结协议

一个稳定审计标识**只代表一份确定的恢复输入**。每次提交都会**实际执行完整恢复
校验**，绝不会因该标识已有裁决而直接回放、跳过对后来请求的校验：

| 同一 `auditId` 的后来提交 | 裁决 | HTTP |
| --- | --- | --- |
| 与首份**语义等价**（JSON 字段顺序、十六进制大小写 / `0x` 前缀 / 空白不同） | 保持首份冻结证据，**稳定回放**原裁决，响应含 `replayed:true` | 200 |
| **业务内容不同、但本身合法**的另一份恢复历史 | 判为**标识冲突**，首份证据原样保留，本次不写入、不覆盖 | 409 |
| 形式完整但 WAL 不合法（断链、引用已结束事务、错误前像……） | 实际校验后**稳定拒绝**，旧成功证据在同一事务中清除，`GET` 不再返回 verdict | 422 |

语义判定基于规范化指纹（剔除路由键 `auditId`、键排序、hex 统一为小写无
前缀），因此字节级业务差异（多/少一页、某个字节、LSN/prevLSN/offset 变化）
必然改变指纹并成为冲突；而仅表面形式不同的重传回放原裁决。

- **重启一致**：指纹、裁决与拒绝记录均持久化在 SQLite；服务重启后，相同输入仍
  回放、不同合法输入仍冲突、拒绝记录仍在。
- **并发首提交**：裁决在单个 `BEGIN IMMEDIATE` 事务内完成。两个并发的不同合法
  首提交**恰有一个**冻结成功（200），另一个得到 409，不能覆盖其结果。

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
恢复规则单元测试（提交事务补写 / 失败事务回滚 / 损坏前驱链等）→
对 `web` 的 API/HTTP 冒烟，随后**以退出码结束**（0 表示全部通过）：

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
| POST | `/api/recover` | 提交页像 + WAL：首份合法输入冻结裁决(200)；语义等价重传回放(200, `replayed`)；不同合法历史冲突(409)；不合法请求稳定拒绝(422) |
| GET | `/api/audit?auditId=...` | 读取该稳定审计标识的冻结裁决/拒绝（拒绝时无 `verdict` 字段） |

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
  storage.py     # SQLite 冻结裁决存储（拒绝时清除旧成功证据）
  server.py      # http.server：页面 / API / healthz
  static/        # 浏览器 UI
tests/
  test_recovery.py  # 规则单元测试
  smoke_http.py     # API/HTTP 冒烟
  verify.sh         # verify 容器入口（三阶段）
Dockerfile
docker-compose.yml
```
