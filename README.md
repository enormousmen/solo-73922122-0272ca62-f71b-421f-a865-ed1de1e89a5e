# 跨区 DNS 变更发布顺序规划器

给内网 DNS 值班员用的 FastAPI 服务，包含两个离线接口：

* `POST /plan`：提交最多 8 个**互不嵌套**的权威区的新旧 A / CNAME 记录，以及
  必须持续可解析的业务域名，按**无缓存权威记录**推演每一次**整区切换**后的
  解析状态，回答三件事：

  1. **有没有安全顺序**：有则返回逐步发布顺序，并给出每一步前后的解析结果。
  2. **现状是否已经坏了**：若按现状（所有区都还是旧记录）就查不到 IPv4 地址，
     直接返回故障链路，不再谈发布顺序。
  3. **没有安全顺序时卡在哪**：返回能安全走到的**最大前缀**，并逐个说明剩余
     每个区若紧接着发布会断在哪条解析链上，区分**缺记录**与**成环**。

* `POST /query`：调低内网 DNS 的 UDP 上限前，核对**单条 A/IN 查询**会不会因为
  超出 UDP 预算而被截断（TC），从而迫使客户端转 TCP。提交各区**当前**的
  A/CNAME 快照、查询名、链路允许的 DNS 消息字节数和可选 EDNS UDP 上限；返回
  启用名称压缩的完整应答和 UDP 应答，各自给出 Base64 与字节数。

## 推演模型

* 解析不经过缓存，不使用 TTL；记录里的 `ttl` 只做原样保留，不影响推演结论，
  但会写进 `/query` 应答的 RRset（同一 RRset 内 TTL 不一致时取最小值）。
* 支持 A 与 CNAME。CNAME 链跨已提交的区追踪，最多 32 跳。
* CNAME 链**离开已提交的区**即视为无法确认（`external_target`）。需要把外部区
  纳入推演时，把它按 `records == new_records` 一并提交即可。
* 所有记录必须属于本区；同一名称不能同时有 A 与 CNAME；区顶点不允许 CNAME；
  同名 CNAME 目标必须一致；A 值必须是 IPv4。违反则返回 422。
* `/plan` 中每个区只有两个状态：整区旧记录、整区新记录。一次发布 = 一个区整区
  切换，区内不存在新旧共存的中间态。`/query` 只有一份快照，相当于把每个区都
  当作“新旧相同”提交，沿用同一套权威区约束和无缓存解析规则。

### 为什么不是贪心

安全谓词不单调：发布一个区可能同时修好一个域名、又弄坏另一个；一个“当前会断”
的状态也可能被后发布的区修好。因此“每次挑一个当前安全的区”并不保证找到存在的
安全顺序。服务对 **2^n ≤ 256 个状态**做完整深度优先搜索（带记忆化），
一定给出正确结论；无解时在所有等长的安全前缀中挑“卡点失败域名最少”的那个。

## 启动

```bash
docker compose up --build -d
docker compose ps          # 等待 healthy
curl -s http://localhost:8000/healthz
```

OpenAPI 文档：<http://localhost:8000/docs>

镜像以非 root 用户运行，容器只读挂载根文件系统（`read_only: true`、
`no-new-privileges`），并带 `HEALTHCHECK`。

### 不用 Docker 时

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

## API

### `GET /healthz`

```json
{"status": "ok", "version": "1.0.0"}
```

### `POST /plan`

请求体：

```json
{
  "zones": [
    {
      "name": "a.example.com",
      "records":     [{"name": "www.a.example.com", "type": "CNAME", "value": "svc.b.example.com", "ttl": 60}],
      "new_records": [{"name": "www.a.example.com", "type": "CNAME", "value": "svc2.b.example.com", "ttl": 60}]
    },
    {
      "name": "b.example.com",
      "records":     [{"name": "svc.b.example.com",  "type": "A", "value": "10.20.1.10"}],
      "new_records": [{"name": "svc.b.example.com",  "type": "A", "value": "10.20.1.10"},
                      {"name": "svc2.b.example.com", "type": "A", "value": "10.20.2.10"}]
    }
  ],
  "required_domains": ["www.a.example.com"]
}
```

`records` 是现状，`new_records` 是该区切换后的状态；两者相同表示“这个区不变，
但仍参与解析”。

响应 `status` 有三种：

| status | 含义 |
| --- | --- |
| `safe_order_found` | 存在安全顺序，`order` / `steps` 给出逐步操作与前后解析结果 |
| `already_broken` | 现状就解析不到 IPv4，`fault_chains` 给出故障链 |
| `no_safe_order` | 无完整安全顺序，`safe_prefix` + `blocked_zones` 给出卡点 |

每条失败链都带：

* `category`：`missing_record` / `cname_loop` / `external_target` / `chain_too_long`
* `category_label`：`缺记录` / `成环` / `链出已提交的权威区` / `CNAME 链过长`
* `detail`：缺记录时进一步区分 `nodata`（名称存在但无 A/CNAME）与
  `nxdomain`（名称不存在）
* `chain`：可读链路，例如
  `www.a.example.com --CNAME--> u.b.example.com => 无记录（NXDOMAIN）`
* `trace`：结构化的逐跳记录，便于值班员复制进工单

## 调用示例

仓库自带可直接用 curl 调用的场景：`examples/01`–`04` 对应 `/plan`，
`examples/05`–`07` 对应 `/query`。

```bash
# 1) 存在安全顺序：必须先发 b，再发 a
curl -s -X POST http://localhost:8000/plan \
  -H 'Content-Type: application/json' \
  --data-binary @examples/01-safe-order.json | python -m json.tool

# 2) 现状即故障：CNAME 指向一个没有记录的区
curl -s -X POST http://localhost:8000/plan \
  -H 'Content-Type: application/json' \
  --data-binary @examples/02-already-broken.json | python -m json.tool

# 3) 无安全顺序：a/b 互为前置，c 可安全先发
curl -s -X POST http://localhost:8000/plan \
  -H 'Content-Type: application/json' \
  --data-binary @examples/03-no-safe-order.json | python -m json.tool

# 4) 无安全顺序且卡点同时含“缺记录 + 成环”
curl -s -X POST http://localhost:8000/plan \
  -H 'Content-Type: application/json' \
  --data-binary @examples/04-blocked-mixed.json | python -m json.tool

# 5) /query：无 EDNS，budget=min(512, 512)=512，完整应答 121 字节，UDP 不截断
curl -s -X POST http://localhost:8000/query \
  -H 'Content-Type: application/json' \
  --data-binary @examples/05-query-fits.json | python -m json.tool

# 6) /query：带 EDNS(1232)，但链路只有 120 字节，两种应答都带 OPT，UDP 置 TC
curl -s -X POST http://localhost:8000/query \
  -H 'Content-Type: application/json' \
  --data-binary @examples/06-query-edns-truncated.json | python -m json.tool

# 7) /query：CNAME 链出已提交的区，返回故障链（不生成 DNS 应答）
curl -s -X POST http://localhost:8000/query \
  -H 'Content-Type: application/json' \
  --data-binary @examples/07-query-broken.json | python -m json.tool
```

场景 1 的响应节选：

```json
{
  "status": "safe_order_found",
  "order": ["b.example.com", "a.example.com"],
  "steps": [
    {"step": 1, "zone": "b.example.com",
     "addresses_before": {"www.a.example.com": ["10.20.1.10"]},
     "addresses_after":  {"www.a.example.com": ["10.20.1.10"]},
     "all_required_resolvable": true},
    {"step": 2, "zone": "a.example.com",
     "addresses_before": {"www.a.example.com": ["10.20.1.10"]},
     "addresses_after":  {"www.a.example.com": ["10.20.2.10"]},
     "all_required_resolvable": true}
  ]
}
```

场景 4 的响应节选：

```json
{
  "status": "no_safe_order",
  "safe_prefix": ["d.example.com"],
  "blocked_zones": [
    {"zone": "a.example.com",
     "categories": [{"category": "missing_record", "label": "缺记录"}],
     "failures": [{"chain": "one.a.example.com --CNAME--> gone.b.example.com => 无记录（NXDOMAIN）"}]},
    {"zone": "c.example.com",
     "categories": [{"category": "cname_loop", "label": "成环"}],
     "failures": [{"chain": "two.a.example.com --CNAME--> keep.c.example.com --CNAME--> keep.c.example.com => 回到 keep.c.example.com，成环"}]}
  ]
}
```

也可以不启动服务、直接跑同一套逻辑：

```bash
python examples/demo.py
```

### `POST /query`

请求体（`examples/06-query-edns-truncated.json`）：

```json
{
  "zones": [
    {
      "name": "a.example.com",
      "records": [
        {"name": "www.a.example.com", "type": "CNAME", "value": "svc.b.example.com", "ttl": 60},
        {"name": "api.a.example.com", "type": "CNAME", "value": "www.a.example.com", "ttl": 60}
      ]
    },
    {
      "name": "b.example.com",
      "records": [
        {"name": "svc.b.example.com", "type": "A", "value": "10.20.1.10", "ttl": 60},
        {"name": "svc.b.example.com", "type": "A", "value": "10.20.1.11", "ttl": 60},
        {"name": "svc.b.example.com", "type": "A", "value": "10.20.1.12", "ttl": 60}
      ]
    }
  ],
  "qname": "api.a.example.com",
  "qtype": "A",
  "qclass": "IN",
  "link_udp_size": 120,
  "edns_udp_size": 1232
}
```

* `zones[].records` 是该区的**当前快照**（没有 `new_records`）。约束与 `/plan`
  相同：互不嵌套、记录属于本区、同一名称不能既有 A 又有 CNAME、区顶点不能
  CNAME、CNAME 目标唯一。
* `qname` 必须落在某个已提交的区内，否则 422。`qtype` 只接受 `A`，
  `qclass` 只接受 `IN`。
* `link_udp_size` 是链路允许的 DNS 消息字节数（1–65535）。服务不强制 512 下限，
  正因为要评估“调到 512 以下”的后果。
* `edns_udp_size` 可选（512–65535）。不提供 = 请求不带 EDNS，客户端上限按
  512 字节；提供 = 两种应答都带 OPT，OPT 的 11 字节计入字节数，OPT 的 CLASS
  广告 `min(1232, edns_udp_size)`（1232 为服务端自身建议接收大小）。
* UDP 预算 = `min(link_udp_size, 客户端上限)`，响应里的 `udp_budget.effective`
  就是该值。

响应 `status`：

| status | 含义 |
| --- | --- |
| `resolved` | 查询可解析；`full_response` 与 `udp_response` 给出应答 |
| `broken` | 查询无法解析；`fault_chain` 给出故障链（缺记录 / 成环 / 链出区 / 链过长），不生成 DNS 应答 |

`full_response` / `udp_response` 字段：

* `base64`：DNS 报文的 Base64；`bytes`：报文实际字节数；`format: "dns_wire"`。
* `name_compression: true`：启用 RFC 1035 名称压缩（两种应答都启用）。
* `has_opt`：是否带 EDNS OPT（仅当请求给了 `edns_udp_size`）。
* `rr_count` / `rrset_count` / `answer_rrsets`：应答里的记录与 RRset。
  多地址 A 记录是**一个 RRset、多条 RR**，截断时整体保留或整体丢弃。
* `udp_response.budget`、`fits_budget`、`tc`、`truncated`、`dropped_rrsets`：
  UDP 侧预算与截断情况；`tc: true` 表示客户端应转 TCP。

`full_response.fits_udp_budget` 表示完整应答是否落在预算内；
`udp_budget_insufficient: true` 表示预算连报头、问题段（和 EDNS 的 OPT）都放
不下：此时不生成 `udp_response`，只返回 `full_response`，并在 `message` 中报告
所需的最小开销 `udp_overhead`。

场景 6 的响应节选（链路 120 字节，EDNS 1232，两种应答都带 OPT）：

```json
{
  "status": "resolved",
  "udp_budget": {"link_udp_size": 120, "client_udp_size": 1232, "effective": 120},
  "udp_overhead": 46,
  "udp_budget_insufficient": false,
  "full_response": {"bytes": 132, "name_compression": true, "has_opt": true,
                    "rr_count": 5, "rrset_count": 3, "fits_udp_budget": false, "base64": "..."},
  "udp_response":  {"bytes": 84, "budget": 120, "has_opt": true, "truncated": true,
                    "tc": true, "rrset_count": 2, "dropped_rrsets": 1,
                    "rr_count": 2, "base64": "..."},
  "message": "完整应答 132 字节超出 UDP 预算 120 字节，UDP 应答置 TC 并保留前 2 个完整 RRset（丢弃 1 个），客户端需转 TCP。"
}
```

完整应答按 TCP 语义给出（不截断）；UDP 应答按**解析顺序**保留能放下的最长
**完整 RRset 前缀**（CNAME 逐跳，最后一组 A 整体）。把两个 Base64 解开就是
标准 DNS 报文，可直接用 `dig`/`dnspython` 等工具解析核对。

## 测试

```bash
pip install -r requirements-dev.txt
pytest
```

覆盖：安全顺序、必须后发/先发的依赖、现状故障（缺记录 / 成环 / 链出区 /
链过长 / NODATA vs NXDOMAIN）、无解时的最大前缀与逐区卡点、随机小规模实例与
穷举结果的等价性校验、请求校验与 HTTP 状态码；`/query` 部分额外用独立的
DNS 报文解析器核对名称压缩指针、RR 边界、OPT、TC 与整个预算区间的截断行为。

## 限制

* 只支持 A / CNAME；AAAA、SRV、通配符等不参与推演或应答编码。
* 最多 8 个区、每区 256 条记录、最多 64 个必保域名。
* 同一名称的多条 A 记录视为一个 RRset（多个地址任选其一即视为可解析）。
* 不校验外部区真实状态；链出已提交区一律按“无法确认”处理。
* `/query` 只回答单条 A/IN 查询，不合成授权段（NS/SOA）或否定应答
  （NXDOMAIN/NODATA），也无法解释 `/plan` 中的新旧切换态；故障时只报告故障链。
* `/query` 不做 DNSSEC、EDNS 选项（cookie/NSID 等）与 DO 位处理，OPT 为
  最小合法形态（RDATA 为空）。
* `/query` 的 UDP 报文只用于预算核对，不监听 53 端口、不代替真实 DNS 服务器。
