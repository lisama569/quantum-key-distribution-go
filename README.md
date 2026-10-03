# 本地量子密钥分发会话协议（QKD, BB84 风格）

一个**纯本地、确定性、无外部依赖**的量子密钥分发（QKD）会话协议模拟组件（Go）。
通过可注入的种子化随机源与本地信道模型，模拟 Alice / Bob 双方端到端协商，
使**噪声、窃听与并发会话**下的结论一致、可复现、可解释。不访问任何网络服务或真实硬件。

- 模块路径：`github.com/lisama569/quantum-key-distribution-go`
- 包：`qkd`（仅依赖 Go 标准库，`crypto/sha256` 用于保密放大与一致性校验）

---

## 1. 协议流程

单次会话由 `Session.Run(ctx)` 驱动，严格按以下状态机推进，任何阶段失败都会进入
`aborted` 终态并**清零全部中间材料**：

| 阶段 | 名称 | 内容 |
|------|------|------|
| 1 | `quantum_transmit` 量子态传输 | Alice 用确定性随机源生成比特与基，制备 BB84 量子比特；经 `LocalChannel` 传输，Bob 用各自随机基测量。信道依次模拟 **Eve 拦截-重发 → 固有噪声翻转 → Bob 测量**。 |
| 2 | `sift` 基比对与筛选 | 双方在公共信道比对测量基，**仅保留基一致**的位置，得到筛选密钥串（sifted key）。 |
| 3 | `qber_estimate` 误码率估计 | 随机抽取 `SampleFraction` 比例的筛选位公开比对，计算观测误码率 **QBER**；抽样位随后从密钥材料中**移除**。 |
| 4 | `reconcile` 纠错（信息协调） | 对剩余串做确定性的**级联/CASCADE 风格**纠错：逐轮置换 → 分块比奇偶 → 二分定位并翻转 Bob 的错误比特；达到轮数上限后以 SHA-256 哈希终验。 |
| 5 | `privacy_amplify` 保密放大 | 对纠错串做 SHA-256 计数器模式提取，输出**长度严格等于 `KeyBytes`** 的最终密钥；提取上下文与“会话 ID + 参数版本 + 种子”绑定。 |
| 6 | `completed` 完成 | 返回最终密钥；所有中间比特/字节缓冲立即清零。 |

### 一致性与“不重复产出”保证

- 成功后双方（本模拟同居一地，分别持有 `restA` 与经纠错的 `restB`）得到**同一串**
  纠错后比特，保密放大输出**长度确定**的密钥。
- 一个 `Session` 对象**至多产出一把密钥**：再次调用 `Run` 返回
  `session_reused` 错误；失败后重跑同样被拒绝。
- 失败路径（中止、取消、纠错失败、材料不足）会 wipe 掉量子比特、各阶段比特串等
  全部中间材料，密钥库不会写入半成品。

---

## 2. 参数含义与版本升级（版本化配置 `Params`）

参数带版本号 `ParamsVersion`，随会话一起归档；
**相同参数版本 + 相同主种子 + 相同信道配置 → 结果逐比特可复现**。

| 版本 | 常量 | 状态 | 说明 |
|------|------|------|------|
| v1 | `qkd-params-v1` | **继续支持** | 初始版本：`N=2048`、`KeyBytes=32`、`ReconcilePasses=16`，保密放大域标签 `qkd-pa-v1` |
| v2 | `qkd-params-v2` | **新会话默认** | 协议流程与 v1 完全相同，默认值升级：`N=4096`、`KeyBytes=64`、`ReconcilePasses=24`，域标签 `qkd-pa-v2` |

- `qkd.DefaultParams()` 返回当前默认（**v2**）；需要固定旧行为请显式使用
  `qkd.DefaultParamsV1()`，也可显式构造任意受支持版本的 `Params`。
- 未知版本（如 `qkd-params-v99`）在构造/校验/重放时返回独立原因
  `unsupported_version`，与“参数取值非法”（`config_invalid`）及其它失败可区分。

### 兼容性范围（升级保证）

- **老会话记录仍可解析**：记录格式 `qkd-record-v1` 与参数版本正交保存；解析器向后兼容
  （旧别名、缺字段、未知字段均容忍，见第 5 节），未知参数版本的记录**仍能解析**，
  只是在“重放”时才以 `unsupported_version` 拒绝。
- **按记录重放逐比特一致**：`qkd.ReplayRecord(rec)` 用记录里的版本/参数/种子重新协商，
  v1 记录在 v2 时代重放，协议过程、`SessionStats`、密钥 ID 与密钥字节都与当初一致
  （v1 的随机流派生与域标签被冻结，不会因升级而改变）。
- **老密钥照常取用**：v1 时代签发入库的密钥带 `ParamsVer=v1` 标记，升级到默认 v2 的
  新管理器后（复用同一个 `KeyStore`）仍可正常 `Get`、退役、撤销、销毁；v2 新会话签发
  的 v2 密钥与老密钥并存、互不影响。

| 字段 | 含义 | v1 默认 | v2 默认 | 约束 |
|------|------|--------|--------|------|
| `Version` | 参数版本 | `qkd-params-v1` | `qkd-params-v2` | 必须受支持 |
| `N` | Alice 发送的量子比特数 | `2048` | `4096` | ≥ 16 |
| `SampleFraction` | QBER 抽样比例 | `0.2` | `0.2` | (0,1) |
| `QBERThreshold` | 可接受误码率上限 | `0.15` | `0.15` | (0,1)，观测 QBER **严格大于**即中止 |
| `NoiseRate` | 信道固有噪声翻转概率 | `0.03` | `0.03` | [0,1] |
| `EavesdropRate` | Eve 拦截-重发比例 | `0.0` | `0.0` | [0,1] |
| `KeyBytes` | 最终密钥长度（字节） | `32` | `64` | > 0（必填，0 直接判错而非取默认） |
| `ReconcilePasses` | 纠错最大轮数 | `16` | `24` | > 0 |
| `BlockSize` | 纠错分块大小 | `32` | `32` | > 1 |

### 版本化与可复现

- 管理器按 `sessionSeed = deriveSeed(MasterSeed, "session:"+sessionID)`
  为每个会话派生**专属、互不相关**的随机流；信道内部还为“事件判定 / Eve / Bob”
  三类随机决策分别域隔离派生，避免角色间伪相关。
- `History` 记录的 `seed` 即该会话种子；可用它在任何时候重放出完全相同的过程与密钥。

---

## 3. 失败与中止判定规则（错误可区分）

所有错误均为 `*qkd.ProtocolError`，携带机器可判别的 `FailureReason`，
用 `qkd.IsFailure(err, reason)` 判别：

| FailureReason | 触发条件 | 是否产出密钥 |
|---------------|----------|--------------|
| `config_invalid` | 参数取值非法（范围/必填），或密钥入库参数不合法 | 否 |
| `unsupported_version` | 使用了本版本不认识的参数版本（构造/重放） | 否 |
| `session_reused` | 同一 `Session` 重复 `Run`，或同一成功会话 ID 再次签发 | 否 |
| `insufficient_bits` | 筛选后位 < 16、无抽样位，或抽样后不足以构成 `KeyBytes*8` 位 | 否 |
| `reconcile_failed` | 达到纠错轮数上限双方仍不一致（终验哈希不等） | 否 |
| `channel_quality_exceeded` | QBER 超阈，且信道诊断**无**窃听拦截事件（判定为固有噪声过差） | 否 |
| `eavesdropping_suspected` | QBER 超阈，且信道诊断**存在** Eve 拦截事件 | 否 |
| `session_aborted` | 上下文取消等其它中止 | 否 |
| `store_full` | 密钥库到达容量上限且没有任何失效/退役密钥可回收，本次签发明确失败 | 否（协商密钥随即清零） |
| `key_not_found` | 取用/操作一个库里根本不存在的密钥 ID | 否 |
| `key_expired` | 密钥已过 `NotAfter` 有效期 | 否 |
| `key_retired` | 密钥已被显式提前退役 | 否 |
| `key_revoked` | 密钥已被撤销 | 否 |
| `key_destroyed` | 密钥已被销毁（终态） | 否 |

> 取用失败的五种结论（不存在 / 已过期 / 已退役 / 已撤销 / 已销毁）彼此互斥、
> 可机器判别，调用方可据此决定是报错、换一把还是走重协商。
> **已撤销 / 已销毁 / 已过期 / 已退役的状态具有粘性**：容量回收只会删除它们的条目
> （删除后表现为 `key_not_found`，且回收事实留在审计日志），版本升级或任何操作都
> 不可能让它们重新变回 `active`。

### 噪声 vs 窃听如何区分

BB84 中窃听者（拦截-重发）和噪声都会抬高 QBER。本组件的判定依据是**可观测的信道
诊断 `ChannelStats`**：

- `QBER > QBERThreshold` 是中止的**必要且直接**条件；
- 中止后，若 `ChannelStats.EveIntercepted > 0`（模型全知记录了拦截行为），
  归类为 `eavesdropping_suspected`；否则归类为 `channel_quality_exceeded`。

> 物理直觉：Eve 对拦截的比特以随机基测量，约一半概率选错基而扰动重发态；
> 拦截率 50% 时同基位置的理论 QBER 增量约 50% × 1/2 × 1/2 ≈ 0.125。

`SessionStats` 完整记录判定依据：发送/筛选/抽样数量、抽样错误数、QBER 与阈值、
噪声翻转数、Eve 拦截与扰动数、纠错翻转数与轮数等；单测日志会打印
“输入参数 → 判定依据 → 结论”。

---

## 4. 并发会话隔离与密钥库

- `Manager.RunSessions(ctx, ids)` 为每个会话启动独立 goroutine，使用各自独立的
  `Session` 与派生随机源；**会话之间不共享任何密钥材料**，密钥两两不同。
- 任一会话失败：只归档失败记录，**不写入密钥**；不取消其它会话，也不改动密钥库
  既有内容。`KeyStore` 与 `History` 均为线程安全（互斥 / 读写锁），已通过
  `go test -race` 验证（含“并发签发 + 并发退役 + TTL 到期”的交织场景）。
- **同一成功会话绝不重复产出密钥**：`RunSession` 以会话 ID + 归档（`success && issued`）
  做防护，重复调用返回 `session_reused`；仅协商成功但因 `store_full` 未入库的会话
  允许重试（它们事实上没有产出过密钥）。

### 密钥生命周期（`KeyStore`）

五状态模型，只有 `active` 可取回密钥字节（返回副本）：

```
                 Put(带可选 NotAfter)
                        │
                        ▼
                     active ──Retire()──► retired ──┐
                        │                            │
              到达 NotAfter（惰性判定）             Revoke()
                        ▼                            ▼
                     expired ────────────────► revoked ──Destroy()──► destroyed
                        └──────────────Destroy()──────────────────────────►
```

| 操作 | 行为 |
|------|------|
| `Put(k)` | 仅接受 `active` 新密钥；容量满时先回收（见下），无空间则 `store_full`，不覆盖任何已有密钥 |
| `Get(id)` | 仅 `active` 返回字节副本；不存在/过期/退役/撤销/销毁分别返回独立原因，不返回字节 |
| `Retire(id)` | active → `retired`（提前显式退役）并清零字节；重复退役幂等；对过期/撤销/销毁调用报各自可区分错误 |
| `Revoke(id)` | active/retired → `revoked` 并清零字节；重复撤销幂等；过期/销毁状态保持粘性 |
| `Destroy(id)` | 任意非销毁状态 → 终态 `destroyed` 并清零字节；重复销毁幂等，不可逆 |
| `State(id)` / `IDs()` / `Len()` | 状态查询（触发到期惰性迁移）/ 盘点 / 条目数 |

- **有效期**：`StoredKey.NotAfter` 为截止时刻，当前时间到达/超过即惰性转 `expired`；
  零值表示长期有效。管理器可用 `ManagerConfig.KeyTTL > 0` 在签发时自动设置
  （`NotAfter = 签发时刻 + TTL`）。`KeyStoreConfig.Now` / `ManagerConfig.Now` 可注入
  时钟，便于确定性测试。
- 密钥 ID 由 `SHA256("qkd-keyid" ‖ sessionID ‖ paramsVersion ‖ seed)` 确定性派生，
  重放一致且不同会话不撞 ID。

### 容量上限与回收策略（长期运行不膨胀）

- `NewKeyStoreWith(KeyStoreConfig{Capacity: n})` 设置按**条数**计算的上限
  （`n<=0` 表示不限，`NewKeyStore()` 即不限）。
- 到达上限再 `Put` 时：
  1. **只**回收 `expired / retired / revoked / destroyed` 的条目，按“最早失效优先
     （其次 ID 字典序）”逐个腾位，直到能放入新密钥；
  2. **绝不回收或覆盖仍在有效期内的 `active` 密钥**；
  3. 若一把可回收的都没有，本次写入以 `store_full` 明确失败，库内容一字不动。
- 每次回收都追加一条 `ReclaimEvent` 审计：`KeyID / ParamsVer / Reason
  (expired|retired|revoked|destroyed) / StateBefore / InactiveAt / ReclaimedAt`，
  通过 `store.ReclaimLog()` 可查“回收了谁、为什么、什么时候”。

---

## 5. 会话归档与确定性重放（历史记录）

- `SessionRecord` 是一次会话（成功或失败）的完整可复现归档：记录格式版本
  `RecordSchemaVersion`（`qkd-record-v1`）与协议参数版本正交保存。
- 生命周期相关字段（新增，缺省自动兼容）：`issued`（协议成功但因 `store_full`
  未入库时为 `false`；老记录缺省按 `success` 归一）、`issued_at`（签发时刻）、
  `not_after`（有效期截止，零值为长期有效）。
- `MarshalRecord` / `UnmarshalRecord` 提供 JSON 序列化。解析器**向后兼容**：
  - 缺失 `schema` 时归一为 `qkd-record-v1`；
  - 接受旧字段别名 `params_version`、`abort_reason`；
  - 忽略未知字段，保证“历史会话记录在新版本下仍可解析”；携带未知参数版本的记录
    同样可解析，仅在重放时以 `unsupported_version` 拒绝。
- `qkd.ReplayRecord(rec)` 依据记录里的参数版本/参数/种子做**纯函数式**重放
  （不读写密钥库），返回重放密钥、密钥 ID、统计与失败原因；当记录自带结论时，
  还会比对成功/失败、失败归类、密钥 ID 与密钥长度是否一致，任何漂移都报错。
  v1 记录在 v2 下重放必须与当初**逐比特一致**（由
  `TestV1RecordReplayBitIdentical` 守护）。

---

## 6. 快速上手

```go
// 限容 1000 条的密钥库 + 默认 24h 有效期；时钟可注入（测试用）。
store := qkd.NewKeyStoreWith(qkd.KeyStoreConfig{Capacity: 1000})

mgr, _ := qkd.NewManager(qkd.ManagerConfig{
    Params:     qkd.DefaultParams(),                    // 当前默认 qkd-params-v2
    Channel:    qkd.ChannelConfig{NoiseRate: 0.03},     // 干净信道
    Store:      store,                                  // 可省略，内部新建
    History:    qkd.NewHistory(),                       // 可省略
    MasterSeed: 42,
    KeyTTL:     24 * time.Hour,                         // <=0 表示长期有效
})

keyID, err := mgr.RunSession(context.Background(), "session-001")
switch {
case err == nil:
    // 成功
case qkd.IsFailure(err, qkd.ReasonStoreFull):
    // 容量满且无失效密钥可回收：先 Retire/Destroy 旧密钥，或扩容后重试
case qkd.IsFailure(err, qkd.ReasonEavesdropping):
    // 疑似窃听
case qkd.IsFailure(err, qkd.ReasonUnsupportedVersion):
    // 参数版本不认识
}

key, err := mgr.Store().Get(keyID)
switch {
case err == nil:                                   // active，可用
case qkd.IsFailure(err, qkd.ReasonKeyNotFound):    // 不存在（或已被容量回收）
case qkd.IsFailure(err, qkd.ReasonKeyExpired):     // 已过期
case qkd.IsFailure(err, qkd.ReasonKeyRetired):     // 已退役
case qkd.IsFailure(err, qkd.ReasonKeyRevoked):     // 已撤销
case qkd.IsFailure(err, qkd.ReasonKeyDestroyed):   // 已销毁
}

mgr.Store().Retire(keyID)          // 提前退役（可被容量回收）
mgr.Store().Revoke(keyID)          // 撤销
mgr.Store().Destroy(keyID)         // 销毁（终态）
for _, ev := range mgr.Store().ReclaimLog() { // 回收审计
    log.Printf("reclaimed %s because %s at %s", ev.KeyID, ev.Reason, ev.ReclaimedAt)
}
```

按老记录重放（升级后验证逐比特一致）：

```go
rec, _ := mgr.History().Get("session-001")
rep, err := qkd.ReplayRecord(rec) // 纯计算，不碰密钥库
// rep.Key / rep.KeyID / rep.Stats / rep.Reason 应与归档结论一致
```

并发：

```go
results := mgr.RunSessions(ctx, []string{"a", "b", "c"})
for _, r := range results {          // 各自独立，互不影响
    log.Printf("%s -> %s / %v", r.SessionID, r.KeyID, r.Err)
}
```

需要把新部署钉在旧版本时，显式使用 v1：

```go
mgr, _ := qkd.NewManager(qkd.ManagerConfig{Params: qkd.DefaultParamsV1(), /* ... */})
```

---

## 7. 本地验证方法

无需任何外部服务或硬件，在仓库根目录执行：

```bash
go build ./...          # 编译
go vet ./...            # 静态检查
go test ./...           # 全部单测
go test -race ./...     # 竞态检测（并发隔离）
go test -v ./...        # 查看每个用例打印的“输入参数/判定依据/结论”
```

测试覆盖（新增能力相关以 ★ 标注）：

- `TestSuccessfulNegotiation`：正常协商，得到长度确定且可取回的密钥；
- `TestRepeatability`：相同种子/参数/信道重放，密钥与统计逐比特一致；
- `TestThresholdBoundary`：阈值上下严格判定（0.1471 成功 vs 0.1644 中止）；
- `TestAbortEavesdropping`：高窃听率中止且归类 `eavesdropping_suspected`，无密钥残留；
- `TestAbortChannelNoise`：纯噪声超阈中止且归类 `channel_quality_exceeded`，与窃听可区分；
- `TestSessionCannotProduceTwice`：同一会话不得重复产出密钥；
- `TestConcurrentSessionIsolation`：多会话并发，密钥两两不同、无串扰；
- `TestOneFailureDoesNotAffectOthers`：并发中混入必然失败会话，其它会话与既有密钥完好；
- `TestKeyRevokeAndDestroy`：撤销/销毁后密钥不可再取出，销毁为不可逆终态；
- `TestFailedSessionNoHalfKey`：中途失败不留半成品密钥；
- `TestInvalidParamsRejected`：非法参数归类 `config_invalid`；
- `TestRecordBackwardCompatibility` / `TestRecordRoundTrip`：历史记录兼容解析与往返；
- ★ `TestCapacityEvictsOnlyDeadKeys`：容量满只回收过期密钥，活动密钥不被覆盖，无可回收空间时 `store_full`，回收审计可查；
- ★ `TestCapacityReclaimPriority`：退役/撤销墓碑“最早失效优先”回收；
- ★ `TestCapacityFullEndToEnd`：端到端容量耗尽→会话失败不污染库→退役腾位后恢复签发；
- ★ `TestKeyExpiryAndRetire`：TTL 到期惰性失效、显式退役、状态迁移可区分；
- ★ `TestKeyFailureReasonDistinction`：not_found/expired/retired/revoked/destroyed 五类取用失败两两可区分；
- ★ `TestTerminalStatesCannotRevive`：撤销/销毁/过期密钥不会因回收或升级复活；
- ★ `TestManagerKeyTTL` / `TestSessionCannotIssueTwice`：管理器 TTL 签发、成功会话重复签发防护；
- ★ `TestV2IsDefaultAndV1Supported` / `TestReplayUnknownVersion`：v2 默认、v1 继续支持、未知版本独立归类；
- ★ `TestV1RecordReplayBitIdentical` / `TestV2RecordReplayBitIdentical`：跨版本（含 JSON 往返）重放逐比特一致；
- ★ `TestOldKeyUsableUnderNewVersion`：v1 老密钥在 v2 默认下照常取用并可走生命周期；
- ★ `TestConcurrentSessionsWithReclaim`：并发签发 + 退役 + TTL 到期交织，`-race` 下无竞态、无重复产出、活动密钥不被回收。
