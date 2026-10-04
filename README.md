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
- **会话签发的幂等性以会话 ID 为准，且由密钥库永久记账**：`Manager.RunSession`
  成功一次后，该 sessionID 在**这个密钥库内永远不可能再产出第二把密钥**——
  即使它的密钥后来被容量回收、显式退役、撤销、到期清理或销毁，登记都保留；
  即使之后把管理器升级到新参数版本（`ParamsVersion` 变了、派生出的 KeyID
  随之不同），会话级登记依旧把第二次签发挡在门外。第二次调用返回
  `session_reused`（错误信息带当初的 KeyID）。
  - 去重检查与密钥入库在密钥库的**同一把互斥锁内原子完成**
    （`KeyStore.IssueSession`），所以多个 goroutine / 多个共享同一库的管理器
    并发签发同一会话时，**恰有一个成功**，其余全部 `session_reused`，不存在
    “先查后写”的竞态窗口。
  - 只有**成功入库**才会记账；协商中止、取消、库满（`keystore_full`）等失败
    不占用会话名额，排除失败原因后可用同一会话名重试，直到成功一次为止。
  - 可用 `KeyStore.IssuedSession(id)` / `IssuedSessions()` 查询“谁已经成功
    签发过”；该记账不随密钥回收而移除，也不占容量。
- 失败路径（中止、取消、纠错失败、材料不足）会 wipe 掉量子比特、各阶段比特串等
  全部中间材料，密钥库不会写入半成品。

---

## 2. 参数含义与版本升级（版本化配置 `Params`）

参数带版本号 `ParamsVersion`，随会话一起归档；
**相同参数版本 + 相同主种子 + 相同信道配置 → 结果逐比特可复现**。

| 版本 | 状态 | 默认参数（N / 抽样比例 / 阈值 / 纠错轮数） |
|------|------|--------------------------------------------|
| `qkd-params-v1` | **继续支持**（老记录、老密钥行为冻结） | 2048 / 0.20 / 0.15 / 16 |
| `qkd-params-v2` | **新会话默认版本** | 4096 / 0.25 / 0.12 / 24 |

- `DefaultParams()` 返回当前默认（**V2**）；需要钉住旧行为时显式使用
  `DefaultParamsV1()`。两版 `KeyBytes` 默认均为 32、`BlockSize` 均为 32。
- **平滑升级、向后兼容**：
  - 老的 V1 会话记录仍可解析，`ReplayRecord` 按记录重放得到与当初
    **逐比特一致**的密钥、KeyID 与统计/失败结论（V1 的保密放大域标签
    保持原始字节不变）；
  - V1 签发并入库的密钥在 V2 管理器下**照常取用**，版本标记保留、字节不变；
  - 传入不认识的版本（如 `qkd-params-v999`）一律返回
    `unsupported_version`，与 `config_invalid` 等其它失败**明确可区分**；
  - V2 使用独立的保密放大域标签 `qkd-pa-v2`，新旧版本密钥互不串用。

| 字段 | 含义 | V1 默认 | V2 默认 | 约束 |
|------|------|---------|---------|------|
| `Version` | 参数版本 | `qkd-params-v1` | `qkd-params-v2` | 必须受支持，否则 `unsupported_version` |
| `N` | Alice 发送的量子比特数 | `2048` | `4096` | ≥ 16 |
| `SampleFraction` | QBER 抽样比例 | `0.2` | `0.25` | (0,1) |
| `QBERThreshold` | 可接受误码率上限 | `0.15` | `0.12` | (0,1)，观测 QBER **严格大于**即中止 |
| `NoiseRate` | 信道固有噪声翻转概率 | `0.03` | `0.02` | [0,1] |
| `EavesdropRate` | Eve 拦截-重发比例 | `0.0` | `0.0` | [0,1] |
| `KeyBytes` | 最终密钥长度（字节） | `32` | `32` | > 0（必填，0 直接判错而非取默认） |
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
| `config_invalid` | 参数取值非法（阈值范围、批量过小、空密钥、已过期入库等） | 否 |
| `unsupported_version` | 参数版本不被认识（含重放未知版本记录），与 `config_invalid` 可区分 | 否 |
| `session_reused` | 同一 `Session` 重复 `Run`；密钥 ID 冲突；或**同一会话已成功签发过又被再次提交（含密钥被回收/退役/撤销/到期/销毁之后、参数版本升级之后、并发重复提交）** | 否 |
| `insufficient_bits` | 筛选后位 < 16、无抽样位，或抽样后不足以构成 `KeyBytes*8` 位 | 否 |
| `reconcile_failed` | 达到纠错轮数上限双方仍不一致（终验哈希不等） | 否 |
| `channel_quality_exceeded` | QBER 超阈，且信道诊断**无**窃听拦截事件（判定为固有噪声过差） | 否 |
| `eavesdropping_suspected` | QBER 超阈，且信道诊断**存在** Eve 拦截事件 | 否 |
| `keystore_full` | 容量已满且没有任何可回收（已失效/退役）密钥，本次签发被拒 | 否 |
| `key_not_found` | 取用/操作一个库中不存在（或已被回收删除）的密钥 | 否 |
| `key_expired` | 密钥超过有效期（`Get` 惰性物化） | 否 |
| `key_retired` | 密钥已被显式提前退役 | 否 |
| `key_revoked` | 密钥已被撤销 | 否 |
| `key_destroyed` | 密钥已被销毁（终态） | 否 |
| `session_aborted` | 上下文取消等其它中止 | 否 |

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
  `go test -race` 验证。
- 容量回收、显式退役/撤销与多个会话并发发生时同样安全：会话去重检查、回收判定
  与入库在同一把互斥锁内原子完成，**同一会话即使被多个 goroutine / 多个共享库的
  管理器同时提交，也恰有一次成功，其余得到 `session_reused`**；任一会话失败
  （含库满）不影响其它会话与库内已有密钥，会话之间密钥两两不同。

### 容量上限与回收策略（长期运行不膨胀）

- `NewKeyStoreWith(KeyStoreConfig{Capacity: n, Clock: clk})` 按**条数**设置上限；
  `Capacity <= 0` 表示不限制。`ManagerConfig.StoreCapacity` 可在管理器层配置。
- 库已满又要签发新密钥时，**只回收已不可取用的密钥**，按确定性优先级腾位：
  `destroyed → expired → retired → revoked`，同级按“最早到期 → 最早入库 → ID”
  排序。**有效期内的 `active` 密钥永远不会被回收或覆盖。**
- 若库里全是有效密钥、腾不出空间，本次签发**明确失败**为 `keystore_full`，
  库内容一字节不变，失败仅写入会话归档（不会悄悄挤掉老密钥，也不留半成品）。
- **回收只腾位、不抹掉“不可用”的结论**：一条密钥被回收删除时，会留下一块只记
  状态、不含任何密钥字节、也不占容量的**墓碑（tombstone）**。因此：
  - 同一 ID 此后**永远不可能**以 `active` 或任何状态重新 `Put` 入库“复活”，
    容量回收、参数版本升级都不行；尝试入库会按它**当初**的不可用原因
    （`key_expired` / `key_retired` / `key_revoked` / `key_destroyed`）拒绝；
  - 记录虽已从库中删除（不再计入 `Len()` / `IDs()`），对它 `Get` 仍返回
    **当初那一种**可区分的失败原因，而不是笼统的 `key_not_found`；
    `State(id)` / `Tombstone(id)` 仍能查到其终态结论。
- 每一次回收都追加一条 `ReclamationRecord` 审计（回收了谁、当时状态、
  回收原因、回收时间、为哪条新密钥腾位），可经 `KeyStore.Reclamations()` 查询。

### 密钥生命周期（`KeyStore`，五态）

```
                 TTL 到期(惰性)
   active ───────────────────────▶ expired
     │  Retire         ▲ 过期即物化，时钟回退也不复活
     ├──────────────▶ retired
     │  Revoke        │  （退役/过期可升级为撤销）
     ├──────────────▶ revoked
     │  Destroy       ▼
     └──────────────▶ destroyed（终态：撤销/退役/过期均被拒绝，不可复活）
```

| 操作 | 行为 |
|------|------|
| `Get(id)` | 仅“未过期的 `active`”可取回（返回字节**副本**）；不存在 / 已过期 / 已退役 / 已撤销 / 已销毁分别返回 **5 个互不相同**的原因，不返回字节。**记录即使已被容量回收删除，只要留有墓碑，仍按它当初那一种原因失败（可区分、不复活）**；只有从未入库过的 ID 才是 `key_not_found` |
| `Put(k)` | 存入一条密钥；ID 已在库报错；**ID 留有墓碑（曾以某不可用状态被回收）时按原终态原因拒绝，杜绝复活** |
| `IssueSession(sessionID, k)` | 会话签发专用的**原子**入口：同一会话已成功签发过则 `session_reused`，否则在同一把锁内完成容量回收 + 入库 + 会话记账。管理器使用此入口 |
| `IssuedSession(id)` / `IssuedSessions()` | 查询会话是否已成功签发过（及其 KeyID / 参数版本）；记账永久保留、不随回收移除、不占容量 |
| `Tombstone(id)` | 查询已回收 ID 留下的终态结论（`expired/retired/revoked/destroyed`）；未回收或从未入库返回 `false` |
| `Retire(id)` | 显式提前退役并清零字节；记录留存可审计、可被容量回收；幂等；对已撤销/销毁/过期密钥报错 |
| `Revoke(id)` | 置为 `revoked` 并清零字节；幂等；可从 active/retired 转入；对已销毁/已过期报错 |
| `Destroy(id)` | 置为终态 `destroyed` 并清零字节；幂等；**此后回收/版本升级都不可能让它恢复可用** |
| `State(id)` / `IDs()` / `Snapshot()` | 状态查询（会惰性物化过期；墓碑 ID 也可查终态）/ ID 盘点（不含已回收）/ 元数据快照（不带密钥字节） |
| `Reclamations()` / `ReclaimableCount()` / `Len()` / `Cap()` | 回收审计与容量盘点（墓碑与会话记账均不计入条数/容量） |

- 有效期由 `ManagerConfig.KeyTTL`（`time.Duration`）配置，`<=0` 表示不过期；
  也可在 `StoredKey.ExpiresAt` 上直接给出绝对截止时刻。时钟经
  `KeyStoreConfig.Clock` / `ManagerConfig.Clock` 注入（默认 `time.Now`），
  便于用固定时钟验证到期行为。
- 过期判定为 **`ExpiresAt <= now`**（到期时刻即不可用），在 `Get/State/Snapshot`
  及容量回收时惰性物化。

密钥 ID 由 `SHA256("qkd-keyid" ‖ sessionID ‖ paramsVersion ‖ seed)` 确定性派生，
重放一致且不同会话不撞 ID。

---

## 5. 会话归档（历史记录）

- `SessionRecord` 是一次会话（成功或失败）的完整可复现归档：记录格式版本
  `RecordSchemaVersion`（`qkd-record-v1`）与协议参数版本正交保存。
- `MarshalRecord` / `UnmarshalRecord` 提供 JSON 序列化。解析器**向后兼容**：
  - 缺失 `schema` 时归一为 `qkd-record-v1`；
  - 接受旧字段别名 `params_version`、`abort_reason`；
  - 忽略未知字段，保证“历史会话记录在新版本下仍可解析”。
- `ReplayRecord(ctx, record)` 仅凭归档记录（参数版本/参数/种子/信道）重建并重放
  会话，**不读写任何 KeyStore/History**，可并发安全调用。老的 V1 记录在 V2
  成为默认后重放，仍得到与当初**逐比特一致**的密钥、KeyID、统计与失败原因；
  记录版本未知时返回 `unsupported_version`。

---

## 6. 快速上手

```go
mgr, _ := qkd.NewManager(qkd.ManagerConfig{
    Params:        qkd.DefaultParams(),                 // 默认 qkd-params-v2
    Channel:       qkd.ChannelConfig{NoiseRate: 0.02},  // 干净信道
    Store:         qkd.NewKeyStoreWith(qkd.KeyStoreConfig{
        Capacity: 1024,                                 // 按条计数的容量上限
        // Clock: clk,                                  // 可选：注入可控时钟
    }),
    History:       qkd.NewHistory(),                    // 可省略，内部新建
    MasterSeed:    42,
    KeyTTL:        24 * time.Hour,                      // 新密钥有效期（<=0 不过期）
})

keyID, err := mgr.RunSession(context.Background(), "session-001")
if err != nil {
    var pe *qkd.ProtocolError
    errors.As(err, &pe)
    switch pe.Reason {
    case qkd.ReasonEavesdropping:  // 疑似窃听
    case qkd.ReasonChannelQuality: // 噪声过差
    case qkd.ReasonStoreFull:      // 库满且没有可回收的失效密钥
    case qkd.ReasonUnsupportedVer: // 参数版本不认识
    default:                       // 其它失败
    }
}

key, err := mgr.Store().Get(keyID) // 未过期 active：可取回
if err != nil {
    switch {
    case qkd.IsFailure(err, qkd.ReasonKeyNotFound):  // 根本不存在/已被回收
    case qkd.IsFailure(err, qkd.ReasonKeyExpired):   // 已过期
    case qkd.IsFailure(err, qkd.ReasonKeyRetired):   // 已退役
    case qkd.IsFailure(err, qkd.ReasonKeyRevoked):   // 已撤销
    case qkd.IsFailure(err, qkd.ReasonKeyDestroyed): // 已销毁
    }
}
mgr.Store().Retire(keyID)           // 显式提前退役（记录留存，可被回收）
mgr.Store().Revoke(keyID)           // 撤销
mgr.Store().Destroy(keyID)          // 销毁（终态）
for _, rc := range mgr.Store().Reclamations() {
    log.Printf("reclaimed %s because %s at %s for %s",
        rc.KeyID, rc.Cause, rc.ReclaimedAt, rc.ReplacedByID) // 回收审计
}
```

钉住 V1 行为 / 升级后校验老记录重放：

```go
v1 := qkd.DefaultParamsV1()                         // 老版本继续支持
rec, _ := qkd.UnmarshalRecord(archivedJSON)         // 老记录仍可解析
res, err := qkd.ReplayRecord(ctx, rec)              // 不触碰库，纯重放
// res.Key 与当初逐比特一致；未知版本 -> unsupported_version
```

并发：

```go
results := mgr.RunSessions(ctx, []string{"a", "b", "c"})
for _, r := range results {          // 各自独立，互不影响
    log.Printf("%s -> %s / %v", r.SessionID, r.KeyID, r.Err)
}
```

会话幂等与“不可用不复活”：

```go
id1, err := mgr.RunSession(ctx, "session-001")   // 成功，入库 key A
mgr.Store().Revoke(id1)                          // 撤销 A
// ……容量回收把 A 的记录删掉后……
_, err = mgr.RunSession(ctx, "session-001")      // session_reused：绝不会产出第二把
// 即使另起一个 V2 管理器（共享同一密钥库）也是如此

// 直接往库里写一个与被回收密钥同 ID 的 active 密钥，会被墓碑按原终态拒绝：
err = mgr.Store().Put(qkd.StoredKey{ID: id1, Key: k, State: qkd.KeyActive})
// -> key_revoked（曾是 revoked 被回收），不可能复活

if prevKey, ver, ok := mgr.Store().IssuedSession("session-001"); ok {
    log.Print(prevKey, ver)                       // 会话成功签发记录永久可查
}
if state, ok := mgr.Store().Tombstone(id1); ok {  // state == revoked
    log.Print("reclaimed while ", state)
}
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

测试覆盖（原有用例全部保留并保持通过，新增用例标记 🆕）：

- `TestSuccessfulNegotiation`：正常协商，得到长度确定且可取回的密钥；
- `TestRepeatability`：相同种子/参数/信道重放，密钥与统计逐比特一致；
- `TestThresholdBoundary`：V1 阈值上下严格判定（钉住旧版本行为不回归）；
- `TestAbortEavesdropping`：高窃听率中止且归类 `eavesdropping_suspected`，无密钥残留；
- `TestAbortChannelNoise`：纯噪声超阈中止且归类 `channel_quality_exceeded`，与窃听可区分；
- `TestSessionCannotProduceTwice`：同一会话不得重复产出密钥；
- `TestConcurrentSessionIsolation`：多会话并发，密钥两两不同、无串扰；
- `TestOneFailureDoesNotAffectOthers`：并发中混入必然失败会话，其它会话与既有密钥完好；
- `TestKeyRevokeAndDestroy`：撤销/销毁后密钥不可再取出，销毁为不可逆终态；
- `TestFailedSessionNoHalfKey`：中途失败不留半成品密钥；
- `TestInvalidParamsRejected`：非法参数归类 `config_invalid`；
- `TestRecordBackwardCompatibility` / `TestRecordRoundTrip`：历史记录兼容解析与往返；
- 🆕 `TestCapacityEvictsOnlyInvalidKeys`：满库只回收失效密钥、全有效时 `keystore_full`
  明确失败、回收审计（谁/为什么/何时/为谁腾位）可查；
- 🆕 `TestCapacityEvictionPriority`：回收优先级 destroyed→expired→retired→revoked；
- 🆕 `TestCapacityManagerFullFailsSession`：管理器端到端库满失败且既有密钥不动；
- 🆕 `TestKeyExpiry`：TTL 到期不可取用、状态物化、时钟回退不复活；
- 🆕 `TestKeyRetireLifecycle`：显式退役不可取用但留存可审计、可回收、终态不可退役；
- 🆕 `TestGetFailureReasonsDistinct`：不存在/过期/退役/撤销/销毁五种取用失败互不相同；
- 🆕 `TestTerminalStatesNeverRevive`：撤销/销毁密钥不会因回收或升级复活；
- 🆕 `TestManagerTTL`：管理器签发的密钥带有效期且到期不可取用；
- 🆕 `TestV1RecordReplayBitIdentical` / `TestV1FailedRecordReplay`：老 V1 记录在
  V2 默认下重放，成功密钥/失败原因/统计逐比特一致；
- 🆕 `TestDefaultIsV2AndV2Negotiates`：默认版本为 V2 且协商正常；
- 🆕 `TestV1KeyUsableUnderV2Manager`：V1 老密钥在 V2 管理器下照常取用、字节不变；
- 🆕 `TestUnknownVersionRejectedDistinctly`：未知版本归类 `unsupported_version`
  （管理器构造与记录重放两条路径均可区分）；
- 🆕 `TestConcurrentSessionsWithReclamation`：并发协商与过期回收/退役同时发生，
  会话不串扰、结论确定、失败不影响其它会话与库内密钥。
- 🆕 `TestSessionReissueBlockedAfterReclamation`：同一会话成功后，其密钥被
  撤销/退役/销毁/到期并经容量回收后重跑，一律 `session_reused`，绝不产出第二把；
- 🆕 `TestTerminalKeysNeverRevive`：撤销/销毁/退役/过期密钥在容量回收之后、
  以及参数版本升级（V2 管理器、同 ID 重新入库）之后都不复活，取用失败原因
  始终按当初状态可区分；
- 🆕 `TestSessionReissueBlockedAcrossVersionUpgrade`：升级到 V2（KeyID 派生
  结果不同）后同一会话仍不能二次签发，首把 V1 密钥完好；
- 🆕 `TestConcurrentSessionsNoCrossImpactNoDoubleIssue`：A/B 两组会话在容量
  受限、并发回收/退役交织下互不影响，成功密钥两两不同、失败只可能是 `keystore_full`；
- 🆕 `TestConcurrentSameSessionSingleIssue`：同一会话并发提交多次恰有一次成功、
  其余 `session_reused`，库内只有一把密钥，串行重跑同样被拒；
- 🆕 `TestFailedSessionCanRetryUntilSuccess`：协商中止不占会话名额、可重试，
  一旦成功则永久不可再签。

每个用例通过 `t.Logf` 打印 `[输入参数] → [判定依据] → [结论]`，用
`go test -v` 可看到每个场景的输入、判定依据与结论；`go test -race` 覆盖并发路径。
