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

## 2. 参数含义（版本化配置 `Params`）

参数带版本号 `ParamsVersion`（当前为 `qkd-params-v1`），随会话一起归档；
**相同参数版本 + 相同主种子 + 相同信道配置 → 结果逐比特可复现**。

| 字段 | 含义 | 默认值 | 约束 |
|------|------|--------|------|
| `Version` | 参数版本 | `qkd-params-v1` | 必须受支持 |
| `N` | Alice 发送的量子比特数 | `2048` | ≥ 16 |
| `SampleFraction` | QBER 抽样比例 | `0.2` | (0,1) |
| `QBERThreshold` | 可接受误码率上限 | `0.15` | (0,1)，观测 QBER **严格大于**即中止 |
| `NoiseRate` | 信道固有噪声翻转概率 | `0.03` | [0,1] |
| `EavesdropRate` | Eve 拦截-重发比例 | `0.0` | [0,1] |
| `KeyBytes` | 最终密钥长度（字节） | `32` | > 0（必填，0 直接判错而非取默认） |
| `ReconcilePasses` | 纠错最大轮数 | `16` | > 0 |
| `BlockSize` | 纠错分块大小 | `32` | > 1 |

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
| `config_invalid` | 参数版本不受支持或取值非法 | 否 |
| `session_reused` | 同一 `Session` 重复 `Run`，或密钥 ID 冲突 | 否 |
| `insufficient_bits` | 筛选后位 < 16、无抽样位，或抽样后不足以构成 `KeyBytes*8` 位 | 否 |
| `reconcile_failed` | 达到纠错轮数上限双方仍不一致（终验哈希不等） | 否 |
| `channel_quality_exceeded` | QBER 超阈，且信道诊断**无**窃听拦截事件（判定为固有噪声过差） | 否 |
| `eavesdropping_suspected` | QBER 超阈，且信道诊断**存在** Eve 拦截事件 | 否 |
| `session_aborted` | 上下文取消等其它中止，以及密钥已撤销/销毁/不存在等库操作 | 否 |

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

### 密钥生命周期（`KeyStore`）

| 操作 | 行为 |
|------|------|
| `Get(id)` | 仅 `active` 可取回（返回字节**副本**）；不存在 / 已撤销 / 已销毁均报错，不返回字节 |
| `Revoke(id)` | 置为 `revoked` 并清零字节；幂等；对已销毁密钥调用报错 |
| `Destroy(id)` | 置为终态 `destroyed` 并清零字节，不可逆 |
| `State(id)` / `IDs()` | 状态查询 / 盘点 |

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

---

## 6. 快速上手

```go
mgr, _ := qkd.NewManager(qkd.ManagerConfig{
    Params:     qkd.DefaultParams(),                    // qkd-params-v1
    Channel:    qkd.ChannelConfig{NoiseRate: 0.03},     // 干净信道
    Store:      qkd.NewKeyStore(),                      // 可省略，内部新建
    History:    qkd.NewHistory(),                       // 可省略
    MasterSeed: 42,
})

keyID, err := mgr.RunSession(context.Background(), "session-001")
if err != nil {
    var pe *qkd.ProtocolError
    errors.As(err, &pe)
    switch pe.Reason {
    case qkd.ReasonEavesdropping:   // 疑似窃听
    case qkd.ReasonChannelQuality:  // 噪声过差
    default:                        // 其它失败
    }
}

key, _ := mgr.Store().Get(keyID)     // 32 字节
mgr.Store().Revoke(keyID)            // 撤销后不可再 Get
mgr.Store().Destroy(keyID)           // 销毁（终态）
```

并发：

```go
results := mgr.RunSessions(ctx, []string{"a", "b", "c"})
for _, r := range results {          // 各自独立，互不影响
    log.Printf("%s -> %s / %v", r.SessionID, r.KeyID, r.Err)
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

测试覆盖：

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
- `TestRecordBackwardCompatibility` / `TestRecordRoundTrip`：历史记录兼容解析与往返。
