# 本地量子密钥分发会话协议组件（Go）

一套**完全本地化、确定性**的 BB84 量子密钥分发（QKD）会话协议模拟组件。
量子信道、随机源与通信双方都在进程内模拟，**不依赖任何外部服务或真实硬件**。
随机源可注入，因此相同输入（会话 ID + 参数版本 + 种子）可逐比特复现协商结果，
噪声、窃听与并发会话下的结论一致且可解释。

- 模块路径：`github.com/lisama569/quantum-key-distribution-go`
- 包：`qkd`（仅使用 Go 标准库）

## 目录结构

| 文件 | 职责 |
| --- | --- |
| `qkd/random.go` | 可注入的确定性随机源（splitmix64），按标签派生子流，并发安全 |
| `qkd/config.go` | 版本化会话参数（`qkd-bb84/v1`、`qkd-bb84/v2`）与范围校验 |
| `qkd/quantum.go` | BB84 量子态与本地信道模型：本征噪声 + 截获-重发窃听，全程记录 |
| `qkd/crypto.go` | 位工具、确定性奇偶纠错（cascade 风格二分）、GF(2) 保密放大 |
| `qkd/session.go` | 会话状态机：量子传输→基比对筛选→误码估计→纠错→保密放大 |
| `qkd/keystore.go` | 密钥生命周期：查询 / 撤销 / 销毁（清零），防御性拷贝，并发安全 |
| `qkd/record.go` | 版本化历史会话记录（JSON 前向/后向兼容），只存统计不存密钥 |
| `qkd/manager.go` | 多会话并发管理：独立种子、独立材料、共享存储互斥隔离 |
| `qkd/errors.go` | 稳定可区分的失败原因分类码 |

## 协议流程

一次会话（`Session.Run`）严格按以下阶段推进，任一步失败立即终态化、
**不产生也不残留任何半成品密钥**：

1. **建立（参数校验）**：校验参数版本与取值范围；从根随机源按
   `alice:<id>` / `bob:<id>` / `noise:<id>` / `eve:<id>` 标签派生相互独立的
   随机流，保证不同会话不共享随机前缀或密钥材料。
2. **量子态传输**：Alice 生成随机比特与基，通过本地信道逐个发送光子；
   Bob 用自己的随机基测量。信道确定性地施加：
   - **本征噪声**：以 `NoiseRate` 概率独立翻转测量结果；
   - **截获-重发窃听**（`Eavesdrop=true` 时）：Eve 以随机基测量并按坍缩态重发，
     基不匹配时会以 50% 概率向 Bob 引入错误。每个窃听位置都被记录。
3. **基比对与筛选（sifting）**：双方公开比对测量基，只保留基一致的位置。
   筛选位过少（无法估错或不足以产出目标长度密钥）时以
   `sifted_key_too_short` 中止。
4. **误码率估计**：确定性地牺牲筛选密钥的前 `SampleFraction` 比例作为样本，
   统计样本错误数并计算 QBER = 样本错误数 / 样本位数。
5. **质量判定 / 窃听识别**（见下文规则）。
6. **信息纠错（reconciliation）**：对剩余位运行确定性奇偶块协议；
   块奇偶不一致时递归二分定位并翻转单个错误位，各轮间双方使用同一公开
   确定性置换打散“偶数错误抵消”。结束后用 SHA-256 摘要互相验证；
   不一致分别返回 `reconciliation_failed` / `verification_mismatch`。
   公开的奇偶位数计入保密放大的“泄露预算”。
7. **保密放大（privacy amplification）**：以“会话 ID + 参数版本”为种子，
   用 SHA-256 计数器模式确定性生成 GF(2) 矩阵，把纠错后位串线性压缩为
   **恰好 `FinalKeyLength` 字节**的最终密钥。泄露位（奇偶披露 + 落入密钥区的
   窃听接触位）后熵不足时返回 `privacy_amplification_failed`。
8. **产出**：双方独立做保密放大并确认结果一致；密钥 ID 由
   `会话 ID + 版本 + 密钥材料` 的 SHA-256 确定性派生。成功只此一次，
   会话进入终态；重复 `Run` 返回 `session_reused`。

## 参数含义（版本化）

| 字段 | 含义 | v1 默认 | v2 默认 |
| --- | --- | --- | --- |
| `Version` | 参数集版本标识 | `qkd-bb84/v1` | `qkd-bb84/v2` |
| `PhotonCount` | 量子阶段发送的光子数 | 2048 | 4096 |
| `SampleFraction` | 用于估错而牺牲的筛选位比例，取值 (0,1) | 0.20 | 0.25 |
| `QBERThreshold` | 误码率中止阈值，取值 [0,1] | 0.15 | 0.11 |
| `CorrectPasses` | 纠错轮数上界 | 3 | 3 |
| `FinalKeyLength` | 最终密钥长度（字节），确定性产出 | 32 | 64 |
| `NoiseRate` | 信道本征翻转概率 [0,1] | 0.02 | 0.02 |
| `Eavesdrop` | 是否启用截获-重发对手 | false | false |

同一版本的相同输入结果可复现；不同版本彼此独立。`DefaultParameters(version)`
返回内置默认值，`Parameters.Validate()` 做范围校验。

## 失败与中止判定规则

判定为**严格比较**：仅当 `QBER > QBERThreshold` 时中止（相等放行）。

- 超阈值且**样本中存在窃听接触** → `eavesdropping_detected`
  （消息中给出 QBER、阈值、样本内窃听接触数与错误位数）。
- 超阈值但**无窃听接触**（纯噪声导致信道质量过差）→ `qber_threshold_exceeded`
  （给出 QBER、阈值、错误位数与总噪声翻转数）。
- 两者 QBER 可能非常接近，但失败码不同，**原因可区分**。
- 其余失败码：`bad_parameters`、`aborted`（上下文取消）、
  `sifted_key_too_short`、`reconciliation_failed`、`verification_mismatch`、
  `privacy_amplification_failed`、`session_reused`；
  密钥访问侧：`key_not_found` / `key_revoked` / `key_destroyed`。

所有错误均为 `*qkd.ProtocolError`，可用 `qkd.AsProtocolError(err)` 取出
`Code` 做程序化判别。失败会话：状态 `failed`、记录中 `success=false`、
`key_id` 为空，密钥库不写入任何内容，内部中间位串被清零。

## 密钥生命周期

- `KeyStore.Put` 存储新密钥（拒绝空密钥与重复 ID）；
- `Get` 仅返回 **active** 密钥的防御性拷贝；
  - 未知 ID → `key_not_found`
  - 已撤销 → `key_revoked`
  - 已销毁 → `key_destroyed`（材料已被清零，长度记 0）
- `Revoke` 行政撤销；`Destroy` 覆写并解链密钥字节（幂等）。
- 撤销/销毁后的密钥**永远无法再被取出**。

## 并发会话隔离

`Manager` 为每个会话从根随机源按唯一会话 ID 与调用方 salt 派生独立种子；
各会话在 goroutine 中并发运行，共享的密钥库与记录簿均由互斥锁保护。
终态记录通过单一 `onFinish` 钩子落库：**无论成败都写记录，只有成功才写密钥**。
任一会话失败不影响其它会话，也不改动密钥库既有内容。

## 历史记录可解析性

会话记录使用 `qkd-record/v1` JSON schema：
- 只含统计与元数据，**不含任何密钥字节**（有测试断言序列化结果不含密钥）；
- 解析旧记录时忽略未知字段，缺失的参数字段按该参数版本的默认值补齐；
- `SessionRecord.Marshal()` / `qkd.ParseRecord()` 负责序列化与兼容解析。

## 本地验证方法

```bash
# 构建
go build ./...

# 全量单测（含正常协商、超阈值中止、窃听识别、错误归类、
# 并发隔离、撤销/销毁后访问、记录兼容性）
go test ./... -v

# 带竞态检测（并发隔离用例）
go test ./... -race -count=1
```

测试通过注入的 `Logger` 在单测日志中打印每一步的**输入参数与判定依据**
（光子数、样本位、错误数、QBER、阈值、窃听接触数、泄露位、最终长度等）。
最小用法见 `qkd.ExampleSession`，典型用法：

```go
p, _ := qkd.DefaultParameters(qkd.ConfigV1)
s := qkd.NewSession("session-1", p, qkd.NewSeededRand(42))
key, err := s.Run(context.Background())
if err != nil {
    var pe *qkd.ProtocolError
    errors.As(err, &pe)
    log.Fatal(pe.Code, pe.Message) // 稳定失败码 + 可解释原因
}
// key.Secret 长度恰为 p.FinalKeyLength；再次调用 s.Run 会得到 session_reused。
```

使用 `Manager` 并发执行：

```go
mgr := qkd.NewManager(qkd.NewSeededRand(999), logger)
ch := mgr.StartSession("a", paramsV1, 11) // 异步
result := <-ch
mgr.Keys().Revoke(result.Key.ID, time.Now())
mgr.Keys().Destroy(result.Key.ID, time.Now())
```
