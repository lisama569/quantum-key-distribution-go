// Package qkd 是一套纯本地的量子密钥分发（BB84 风格）会话协议模拟组件。
//
// 它不依赖任何外部服务或真实硬件：量子信道由本地确定性模型描述，
// 所有“随机”事件（基选择、噪声翻转、窃听拦截、纠错置换等）均来自可注入、
// 可种子化的 RandSource。相同参数版本 + 相同种子 + 相同信道配置下，
// 会话结果逐比特可复现。
//
// 主要组成：
//   - Params / config.go：版本化会话参数（V1 继续支持，V2 为新会话默认；
//     未知版本以 unsupported_version 拒绝）；
//   - LocalChannel / channel.go：噪声与拦截-重发窃听的本地信道模型；
//   - Session / session.go：单会话状态机（量子传输→基比对筛选→误码率
//     估计→纠错→保密放大），失败即销毁全部中间材料；
//   - KeyStore / keystore.go：密钥生命周期与容量治理——active/retired/
//     expired/revoked/destroyed 五态、TTL 有效期、显式退役、按条计数的
//     容量上限与“只回收失效/退役密钥”的回收策略及回收审计；
//   - Manager / manager.go：多会话并发调度，会话间密钥材料隔离；
//   - History / history.go：版本化、向后兼容的会话归档；
//   - ReplayRecord / replay.go：仅凭归档记录重放协商，老记录得到与当初
//     逐比特一致的结论，供升级后验证兼容性。
package qkd
