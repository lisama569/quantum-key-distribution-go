package qkd

import "context"

// ReplayResult 是按归档记录重放一次会话的结果。
type ReplayResult struct {
	KeyID      string
	Key        []byte
	Stats      SessionStats
	Success    bool
	FailReason FailureReason
}

// ReplayRecord 不经过密钥库与历史归档，仅凭一条会话记录重放其协商过程，
// 用于验证“老记录重放得到与当初逐比特一致的结论”。
//
// 它完全依据记录中归档的参数版本/参数/种子/信道配置重建会话，不读取、
// 不改动任何 KeyStore/History，因而重放彼此隔离、可并发安全调用：
//
//   - 记录缺省参数版本时按 ParamsV1 归一（与旧记录解析规则一致）；
//   - 参数版本不受支持时返回 unsupported_version，与其它失败可区分；
//   - 成功时返回与当初逐比特相同的密钥与 KeyID；失败时返回与归档相同的
//     FailureReason 与统计（确定性随机源保证）。
func ReplayRecord(ctx context.Context, rec SessionRecord) (ReplayResult, error) {
	p := rec.Params
	ver := rec.ParamsVer
	if ver == "" {
		ver = ParamsV1
	}
	p.Version = ver
	p = p.withDefaults()
	if err := p.Validate(); err != nil {
		return ReplayResult{Stats: rec.Stats}, err
	}
	seed := rec.Seed
	// 信道配置以归档 Channel 为准，并同步进参数（与 NewManager 的归一一致）。
	ch := rec.Channel
	p.NoiseRate = ch.NoiseRate
	p.EavesdropRate = ch.EavesdropRate

	sess, err := NewSession(SessionConfig{
		ID:     rec.ID,
		Params: p,
		Rand:   NewSeededRand(seed),
	})
	if err != nil {
		return ReplayResult{Stats: rec.Stats}, err
	}
	key, runErr := sess.Run(ctx)
	res := ReplayResult{
		KeyID: KeyID(rec.ID, ver, seed),
		Stats: sess.Stats(),
	}
	if runErr != nil {
		if pe, ok := runErr.(*ProtocolError); ok {
			res.FailReason = pe.Reason
		} else {
			res.FailReason = ReasonSessionAborted
		}
		return res, runErr
	}
	res.Success = true
	res.Key = key
	return res, nil
}
