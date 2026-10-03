package qkd

import "context"

// ReplayResult 为按归档记录重放会话的结论。
type ReplayResult struct {
	Key     []byte // 成功时的最终密钥（全新副本）；失败时为 nil
	KeyID   string // 重放派生的密钥 ID
	Stats   SessionStats
	Reason  FailureReason // 失败时的归类原因；成功为 ReasonNone
	Success bool
}

// ReplayRecord 依据一条历史会话记录做确定性重放：
// 使用记录中的参数版本、参数、种子（信道噪声/窃听率随 Params 一并归档），
// 不依赖任何外部状态。
//
// 兼容性约定：
//   - v1/v2 记录均受支持；记录使用未知参数版本时返回 unsupported_version，
//     与其它失败可区分；
//   - v1 记录在新版本下重放，协议过程、统计与密钥必须与当初逐比特一致；
//   - 重放只计算结论，不读写任何密钥库，因此不会影响库内已有密钥。
//
// 当记录自身带有结论（Success/KeyID/FailReason）时，重放会比对结论一致性，
// 不一致即返回错误（说明版本升级破坏了可复现性）。
func ReplayRecord(rec SessionRecord) (ReplayResult, error) {
	p := rec.Params
	if p.Version == "" {
		p.Version = rec.ParamsVer
	}
	p = p.withDefaults()
	if err := p.Validate(); err != nil {
		return ReplayResult{}, err
	}
	// 记录中的信道配置以 Params 内字段为准（管理器归档时二者已归一）。
	sess, err := NewSession(SessionConfig{
		ID:     rec.ID,
		Params: p,
		Rand:   NewSeededRand(rec.Seed),
	})
	if err != nil {
		return ReplayResult{}, err
	}
	keyID := KeyID(rec.ID, p.Version, rec.Seed)
	key, runErr := sess.Run(context.Background())
	stats := sess.Stats()
	res := ReplayResult{KeyID: keyID, Stats: stats}

	if runErr != nil {
		pe, ok := runErr.(*ProtocolError)
		if !ok {
			return ReplayResult{}, fail(ReasonSessionAborted, "replay aborted: %v", runErr)
		}
		res.Reason = pe.Reason
		// 若原记录声明成功而重放失败，说明升级破坏了逐比特可复现性。
		if rec.Success {
			return ReplayResult{}, fail(pe.Reason,
				"replay of session %q failed (%v) but the original record succeeded", rec.ID, runErr)
		}
		if rec.FailReason != "" && pe.Reason != rec.FailReason {
			return ReplayResult{}, fail(pe.Reason,
				"replay failure reason %q != recorded %q for session %q",
				pe.Reason, rec.FailReason, rec.ID)
		}
		return res, nil
	}

	res.Success = true
	res.Key = key
	if !rec.Success {
		return ReplayResult{}, fail(ReasonSessionAborted,
			"replay of session %q succeeded but the original record failed (%q)",
			rec.ID, rec.FailReason)
	}
	if rec.KeyID != "" && rec.KeyID != keyID {
		return ReplayResult{}, fail(ReasonSessionAborted,
			"replay key id %q != recorded %q for session %q", keyID, rec.KeyID, rec.ID)
	}
	if rec.KeyBytes > 0 && len(key) != rec.KeyBytes {
		return ReplayResult{}, fail(ReasonInsufficientBits,
			"replay key length %d != recorded %d for session %q", len(key), rec.KeyBytes, rec.ID)
	}
	return res, nil
}
