package qkd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
)

// SessionStage 标记会话状态机当前阶段。
type SessionStage string

const (
	StageInit      SessionStage = "init"
	StageQuantum   SessionStage = "quantum_transmit"
	StageSift      SessionStage = "sift"
	StageEstimate  SessionStage = "qber_estimate"
	StageReconcile SessionStage = "reconcile"
	StageAmplify   SessionStage = "privacy_amplify"
	StageCompleted SessionStage = "completed"
	StageAborted   SessionStage = "aborted"
)

// SessionStats 记录会话各阶段的可解释判定数据，
// 测试与日志可据此核对“输入参数 → 判定依据 → 结论”。
type SessionStats struct {
	Stage           SessionStage  `json:"stage"`
	Sent            int           `json:"sent"`
	Sifted          int           `json:"sifted"`
	Sampled         int           `json:"sampled"`
	SampledErrors   int           `json:"sampled_errors"`
	QBER            float64       `json:"qber"`
	Threshold       float64       `json:"threshold"`
	Channel         ChannelStats  `json:"channel"`
	ReconcileFixes  int           `json:"reconcile_fixes"`
	ReconcilePasses int           `json:"reconcile_passes"`
	FinalKeyBytes   int           `json:"final_key_bytes"`
	FinalKeyID      string        `json:"final_key_id,omitempty"`
	AbortReason     FailureReason `json:"abort_reason,omitempty"`
}

// Session 是一次端到端 QKD 协商（Alice 与 Bob 同居于本地模拟中）。
//
// 一个 Session 至多产出一把密钥：Run 成功后再次调用返回
// ReasonSessionReused；Run 失败则会话进入 aborted，且所有中间比特材料
// 立刻清零，不存在可用的半成品密钥。
type Session struct {
	id     string
	params Params
	rng    RandSource // 会话私有随机源（基选择、抽样、置换等）
	stage  SessionStage
	done   bool
	stats  SessionStats
}

// SessionConfig 为构造会话所需的注入项。
type SessionConfig struct {
	ID     string
	Params Params
	// Rand 为会话私有随机源；并发会话应注入互不相同（或域隔离派生）的实例。
	Rand RandSource
}

// NewSession 构造会话（填充默认值并校验参数）。
func NewSession(cfg SessionConfig) (*Session, error) {
	if cfg.ID == "" {
		return nil, fail(ReasonConfigInvalid, "session id must not be empty")
	}
	if cfg.Rand == nil {
		return nil, fail(ReasonConfigInvalid, "session %q requires a RandSource", cfg.ID)
	}
	p := cfg.Params.withDefaults()
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &Session{id: cfg.ID, params: p, rng: cfg.Rand, stage: StageInit,
		stats: SessionStats{Stage: StageInit, Threshold: p.QBERThreshold}}, nil
}

// ID 返回会话标识。
func (s *Session) ID() string { return s.id }

// Stage 返回当前阶段。
func (s *Session) Stage() SessionStage { return s.stage }

// Stats 返回当前统计快照。
func (s *Session) Stats() SessionStats { return s.stats }

// Params 返回会话使用的（已归一化）参数。
func (s *Session) Params() Params { return s.params }

// KeyID 按会话标识、参数版本与所用种子确定性派生密钥 ID，
// 保证相同输入下重放得到相同 ID，也保证不同会话 ID 不会撞 ID。
func KeyID(sessionID string, v ParamsVersion, seed int64) string {
	h := sha256.New()
	h.Write([]byte("qkd-keyid"))
	h.Write([]byte(sessionID))
	h.Write([]byte{0})
	h.Write([]byte(v))
	h.Write([]byte{0})
	var sb [8]byte
	for i := 0; i < 8; i++ {
		sb[i] = byte(seed >> (8 * i))
	}
	h.Write(sb[:])
	sum := h.Sum(nil)
	return "key-" + hex.EncodeToString(sum[:16])
}

// Run 执行完整协商。
func (s *Session) Run(ctx context.Context) ([]byte, error) {
	if s.done {
		return nil, fail(ReasonSessionReused, "session %q has already been run", s.id)
	}
	if err := ctx.Err(); err != nil {
		return nil, s.abort(ReasonSessionAborted, "cancelled before start: %v", err)
	}

	// ---- 阶段 1：量子态制备与传输 ----
	s.stage = StageQuantum
	s.stats.Stage = s.stage
	n := s.params.N
	qubits := make([]Qubit, n)
	aliceBits := make([]uint8, n)
	aliceBases := make([]Basis, n)
	bobBases := make([]Basis, n)
	for i := 0; i < n; i++ {
		aliceBits[i] = uint8(s.rng.Intn(2))
		aliceBases[i] = Basis(s.rng.Intn(2))
		bobBases[i] = Basis(s.rng.Intn(2))
		qubits[i] = Qubit{Basis: aliceBases[i], Bit: aliceBits[i]}
	}
	// 信道噪声/窃听使用独立派生随机流，保证职责清晰且互不污染。
	chRng := NewSeededRand(deriveSeed(s.rng.Seed(), "channel", hashIndex(s.id)))
	ch := NewLocalChannel(ChannelConfig{
		NoiseRate:     s.params.NoiseRate,
		EavesdropRate: s.params.EavesdropRate,
	}, chRng)
	bobBits, _, err := ch.Transmit(QubitSet{Qubits: qubits}, bobBases)
	if err != nil {
		return nil, s.abort(ReasonSessionAborted, "quantum transmit failed: %v", err)
	}
	s.stats.Sent = n
	s.stats.Channel = ch.Stats()
	if err := ctx.Err(); err != nil {
		return nil, s.abort(ReasonSessionAborted, "cancelled: %v", err)
	}

	// ---- 阶段 2：基比对与筛选（sifting）----
	s.stage = StageSift
	s.stats.Stage = s.stage
	type pos struct{ idx int }
	var matchIdx []int
	for i := 0; i < n; i++ {
		if aliceBases[i] == bobBases[i] {
			matchIdx = append(matchIdx, i)
		}
	}
	siftedA := make([]uint8, 0, len(matchIdx))
	siftedB := make([]uint8, 0, len(matchIdx))
	for _, i := range matchIdx {
		siftedA = append(siftedA, aliceBits[i])
		siftedB = append(siftedB, bobBits[i])
	}
	s.stats.Sifted = len(siftedA)
	if len(siftedA) < 16 {
		s.wipeAll(qubits, aliceBits, aliceBases, bobBases, bobBits, siftedA, siftedB)
		return nil, s.abort(ReasonInsufficientBits,
			"only %d sifted bits (need >= 16)", len(siftedA))
	}

	// ---- 阶段 3：抽样误码率估计 ----
	s.stage = StageEstimate
	s.stats.Stage = s.stage
	// 公共信道上随机选取抽样位置；抽样比特从密钥材料中移除。
	restA := make([]uint8, 0, len(siftedA))
	restB := make([]uint8, 0, len(siftedB))
	sampled, errs := 0, 0
	for i := range siftedA {
		if s.drawSample() {
			sampled++
			if siftedA[i] != siftedB[i] {
				errs++
			}
		} else {
			restA = append(restA, siftedA[i])
			restB = append(restB, siftedB[i])
		}
	}
	s.stats.Sampled = sampled
	s.stats.SampledErrors = errs
	if sampled == 0 {
		s.wipeAll(qubits, aliceBits, aliceBases, bobBases, bobBits, siftedA, siftedB, restA, restB)
		return nil, s.abort(ReasonInsufficientBits, "no bits were sampled for QBER estimation")
	}
	qber := float64(errs) / float64(sampled)
	s.stats.QBER = qber
	s.stats.Threshold = s.params.QBERThreshold
	if qber > s.params.QBERThreshold {
		reason := ReasonChannelQuality
		basis := "channel noise"
		if s.stats.Channel.EveIntercepted > 0 {
			reason = ReasonEavesdropping
			basis = "eavesdropping detected"
		}
		s.wipeAll(qubits, aliceBits, aliceBases, bobBases, bobBits, siftedA, siftedB, restA, restB)
		return nil, s.abort(reason,
			"QBER %.4f > threshold %.4f (sampled=%d errors=%d, eveIntercepted=%d); classified as %s",
			qber, s.params.QBERThreshold, sampled, errs,
			s.stats.Channel.EveIntercepted, basis)
	}
	if err := ctx.Err(); err != nil {
		s.wipeAll(qubits, aliceBits, aliceBases, bobBases, bobBits, siftedA, siftedB, restA, restB)
		return nil, s.abort(ReasonSessionAborted, "cancelled: %v", err)
	}
	if len(restA) < s.params.KeyBytes*8 {
		s.wipeAll(qubits, aliceBits, aliceBases, bobBases, bobBits, siftedA, siftedB, restA, restB)
		return nil, s.abort(ReasonInsufficientBits,
			"post-sampling bits %d < required %d for a %d-byte key",
			len(restA), s.params.KeyBytes*8, s.params.KeyBytes)
	}

	// ---- 阶段 4：纠错（信息协调）----
	s.stage = StageReconcile
	s.stats.Stage = s.stage
	recRng := NewSeededRand(deriveSeed(s.rng.Seed(), "reconcile", hashIndex(s.id)))
	rec, err := Reconcile(restA, restB, s.params.BlockSize, s.params.ReconcilePasses, recRng)
	if err != nil {
		s.wipeAll(qubits, aliceBits, aliceBases, bobBases, bobBits, siftedA, siftedB, restA, restB)
		if pe, ok := err.(*ProtocolError); ok {
			return nil, s.abort(pe.Reason, "reconciliation failed: %v", err)
		}
		return nil, s.abort(ReasonReconcileFailed, "reconciliation failed: %v", err)
	}
	s.stats.ReconcileFixes = len(rec.Corrections)
	s.stats.ReconcilePasses = rec.Passes
	// 校验 Bob 与 Alice 已一致（Reconcile 已终验，这里做断言式复核）。
	if !bitsEqual(restA, rec.Corrected) {
		s.wipeAll(qubits, aliceBits, aliceBases, bobBases, bobBits, siftedA, siftedB, restA, restB, rec.Corrected)
		return nil, s.abort(ReasonReconcileFailed, "post-reconcile verification mismatch")
	}

	// ---- 阶段 5：保密放大 ----
	s.stage = StageAmplify
	s.stats.Stage = s.stage
	ctxBytes := buildContext(s.id, s.params.Version, s.rng.Seed())
	key, err := PrivacyAmplify(rec.Corrected, s.params.KeyBytes, ctxBytes)
	if err != nil {
		s.wipeAll(qubits, aliceBits, aliceBases, bobBases, bobBits, siftedA, siftedB, restA, restB, rec.Corrected)
		return nil, s.abort(ReasonSessionAborted, "privacy amplification failed: %v", err)
	}

	// ---- 完成：清除全部中间材料，只返回最终密钥 ----
	s.wipeAll(qubits, aliceBits, aliceBases, bobBases, bobBits, siftedA, siftedB, restA, restB, rec.Corrected)
	s.done = true
	s.stage = StageCompleted
	s.stats.Stage = s.stage
	s.stats.FinalKeyBytes = len(key)
	s.stats.FinalKeyID = KeyID(s.id, s.params.Version, s.rng.Seed())
	return key, nil
}

// drawSample 以 SampleFraction 概率选择一个抽样位置（64 位精度）。
func (s *Session) drawSample() bool {
	return draw(s.rng, s.params.SampleFraction)
}

// abort 将会话置为中止终态并返回携带原因的错误；中止会话不可重跑。
func (s *Session) abort(reason FailureReason, format string, args ...any) error {
	s.done = true
	s.stage = StageAborted
	s.stats.Stage = s.stage
	s.stats.AbortReason = reason
	return fail(reason, format, args...)
}

// wipeAll 清零所有中间比特/字节材料。
func (s *Session) wipeAll(mats ...any) {
	for _, m := range mats {
		switch v := m.(type) {
		case []uint8:
			wipeBytes8(v)
		case []Qubit:
			for i := range v {
				v[i] = Qubit{}
			}
		case []Basis:
			for i := range v {
				v[i] = 0
			}
		}
	}
}

func wipeBytes8(b []uint8) {
	for i := range b {
		b[i] = 0
	}
}

// buildContext 构造与“会话+参数版本+种子”绑定的保密放大上下文，
// 避免不同会话派生出相同密钥。
//
// 域标签按参数版本区分：V1 必须保持原始标签 "qkd-pa-v1" 逐字节不变，
// 以保证老记录重放逐比特一致；V2 使用 "qkd-pa-v2"。
func buildContext(sessionID string, v ParamsVersion, seed int64) []byte {
	tag := "qkd-pa-v2"
	if v == ParamsV1 {
		tag = "qkd-pa-v1"
	}
	out := []byte(tag)
	out = append(out, 0)
	out = append(out, []byte(sessionID)...)
	out = append(out, 0)
	out = append(out, []byte(v)...)
	out = append(out, 0)
	for i := 0; i < 8; i++ {
		out = append(out, byte(seed>>(8*i)))
	}
	return out
}

// hashIndex 从字符串派生一个稳定的非负 int，用于随机流域分隔。
func hashIndex(s string) int {
	sum := sha256.Sum256([]byte(s))
	var v uint64
	for i := 0; i < 8; i++ {
		v = (v << 8) | uint64(sum[i])
	}
	return int(v & 0x7fffffffffffffff)
}
