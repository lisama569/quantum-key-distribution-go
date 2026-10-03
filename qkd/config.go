package qkd

// ParamsVersion 标识会话参数的版本号。历史会话记录按其产生时的版本归档，
// 新版本必须仍能解析旧版本记录（见 history.go）。
type ParamsVersion string

const (
	// ParamsV1：初始参数版本，继续受支持。
	ParamsV1 ParamsVersion = "qkd-params-v1"
	// ParamsV2：平滑升级的新参数版本，为新会话默认版本；
	// V1 会话记录仍可解析/重放，V1 签发的密钥在 V2 下照常可用。
	ParamsV2 ParamsVersion = "qkd-params-v2"
)

// supportedVersions 为当前实现支持的参数版本集合。
// 老版本只增支持、永不移除；未知版本一律以 unsupported_version 拒绝。
var supportedVersions = map[ParamsVersion]bool{
	ParamsV1: true,
	ParamsV2: true,
}

// Params 是一次会话所用的版本化参数集合。
type Params struct {
	// Version 为参数版本标识；零值按 ParamsV1 处理。
	Version ParamsVersion `json:"version"`
	// N 为 Alice 发送的量子比特（光脉冲）数量。
	N int `json:"n"`
	// SampleFraction 为用于误码率估计的抽样比例，范围 (0,1)。
	SampleFraction float64 `json:"sample_fraction"`
	// QBERThreshold 为可接受的误码率上限；观测 QBER 严格大于该值即中止。
	QBERThreshold float64 `json:"qber_threshold"`
	// NoiseRate 为信道固有噪声造成比特翻转的概率，范围 [0,1]。
	NoiseRate float64 `json:"noise_rate"`
	// EavesdropRate 为 Eve 对量子比特实施拦截-重发攻击的比例，范围 [0,1]。
	EavesdropRate float64 `json:"eavesdrop_rate"`
	// KeyBytes 为保密放大后最终密钥的确定长度（字节）。
	KeyBytes int `json:"key_bytes"`
	// ReconcilePasses 为纠错（级联风格）最大轮数。
	ReconcilePasses int `json:"reconcile_passes"`
	// BlockSize 为纠错分块大小。
	BlockSize int `json:"block_size"`
}

// DefaultParams 返回当前默认版本参数（V2，见 DefaultParamsV2）。
func DefaultParams() Params {
	return DefaultParamsV2()
}

// DefaultParamsV1 返回 v1 默认参数；V1 继续受支持，老会话/老测试可用它钉住旧行为。
func DefaultParamsV1() Params {
	return Params{
		Version:         ParamsV1,
		N:               2048,
		SampleFraction:  0.2,
		QBERThreshold:   0.15,
		NoiseRate:       0.03,
		EavesdropRate:   0.0,
		KeyBytes:        32,
		ReconcilePasses: 16,
		BlockSize:       32,
	}
}

// DefaultParamsV2 返回 v2 默认参数：更大批量、更严格阈值与更多纠错轮数，
// 在同样的确定性随机源下获得更低的抽样噪声与更稳的纠错余量。
func DefaultParamsV2() Params {
	return Params{
		Version:         ParamsV2,
		N:               4096,
		SampleFraction:  0.25,
		QBERThreshold:   0.12,
		NoiseRate:       0.02,
		EavesdropRate:   0.0,
		KeyBytes:        32,
		ReconcilePasses: 24,
		BlockSize:       32,
	}
}

// withDefaults 用“该版本对应”的默认值填充零值字段并归一化版本号，
// 不改变显式给出的字段。
func (p Params) withDefaults() Params {
	var d Params
	switch p.Version {
	case ParamsV2:
		d = DefaultParamsV2()
	default:
		// 零值版本与 V1 一律按 V1 默认归一。
		d = DefaultParamsV1()
	}
	if p.Version == "" {
		p.Version = d.Version
	}
	if p.N == 0 {
		p.N = d.N
	}
	if p.SampleFraction == 0 {
		p.SampleFraction = d.SampleFraction
	}
	if p.QBERThreshold == 0 {
		p.QBERThreshold = d.QBERThreshold
	}
	// KeyBytes 为必填安全参数，0 不做默认填充而交由 Validate 拒绝。
	if p.ReconcilePasses == 0 {
		p.ReconcilePasses = d.ReconcilePasses
	}
	if p.BlockSize == 0 {
		p.BlockSize = d.BlockSize
	}
	return p
}

// Validate 校验参数取值是否合法且版本受支持。
// 未知版本返回 unsupported_version，与其它 config_invalid 失败可区分。
func (p Params) Validate() error {
	if p.Version == "" {
		p = p.withDefaults()
	}
	if !supportedVersions[p.Version] {
		return fail(ReasonUnsupportedVer, "unsupported params version %q", p.Version)
	}
	if p.N < 16 {
		return fail(ReasonConfigInvalid, "n=%d too small (minimum 16)", p.N)
	}
	if p.SampleFraction <= 0 || p.SampleFraction >= 1 {
		return fail(ReasonConfigInvalid, "sample_fraction=%v must be within (0,1)", p.SampleFraction)
	}
	if p.QBERThreshold <= 0 || p.QBERThreshold >= 1 {
		return fail(ReasonConfigInvalid, "qber_threshold=%v must be within (0,1)", p.QBERThreshold)
	}
	if p.NoiseRate < 0 || p.NoiseRate > 1 {
		return fail(ReasonConfigInvalid, "noise_rate=%v must be within [0,1]", p.NoiseRate)
	}
	if p.EavesdropRate < 0 || p.EavesdropRate > 1 {
		return fail(ReasonConfigInvalid, "eavesdrop_rate=%v must be within [0,1]", p.EavesdropRate)
	}
	if p.KeyBytes <= 0 {
		return fail(ReasonConfigInvalid, "key_bytes=%d must be positive", p.KeyBytes)
	}
	if p.ReconcilePasses <= 0 {
		return fail(ReasonConfigInvalid, "reconcile_passes=%d must be positive", p.ReconcilePasses)
	}
	if p.BlockSize <= 1 {
		return fail(ReasonConfigInvalid, "block_size=%d must be greater than 1", p.BlockSize)
	}
	return nil
}
