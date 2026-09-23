package qkd

// ChannelConfig 描述本地信道模型的物理参数。
type ChannelConfig struct {
	NoiseRate     float64 `json:"noise_rate"`     // 固有噪声：量子传输后比特翻转概率
	EavesdropRate float64 `json:"eavesdrop_rate"` // Eve 拦截-重发比例
}

// ChannelStats 为一次量子传输结束后信道自报的诊断信息，
// 用于区分“噪声超阈”与“疑似窃听”两类中止原因。
type ChannelStats struct {
	Sent           int     `json:"sent"`
	SameBasis      int     `json:"same_basis"`      // Bob 与 Alice 基一致的位置数
	NoiseFlips     int     `json:"noise_flips"`     // 噪声导致的翻转事件数
	EveIntercepted int     `json:"eve_intercepted"` // Eve 拦截的比特数
	EveDisturbed   int     `json:"eve_disturbed"`   // 拦截且测量基不一致的比特数
	Errors         int     `json:"errors"`          // 同基位置上的实际误码数
	EffectiveQBER  float64 `json:"effective_qber"`  // 同基位置误码率
}

// LocalChannel 是纯本地、确定性的量子信道模型：
// 噪声与窃听事件均由可注入随机源决定，不访问任何外部服务或硬件。
//
// 信道内部为“事件判定 / Eve 行为 / Bob 测量”分别派生独立随机流，
// 避免不同角色共享同一随机序列而产生伪相关（这对窃听扰动的正确
// 模拟至关重要：Eve 必须以独立的 1/2 概率选基并测量）。
type LocalChannel struct {
	cfg    ChannelConfig
	eventR RandSource // 拦截/噪声事件判定
	eveR   RandSource // Eve 选基与测量
	bobR   RandSource // Bob 在错基时的随机测量
	last   ChannelStats
}

// NewLocalChannel 构造本地信道。rng 作为信道根随机源，内部再域隔离派生。
func NewLocalChannel(cfg ChannelConfig, rng RandSource) *LocalChannel {
	return &LocalChannel{
		cfg:    cfg,
		eventR: NewSeededRand(deriveSeed(rng.Seed(), "ch-event", 0)),
		eveR:   NewSeededRand(deriveSeed(rng.Seed(), "ch-eve", 0)),
		bobR:   NewSeededRand(deriveSeed(rng.Seed(), "ch-bob", 0)),
	}
}

// Transmit 模拟一整批量子比特从 Alice 到 Bob 的传输。
//
// 每个量子比特依次经历：
//  1. Eve 以 EavesdropRate 概率拦截：随机选基测量并重发
//     （拦截基与制备基不一致时，重发态被扰动）；
//  2. 信道噪声以 NoiseRate 概率翻转比特；
//  3. Bob 以自己的测量基测量最终到达的量子比特。
//
// 返回 Bob 的测量比特与测量基（即入参 bobBases）。
func (c *LocalChannel) Transmit(qs QubitSet, bobBases []Basis) ([]uint8, []Basis, error) {
	n := len(qs.Qubits)
	if len(bobBases) != n {
		return nil, nil, fail(ReasonConfigInvalid, "bob bases length %d != qubits %d", len(bobBases), n)
	}
	out := make([]uint8, n)
	st := ChannelStats{Sent: n}

	for i, q := range qs.Qubits {
		origBasis := q.Basis
		origBit := q.Bit
		// 1. Eve 拦截-重发（本模拟中全知地记录其行为，仅用于可解释诊断）。
		if c.cfg.EavesdropRate > 0 && draw(c.eventR, c.cfg.EavesdropRate) {
			eveBasis := Basis(c.eveR.Intn(2))
			eveBit := q.Measure(eveBasis, c.eveR)
			st.EveIntercepted++
			if eveBasis != origBasis {
				st.EveDisturbed++
			}
			// Eve 按自己的测量结果重发制备态。
			q = Qubit{Basis: eveBasis, Bit: eveBit}
		}
		// 2. 信道固有噪声：翻转编码比特。
		if c.cfg.NoiseRate > 0 && draw(c.eventR, c.cfg.NoiseRate) {
			q.Bit ^= 1
			st.NoiseFlips++
		}
		// 3. Bob 测量（错基结果走独立的 Bob 随机流）。
		b := bobBases[i]
		var got uint8
		if b == q.Basis {
			got = q.Bit
		} else {
			got = uint8(c.bobR.Intn(2))
		}
		out[i] = got
		// 统计同基（以 Alice 原始制备基为准）位置上的实际误码。
		if b == origBasis && got != origBit {
			st.Errors++
		}
		if b == origBasis {
			st.SameBasis++
		}
	}
	if st.SameBasis > 0 {
		st.EffectiveQBER = float64(st.Errors) / float64(st.SameBasis)
	}
	c.last = st
	return out, bobBases, nil
}

// draw 以概率 p 返回 true，使用 64 位确定性随机源，精度足够区分常见小概率。
func draw(rng RandSource, p float64) bool {
	// 复用 Read 获得 8 个随机字节，映射到 [0,1)。
	var buf [8]byte
	_, _ = rng.Read(buf[:])
	v := float64(uint64FromBytes(buf[:])>>11) / float64(uint64(1)<<53)
	return v < p
}

func uint64FromBytes(b []byte) uint64 {
	var v uint64
	for i := 0; i < 8; i++ {
		v = (v << 8) | uint64(b[i])
	}
	return v
}

// Stats 返回最近一次 Transmit 的诊断统计。
func (c *LocalChannel) Stats() ChannelStats { return c.last }
