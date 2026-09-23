package qkd

import "encoding/binary"

// RandSource 是可注入的确定性随机源接口。
// 只要两个 RandSource 种子相同，它们产出的“随机”序列就完全一致，
// 从而保证同参数版本、同种子、同信道条件下的会话结果可复现。
type RandSource interface {
	// Intn 返回 [0,n) 的整数；n<=0 时 panic。
	Intn(n int) int
	// Read 用伪随机字节填满 p，始终填满且返回 len(p)。
	Read(p []byte) (int, error)
	// Seed 返回构造该随机源时使用的种子（仅用于记录/展示）。
	Seed() int64
}

// SeededRand 是一个自包含的确定性伪随机源（SplitMix64），
// 不依赖全局 math/rand 状态：每个会话持有各自的实例，
// 因而并发会话之间不存在随机流串扰。
type SeededRand struct {
	seed int64
	s    uint64
}

// NewSeededRand 以 seed 构造确定性随机源。
// seed==0 时映射为固定非零常数，保证“零值”也是确定性的。
func NewSeededRand(seed int64) *SeededRand {
	r := &SeededRand{seed: seed}
	// 用 SplitMix64 把任意种子混入一个高质量初始状态。
	r.s = splitMix64(uint64(seed) + 0x9E3779B97F4A7C15)
	return r
}

// next 返回下一个 64 位伪随机数（SplitMix64）。
func (r *SeededRand) next() uint64 {
	r.s += 0x9E3779B97F4A7C15
	return splitMix64(r.s)
}

func splitMix64(z uint64) uint64 {
	z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
	z = (z ^ (z >> 27)) * 0x94D049BB133111EB
	return z ^ (z >> 31)
}

func (r *SeededRand) Intn(n int) int {
	if n <= 0 {
		panic("qkd: Intn argument must be positive")
	}
	return int(r.next() % uint64(n))
}

func (r *SeededRand) Read(p []byte) (int, error) {
	var buf [8]byte
	i := 0
	for ; i+8 <= len(p); i += 8 {
		binary.LittleEndian.PutUint64(p[i:i+8], r.next())
	}
	if i < len(p) {
		binary.LittleEndian.PutUint64(buf[:], r.next())
		copy(p[i:], buf[:len(p)-i])
	}
	return len(p), nil
}

func (r *SeededRand) Seed() int64 { return r.seed }

var _ RandSource = (*SeededRand)(nil)

// deriveSeed 以父种子、域分隔标签与序号派生子种子。
// 不同 label / index 派生出相互独立（经混合）的子种子，
// 用于把“一个主种子”安全地展开成会话内多个用途各自独立的随机流。
func deriveSeed(parent int64, label string, index int) int64 {
	var h uint64 = splitMix64(uint64(parent) ^ 0xD1B54A32D192ED03)
	for i := 0; i < len(label); i++ {
		h = splitMix64(h ^ uint64(label[i]))
	}
	h = splitMix64(h ^ uint64(index)*0x9E3779B97F4A7C15)
	return int64(h)
}
