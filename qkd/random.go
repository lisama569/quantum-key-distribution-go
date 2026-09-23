package qkd

import "sync"

// Rand is the deterministic random source injected into every protocol
// operation. Implementations must be safe for concurrent use if sessions
// sharing a source run concurrently; the provided implementations are.
type Rand interface {
	// Intn returns a pseudo-random integer in [0,n). It panics when n <= 0,
	// mirroring math/rand.
	Intn(n int) int
	// Uint64 returns a pseudo-random 64-bit value.
	Uint64() uint64
	// Bool returns a pseudo-random boolean.
	Bool() bool
	// Float64 returns a pseudo-random value in [0,1).
	Float64() float64
	// Read fills p with pseudo-random bytes and returns len(p).
	Read(p []byte) (int, error)
	// Seed derives an independent child source from this source using the
	// given label. Derivation is deterministic: the same parent state and
	// label always yield the same child stream, and different labels never
	// share a stream prefix.
	Seed(label string) Rand
}

// NewSeededRand creates a deterministic Rand from a 64-bit seed.
// The generator uses the splitmix64 update (deterministic, no external
// state) and is safe for concurrent use.
func NewSeededRand(seed uint64) Rand {
	return newSplitMix(seed)
}

// splitMix is a concurrency-safe splitmix64 stream.
type splitMix struct {
	mu    sync.Mutex
	state uint64
}

func newSplitMix(seed uint64) *splitMix {
	return &splitMix{state: seed}
}

// next applies one splitmix64 step and returns the mixed value.
func (s *splitMix) next() uint64 {
	s.state += 0x9e3779b97f4a7c15
	z := s.state
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb
	return z ^ (z >> 31)
}

func (s *splitMix) Uint64() uint64 {
	s.mu.Lock()
	v := s.next()
	s.mu.Unlock()
	return v
}

func (s *splitMix) Intn(n int) int {
	if n <= 0 {
		panic("qkd: Rand.Intn called with non-positive n")
	}
	// Uniform modulo rejection is unnecessary for a simulation that never
	// performs cryptographic judgments on this value directly; division
	// bias here cannot change pass/fail conclusions.
	return int(s.Uint64() % uint64(n))
}

func (s *splitMix) Bool() bool { return s.Uint64()>>63 == 1 }

// float64 returns a value in [0,1) from the top 53 bits of a draw.
func (s *splitMix) Float64() float64 {
	const denom = 1 << 53
	return float64(s.Uint64()>>11) / float64(denom)
}

func (s *splitMix) Read(p []byte) (int, error) {
	for i := 0; i < len(p); {
		v := s.Uint64()
		for j := 0; j < 8 && i < len(p); j++ {
			p[i] = byte(v)
			v >>= 8
			i++
		}
	}
	return len(p), nil
}

// Seed derives a child stream. It draws a label-derived 64-bit salt from the
// parent so two sibling children with different labels get unrelated
// states; the label itself is FNV-1a mixed in as extra separation.
func (s *splitMix) Seed(label string) Rand {
	// FNV-1a 64-bit mix of the label.
	h := uint64(14695981039346656037)
	for i := 0; i < len(label); i++ {
		h ^= uint64(label[i])
		h *= 1099511628211
	}
	parentDraw := s.Uint64()
	return newSplitMix(parentDraw ^ h)
}
