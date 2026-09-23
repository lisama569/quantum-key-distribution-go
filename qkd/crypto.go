package qkd

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// bitsToBytes packs a bit slice MSB-first into bytes.
func bitsToBytes(bits []Bit) []byte {
	out := make([]byte, (len(bits)+7)/8)
	for i, b := range bits {
		if b&1 == 1 {
			out[i/8] |= 1 << uint(7-i%8)
		}
	}
	return out
}

// bytesToBits unpacks bytes MSB-first into a bit slice of length nbits.
func bytesToBits(b []byte, nbits int) []Bit {
	out := make([]Bit, nbits)
	for i := 0; i < nbits; i++ {
		if b[i/8]&(1<<uint(7-i%8)) != 0 {
			out[i] = 1
		}
	}
	return out
}

// hashBits returns SHA-256 over a domain-separated prefix and packed bits.
func hashBits(domain string, bits []Bit) [32]byte {
	var out [32]byte
	h := sha256.New()
	h.Write([]byte(domain))
	h.Write([]byte{0})
	h.Write(bitsToBytes(bits))
	h.Sum(out[0:0])
	return out
}

// equalBits reports whether two bit slices are identical.
func equalBits(a, b []Bit) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// countDiffs returns the number of disagreeing positions.
func countDiffs(a, b []Bit) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	d := 0
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			d++
		}
	}
	return d
}

// parity returns the XOR of bits in b[lo:hi].
func parity(b []Bit, lo, hi int) Bit {
	var p Bit
	for i := lo; i < hi; i++ {
		p ^= b[i] & 1
	}
	return p
}

// reconcileBlockSize is the parity block width. At low QBER a block holds at
// most one error with high probability; pairs that cancel parity are broken
// up by the inter-pass permutation.
const reconcileBlockSize = 8

// reconcileResult summarises information reconciliation.
type reconcileResult struct {
	// flips are the positions corrected during bisecting.
	flips []int
	// disclosedBits counts parity bits revealed over the classical channel,
	// consumed later as leakage by privacy amplification.
	disclosedBits int
	rounds        int
}

// reconcile runs a deterministic cascade-like parity protocol that drives
// Bob's bits toward Alice's. Each pass reveals one parity bit per block;
// mismatching blocks are recursively bisected until the single differing
// bit is located and flipped. Between passes both parties apply the same
// public deterministic permutation, so error pairs that produced even
// parity in one pass are separated in the next.
//
// Every revealed block/half parity counts as leaked information and is
// consumed later by privacy amplification. FailureReconcileFailed is
// returned if disagreement remains after all passes.
func reconcile(alice, bob []Bit, passes int) (reconcileResult, error) {
	res := reconcileResult{}
	if len(alice) != len(bob) {
		return res, NewError(FailureReconcileFailed,
			fmt.Sprintf("length mismatch %d vs %d", len(alice), len(bob)))
	}
	n := len(alice)
	idx := make([]int, n)
	for i := range idx {
		idx[i] = i
	}
	permRand := newSplitMix(0xca5cade)
	for round := 0; round < passes; round++ {
		res.rounds++
		if round > 0 {
			shufflePairs(alice, bob, idx, permRand)
		}
		for lo := 0; lo < n; lo += reconcileBlockSize {
			hi := lo + reconcileBlockSize
			if hi > n {
				hi = n
			}
			res.disclosedBits++
			if parity(alice, lo, hi) != parity(bob, lo, hi) {
				res.disclosedBits += bisectFix(alice, bob, lo, hi, &res)
			}
		}
	}
	if !equalBits(alice, bob) {
		return res, NewError(FailureReconcileFailed,
			fmt.Sprintf("residual disagreement %d bits after %d passes",
				countDiffs(alice, bob), passes))
	}
	return res, nil
}

// shufflePairs applies one Fisher-Yates permutation to two aligned bit
// slices and the position map, using the shared public RNG.
func shufflePairs(a, b []Bit, idx []int, rng *splitMix) {
	for i := len(a) - 1; i > 0; i-- {
		j := rng.Intn(i + 1)
		a[i], a[j] = a[j], a[i]
		b[i], b[j] = b[j], b[i]
		idx[i], idx[j] = idx[j], idx[i]
	}
}

// bisectFix recursively locates and flips one error inside [lo,hi). Each
// recursion step discloses one parity bit.
func bisectFix(alice, bob []Bit, lo, hi int, res *reconcileResult) int {
	if hi-lo <= 1 {
		if bob[lo] != alice[lo] {
			bob[lo] ^= 1
			res.flips = append(res.flips, lo)
		}
		return 0
	}
	mid := lo + (hi-lo)/2
	if parity(alice, lo, mid) != parity(bob, lo, mid) {
		return 1 + bisectFix(alice, bob, lo, mid, res)
	}
	return 1 + bisectFix(alice, bob, mid, hi, res)
}

// privacyAmplify derives exactly outBytes bytes from n input bits using a
// deterministic GF(2) linear map. The matrix is generated from a
// session-bound seed so distinct sessions yield unrelated matrices.
//
// leakageBits is information known to the adversary (parity disclosure plus
// estimated eavesdropper knowledge); when the input is too short to produce
// the requested length, FailurePrivacyAmplification is returned.
func privacyAmplify(seed string, in []Bit, leakageBits, outBytes int) ([]byte, error) {
	outBits := outBytes * 8
	if len(in)-leakageBits < outBits {
		return nil, NewError(FailurePrivacyAmplification,
			fmt.Sprintf("insufficient entropy: %d reconciled bits - %d leakage < %d required",
				len(in), leakageBits, outBits))
	}
	rows := buildMatrix(seed, outBits, len(in))
	out := make([]byte, outBytes)
	for r := 0; r < outBits; r++ {
		var acc Bit
		row := rows[r]
		for c := 0; c < len(in); c++ {
			if row[c] == 1 {
				acc ^= in[c]
			}
		}
		if acc == 1 {
			out[r/8] |= 1 << uint(7-r%8)
		}
	}
	return out, nil
}

// buildMatrix deterministically generates rows x cols GF(2) entries from a
// seed via SHA-256 in counter mode.
func buildMatrix(seed string, rows, cols int) [][]Bit {
	m := make([][]Bit, rows)
	buf := make([]Bit, 0, rows*cols)
	var counter uint64
	for len(buf) < rows*cols {
		h := sha256.New()
		h.Write([]byte("qkd-pa-matrix"))
		h.Write([]byte{0})
		h.Write([]byte(seed))
		var ctr [8]byte
		binary.BigEndian.PutUint64(ctr[:], counter)
		h.Write(ctr[:])
		sum := h.Sum(nil)
		for _, x := range sum {
			for j := 7; j >= 0; j-- {
				buf = append(buf, Bit((x>>uint(j))&1))
			}
		}
		counter++
	}
	for r := 0; r < rows; r++ {
		m[r] = buf[r*cols : (r+1)*cols]
	}
	return m
}
