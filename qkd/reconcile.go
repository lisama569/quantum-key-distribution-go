package qkd

// ReconcileResult 为纠错阶段结果。
type ReconcileResult struct {
	// Corrected 为纠错后双方一致的密钥串（以 Alice 视角为准，未做置换）。
	Corrected []uint8
	// Corrections 为在 Bob 视角原串上执行的翻转位置（仅用于记录/可解释性）。
	Corrections []int
	// Passes 为实际执行的纠错轮数。
	Passes int
}

// Reconcile 在公共信道上对筛选后的串做交互式纠错（级联/CASCADE 风格的本地
// 确定性模拟）。alice 视为基准，bob 被修正；rng 用于确定性地选择每轮置换，
// 因此相同输入与种子下纠错过程与结果完全可复现。
//
// 每轮：双方对串做相同的确定性置换，按 blockSize 分块比对奇偶；
// 奇偶不一致的块递归二分，直到定位并翻转 Bob 的单个错误比特。
// 达到 maxPasses 后用哈希做终验；若仍不一致则返回 ReasonReconcileFailed
// （调用方必须中止会话）。
func Reconcile(alice, bob []uint8, blockSize, maxPasses int, rng RandSource) (ReconcileResult, error) {
	if len(alice) != len(bob) {
		return ReconcileResult{}, fail(ReasonReconcileFailed,
			"length mismatch: alice=%d bob=%d", len(alice), len(bob))
	}
	n := len(alice)
	res := ReconcileResult{Corrected: cloneBits(bob)}
	if n == 0 {
		// 空串天然一致；终验也会通过。
		return res, nil
	}
	if blockSize < 2 {
		blockSize = 2
	}

	for pass := 0; pass < maxPasses; pass++ {
		perm := deterministicPermutation(n, pass, rng)
		aPerm := applyPermutation(alice, perm)
		bPerm := applyPermutation(res.Corrected, perm)
		var fixedInPass []int

		for start := 0; start < n; start += blockSize {
			end := start + blockSize
			if end > n {
				end = n
			}
			if parity(aPerm[start:end]) != parity(bPerm[start:end]) {
				idx := bisectLocate(aPerm, bPerm, start, end)
				if idx >= 0 {
					bPerm[idx] ^= 1
					fixedInPass = append(fixedInPass, perm[idx])
				}
			}
		}

		// 把置换空间中的翻转映射回原始顺序。
		for _, idx := range fixedInPass {
			res.Corrected[idx] ^= 1
		}
		res.Corrections = append(res.Corrections, fixedInPass...)
		res.Passes = pass + 1
		if bitsEqual(alice, res.Corrected) {
			return res, nil
		}
	}
	// 终验：哈希仍不一致则纠错失败。
	ha := bitHash(alice, []byte("reconcile-verify"))
	hb := bitHash(res.Corrected, []byte("reconcile-verify"))
	if ha != hb {
		return ReconcileResult{}, fail(ReasonReconcileFailed,
			"strings differ after %d passes (aliceHash=%x bobHash=%x)",
			maxPasses, ha[:8], hb[:8])
	}
	return res, nil
}

// parity 返回区间内 1 的个数奇偶性（公共信道上交换的奇偶信息）。
func parity(b []uint8) uint8 {
	var p uint8
	for _, v := range b {
		p ^= v
	}
	return p
}

// bisectLocate 在 aPerm/bPerm 的 [lo,hi) 中递归二分，
// 返回一个确定存在的错误比特下标（左半奇偶不符则向左，否则向右）。
func bisectLocate(a, b []uint8, lo, hi int) int {
	if hi-lo <= 1 {
		if a[lo] != b[lo] {
			return lo
		}
		return -1
	}
	mid := lo + (hi-lo)/2
	if parity(a[lo:mid]) != parity(b[lo:mid]) {
		return bisectLocate(a, b, lo, mid)
	}
	return bisectLocate(a, b, mid, hi)
}

// deterministicPermutation 返回基于 pass 与 rng 的 Fisher-Yates 置换。
func deterministicPermutation(n, pass int, rng RandSource) []int {
	p := make([]int, n)
	for i := range p {
		p[i] = i
	}
	for i := n - 1; i > 0; i-- {
		j := rng.Intn(i + 1)
		p[i], p[j] = p[j], p[i]
	}
	return p
}

// applyPermutation 返回 out[i] = in[perm[i]]。
func applyPermutation(in []uint8, perm []int) []uint8 {
	out := make([]uint8, len(in))
	for i, j := range perm {
		out[i] = in[j]
	}
	return out
}

func bitsEqual(a, b []uint8) bool {
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

func cloneBits(b []uint8) []uint8 {
	out := make([]uint8, len(b))
	copy(out, b)
	return out
}
