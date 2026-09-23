package qkd

// Basis 表示 BB84 制备/测量基：标准基 Z（+）或对角基 X（×）。
type Basis uint8

const (
	BasisZ Basis = 0 // 标准基（+）
	BasisX Basis = 1 // 对角基（×）
)

// Qubit 是 BB84 量子比特的本地抽象。
// 它仅记录制备基与编码比特；模拟信道在“被错误基测量”时
// 表现为测量结果随机化，从而体现 BB84 的物理语义：
//
//   - 测量基与制备基一致：测量结果确定等于制备比特；
//   - 测量基与制备基不一致：测量结果以 1/2 概率为 0/1。
type Qubit struct {
	Basis Basis
	Bit   uint8
}

// QubitSet 是一次会话中 Alice 发出的全部量子比特。
type QubitSet struct {
	Qubits []Qubit
}

// Measure 用给定测量基测量量子比特：
// 基一致时得到制备比特；基不一致时结果由 rng 等概率随机决定。
func (q Qubit) Measure(basis Basis, rng RandSource) uint8 {
	if basis == q.Basis {
		return q.Bit
	}
	return uint8(rng.Intn(2))
}

// ClassicalMessage 表示一条经公共信道交换的经典消息
// （基公告、抽样位置、纠错奇偶信息等）。
// 本模拟中公共消息仅承载数据，不改变机密性假设。
type ClassicalMessage struct {
	Type    string
	Bases   []Basis
	Payload []int
}
