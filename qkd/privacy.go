package qkd

import (
	"crypto/sha256"
	"encoding/binary"
)

// PrivacyAmplify 对纠错后的比特串执行保密放大，
// 输出长度由 keyBytes 唯一确定，context 与会话/阶段绑定以防跨会话串扰。
//
// 采用 SHA-256 计数器模式提取：
//
//	K_i = SHA256(context || be64(i) || packBits(input))
//
// 并将各 K_i 顺序拼接后截取前 keyBytes 字节。SHA-256 是标准库内的
// 确定性原语，无需任何外部服务。
func PrivacyAmplify(input []uint8, keyBytes int, context []byte) ([]byte, error) {
	if keyBytes <= 0 {
		return nil, fail(ReasonConfigInvalid, "key_bytes=%d must be positive", keyBytes)
	}
	if len(input) == 0 {
		return nil, fail(ReasonInsufficientBits, "privacy amplification requires non-empty input")
	}
	packed := packBits(input)
	out := make([]byte, 0, keyBytes)
	var ctrBuf [8]byte
	for ctr := uint64(0); len(out) < keyBytes; ctr++ {
		h := sha256.New()
		h.Write(context)
		binary.BigEndian.PutUint64(ctrBuf[:], ctr)
		h.Write(ctrBuf[:])
		h.Write(packed)
		out = h.Sum(out)
	}
	return out[:keyBytes], nil
}

// packBits 将比特串按高位优先（MSB-first）打包为字节；
// 末尾不足 8 位的部分以 0 填充。
func packBits(bits []uint8) []byte {
	out := make([]byte, (len(bits)+7)/8)
	for i, b := range bits {
		if b&1 == 1 {
			out[i>>3] |= 1 << uint(7-(i&7))
		}
	}
	return out
}

// bitHash 计算“带域标签”的比特串 SHA-256 摘要，
// 用于纠错终验等一致性检查；不同 tag 区分不同用途，避免摘要混用。
func bitHash(bits []uint8, tag []byte) [32]byte {
	h := sha256.New()
	h.Write(tag)
	h.Write([]byte("||"))
	h.Write(packBits(bits))
	var l [8]byte
	binary.BigEndian.PutUint64(l[:], uint64(len(bits)))
	h.Write(l[:])
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return sum
}
