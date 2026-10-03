// Package qkd implements a purely local, deterministic simulation of a
// quantum-key-distribution (BB84-style) session protocol.
package qkd

import "fmt"

// FailureReason 以类型化枚举的形式给出会话失败/中止原因，
// 调用方可以据此区分“因窃听/噪声中止”与其它失败。
type FailureReason string

const (
	ReasonNone             FailureReason = ""
	ReasonConfigInvalid    FailureReason = "config_invalid"
	ReasonSessionReused    FailureReason = "session_reused"
	ReasonSessionAborted   FailureReason = "session_aborted"
	ReasonInsufficientBits FailureReason = "insufficient_bits"
	ReasonReconcileFailed  FailureReason = "reconcile_failed"
	ReasonEavesdropping    FailureReason = "eavesdropping_suspected"
	ReasonChannelQuality   FailureReason = "channel_quality_exceeded"
	// 密钥库容量已满且没有任何可回收（失效/退役）密钥：本次签发明确失败。
	ReasonStoreFull FailureReason = "store_full"
	// 参数/记录使用了本版本不认识的参数版本，与其它失败原因可区分。
	ReasonUnsupportedVersion FailureReason = "unsupported_version"
	// 密钥取用失败的五类互相可区分结论：
	ReasonKeyNotFound  FailureReason = "key_not_found"
	ReasonKeyExpired   FailureReason = "key_expired"
	ReasonKeyRetired   FailureReason = "key_retired"
	ReasonKeyRevoked   FailureReason = "key_revoked"
	ReasonKeyDestroyed FailureReason = "key_destroyed"
)

// ProtocolError 是本包返回的统一错误类型，携带可机器判别的失败原因。
type ProtocolError struct {
	Reason  FailureReason
	Message string
}

func (e *ProtocolError) Error() string {
	if e.Reason == ReasonNone {
		return e.Message
	}
	return fmt.Sprintf("qkd: %s: %s", e.Reason, e.Message)
}

// IsFailure 判断 err 是否为本包错误且原因为 reason。
func IsFailure(err error, reason FailureReason) bool {
	pe, ok := err.(*ProtocolError)
	return ok && pe.Reason == reason
}

func fail(reason FailureReason, format string, args ...any) error {
	return &ProtocolError{Reason: reason, Message: fmt.Sprintf(format, args...)}
}
