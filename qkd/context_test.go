package qkd

import (
	"context"
	"testing"
)

// TestContextCancellation 会话开始前被取消：必须中止、归类为 session_aborted、
// 不产出任何密钥。
func TestContextCancellation(t *testing.T) {
	p := DefaultParams()
	sess, err := NewSession(SessionConfig{ID: "cancelled", Params: p, Rand: NewSeededRand(7)})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	key, err := sess.Run(ctx)
	if err == nil {
		t.Fatalf("已取消的上下文必须中止会话，却产出密钥 %x", key)
	}
	if !IsFailure(err, ReasonSessionAborted) {
		t.Fatalf("应归类为 %q，实际: %v", ReasonSessionAborted, err)
	}
	if sess.Stage() != StageAborted {
		t.Fatalf("阶段应为 aborted，实际 %s", sess.Stage())
	}
	// 中止后的会话同样不可重跑。
	if _, err := sess.Run(context.Background()); !IsFailure(err, ReasonSessionReused) {
		t.Fatalf("中止后重跑应返回 session_reused，实际: %v", err)
	}
	t.Logf("[结论] 取消被正确归类: %v；阶段=%s，且不可重跑", err, sess.Stage())
}
