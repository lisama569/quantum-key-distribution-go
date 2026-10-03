package qkd

import (
	"context"
	"testing"
	"time"
)

// TestKeyExpiryAndRetire 有效期到期与显式退役：取用失败原因互相可区分。
func TestKeyExpiryAndRetire(t *testing.T) {
	base := time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC)
	var clock time.Time = base
	store := NewKeyStoreWith(KeyStoreConfig{Now: func() time.Time { return clock }})

	putKey(t, store, "expiring", ParamsV2, base.Add(time.Hour))
	putKey(t, store, "forever", ParamsV2, time.Time{})
	putKey(t, store, "will-retire", ParamsV2, time.Time{})
	t.Logf("[输入参数] T=%s：expiring 有效期至 +1h，forever 长期，will-retire 长期",
		base.Format(time.RFC3339))

	// 未到期正常取用。
	if _, err := store.Get("expiring"); err != nil {
		t.Fatalf("有效期内应可取用: %v", err)
	}
	// 到期：Get/State 惰性迁移为 expired，字节清零。
	clock = base.Add(time.Hour)
	if st, _ := store.State("expiring"); st != KeyExpired {
		t.Fatalf("[判定依据] 到期状态应为 expired，实际 %s", st)
	}
	if _, err := store.Get("expiring"); !IsFailure(err, ReasonKeyExpired) {
		t.Fatalf("[判定依据] 到期取用应返回 key_expired，实际: %v", err)
	}
	// 时间继续流逝也不会“恢复”。
	clock = base.Add(48 * time.Hour)
	if _, err := store.Get("expiring"); !IsFailure(err, ReasonKeyExpired) {
		t.Fatalf("过期状态必须持久: %v", err)
	}
	t.Logf("[结论] expiring 到期后稳定为 expired，且不返回任何字节")

	// 显式退役。
	if err := store.Retire("will-retire"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get("will-retire"); !IsFailure(err, ReasonKeyRetired) {
		t.Fatalf("[判定依据] 退役后取用应返回 key_retired，实际: %v", err)
	}
	if err := store.Retire("will-retire"); err != nil {
		t.Fatalf("重复退役应幂等，实际: %v", err)
	}
	// 对已退役密钥撤销：进入更严格的 revoked（粘性），取用原因随之可区分。
	if err := store.Revoke("will-retire"); err != nil {
		t.Fatalf("退役密钥允许撤销: %v", err)
	}
	if _, err := store.Get("will-retire"); !IsFailure(err, ReasonKeyRevoked) {
		t.Fatalf("撤销后应返回 key_revoked，实际: %v", err)
	}
	// 长期有效密钥不受时间与其它操作影响。
	if _, err := store.Get("forever"); err != nil {
		t.Fatalf("[结论] 未设有效期的密钥应长期可取用: %v", err)
	}
	t.Logf("[结论] retired→revoked 状态迁移可区分；forever 始终可用")
}

// TestKeyFailureReasonDistinction 五种取用失败原因彼此可区分：
// not_found / expired / retired / revoked / destroyed。
func TestKeyFailureReasonDistinction(t *testing.T) {
	base := time.Date(2026, 10, 3, 15, 0, 0, 0, time.UTC)
	var clock time.Time = base
	store := NewKeyStoreWith(KeyStoreConfig{Now: func() time.Time { return clock }})
	putKey(t, store, "exp", ParamsV2, base.Add(time.Minute))
	putKey(t, store, "ret", ParamsV2, time.Time{})
	putKey(t, store, "rev", ParamsV2, time.Time{})
	putKey(t, store, "des", ParamsV2, time.Time{})

	clock = base.Add(2 * time.Minute)
	if err := store.Retire("ret"); err != nil {
		t.Fatal(err)
	}
	if err := store.Revoke("rev"); err != nil {
		t.Fatal(err)
	}
	if err := store.Destroy("des"); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		id     string
		reason FailureReason
		desc   string
	}{
		{"missing", ReasonKeyNotFound, "密钥根本不存在"},
		{"exp", ReasonKeyExpired, "已过期"},
		{"ret", ReasonKeyRetired, "已退役"},
		{"rev", ReasonKeyRevoked, "已撤销"},
		{"des", ReasonKeyDestroyed, "已销毁"},
	}
	for _, c := range cases {
		_, err := store.Get(c.id)
		if err == nil {
			t.Fatalf("%s：取用必须失败", c.desc)
		}
		if !IsFailure(err, c.reason) {
			t.Fatalf("%s：应归类 %q，实际 %v", c.desc, c.reason, err)
		}
		// 每种原因还必须能和其它四种区分开。
		for _, other := range cases {
			if other.reason != c.reason && IsFailure(err, other.reason) {
				t.Fatalf("%s 的错误竟也匹配 %q", c.desc, other.reason)
			}
		}
		t.Logf("[判定依据:%s] Get(%q) => %v", c.desc, c.id, err)
	}
	if st, err := store.State("missing"); err == nil || st != "" {
		t.Fatalf("不存在密钥 State 也应报 key_not_found，实际 %s/%v", st, err)
	}
	t.Logf("[结论] 五类取用失败原因全部可互相区分")
}

// TestTerminalStatesCannotRevive 已撤销/销毁密钥不会因容量回收或“版本升级”复活。
func TestTerminalStatesCannotRevive(t *testing.T) {
	base := time.Date(2026, 10, 3, 18, 0, 0, 0, time.UTC)
	var clock time.Time = base
	store := NewKeyStoreWith(KeyStoreConfig{Capacity: 100, Now: func() time.Time { return clock }})
	putKey(t, store, "revoked-k", ParamsV1, time.Time{})
	putKey(t, store, "destroyed-k", ParamsV1, time.Time{})
	putKey(t, store, "expired-k", ParamsV1, base.Add(time.Minute))
	if err := store.Revoke("revoked-k"); err != nil {
		t.Fatal(err)
	}
	if err := store.Destroy("destroyed-k"); err != nil {
		t.Fatal(err)
	}
	clock = base.Add(2 * time.Minute)
	if _, err := store.Get("expired-k"); !IsFailure(err, ReasonKeyExpired) {
		t.Fatalf("expected expired: %v", err)
	}

	// 制造容量压力并多次 Put：可回收墓碑会被删除，但绝不可能被重新激活；
	// 已删除条目以 not_found 出现，仍在的条目保持原粘性状态。
	for i := 0; i < 5; i++ {
		id := "filler-" + string(rune('a'+i))
		if err := store.Put(StoredKey{ID: id, Key: []byte(id)}); err != nil {
			t.Fatalf("填充签发失败: %v", err)
		}
	}
	if _, err := store.Get("revoked-k"); err != nil &&
		!(IsFailure(err, ReasonKeyRevoked) || IsFailure(err, ReasonKeyNotFound)) {
		t.Fatalf("撤销密钥只能保持 revoked 或被回收删除，实际: %v", err)
	}
	if _, err := store.Get("destroyed-k"); err != nil &&
		!(IsFailure(err, ReasonKeyDestroyed) || IsFailure(err, ReasonKeyNotFound)) {
		t.Fatalf("销毁密钥只能保持 destroyed 或被回收删除，实际: %v", err)
	}
	// 库内不存在任何一把以这些 ID 为名、可正常取用的“复活”密钥。
	for _, id := range []string{"revoked-k", "destroyed-k", "expired-k"} {
		if k, err := store.Get(id); err == nil {
			t.Fatalf("%s 竟在回收后复活为可用: %+v", id, k)
		}
	}
	// 审计记录说明这些墓碑是被“回收”而非变回 active。
	for _, ev := range store.ReclaimLog() {
		if ev.StateBefore == KeyActive {
			t.Fatalf("回收审计绝不能出现 active 被回收: %+v", ev)
		}
	}
	t.Logf("[结论] 撤销/销毁/过期密钥均未复活；回收审计 %d 条，被回收前状态均非 active",
		len(store.ReclaimLog()))
}

// TestManagerKeyTTL 端到端：管理器按 KeyTTL 为新密钥设有效期，到期不可取用。
func TestManagerKeyTTL(t *testing.T) {
	base := time.Date(2026, 10, 3, 6, 0, 0, 0, time.UTC)
	var clock time.Time = base
	store := NewKeyStoreWith(KeyStoreConfig{Now: func() time.Time { return clock }})
	m, err := NewManager(ManagerConfig{
		Params:     DefaultParams(),
		Channel:    ChannelConfig{NoiseRate: 0.02},
		Store:      store,
		MasterSeed: 31337,
		KeyTTL:     2 * time.Hour,
		Now:        func() time.Time { return clock },
	})
	if err != nil {
		t.Fatal(err)
	}
	id, err := m.RunSession(context.Background(), "ttl-session")
	if err != nil {
		t.Fatal(err)
	}
	rec, _ := m.History().Get("ttl-session")
	wantExpiry := rec.IssuedAt.Add(2 * time.Hour)
	if !rec.NotAfter.Equal(wantExpiry) {
		t.Fatalf("[判定依据] 归档有效期 %s 应=签发时间+TTL %s", rec.NotAfter, wantExpiry)
	}
	t.Logf("[输入参数] KeyTTL=2h issuedAt=%s notAfter=%s",
		rec.IssuedAt.Format(time.RFC3339), rec.NotAfter.Format(time.RFC3339))

	if _, err := store.Get(id); err != nil {
		t.Fatalf("TTL 内应可取用: %v", err)
	}
	clock = base.Add(2 * time.Hour)
	_, expErr := store.Get(id)
	if !IsFailure(expErr, ReasonKeyExpired) {
		t.Fatalf("[结论] 到达有效期应返回 key_expired，实际: %v", expErr)
	}
	t.Logf("[结论] T=%s 密钥到期不可取用: %v", clock.Format(time.RFC3339), expErr)
}

// TestSessionCannotIssueTwice 同一成功会话 ID 不得重复产出密钥
// （管理器层归档防护），失败会话允许重试。
func TestSessionCannotIssueTwice(t *testing.T) {
	m, err := NewManager(ManagerConfig{
		Params: DefaultParams(), Channel: ChannelConfig{NoiseRate: 0.02}, MasterSeed: 2718,
	})
	if err != nil {
		t.Fatal(err)
	}
	id1, err := m.RunSession(context.Background(), "dup")
	if err != nil {
		t.Fatal(err)
	}
	_, err = m.RunSession(context.Background(), "dup")
	if err == nil || !IsFailure(err, ReasonSessionReused) {
		t.Fatalf("[判定依据] 重复会话应返回 session_reused，实际: %v", err)
	}
	// 旧密钥仍然只有一把且可用。
	if _, err := m.Store().Get(id1); err != nil {
		t.Fatalf("[结论] 重复请求不得影响既有密钥: %v", err)
	}
	if len(m.Store().IDs()) != 1 {
		t.Fatalf("库内应仍只有一把密钥，实际 %v", m.Store().IDs())
	}
	t.Logf("[结论] 成功会话 %s 不可重复签发，既有密钥完好: %v", id1, err)
}
