package qkd

import (
	"context"
	"testing"
	"time"
)

// TestKeyExpiry 有效期：到期前可取，到期后 Get 归类 expired；
// 撤销/销毁不会因为后续时间推进或“版本升级”重新可用。
func TestKeyExpiry(t *testing.T) {
	clk := &fakeClock{t: time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)}
	store := NewKeyStoreWith(KeyStoreConfig{Capacity: 10, Clock: clk.now})
	putKey(t, store, "ttl-key", ParamsV2, clk.now().Add(time.Hour))

	k, err := store.Get("ttl-key")
	if err != nil {
		t.Fatalf("未到期应可取用: %v", err)
	}
	t.Logf("[输入参数] now=%s expiresAt=%s => [判定依据] 到期前 Get 成功 len=%d state=%s",
		clk.now(), k.ExpiresAt, len(k.Key), k.State)

	clk.advance(time.Hour + time.Second)
	_, err = store.Get("ttl-key")
	if !IsFailure(err, ReasonKeyExpired) {
		t.Fatalf("到期后应归类 key_expired，实际: %v", err)
	}
	if st, _ := store.State("ttl-key"); st != KeyExpired {
		t.Fatalf("状态应物化为 expired，实际 %s", st)
	}
	expiredErr := err
	// 时间倒回去也不能复活：expired 是已物化的终态。
	clk.advance(-2 * time.Hour)
	if _, err := store.Get("ttl-key"); !IsFailure(err, ReasonKeyExpired) {
		t.Fatalf("过期物化后即使时钟回退也不得复活，实际: %v", err)
	}
	t.Logf("[结论] 到期即不可取用且状态物化为 expired，时钟回退不复活: %v", expiredErr)
}

// TestKeyRetireLifecycle 显式退役：退役后不可取用、可审计、可被容量回收；
// 退役不能作用于已撤销/已销毁/已过期密钥。
func TestKeyRetireLifecycle(t *testing.T) {
	clk := &fakeClock{t: time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)}
	store := NewKeyStoreWith(KeyStoreConfig{Capacity: 2, Clock: clk.now})
	putKey(t, store, "r1", ParamsV1, time.Time{})
	putKey(t, store, "r2", ParamsV2, time.Time{})

	if err := store.Retire("r1"); err != nil {
		t.Fatalf("退役失败: %v", err)
	}
	if _, err := store.Get("r1"); !IsFailure(err, ReasonKeyRetired) {
		t.Fatalf("退役后应归类 key_retired，实际: %v", err)
	}
	if st, _ := store.State("r1"); st != KeyRetired {
		t.Fatalf("状态应为 retired，实际 %s", st)
	}
	// 退役记录仍可盘点（不是销毁）。
	snap := store.Snapshot()
	var found bool
	for _, sk := range snap {
		if sk.ID == "r1" && sk.State == KeyRetired {
			found = true
		}
	}
	if !found {
		t.Fatal("退役记录应仍留存于盘点中")
	}
	// 退役幂等。
	if err := store.Retire("r1"); err != nil {
		t.Fatalf("重复退役应幂等: %v", err)
	}
	// 容量满且无过期项：新签发应回收已退役的 r1。
	putKey(t, store, "r3", ParamsV2, time.Time{})
	rs := store.Reclamations()
	if len(rs) != 1 || rs[0].KeyID != "r1" || rs[0].Cause != ReclaimRetired {
		t.Fatalf("应回收退役密钥 r1，实际 %+v", rs)
	}
	t.Logf("[结论] 退役密钥不可取用但记录留存，并可被容量回收（%s，原因=%s，为 %s 腾位）",
		rs[0].KeyID, rs[0].Cause, rs[0].ReplacedByID)

	// 过期/撤销/销毁等终态不能再退役。
	clk2 := &fakeClock{t: time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)}
	ts := NewKeyStoreWith(KeyStoreConfig{Clock: clk2.now})
	putKey(t, ts, "exp", ParamsV1, clk2.now().Add(time.Minute))
	putKey(t, ts, "rev", ParamsV1, time.Time{})
	putKey(t, ts, "des", ParamsV1, time.Time{})
	if err := ts.Revoke("rev"); err != nil {
		t.Fatal(err)
	}
	if err := ts.Destroy("des"); err != nil {
		t.Fatal(err)
	}
	clk2.advance(time.Hour)
	if err := ts.Retire("exp"); !IsFailure(err, ReasonKeyExpired) {
		t.Fatalf("对已过期密钥退役应报 key_expired，实际: %v", err)
	}
	if err := ts.Retire("rev"); !IsFailure(err, ReasonKeyRevoked) {
		t.Fatalf("对已撤销密钥退役应报 key_revoked，实际: %v", err)
	}
	if err := ts.Retire("des"); !IsFailure(err, ReasonKeyDestroyed) {
		t.Fatalf("对已销毁密钥退役应报 key_destroyed，实际: %v", err)
	}
	t.Logf("[判定依据] 已过期/已撤销/已销毁密钥均不可退役，[结论] 退役规则区分正确")
}

// TestGetFailureReasonsDistinct 五种取用失败必须互相可区分。
func TestGetFailureReasonsDistinct(t *testing.T) {
	store := NewKeyStore()
	putKey(t, store, "k-revoked", ParamsV1, time.Time{})
	putKey(t, store, "k-destroyed", ParamsV1, time.Time{})
	putKey(t, store, "k-retired", ParamsV1, time.Time{})
	if err := store.Revoke("k-revoked"); err != nil {
		t.Fatal(err)
	}
	if err := store.Destroy("k-destroyed"); err != nil {
		t.Fatal(err)
	}
	if err := store.Retire("k-retired"); err != nil {
		t.Fatal(err)
	}
	// expired 需要可控时钟。
	clk := &fakeClock{t: time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)}
	st2 := NewKeyStoreWith(KeyStoreConfig{Clock: clk.now})
	putKey(t, st2, "k-expired", ParamsV1, clk.now().Add(time.Minute))
	clk.advance(time.Hour)

	cases := []struct {
		name   string
		store  *KeyStore
		id     string
		reason FailureReason
	}{
		{"不存在", store, "nope", ReasonKeyNotFound},
		{"已撤销", store, "k-revoked", ReasonKeyRevoked},
		{"已销毁", store, "k-destroyed", ReasonKeyDestroyed},
		{"已退役", store, "k-retired", ReasonKeyRetired},
		{"已过期", st2, "k-expired", ReasonKeyExpired},
	}
	seen := map[FailureReason]bool{}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := c.store.Get(c.id)
			if !IsFailure(err, c.reason) {
				t.Fatalf("%s 应归类 %q，实际: %v", c.name, c.reason, err)
			}
			seen[c.reason] = true
			t.Logf("[判定依据:%s] id=%s => [结论] %v", c.name, c.id, err)
		})
	}
	if len(seen) != 5 {
		t.Fatalf("五种失败原因必须互不相同，实际收集到 %d 种", len(seen))
	}
}

// TestTerminalStatesNeverRevive 已撤销/已销毁密钥不会因容量回收或“版本升级”
// 重新变成可用；撤销/销毁也不会让记录变成 active。
func TestTerminalStatesNeverRevive(t *testing.T) {
	clk := &fakeClock{t: time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)}
	// 容量 2：r 被撤销后，新密钥入库时回收它，但回收只是删除记录，绝不复活。
	store := NewKeyStoreWith(KeyStoreConfig{Capacity: 2, Clock: clk.now})
	putKey(t, store, "rev", ParamsV1, time.Time{})
	putKey(t, store, "alive", ParamsV2, time.Time{})
	if err := store.Revoke("rev"); err != nil {
		t.Fatal(err)
	}
	putKey(t, store, "new", ParamsV2, time.Time{}) // 触发回收 rev
	// 回收删除了库内记录（Len/IDs 不再含 rev，墓碑可查其原结论），
	// 但 Get 仍按它当初的不可用原因归类为 revoked，而不是笼统的 not_found，
	// 更不可能复活成 active。
	if st, buried := store.Tombstone("rev"); !buried || st != KeyRevoked {
		t.Fatalf("rev 应已被回收并留下 revoked 墓碑，实际 buried=%v state=%s", buried, st)
	}
	if got := store.IDs(); containsID(got, "rev") {
		t.Fatalf("rev 记录应已从库中删除，实际 IDs=%v", got)
	}
	if _, err := store.Get("rev"); !IsFailure(err, ReasonKeyRevoked) {
		t.Fatalf("被回收的撤销记录取用应仍归类 key_revoked（原因可区分、不复活），实际 %v", err)
	}
	if _, err := store.Get("alive"); err != nil {
		t.Fatalf("active 密钥应仍可用: %v", err)
	}

	// 销毁是终态：重复销毁幂等，撤销/退役都被拒绝。
	dstore := NewKeyStore()
	putKey(t, dstore, "d", ParamsV1, time.Time{})
	if err := dstore.Destroy("d"); err != nil {
		t.Fatal(err)
	}
	if err := dstore.Destroy("d"); err != nil {
		t.Fatalf("重复销毁应幂等: %v", err)
	}
	if err := dstore.Revoke("d"); !IsFailure(err, ReasonKeyDestroyed) {
		t.Fatalf("销毁后撤销应报 key_destroyed，实际: %v", err)
	}
	if err := dstore.Retire("d"); !IsFailure(err, ReasonKeyDestroyed) {
		t.Fatalf("销毁后退役应报 key_destroyed，实际: %v", err)
	}
	t.Logf("[结论] 撤销/销毁密钥不会复活：回收只删除失效记录，销毁为不可逆终态")
}

// TestManagerTTL 管理器端到端：配置 KeyTTL 后，新密钥带有效期且到期不可取用。
func TestManagerTTL(t *testing.T) {
	clk := &fakeClock{t: time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)}
	m, err := NewManager(ManagerConfig{
		Params:     DefaultParamsV1(),
		Channel:    ChannelConfig{NoiseRate: 0.02},
		MasterSeed: 909,
		KeyTTL:     time.Hour,
		Clock:      clk.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	id, err := m.RunSession(context.Background(), "ttl-sess")
	if err != nil {
		t.Fatal(err)
	}
	k, err := m.Store().Get(id)
	if err != nil {
		t.Fatal(err)
	}
	want := clk.now().Add(time.Hour)
	if !k.ExpiresAt.Equal(want) {
		t.Fatalf("密钥有效期应为 %v，实际 %v", want, k.ExpiresAt)
	}
	t.Logf("[输入参数] keyTTL=1h；[判定依据] 入库 ExpiresAt=%s", k.ExpiresAt)
	clk.advance(time.Hour + time.Nanosecond)
	_, err = m.Store().Get(id)
	if !IsFailure(err, ReasonKeyExpired) {
		t.Fatalf("TTL 到期后应 key_expired，实际: %v", err)
	}
	t.Logf("[结论] TTL 到期后会话密钥不可取用: %v", err)
}
