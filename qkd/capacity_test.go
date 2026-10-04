package qkd

import (
	"context"
	"sync"
	"testing"
	"time"
)

// fakeClock 是测试用可控时钟；并发测试中可能一边 advance 一边被库读取，
// 故自带互斥保护。
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// putKey 是测试辅助：直接向库存入一条 active 密钥。
func putKey(t *testing.T, s *KeyStore, id string, ver ParamsVersion, exp time.Time) {
	t.Helper()
	if err := s.Put(StoredKey{
		ID: id, Key: []byte("key-material-" + id), State: KeyActive,
		ParamsVer: ver, ExpiresAt: exp,
	}); err != nil {
		t.Fatalf("Put(%s) 失败: %v", id, err)
	}
}

// containsID 判断有序 ID 列表中是否包含某 ID（测试盘点辅助）。
func containsID(ids []string, want string) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}

// TestCapacityEvictsOnlyInvalidKeys 容量上限：库满后只能回收已失效/已退役密钥，
// 绝不丢弃仍可正常取用的密钥；回收审计记录可查。
func TestCapacityEvictsOnlyInvalidKeys(t *testing.T) {
	clk := &fakeClock{t: time.Date(2026, 10, 3, 10, 0, 0, 0, time.UTC)}
	store := NewKeyStoreWith(KeyStoreConfig{Capacity: 3, Clock: clk.now})

	base := clk.now()
	// k1 有效期 1 小时（之后会过期），k2/k3 长期有效。
	putKey(t, store, "k1", ParamsV1, base.Add(time.Hour))
	putKey(t, store, "k2", ParamsV1, time.Time{})
	putKey(t, store, "k3", ParamsV2, time.Time{})
	t.Logf("[输入参数] capacity=%d 初始密钥=k1(1h有效),k2(长期),k3(长期)；当前条数=%d",
		store.Cap(), store.Len())

	// 三条全是 active、且 k1 尚未过期：此时无空间可回收，签发必须明确失败。
	err := store.Put(StoredKey{ID: "k4", Key: []byte("k4mat"), State: KeyActive})
	if err == nil {
		t.Fatal("库满且全部有效时，签发必须失败而不是悄悄挤掉老密钥")
	}
	if !IsFailure(err, ReasonStoreFull) {
		t.Fatalf("满库失败应归类 keystore_full，实际: %v", err)
	}
	if store.Len() != 3 {
		t.Fatalf("失败签发不得改变库内容，实际条数=%d", store.Len())
	}
	for _, id := range []string{"k1", "k2", "k3"} {
		if _, gerr := store.Get(id); gerr != nil {
			t.Fatalf("有效密钥 %s 绝不能被挤掉: %v", id, gerr)
		}
	}
	t.Logf("[判定依据] 全有效时满库 Put 被拒: %v；k1/k2/k3 仍可正常取用", err)

	// 时间推进 2 小时，k1 过期；此时签发 k4 应回收 k1。
	clk.advance(2 * time.Hour)
	if st, _ := store.State("k1"); st != KeyExpired {
		t.Fatalf("k1 应已惰性过期，实际 %s", st)
	}
	putKey(t, store, "k4", ParamsV2, time.Time{})

	// k1 被回收后库内记录已删除，但留有 expired 墓碑：Get/State 仍按
	// “它当初是过期才不可用”归类（key_expired），而不是笼统的 not_found，
	// 更不会因腾挪复活；“为什么被回收”同时保留在回收审计中。
	if st, buried := store.Tombstone("k1"); !buried || st != KeyExpired {
		t.Fatalf("k1 应已被回收并留下 expired 墓碑，实际 buried=%v state=%s", buried, st)
	}
	if _, gerr := store.Get("k1"); !IsFailure(gerr, ReasonKeyExpired) {
		t.Fatalf("k1 已被回收，取用应归类 key_expired（原因可区分、不复活），实际错误: %v", gerr)
	}
	if st, err := store.State("k1"); err != nil || st != KeyExpired {
		t.Fatalf("k1 墓碑状态应可查为 expired，实际 state=%s err=%v", st, err)
	}
	for _, id := range []string{"k2", "k3", "k4"} {
		if _, gerr := store.Get(id); gerr != nil {
			t.Fatalf("回收不应影响其它有效密钥 %s: %v", id, gerr)
		}
	}
	recs := store.Reclamations()
	if len(recs) != 1 {
		t.Fatalf("应有 1 条回收审计，实际 %d", len(recs))
	}
	rc := recs[0]
	if rc.KeyID != "k1" || rc.Cause != ReclaimExpired || rc.ReplacedByID != "k4" {
		t.Fatalf("回收审计内容不符: %+v", rc)
	}
	if !rc.ReclaimedAt.Equal(clk.now()) {
		t.Fatalf("回收时间应为 %v，实际 %v", clk.now(), rc.ReclaimedAt)
	}
	t.Logf("[结论] 满库后回收了 %s（原因=%s，时间=%s，为 %s 腾位）；其余有效密钥完好",
		rc.KeyID, rc.Cause, rc.ReclaimedAt, rc.ReplacedByID)
}

// TestCapacityEvictionPriority 验证回收优先级与“退役/撤销/销毁均可回收”。
func TestCapacityEvictionPriority(t *testing.T) {
	clk := &fakeClock{t: time.Date(2026, 10, 3, 8, 0, 0, 0, time.UTC)}
	store := NewKeyStoreWith(KeyStoreConfig{Capacity: 4, Clock: clk.now})
	putKey(t, store, "active-keep", ParamsV2, time.Time{})
	putKey(t, store, "revoked-k", ParamsV1, time.Time{})
	putKey(t, store, "retired-k", ParamsV1, time.Time{})
	putKey(t, store, "destroyed-k", ParamsV1, time.Time{})
	if err := store.Revoke("revoked-k"); err != nil {
		t.Fatal(err)
	}
	if err := store.Retire("retired-k"); err != nil {
		t.Fatal(err)
	}
	if err := store.Destroy("destroyed-k"); err != nil {
		t.Fatal(err)
	}
	t.Logf("[输入参数] capacity=4，库内状态: active-keep/revoked/retired/destroyed")

	// 优先级最高的是 destroyed：第一条新密钥应回收 destroyed-k。
	putKey(t, store, "new-1", ParamsV2, time.Time{})
	if r := store.Reclamations(); len(r) != 1 || r[0].KeyID != "destroyed-k" ||
		r[0].Cause != ReclaimDestroyed {
		t.Fatalf("应优先回收 destroyed，实际 %+v", r)
	}
	// 接下来 expired 优先于 retired/revoked：让 revoked-k 永不过期，
	// 再造一把过期密钥。先回收 retired（此时无 expired）。
	putKey(t, store, "new-2", ParamsV2, time.Time{})
	rs := store.Reclamations()
	if len(rs) != 2 || rs[1].KeyID != "retired-k" || rs[1].Cause != ReclaimRetired {
		t.Fatalf("第二次应回收 retired，实际 %+v", rs)
	}
	// 最后只剩 revoked 可回收。
	putKey(t, store, "new-3", ParamsV2, time.Time{})
	rs = store.Reclamations()
	if len(rs) != 3 || rs[2].KeyID != "revoked-k" || rs[2].Cause != ReclaimRevoked {
		t.Fatalf("第三次应回收 revoked，实际 %+v", rs)
	}
	// active-keep 与三把新密钥必须全程可用。
	for _, id := range []string{"active-keep", "new-1", "new-2", "new-3"} {
		if _, err := store.Get(id); err != nil {
			t.Fatalf("有效密钥 %s 不应被回收: %v", id, err)
		}
	}
	if store.Len() != 4 {
		t.Fatalf("回收后应仍为容量 4，实际 %d", store.Len())
	}
	t.Logf("[结论] 回收顺序 destroyed→retired→revoked（无过期项时），active 全程不被回收，审计共 %d 条", len(rs))
}

// TestCapacityManagerFullFailsSession 通过管理器端到端验证：库满且不可回收时，
// 这次会话签发明确失败（keystore_full），且库内既有密钥一把不动。
func TestCapacityManagerFullFailsSession(t *testing.T) {
	clk := &fakeClock{t: time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC)}
	m, err := NewManager(ManagerConfig{
		Params:        DefaultParamsV1(),
		Channel:       ChannelConfig{NoiseRate: 0.02},
		MasterSeed:    31337,
		StoreCapacity: 2,
		Clock:         clk.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	id1, err := m.RunSession(context.Background(), "cap-a")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.RunSession(context.Background(), "cap-b"); err != nil {
		t.Fatal(err)
	}
	t.Logf("[输入参数] capacity=2，已签发 cap-a/cap-b，两条均为长期 active")
	before := m.Store().IDs()

	_, err = m.RunSession(context.Background(), "cap-c")
	if err == nil {
		t.Fatal("容量 2 且无失效密钥时，第三把必须签发失败")
	}
	if !IsFailure(err, ReasonStoreFull) {
		t.Fatalf("应归类 keystore_full，实际: %v", err)
	}
	after := m.Store().IDs()
	if len(after) != 2 || after[0] != before[0] || after[1] != before[1] {
		t.Fatalf("失败签发不得改动库：before=%v after=%v", before, after)
	}
	if _, err := m.Store().Get(id1); err != nil {
		t.Fatalf("既有密钥必须仍可取用: %v", err)
	}
	rec, ok := m.History().Get("cap-c")
	if !ok || rec.Success || rec.FailReason != ReasonStoreFull {
		t.Fatalf("失败会话应归档为 keystore_full，实际 %+v ok=%v", rec, ok)
	}
	t.Logf("[结论] 第三把签发失败: %v；既有 %v 完好；失败仅归档不入密钥", err, after)
}
