package qkd

import (
	"context"
	"testing"
	"time"
)

// putKey 直接向库存入一把指定状态属性的活动密钥，便于构造容量场景。
func putKey(t *testing.T, s *KeyStore, id string, ver ParamsVersion, notAfter time.Time) {
	t.Helper()
	if err := s.Put(StoredKey{
		ID: id, Key: []byte("key-material-" + id), ParamsVer: ver, NotAfter: notAfter,
	}); err != nil {
		t.Fatalf("存入 %s 失败: %v", id, err)
	}
}

// TestCapacityEvictsOnlyDeadKeys 容量满时：只回收已失效/退役的密钥，
// 活动密钥绝不被覆盖；回收按“最早失效优先”，并留下审计记录。
func TestCapacityEvictsOnlyDeadKeys(t *testing.T) {
	base := time.Date(2026, 10, 3, 10, 0, 0, 0, time.UTC)
	clock := base
	store := NewKeyStoreWith(KeyStoreConfig{Capacity: 3, Now: func() time.Time { return clock }})

	// k1/k2 带有效期；k3 长期有效。
	putKey(t, store, "k1", ParamsV2, base.Add(1*time.Hour))
	putKey(t, store, "k2", ParamsV2, base.Add(2*time.Hour))
	putKey(t, store, "k3", ParamsV2, time.Time{})
	t.Logf("[输入参数] 容量=%d 初始三把活动密钥 k1(1h后过期) k2(2h后过期) k3(长期)", store.Capacity())

	// 容量已满且全部 active：签发必须明确失败，且一把都不能丢。
	err := store.Put(StoredKey{ID: "new-when-full", Key: []byte("x"), ParamsVer: ParamsV2})
	if err == nil || !IsFailure(err, ReasonStoreFull) {
		t.Fatalf("[判定依据] 全活动且容量满应返回 store_full，实际: %v", err)
	}
	if len(store.IDs()) != 3 {
		t.Fatalf("[结论] 签发失败不得改动库内容，实际 %d 把: %v", len(store.IDs()), store.IDs())
	}
	t.Logf("[结论] 无空间可回收时签发明确失败: %v；库内仍为 %v", err, store.IDs())

	// 时间前进 90 分钟：k1 过期（最早失效），k2 仍有效。
	clock = base.Add(90 * time.Minute)
	if st, _ := store.State("k1"); st != KeyExpired {
		t.Fatalf("[判定依据] k1 应已惰性过期，实际 %s", st)
	}
	if err := store.Put(StoredKey{ID: "k4", Key: []byte("y"), ParamsVer: ParamsV2}); err != nil {
		t.Fatalf("存在可回收的过期密钥时应能签发: %v", err)
	}
	if _, getErr := store.Get("k1"); getErr == nil || !IsFailure(getErr, ReasonKeyExpired) {
		// k1 已被回收：记录消失，表现为 not_found；其被回收事实由审计日志保留。
		if getErr == nil || !IsFailure(getErr, ReasonKeyNotFound) {
			t.Fatalf("k1 应已被回收（not_found）或过期不可取，实际: %v", getErr)
		}
	}
	// k2/k3 活动密钥必须原样保留。
	if _, err := store.Get("k2"); err != nil {
		t.Fatalf("[结论] 未过期的 k2 绝不能被回收: %v", err)
	}
	if _, err := store.Get("k3"); err != nil {
		t.Fatalf("[结论] 长期有效的 k3 绝不能被回收: %v", err)
	}
	log := store.ReclaimLog()
	if len(log) != 1 || log[0].KeyID != "k1" || log[0].Reason != ReclaimExpired {
		t.Fatalf("[判定依据] 审计应记录回收 k1(expired)，实际 %+v", log)
	}
	t.Logf("[结论] 回收审计: %+v；库内 %v", log[0], store.IDs())
}

// TestCapacityReclaimPriority 退役/撤销/销毁类墓碑同样可回收，且最早失效优先。
func TestCapacityReclaimPriority(t *testing.T) {
	base := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	clock := base
	store := NewKeyStoreWith(KeyStoreConfig{Capacity: 3, Now: func() time.Time { return clock }})
	putKey(t, store, "active", ParamsV1, time.Time{})
	putKey(t, store, "retired", ParamsV1, time.Time{})
	putKey(t, store, "revoked", ParamsV1, time.Time{})
	if err := store.Retire("retired"); err != nil {
		t.Fatal(err)
	}
	// 让 revoked 的失效时刻早于 retired，确定回收顺序。
	clock = base.Add(time.Minute)
	if err := store.Revoke("revoked"); err != nil {
		t.Fatal(err)
	}
	t.Logf("[输入参数] 容量=3：active/retired(失效于T0)/revoked(失效于T0+1m)")

	err := store.Put(StoredKey{ID: "n1", Key: []byte("n")})
	if err != nil {
		t.Fatalf("有墓碑可回收时签发应成功: %v", err)
	}
	log := store.ReclaimLog()
	if len(log) != 1 || log[0].KeyID != "retired" || log[0].Reason != ReclaimRetired {
		t.Fatalf("[判定依据] 应最早失效优先回收 retired，实际 %+v", log)
	}
	if _, err := store.Get("active"); err != nil {
		t.Fatalf("[结论] active 密钥不得受影响: %v", err)
	}
	t.Logf("[结论] 第一次回收 %s(%s)，活动密钥完好", log[0].KeyID, log[0].Reason)

	// 再签发：此时只剩 revoked 可回收。
	err = store.Put(StoredKey{ID: "n2", Key: []byte("n")})
	if err != nil {
		t.Fatalf("revoked 墓碑应可回收: %v", err)
	}
	log = store.ReclaimLog()
	if log[1].KeyID != "revoked" || log[1].Reason != ReclaimRevoked {
		t.Fatalf("第二次应回收 revoked，实际 %+v", log)
	}
	// 现在 active+n1+n2 三把全活动，再签发必须失败。
	err = store.Put(StoredKey{ID: "n3", Key: []byte("n")})
	if err == nil || !IsFailure(err, ReasonStoreFull) {
		t.Fatalf("[结论] 无可回收密钥时必须 store_full，实际: %v", err)
	}
	t.Logf("[结论] 第二次回收 %s(%s)；全活动时再次签发失败: %v",
		log[1].KeyID, log[1].Reason, err)
}

// TestCapacityFullDoesNotAffectActiveOrManager 端到端：容量耗尽后新会话失败，
// 失败会话不产出密钥，已入库密钥与会话隔离不受影响；腾出空间后恢复签发。
func TestCapacityFullEndToEnd(t *testing.T) {
	base := time.Date(2026, 10, 3, 8, 0, 0, 0, time.UTC)
	var clock time.Time = base
	store := NewKeyStoreWith(KeyStoreConfig{Capacity: 2, Now: func() time.Time { return clock }})
	p := DefaultParams()
	m, err := NewManager(ManagerConfig{
		Params: p, Channel: ChannelConfig{NoiseRate: 0.02},
		Store: store, MasterSeed: 909,
		Now: func() time.Time { return clock },
	})
	if err != nil {
		t.Fatal(err)
	}
	id1, err := m.RunSession(context.Background(), "cap-1")
	if err != nil {
		t.Fatal(err)
	}
	id2, err := m.RunSession(context.Background(), "cap-2")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("[输入参数] 容量=2，已签发 %s %s", id1, id2)

	_, err = m.RunSession(context.Background(), "cap-3")
	if err == nil || !IsFailure(err, ReasonStoreFull) {
		t.Fatalf("[判定依据] 第三把会话应因 store_full 失败，实际: %v", err)
	}
	if _, err := store.Get(id1); err != nil {
		t.Fatalf("[结论] 既有密钥不受影响: %v", err)
	}
	if _, err := store.Get(id2); err != nil {
		t.Fatalf("[结论] 既有密钥不受影响: %v", err)
	}
	if rec, ok := m.History().Get("cap-3"); !ok || rec.Success || rec.Issued || rec.FailReason != ReasonStoreFull {
		t.Fatalf("[判定依据] 入库失败应记为失败归档(issued=false, store_full): %+v", rec)
	}
	t.Logf("[结论] 容量满时会话=%v 且既有两把密钥完好；失败归档 issued=false", err)

	// 显式退役一把腾出空间，新会话可再次签发。
	if err := store.Retire(id2); err != nil {
		t.Fatal(err)
	}
	id4, err := m.RunSession(context.Background(), "cap-4")
	if err != nil {
		t.Fatalf("退役腾出空间后应能签发: %v", err)
	}
	if _, err := store.Get(id4); err != nil {
		t.Fatalf("[结论] 新密钥应可取回: %v", err)
	}
	events := store.ReclaimLog()
	if len(events) != 1 || events[0].KeyID != id2 || events[0].Reason != ReclaimRetired {
		t.Fatalf("应记录退役密钥 %s 被回收，实际 %+v", id2, events)
	}
	t.Logf("[结论] 退役密钥 %s 已回收，新会话签发 %s；审计时刻=%s",
		id2, id4, events[0].ReclaimedAt.Format(time.RFC3339))
}
