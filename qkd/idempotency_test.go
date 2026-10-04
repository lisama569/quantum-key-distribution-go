package qkd

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

// invalidateKey 按场景把管理器签发的密钥置入某种不可用状态。
func invalidateKey(t *testing.T, store *KeyStore, clk *fakeClock, keyID, scene string) {
	t.Helper()
	switch scene {
	case "revoked":
		if err := store.Revoke(keyID); err != nil {
			t.Fatalf("撤销 %s 失败: %v", keyID, err)
		}
	case "destroyed":
		if err := store.Destroy(keyID); err != nil {
			t.Fatalf("销毁 %s 失败: %v", keyID, err)
		}
	case "retired":
		if err := store.Retire(keyID); err != nil {
			t.Fatalf("退役 %s 失败: %v", keyID, err)
		}
	case "expired":
		clk.advance(time.Hour) // TTL=1 分钟，推进后惰性过期
		if st, _ := store.State(keyID); st != KeyExpired {
			t.Fatalf("%s 应已过期，实际状态 %s", keyID, st)
		}
	default:
		t.Fatalf("未知场景 %s", scene)
	}
}

// TestReissueAfterKeyReclaimed 同一会话成功签发后，其密钥无论因撤销/销毁/
// 退役/过期而被容量回收清除，同一会话重跑都必须被拒绝（session_reused），
// 绝不会产出第二把密钥。
func TestReissueAfterKeyReclaimed(t *testing.T) {
	scenes := []string{"revoked", "destroyed", "retired", "expired"}
	for _, scene := range scenes {
		t.Run(scene, func(t *testing.T) {
			clk := &fakeClock{t: time.Date(2026, 10, 4, 10, 0, 0, 0, time.UTC)}
			store := NewKeyStoreWith(KeyStoreConfig{Capacity: 1, Clock: clk.now})
			hist := NewHistory()
			m, err := NewManager(ManagerConfig{
				Params:        DefaultParamsV2(),
				Channel:       ChannelConfig{NoiseRate: 0.02},
				Store:         store,
				History:       hist,
				MasterSeed:    4242,
				StoreCapacity: 1,
				KeyTTL:        time.Minute, // expired 场景使用；其余场景下未到期
				Clock:         clk.now,
			})
			if err != nil {
				t.Fatal(err)
			}
			sessionID := "once-" + scene
			keyID1, err := m.RunSession(context.Background(), sessionID)
			if err != nil {
				t.Fatalf("首次签发应成功: %v", err)
			}
			t.Logf("[输入参数:%s] session=%s 首次密钥=%s capacity=1 ttl=1m",
				scene, sessionID, keyID1)

			// 把密钥置入对应不可用状态，再用一条新密钥把它容量回收掉。
			invalidateKey(t, store, clk, keyID1, scene)
			putKey(t, store, "filler-"+scene, ParamsV2, time.Time{})
			recs := store.Reclamations()
			if len(recs) != 1 || recs[0].KeyID != keyID1 {
				t.Fatalf("[判定依据] 原密钥应已被容量回收，实际审计=%+v", recs)
			}
			if _, gerr := store.Get(keyID1); !IsFailure(gerr, ReasonKeyNotFound) {
				t.Fatalf("[判定依据] 原密钥记录应已被回收删除，实际: %v", gerr)
			}
			t.Logf("[判定依据:%s] 原密钥先置为 %s，再因容量满被回收（cause=%s，由 filler 腾位）",
				scene, scene, recs[0].Cause)

			// 重跑同一会话：必须拒绝，且库里不能多出第二把该会话的密钥。
			keyID2, err := m.RunSession(context.Background(), sessionID)
			if !IsFailure(err, ReasonSessionReused) {
				t.Fatalf("[结论] 密钥被回收后同会话重跑必须 session_reused，实际 key=%s err=%v",
					keyID2, err)
			}
			if keyID2 != "" {
				t.Fatalf("被拒绝时不应返回 KeyID，实际 %q", keyID2)
			}
			if _, gerr := store.Get(keyID1); !IsFailure(gerr, ReasonKeyNotFound) {
				t.Fatalf("重跑不得让被回收的原密钥复活，实际: %v", gerr)
			}
			if ids := store.IDs(); len(ids) != 1 || ids[0] != "filler-"+scene {
				t.Fatalf("库内应只有 filler 一条，实际 %v", ids)
			}
			rec, ok := hist.Get(sessionID)
			if !ok || !rec.Success || rec.KeyID != keyID1 {
				t.Fatalf("归档必须保留首次成功结论且不被失败覆盖: %+v ok=%v", rec, ok)
			}
			t.Logf("[结论:%s] 回收后重跑被拒: %v；归档仍为首次成功 key=%s，库内=%v",
				scene, err, keyID1, store.IDs())
		})
	}
}

// TestReissueRefusedAcrossVersionUpgrade 参数版本升级后，同一会话仍不得
// 二次签发——即使新版本下派生出的 KeyID 与旧密钥不同（旧实现正是因此漏判）。
// 分两种情形：旧密钥仍在库 / 旧密钥已被回收。
func TestReissueRefusedAcrossVersionUpgrade(t *testing.T) {
	for _, evicted := range []bool{false, true} {
		name := "old-key-present"
		if evicted {
			name = "old-key-reclaimed"
		}
		t.Run(name, func(t *testing.T) {
			clk := &fakeClock{t: time.Date(2026, 10, 4, 11, 0, 0, 0, time.UTC)}
			store := NewKeyStoreWith(KeyStoreConfig{Capacity: 2, Clock: clk.now})
			hist := NewHistory()
			v1m, err := NewManager(ManagerConfig{
				Params: DefaultParamsV1(), Channel: ChannelConfig{NoiseRate: 0.02},
				Store: store, History: hist, MasterSeed: 5151, Clock: clk.now,
			})
			if err != nil {
				t.Fatal(err)
			}
			oldID, err := v1m.RunSession(context.Background(), "upgrade-session")
			if err != nil {
				t.Fatalf("V1 首次签发应成功: %v", err)
			}
			oldKey, gerr := store.Get(oldID)
			if gerr != nil {
				t.Fatal(err)
			}
			t.Logf("[输入参数:%s] V1 签发 %s（ver=%s），随后升级到 V2 管理器（共享库/归档）",
				name, oldID, oldKey.ParamsVer)

			if evicted {
				if err := store.Revoke(oldID); err != nil {
					t.Fatal(err)
				}
				putKey(t, store, "occupy-1", ParamsV2, time.Time{})
				putKey(t, store, "occupy-2", ParamsV2, time.Time{})
				if _, gerr := store.Get(oldID); !IsFailure(gerr, ReasonKeyNotFound) {
					t.Fatalf("旧密钥应已被回收: %v", gerr)
				}
				t.Logf("[判定依据] 旧 V1 密钥撤销后被容量回收，库内=%v", store.IDs())
			}

			v2m, err := NewManager(ManagerConfig{
				Params: DefaultParamsV2(), Channel: ChannelConfig{NoiseRate: 0.02},
				Store: store, History: hist, MasterSeed: 6262, Clock: clk.now,
			})
			if err != nil {
				t.Fatal(err)
			}
			newID, err := v2m.RunSession(context.Background(), "upgrade-session")
			if !IsFailure(err, ReasonSessionReused) {
				t.Fatalf("[结论] 升级后同会话重跑必须 session_reused，实际 newID=%s err=%v", newID, err)
			}
			t.Logf("[判定依据] V2 下 KeyID 本会不同，但签发登记以 sessionID 为准；重跑被拒: %v", err)

			if !evicted {
				got, gerr := store.Get(oldID)
				if gerr != nil {
					t.Fatalf("[结论] 旧 V1 密钥应仍可取用: %v", gerr)
				}
				if string(got.Key) != string(oldKey.Key) || got.ParamsVer != ParamsV1 {
					t.Fatalf("[结论] 旧密钥字节/版本标记不得被改动: %+v", got)
				}
			}
			rec, _ := hist.Get("upgrade-session")
			if !rec.Success || rec.ParamsVer != ParamsV1 || rec.KeyID != oldID {
				t.Fatalf("[结论] 归档必须保留 V1 首次成功结论: %+v", rec)
			}
			t.Logf("[结论:%s] 版本升级不产生第二把密钥；旧密钥 %s，归档仍为 V1 成功",
				name, oldID)
		})
	}
}

// TestUnusableKeysNeverReviveManagerLevel 管理器端到端：密钥撤销/销毁/过期后，
// 经历容量回收与参数版本升级都不会重新变成可正常取用的 active 密钥。
func TestUnusableKeysNeverReviveManagerLevel(t *testing.T) {
	scenes := []string{"revoked", "destroyed", "expired"}
	for _, scene := range scenes {
		t.Run(scene, func(t *testing.T) {
			clk := &fakeClock{t: time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)}
			store := NewKeyStoreWith(KeyStoreConfig{Capacity: 1, Clock: clk.now})
			hist := NewHistory()
			newMgr := func(seed int64, p Params) *Manager {
				m, err := NewManager(ManagerConfig{
					Params: p, Channel: ChannelConfig{NoiseRate: 0.02},
					Store: store, History: hist, MasterSeed: int64(seed),
					KeyTTL: time.Minute, Clock: clk.now,
				})
				if err != nil {
					t.Fatal(err)
				}
				return m
			}
			v1m := newMgr(7171, DefaultParamsV1())
			keyID, err := v1m.RunSession(context.Background(), "dead-"+scene)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("[输入参数:%s] session=dead-%s key=%s（V1 签发）", scene, scene, keyID)

			invalidateKey(t, store, clk, keyID, scene)
			if _, err := store.Get(keyID); err == nil {
				t.Fatalf("置为 %s 后应不可取用", scene)
			}
			// 容量回收删除记录。
			putKey(t, store, "filler", ParamsV2, time.Time{})
			if _, gerr := store.Get(keyID); !IsFailure(gerr, ReasonKeyNotFound) {
				t.Fatalf("[判定依据] 回收后应为 not_found，绝不能变回 active: %v", gerr)
			}
			// 用升级后的 V2 管理器重跑同一会话：被幂等拒绝，旧 ID 仍不存在。
			v2m := newMgr(8282, DefaultParamsV2())
			if _, err := v2m.RunSession(context.Background(), "dead-"+scene); !IsFailure(err, ReasonSessionReused) {
				t.Fatalf("[结论] 升级后重跑应 session_reused，实际: %v", err)
			}
			if _, gerr := store.Get(keyID); !IsFailure(gerr, ReasonKeyNotFound) {
				t.Fatalf("[结论] %s 密钥经回收+升级后不得复活，实际: %v", scene, gerr)
			}
			t.Logf("[结论:%s] 密钥不可取用→被回收→版本升级，全程未复活；重跑被 session_reused 拒绝", scene)
		})
	}
}

// TestFailedSessionRetryThenIdempotent 仅失败过的会话允许重试；一旦重试成功，
// 之后再次重跑仍被拒绝（成功只认一次）。
func TestFailedSessionRetryThenIdempotent(t *testing.T) {
	hist := NewHistory()
	store := NewKeyStore()
	bad, err := NewManager(ManagerConfig{
		Params: DefaultParamsV1(), Channel: ChannelConfig{EavesdropRate: 0.7},
		Store: store, History: hist, MasterSeed: 11,
	})
	if err != nil {
		t.Fatal(err)
	}
	// (seed=11, id=sess-eve, eavesdrop=0.7) 已被既有测试钉住必然因窃听中止。
	if _, err := bad.RunSession(context.Background(), "sess-eve"); !IsFailure(err, ReasonEavesdropping) {
		t.Fatalf("[输入参数] 坏信道首跑应因窃听中止，实际: %v", err)
	}
	good, err := NewManager(ManagerConfig{
		Params: DefaultParamsV1(), Channel: ChannelConfig{NoiseRate: 0.02},
		Store: store, History: hist, MasterSeed: 12,
	})
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := good.RunSession(context.Background(), "sess-eve")
	if err != nil {
		t.Fatalf("[判定依据] 仅失败过的会话应允许重试成功，实际: %v", err)
	}
	t.Logf("[判定依据] 首跑 eavesdropping 失败后，换好信道重试成功 key=%s", keyID)
	if _, err := good.RunSession(context.Background(), "sess-eve"); !IsFailure(err, ReasonSessionReused) {
		t.Fatalf("[结论] 成功之后再次重跑必须 session_reused，实际: %v", err)
	}
	rec, _ := hist.Get("sess-eve")
	if !rec.Success {
		t.Fatalf("[结论] 归档最终应保留成功结论，实际 %+v", rec)
	}
	t.Logf("[结论] 失败可重试、成功只认一次；归档为成功 key=%s", keyID)
}

// TestConcurrentSameSessionSingleIssuance 并发重复提交同一会话：
// 恰好一次成功，其余全部 session_reused，库里至多一把该会话密钥。
func TestConcurrentSameSessionSingleIssuance(t *testing.T) {
	m, err := NewManager(ManagerConfig{
		Params:     DefaultParamsV2(),
		Channel:    ChannelConfig{NoiseRate: 0.02},
		MasterSeed: 9090,
	})
	if err != nil {
		t.Fatal(err)
	}
	const n = 16
	var wg sync.WaitGroup
	var mu sync.Mutex
	var successID string
	successes, reused := 0, 0
	wg.Add(n)
	t.Logf("[输入参数] 同一会话 %q 被 %d 个 goroutine 同时 RunSession", "race-once", n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			id, runErr := m.RunSession(context.Background(), "race-once")
			mu.Lock()
			defer mu.Unlock()
			switch {
			case runErr == nil:
				successes++
				successID = id
			case IsFailure(runErr, ReasonSessionReused):
				reused++
			default:
				t.Errorf("出现非预期错误: %v", runErr)
			}
		}()
	}
	wg.Wait()
	if successes != 1 || reused != n-1 {
		t.Fatalf("[判定依据] 应恰好 1 次成功、%d 次 session_reused，实际成功=%d reused=%d",
			n-1, successes, reused)
	}
	k, gerr := m.Store().Get(successID)
	if gerr != nil {
		t.Fatalf("[结论] 唯一成功的密钥应可取用: %v", gerr)
	}
	if ids := m.Store().IDs(); len(ids) != 1 {
		t.Fatalf("[结论] 库内应只有一把密钥，实际 %v", ids)
	}
	rec, ok := m.History().Get("race-once")
	if !ok || !rec.Success || rec.KeyID != successID {
		t.Fatalf("[结论] 归档应只有一条成功记录: %+v ok=%v", rec, ok)
	}
	t.Logf("[结论] %d 个并发提交中 1 成功（%s，len=%d）、%d 被拒；库内仅 1 把",
		n, successID, len(k.Key), reused)
}

// TestConcurrentMixedSessionsWithReclamation 并发跑互不相同的会话，同时
// 穿插回收/退役：会话之间互不影响；并在批次中混入同一会话的重复提交，
// 验证同会话仍只签发一次。
func TestConcurrentMixedSessionsWithReclamation(t *testing.T) {
	clk := &fakeClock{t: time.Date(2026, 10, 4, 13, 0, 0, 0, time.UTC)}
	// 容量 9：4 把预置密钥 + 8 个独立会话 + 1 个 dup 成功恰好填满，
	// 因此重复提交只会得到 session_reused，结论确定。
	store := NewKeyStoreWith(KeyStoreConfig{Capacity: 9, Clock: clk.now})
	hist := NewHistory()
	// 预置 4 把一分钟后过期的密钥，占住部分容量。
	for _, id := range []string{"seed-a", "seed-b", "seed-c", "seed-d"} {
		putKey(t, store, id, ParamsV1, clk.now().Add(time.Minute))
	}
	// 先确定性地让预置密钥全部到期，使其成为回收候选。
	clk.advance(2 * time.Minute)
	m, err := NewManager(ManagerConfig{
		Params: DefaultParamsV2(), Channel: ChannelConfig{NoiseRate: 0.02},
		Store: store, History: hist, MasterSeed: 20261004,
		Clock: clk.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	// 8 个互不相同的会话 + 对 "dup" 的 6 个重复并发提交。
	uniq := make([]string, 8)
	for i := range uniq {
		uniq[i] = fmt.Sprintf("mix-%d", i)
	}
	t.Logf("[输入参数] capacity=9，预置 4 把已过期密钥；8 个独立会话 + 6 个重复提交(dup) 并发")

	var wg sync.WaitGroup
	var mu sync.Mutex
	uniqSuccess, uniqFull := 0, 0
	dupSuccess, dupReused := 0, 0
	gotKeys := map[string]string{}

	run := func(id string, dup bool) {
		defer wg.Done()
		keyID, runErr := m.RunSession(context.Background(), id)
		mu.Lock()
		defer mu.Unlock()
		switch {
		case runErr == nil:
			if dup {
				dupSuccess++
			} else {
				uniqSuccess++
			}
			k, gerr := store.Get(keyID)
			if gerr != nil {
				t.Errorf("成功密钥 %s 取不回: %v", keyID, gerr)
				return
			}
			for other, mat := range gotKeys {
				if mat == string(k.Key) {
					t.Errorf("会话 %s 与 %s 产出相同密钥，存在串扰", id, other)
				}
			}
			gotKeys[id] = string(k.Key)
		case IsFailure(runErr, ReasonSessionReused):
			if !dup {
				t.Errorf("独立会话 %s 不应被判重: %v", id, runErr)
			}
			dupReused++
		case IsFailure(runErr, ReasonStoreFull):
			if dup {
				t.Errorf("重复提交只应 session_reused，却得到库满: %v", runErr)
			}
			uniqFull++
		default:
			t.Errorf("会话 %s 非预期错误: %v", id, runErr)
		}
	}

	// 后台并发盘点/撤销，与协商和容量回收交织（对已过期密钥返回 expired，
	// 不改变其可回收性，仅制造锁竞争）。
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 20; i++ {
			_ = store.Snapshot()
			_ = store.ReclaimableCount()
			_ = store.Revoke("seed-a")
			_ = store.Retire("seed-b")
		}
	}()
	for _, id := range uniq {
		wg.Add(1)
		go run(id, false)
	}
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go run("dup", true)
	}
	wg.Wait()

	if dupSuccess != 1 || dupReused != 5 {
		t.Fatalf("[判定依据] dup 应恰好 1 成功 5 拒绝，实际成功=%d 拒绝=%d", dupSuccess, dupReused)
	}
	if uniqSuccess != len(uniq) || uniqFull != 0 {
		t.Fatalf("[判定依据] 8 个独立会话都应成功，实际成功=%d 库满=%d", uniqSuccess, uniqFull)
	}
	if store.Len() != 9 {
		t.Fatalf("[结论] 库内应恰好 9 条（4 预置全被回收 + 9 新签发），实际 %d", store.Len())
	}
	// 被回收的只能是预置失效密钥：任何 active 新密钥都不得被回收。
	for _, rc := range store.Reclamations() {
		switch rc.KeyID {
		case "seed-a", "seed-b", "seed-c", "seed-d":
		default:
			t.Fatalf("[结论] 只允许回收预置失效密钥，实际回收了 %s（%+v）", rc.KeyID, rc)
		}
	}
	t.Logf("[结论] 独立会话成功=%d；重复提交 1 成功 5 拒绝；成功密钥两两不同；回收 %d 条均为预置失效密钥；库内=%d",
		uniqSuccess, len(store.Reclamations()), store.Len())
}

// TestHistoryIssuedRegistryAppendOnly 签发登记表只追加：失败记录不能覆盖
// 成功结论；重复 MarkIssued 无效；失败后可再登记成功。
func TestHistoryIssuedRegistryAppendOnly(t *testing.T) {
	h := NewHistory()
	ok := h.MarkIssued(SessionRecord{Schema: RecordV1, ID: "s", ParamsVer: ParamsV1, KeyID: "k-1"})
	if !ok {
		t.Fatal("首次 MarkIssued 应返回 true")
	}
	if ok := h.MarkIssued(SessionRecord{Schema: RecordV1, ID: "s", KeyID: "k-2"}); ok {
		t.Fatal("重复 MarkIssued 必须返回 false")
	}
	// 失败归档不得覆盖成功记录。
	h.Add(SessionRecord{Schema: RecordV1, ID: "s", Success: false, FailReason: ReasonStoreFull})
	rec, ok := h.Get("s")
	if !ok || !rec.Success || rec.KeyID != "k-1" {
		t.Fatalf("失败 Add 不得覆盖成功记录: %+v ok=%v", rec, ok)
	}
	if ir, ok := h.IsIssued("s"); !ok || ir.KeyID != "k-1" {
		t.Fatalf("签发登记应保持首次成功: %+v ok=%v", ir, ok)
	}
	// 仅失败过的 ID 不算签发。
	h.Add(SessionRecord{Schema: RecordV1, ID: "f", Success: false, FailReason: ReasonEavesdropping})
	if _, ok := h.IsIssued("f"); ok {
		t.Fatal("仅失败的会话不应进入签发登记")
	}
	if !h.MarkIssued(SessionRecord{Schema: RecordV1, ID: "f", KeyID: "k-f"}) {
		t.Fatal("失败后首次成功应允许登记")
	}
	t.Logf("[结论] 签发登记只追加：成功记录不被失败/重复成功覆盖，失败会话之后可登记成功")
}
