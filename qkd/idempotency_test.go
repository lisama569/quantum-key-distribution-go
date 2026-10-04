package qkd

import (
	"context"
	"sync"
	"testing"
	"time"
)

// TestSessionReissueBlockedAfterReclamation 同一成功过的会话，在其密钥被
// 回收/退役/撤销/到期/销毁后重跑，都不允许产出第二把密钥。
func TestSessionReissueBlockedAfterReclamation(t *testing.T) {
	cases := []struct {
		name    string
		dispose func(*KeyStore, string) error // 让首把密钥进入不可用并被回收
		reason  FailureReason                 // 重跑同会话时第二次签发期望的拦截原因
	}{
		{
			name: "撤销后被回收",
			dispose: func(s *KeyStore, id string) error {
				if err := s.Revoke(id); err != nil {
					return err
				}
				return s.Put(StoredKey{ID: "filler-revoked", Key: []byte("filler-material-1")})
			},
		},
		{
			name: "退役后被回收",
			dispose: func(s *KeyStore, id string) error {
				if err := s.Retire(id); err != nil {
					return err
				}
				return s.Put(StoredKey{ID: "filler-retired", Key: []byte("filler-material-2")})
			},
		},
		{
			name: "销毁后被回收",
			dispose: func(s *KeyStore, id string) error {
				if err := s.Destroy(id); err != nil {
					return err
				}
				return s.Put(StoredKey{ID: "filler-destroyed", Key: []byte("filler-material-3")})
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m, err := NewManager(ManagerConfig{
				Params:        DefaultParamsV1(),
				Channel:       ChannelConfig{NoiseRate: 0.02},
				MasterSeed:    4242,
				StoreCapacity: 1, // 容量 1：处置首把密钥后，filler 入库即触发回收
			})
			if err != nil {
				t.Fatal(err)
			}
			sessionID := "once-" + c.name
			keyID1, err := m.RunSession(context.Background(), sessionID)
			if err != nil {
				t.Fatalf("首次签发应成功: %v", err)
			}
			t.Logf("[输入参数] session=%s capacity=1 首次 keyID=%s；处置方式=%s",
				sessionID, keyID1, c.name)

			if err := c.dispose(m.Store(), keyID1); err != nil {
				t.Fatalf("处置首把密钥失败: %v", err)
			}
			if _, buried := m.Store().Tombstone(keyID1); !buried {
				t.Fatalf("首把密钥应已被回收并留下墓碑")
			}
			if _, gerr := m.Store().Get(keyID1); gerr == nil {
				t.Fatalf("处置后首把密钥必须不可取用")
			} else {
				t.Logf("[判定依据] 首把密钥已不可用且被回收: %v", gerr)
			}

			// 再跑同一个会话：无论密钥处于哪种不可用、是否已被回收，都不能再签发。
			keyID2, rerr := m.RunSession(context.Background(), sessionID)
			if rerr == nil {
				t.Fatalf("同一会话不得二次签发，却得到 keyID=%s", keyID2)
			}
			if !IsFailure(rerr, ReasonSessionReused) {
				t.Fatalf("重跑应归类 session_reused，实际: %v", rerr)
			}
			if issued, ver, ok := m.Store().IssuedSession(sessionID); !ok || issued != keyID1 {
				t.Fatalf("会话签发登记应永久指向首把密钥 %s，实际 issued=%s ver=%s ok=%v",
					keyID1, issued, ver, ok)
			}
			t.Logf("[结论] 同一会话重跑被拒绝且未产出新密钥: %v", rerr)
		})
	}

	// 到期清掉的分支需要可控时钟。
	t.Run("到期后被回收", func(t *testing.T) {
		clk := &fakeClock{t: time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)}
		m, err := NewManager(ManagerConfig{
			Params:        DefaultParamsV1(),
			Channel:       ChannelConfig{NoiseRate: 0.02},
			MasterSeed:    4243,
			StoreCapacity: 1,
			KeyTTL:        time.Hour,
			Clock:         clk.now,
		})
		if err != nil {
			t.Fatal(err)
		}
		keyID1, err := m.RunSession(context.Background(), "once-expired")
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("[输入参数] session=once-expired keyTTL=1h 首次 keyID=%s expiresAt 后推进时钟", keyID1)
		clk.advance(time.Hour + time.Second)
		if _, err := m.Store().Get(keyID1); !IsFailure(err, ReasonKeyExpired) {
			t.Fatalf("到期后应 key_expired，实际 %v", err)
		}
		// filler 入库触发对已过期首把密钥的回收。
		if _, err := m.RunSession(context.Background(), "filler-session"); err != nil {
			t.Fatalf("填充会话应成功（回收过期密钥腾位）: %v", err)
		}
		if st, buried := m.Store().Tombstone(keyID1); !buried || st != KeyExpired {
			t.Fatalf("首把密钥应作为 expired 被回收，实际 buried=%v st=%s", buried, st)
		}
		_, rerr := m.RunSession(context.Background(), "once-expired")
		if !IsFailure(rerr, ReasonSessionReused) {
			t.Fatalf("到期回收后重跑同一会话应 session_reused，实际: %v", rerr)
		}
		t.Logf("[结论] 到期回收后同一会话仍不可二次签发: %v", rerr)
	})
}

// TestTerminalKeysNeverRevive 已撤销/销毁/退役/过期的密钥，在容量回收之后
// 或参数版本升级（换管理器、换 KeyID 派生版本）之后，都不可能再变回可用；
// 取用失败原因始终可区分。
func TestTerminalKeysNeverRevive(t *testing.T) {
	clk := &fakeClock{t: time.Date(2026, 10, 5, 6, 0, 0, 0, time.UTC)}
	store := NewKeyStoreWith(KeyStoreConfig{Capacity: 2, Clock: clk.now})
	hist := NewHistory()

	terminals := []struct {
		id     string
		state  KeyState
		reason FailureReason
		act    func(*KeyStore, string) error
	}{
		{"k-revoked", KeyRevoked, ReasonKeyRevoked, func(s *KeyStore, id string) error { return s.Revoke(id) }},
		{"k-destroyed", KeyDestroyed, ReasonKeyDestroyed, func(s *KeyStore, id string) error { return s.Destroy(id) }},
		{"k-retired", KeyRetired, ReasonKeyRetired, func(s *KeyStore, id string) error { return s.Retire(id) }},
	}
	for _, c := range terminals {
		putKey(t, store, c.id, ParamsV1, time.Time{})
		if err := c.act(store, c.id); err != nil {
			t.Fatal(err)
		}
	}
	// 过期密钥：容量 2，需要单独建库以制造“过期后被回收”。
	expStore := NewKeyStoreWith(KeyStoreConfig{Capacity: 1, Clock: clk.now})
	putKey(t, expStore, "k-expired", ParamsV1, clk.now().Add(time.Minute))
	clk.advance(2 * time.Minute)

	t.Logf("[输入参数] 四类不可用密钥 revoked/destroyed/retired/expired；先验证回收前取用原因")
	for _, c := range terminals {
		if _, err := store.Get(c.id); !IsFailure(err, c.reason) {
			t.Fatalf("%s 回收前应归类 %v，实际 %v", c.id, c.reason, err)
		}
	}
	if _, err := expStore.Get("k-expired"); !IsFailure(err, ReasonKeyExpired) {
		t.Fatalf("过期密钥应 key_expired，实际 %v", err)
	}

	// 触发回收：逐条塞入新 active 密钥把四类不可用记录全部挤出。
	putKey(t, store, "n1", ParamsV2, time.Time{}) // 回收 destroyed（优先级最高之一）
	putKey(t, store, "n2", ParamsV2, time.Time{}) // 再回收一条
	putKey(t, expStore, "n-exp", ParamsV2, time.Time{})

	// 回收后：记录已删除（不出现在 IDs），但墓碑保留原结论，Get 仍按原原因失败。
	for _, c := range terminals {
		if containsID(store.IDs(), c.id) {
			t.Fatalf("%s 记录应已被回收删除", c.id)
		}
		if st, buried := store.Tombstone(c.id); !buried || st != c.state {
			t.Fatalf("%s 墓碑应为 %s，实际 buried=%v st=%s", c.id, c.state, buried, st)
		}
		if _, err := store.Get(c.id); !IsFailure(err, c.reason) {
			t.Fatalf("%s 回收后取用仍应归类 %v（不复活、原因可区分），实际 %v", c.id, c.reason, err)
		}
	}
	if st, buried := expStore.Tombstone("k-expired"); !buried || st != KeyExpired {
		t.Fatalf("k-expired 墓碑应为 expired，实际 buried=%v st=%s", buried, st)
	}
	t.Logf("[判定依据] 回收后四类记录均删除但墓碑保留原状态，Get 原因各自可区分")

	// 尝试以同 ID 重新 Put 成 active（模拟任何形式的“复活/腾挪”）：全部拒绝。
	zombie := StoredKey{ID: "k-revoked", Key: []byte("zombie-bytes"), State: KeyActive, ParamsVer: ParamsV2}
	if err := store.Put(zombie); !IsFailure(err, ReasonKeyRevoked) {
		t.Fatalf("撤销 ID 重新入库必须按 revoked 拒绝，实际 %v", err)
	}
	for _, c := range terminals {
		err := store.Put(StoredKey{ID: c.id, Key: []byte("zombie"), State: KeyActive, ParamsVer: ParamsV2})
		if !IsFailure(err, c.reason) {
			t.Fatalf("%s 不得在回收后以 active 复活，期望 %v 实际 %v", c.id, c.reason, err)
		}
	}

	// 参数版本升级路径：用 V2 管理器（共享同一库）也无法让这些 ID 复活。
	v2m, err := NewManager(ManagerConfig{
		Params: DefaultParamsV2(), Channel: ChannelConfig{NoiseRate: 0.02},
		Store: store, History: hist, MasterSeed: 99, Clock: clk.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range terminals {
		err := v2m.Store().Put(StoredKey{ID: c.id, Key: []byte("v2-zombie"), State: KeyActive, ParamsVer: ParamsV2})
		if !IsFailure(err, c.reason) {
			t.Fatalf("版本升级后 %s 仍不得复活，期望 %v 实际 %v", c.id, c.reason, err)
		}
	}
	// 仍然存在于库中的新 active 密钥不受影响。
	for _, id := range store.IDs() {
		if _, err := store.Get(id); err != nil {
			t.Fatalf("在库 active 密钥 %s 应可取用: %v", id, err)
		}
	}
	t.Logf("[结论] 撤销/销毁/退役/过期密钥经回收与版本升级均不复活，取用原因始终可区分")
}

// TestSessionReissueBlockedAcrossVersionUpgrade 参数版本升级后，同一 sessionID
// 即使派生出不同 KeyID，也不允许第二次签发。
func TestSessionReissueBlockedAcrossVersionUpgrade(t *testing.T) {
	store := NewKeyStore()
	hist := NewHistory()
	v1, err := NewManager(ManagerConfig{
		Params: DefaultParamsV1(), Channel: ChannelConfig{NoiseRate: 0.02},
		Store: store, History: hist, MasterSeed: 77,
	})
	if err != nil {
		t.Fatal(err)
	}
	id1, err := v1.RunSession(context.Background(), "upgrade-session")
	if err != nil {
		t.Fatal(err)
	}
	issued1, ver1, ok1 := store.IssuedSession("upgrade-session")
	if !ok1 || issued1 != id1 || ver1 != ParamsV1 {
		t.Fatalf("V1 签发登记不符: issued=%s ver=%s ok=%v", issued1, ver1, ok1)
	}
	t.Logf("[输入参数] session=upgrade-session 首签版本=%s keyID=%s", ParamsV1, id1)

	v2, err := NewManager(ManagerConfig{
		Params: DefaultParamsV2(), Channel: ChannelConfig{NoiseRate: 0.02},
		Store: store, History: hist, MasterSeed: 77,
	})
	if err != nil {
		t.Fatal(err)
	}
	v2KeyID := KeyID("upgrade-session", ParamsV2, v2.sessionSeed("upgrade-session"))
	if v2KeyID == id1 {
		t.Fatal("前置条件不成立：V2 应派生出不同 KeyID")
	}
	id2, rerr := v2.RunSession(context.Background(), "upgrade-session")
	if rerr == nil {
		t.Fatalf("升级后同一会话不得二次签发，却得到 %s", id2)
	}
	if !IsFailure(rerr, ReasonSessionReused) {
		t.Fatalf("应归类 session_reused，实际 %v", rerr)
	}
	if store.Len() != 1 {
		t.Fatalf("被拒签发不得写入第二把密钥，库内实际 %d 条", store.Len())
	}
	got, err := store.Get(id1)
	if err != nil || got.ParamsVer != ParamsV1 {
		t.Fatalf("首把 V1 密钥应完好保留，err=%v ver=%s", err, got.ParamsVer)
	}
	t.Logf("[判定依据] V2 派生 keyID=%s 与首签 %s 不同；[结论] 仍被会话登记拒绝: %v",
		v2KeyID, id1, rerr)
}

// TestConcurrentSessionsNoCrossImpactNoDoubleIssue 并发回收下会话互不影响，
// 且同一会话即使被并发提交多次也只签发一次。
func TestConcurrentSessionsNoCrossImpactNoDoubleIssue(t *testing.T) {
	clk := &fakeClock{t: time.Date(2026, 10, 5, 9, 0, 0, 0, time.UTC)}
	store := NewKeyStoreWith(KeyStoreConfig{Capacity: 5, Clock: clk.now})
	hist := NewHistory()
	m, err := NewManager(ManagerConfig{
		Params: DefaultParamsV2(), Channel: ChannelConfig{NoiseRate: 0.02},
		Store: store, History: hist, MasterSeed: 20261005, Clock: clk.now,
	})
	if err != nil {
		t.Fatal(err)
	}

	// 两组不同会话，容量有限：成功数受容量约束，失败只允许是 keystore_full。
	groupA := []string{"a-1", "a-2", "a-3", "a-4", "a-5", "a-6", "a-7"}
	groupB := []string{"b-1", "b-2", "b-3", "b-4", "b-5", "b-6", "b-7"}

	// 并发中夹着一个 goroutine 不断制造过期/回收：先放 2 把短时有效密钥，
	// 协商进行中推进时钟使其过期，成为回收对象。
	putKey(t, store, "old-exp-1", ParamsV1, clk.now().Add(time.Minute))
	putKey(t, store, "old-exp-2", ParamsV1, clk.now().Add(time.Minute))

	var wg sync.WaitGroup
	wg.Add(3)
	var resA, resB []SessionResult
	go func() { defer wg.Done(); resA = m.RunSessions(context.Background(), groupA) }()
	go func() {
		defer wg.Done()
		clk.advance(2 * time.Minute) // 让 old-exp-* 过期
		resB = m.RunSessions(context.Background(), groupB)
	}()
	go func() {
		defer wg.Done()
		// 与协商并发地对过期密钥做退役/撤销（已过期应返回 expired，不影响结果）。
		_ = store.Retire("old-exp-1")
		_ = store.Revoke("old-exp-2")
	}()
	wg.Wait()

	t.Logf("[输入参数] capacity=5 + 2 条初始过期密钥；A/B 各 %d 个会话并发，夹着回收/退役",
		len(groupA))

	// 校验：每个会话恰有一个确定结论；成功的密钥两两不同且可取回；
	// 失败原因只能是 keystore_full；库内条数不超过容量；无 active 被回收。
	all := append(append([]SessionResult{}, resA...), resB...)
	success := map[string]string{} // sessionID -> keyID
	successN, fullN := 0, 0
	for _, r := range all {
		switch {
		case r.Err == nil:
			successN++
			if prev, dup := success[r.SessionID]; dup {
				t.Fatalf("会话 %s 被重复签发: %s / %s", r.SessionID, prev, r.KeyID)
			}
			success[r.SessionID] = r.KeyID
			k, gerr := store.Get(r.KeyID)
			if gerr != nil {
				t.Fatalf("成功会话 %s 的密钥应可取回: %v", r.SessionID, gerr)
			}
			for otherSID, otherKey := range success {
				if otherSID == r.SessionID {
					continue
				}
				if ok2, _ := store.Get(otherKey); string(ok2.Key) == string(k.Key) {
					t.Fatalf("会话 %s 与 %s 密钥相同，存在串扰", r.SessionID, otherSID)
				}
			}
		case IsFailure(r.Err, ReasonStoreFull):
			fullN++
		default:
			t.Fatalf("会话 %s 出现非预期失败: %v", r.SessionID, r.Err)
		}
	}
	if successN+fullN != len(all) {
		t.Fatalf("每个会话都应有确定结论: 成功=%d 库满=%d 总=%d", successN, fullN, len(all))
	}
	if store.Len() > 5 {
		t.Fatalf("库内条数不得超过容量 5，实际 %d", store.Len())
	}
	for _, rc := range store.Reclamations() {
		// 并发下退役可能先于时钟推进发生，故回收原因可能是 retired/expired；
		// 但被回收对象只能是初始的两条失效密钥，绝不能是任何新产出的 active 密钥。
		if rc.KeyID != "old-exp-1" && rc.KeyID != "old-exp-2" {
			t.Fatalf("只允许回收初始失效密钥，实际回收了 %s (%s)", rc.KeyID, rc.Cause)
		}
		switch rc.Cause {
		case ReclaimExpired, ReclaimRetired, ReclaimRevoked, ReclaimDestroyed:
		default:
			t.Fatalf("回收原因必须是失效类原因，实际 %+v", rc)
		}
	}
	t.Logf("[结论] A/B 共 %d 会话：成功=%d 库满=%d；成功密钥两两不同，会话互不影响，库内 %d 条",
		len(all), successN, fullN, store.Len())
}

// TestConcurrentSameSessionSingleIssue 用无容量约束的库验证：同一会话被并发
// 提交多次时，原子签发保证恰有一次成功，其余全部 session_reused，且成功
// 之后串行重跑也被拒绝。
func TestConcurrentSameSessionSingleIssue(t *testing.T) {
	m, err := NewManager(ManagerConfig{
		Params: DefaultParamsV2(), Channel: ChannelConfig{NoiseRate: 0.02},
		MasterSeed: 31415,
	})
	if err != nil {
		t.Fatal(err)
	}
	const dup = 12
	var dwg sync.WaitGroup
	dRes := make([]error, dup)
	dIDs := make([]string, dup)
	start := make(chan struct{})
	for i := 0; i < dup; i++ {
		dwg.Add(1)
		go func(i int) {
			defer dwg.Done()
			<-start
			dIDs[i], dRes[i] = m.RunSession(context.Background(), "dup-session")
		}(i)
	}
	close(start)
	dwg.Wait()

	dupOK, dupReused := 0, 0
	var winner string
	for i, e := range dRes {
		switch {
		case e == nil:
			dupOK++
			winner = dIDs[i]
		case IsFailure(e, ReasonSessionReused):
			dupReused++
		default:
			t.Fatalf("重复提交出现非预期结果: %v", e)
		}
	}
	t.Logf("[输入参数] 同一会话 dup-session 并发提交 %d 次（无容量约束）", dup)
	if dupOK != 1 || dupReused != dup-1 {
		t.Fatalf("应恰好 1 次成功、%d 次 session_reused，实际成功=%d reused=%d",
			dup-1, dupOK, dupReused)
	}
	if issued, _, ok := m.Store().IssuedSession("dup-session"); !ok || issued != winner {
		t.Fatalf("会话登记应指向唯一胜出密钥 %s，实际 %s ok=%v", winner, issued, ok)
	}
	if m.Store().Len() != 1 {
		t.Fatalf("只应入库一把密钥，实际 %d 条", m.Store().Len())
	}
	if _, err := m.RunSession(context.Background(), "dup-session"); !IsFailure(err, ReasonSessionReused) {
		t.Fatalf("胜出会话串行重跑应 session_reused，实际 %v", err)
	}
	t.Logf("[结论] 同一会话并发提交 %d 次：唯一成功 keyID=%s，其余 %d 次 session_reused，串行重跑同样被拒",
		dup, winner, dupReused)
}

// TestFailedSessionCanRetryUntilSuccess 会话在成功之前（协商中止/库满）不占用
// 签发名额；一旦成功，结论永久。该性质保证“只有成功过”才不可再签发。
func TestFailedSessionCanRetryUntilSuccess(t *testing.T) {
	// 坏信道必然中止：同一会话名换管理器再跑（成功条件具备）应允许成功一次。
	store := NewKeyStore()
	hist := NewHistory()
	bad, _ := NewManager(ManagerConfig{
		Params:  DefaultParamsV2(),
		Channel: ChannelConfig{NoiseRate: 0.05, EavesdropRate: 0.7},
		Store:   store, History: hist, MasterSeed: 5,
	})
	if _, err := bad.RunSession(context.Background(), "retry-me"); !IsFailure(err, ReasonEavesdropping) {
		t.Fatalf("前置：坏信道应因窃听中止，实际 %v", err)
	}
	if _, _, ok := store.IssuedSession("retry-me"); ok {
		t.Fatal("中止会话不应占用签发名额")
	}
	good, _ := NewManager(ManagerConfig{
		Params: DefaultParamsV2(), Channel: ChannelConfig{NoiseRate: 0.02},
		Store: store, History: hist, MasterSeed: 5,
	})
	id, err := good.RunSession(context.Background(), "retry-me")
	if err != nil {
		t.Fatalf("此前从未成功的会话应允许成功: %v", err)
	}
	_, againErr := good.RunSession(context.Background(), "retry-me")
	if !IsFailure(againErr, ReasonSessionReused) {
		t.Fatalf("成功之后必须 session_reused，实际 %v", againErr)
	}
	t.Logf("[结论] 失败不占名额、可重试；成功一次后 keyID=%s 永久不可再签: %v", id, againErr)
}
