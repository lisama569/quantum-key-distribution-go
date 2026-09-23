package qkd

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
)

// mustManager 按给定参数构造管理器并记录输入参数。
func mustManager(t *testing.T, seed int64, p Params, ch ChannelConfig) *Manager {
	t.Helper()
	if p == (Params{}) {
		p = DefaultParams()
	}
	t.Logf("[输入参数] seed=%d params=%+v channel=%+v", seed, p, ch)
	m, err := NewManager(ManagerConfig{Params: p, Channel: ch, MasterSeed: seed})
	if err != nil {
		t.Fatalf("NewManager 失败: %v", err)
	}
	return m
}

// logStats 打印会话的判定依据（基比对、抽样 QBER、信道诊断、纠错等）。
func logStats(t *testing.T, tag string, st SessionStats) {
	t.Helper()
	t.Logf("[判定依据:%s] sent=%d sifted=%d sampled=%d sampleErrors=%d QBER=%.4f threshold=%.4f "+
		"channel={noiseFlips=%d eveIntercepted=%d eveDisturbed=%d sameBasisErrors=%d effectiveQBER=%.4f} "+
		"reconcile={fixes=%d passes=%d} stage=%s abort=%q",
		tag, st.Sent, st.Sifted, st.Sampled, st.SampledErrors, st.QBER, st.Threshold,
		st.Channel.NoiseFlips, st.Channel.EveIntercepted, st.Channel.EveDisturbed,
		st.Channel.Errors, st.Channel.EffectiveQBER,
		st.ReconcileFixes, st.ReconcilePasses, st.Stage, st.AbortReason)
}

// TestSuccessfulNegotiation 正常协商：双方得到长度确定且一致的密钥。
func TestSuccessfulNegotiation(t *testing.T) {
	p := DefaultParams() // QBERThreshold 0.15, noise 0.03
	m := mustManager(t, 42, p, ChannelConfig{NoiseRate: 0.03})

	keyID, err := m.RunSession(context.Background(), "sess-clean")
	if err != nil {
		t.Fatalf("期望协商成功，得到错误: %v", err)
	}
	rec, ok := m.History().Get("sess-clean")
	if !ok {
		t.Fatal("历史中缺少会话记录")
	}
	logStats(t, "正常", rec.Stats)
	if !rec.Success {
		t.Fatalf("记录应标记为成功，failReason=%q", rec.FailReason)
	}
	k, err := m.Store().Get(keyID)
	if err != nil {
		t.Fatalf("密钥应可取回: %v", err)
	}
	if len(k.Key) != p.KeyBytes {
		t.Fatalf("密钥长度应为 %d，实际 %d", p.KeyBytes, len(k.Key))
	}
	t.Logf("[结论] 会话成功 keyID=%s keyLen=%d key=%x", keyID, len(k.Key), k.Key)
	if k.State != KeyActive {
		t.Fatalf("密钥状态应为 active，实际 %s", k.State)
	}
}

// TestRepeatability 相同输入重放：逐字节相同的密钥与相同的统计数据。
func TestRepeatability(t *testing.T) {
	// 相同主种子 + 相同会话 ID + 相同参数/信道，即便在不同 Manager 中也必须复现。
	run := func() (string, []byte, SessionStats) {
		p := DefaultParams()
		m := mustManager(t, 7, p, ChannelConfig{NoiseRate: 0.05})
		id, err := m.RunSession(context.Background(), "rep-fixed")
		if err != nil {
			t.Fatalf("协商失败: %v", err)
		}
		k, _ := m.Store().Get(id)
		rec, _ := m.History().Get("rep-fixed")
		return id, k.Key, rec.Stats
	}
	id1, key1, st1 := run()
	id2, key2, st2 := run()
	if id1 != id2 {
		t.Fatalf("密钥 ID 应可复现: %s != %s", id1, id2)
	}
	if string(key1) != string(key2) {
		t.Fatalf("相同种子/参数/信道下密钥应逐比特一致\n%x\n%x", key1, key2)
	}
	if st1.QBER != st2.QBER || st1.Sifted != st2.Sifted {
		t.Fatalf("统计数据应可复现: %+v != %+v", st1, st2)
	}
	t.Logf("[结论] 重放一致 keyID=%s qber=%.4f sifted=%d", id1, st1.QBER, st1.Sifted)
}

// TestAbortEavesdropping 高窃听率：必须中止，且归类为窃听。
func TestAbortEavesdropping(t *testing.T) {
	p := DefaultParams()
	ch := ChannelConfig{NoiseRate: 0.0, EavesdropRate: 0.7}
	t.Logf("[输入参数] params=%+v channel=%+v（预期窃听导致 QBER 超阈）", p, ch)
	m, err := NewManager(ManagerConfig{Params: p, Channel: ch, MasterSeed: 11})
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := m.RunSession(context.Background(), "sess-eve")
	if err == nil {
		t.Fatalf("预期因窃听中止，但会话产出了密钥 %s", keyID)
	}
	rec, _ := m.History().Get("sess-eve")
	logStats(t, "窃听", rec.Stats)
	if !IsFailure(err, ReasonEavesdropping) {
		t.Fatalf("错误应归类为 %q，实际: %v", ReasonEavesdropping, err)
	}
	if _, getErr := m.Store().Get(keyID); getErr == nil {
		t.Fatal("中止会话绝不能在密钥库中留下密钥")
	}
	if len(m.Store().IDs()) != 0 {
		t.Fatalf("窃听中止后密钥库必须为空，实际有 %d 条", len(m.Store().IDs()))
	}
	t.Logf("[结论] 会话中止且无密钥残留，原因: %v", err)
}

// TestAbortChannelNoise 无窃听但噪声超阈：归类为信道质量，与窃听可区分。
func TestAbortChannelNoise(t *testing.T) {
	p := DefaultParams()
	ch := ChannelConfig{NoiseRate: 0.3, EavesdropRate: 0.0}
	t.Logf("[输入参数] params=%+v channel=%+v（预期噪声导致 QBER 超阈）", p, ch)
	m, err := NewManager(ManagerConfig{Params: p, Channel: ch, MasterSeed: 23})
	if err != nil {
		t.Fatal(err)
	}
	_, err = m.RunSession(context.Background(), "sess-noise")
	if err == nil {
		t.Fatal("预期因信道质量中止，但会话成功了")
	}
	rec, _ := m.History().Get("sess-noise")
	logStats(t, "噪声", rec.Stats)
	if !IsFailure(err, ReasonChannelQuality) {
		t.Fatalf("错误应归类为 %q，实际: %v", ReasonChannelQuality, err)
	}
	if IsFailure(err, ReasonEavesdropping) {
		t.Fatal("无窃听场景不得归类为窃听")
	}
	if rec.Stats.Channel.EveIntercepted != 0 {
		t.Fatalf("窃听拦截数应为 0，实际 %d", rec.Stats.Channel.EveIntercepted)
	}
	var pe *ProtocolError
	if !errors.As(err, &pe) || pe.Reason != ReasonChannelQuality {
		t.Fatalf("错误类型化信息不符: %v", err)
	}
	t.Logf("[结论] 会话因信道质量中止，与窃听原因可区分: %v", err)
}

// TestSessionCannotProduceTwice 同一会话不得重复产出密钥。
func TestSessionCannotProduceTwice(t *testing.T) {
	p := DefaultParams()
	sess, err := NewSession(SessionConfig{ID: "once", Params: p, Rand: NewSeededRand(99)})
	if err != nil {
		t.Fatal(err)
	}
	key1, err := sess.Run(context.Background())
	if err != nil {
		t.Fatalf("首次协商应成功: %v", err)
	}
	key2, err := sess.Run(context.Background())
	if err == nil {
		t.Fatalf("重复运行必须失败，但又产出了密钥 %x", key2)
	}
	if !IsFailure(err, ReasonSessionReused) {
		t.Fatalf("重复运行应归类为 %q，实际: %v", ReasonSessionReused, err)
	}
	if sess.Stage() != StageCompleted {
		t.Fatalf("首次成功后阶段应为 completed，实际 %s", sess.Stage())
	}
	wipe(key1)
	t.Logf("[结论] 同一会话仅产出一次密钥，重复运行被拒绝: %v", err)
}

// TestConcurrentSessionIsolation 多会话并发：互不串扰，单个失败不影响其它。
func TestConcurrentSessionIsolation(t *testing.T) {
	p := DefaultParams()
	m, err := NewManager(ManagerConfig{
		Params:     p,
		Channel:    ChannelConfig{NoiseRate: 0.03},
		MasterSeed: 2026,
	})
	if err != nil {
		t.Fatal(err)
	}
	// 三个正常会话 + 一个必然窃听中止的会话（通过独立管理器构造对照）。
	// 这里在同一管理器参数下使用多个正常会话验证隔离；失败隔离另用独立用例组合。
	ids := []string{"c-1", "c-2", "c-3", "c-4", "c-5"}
	results := m.RunSessions(context.Background(), ids)

	// 并发热身：反复并发运行同一批新会话，检查无竞态、无串扰。
	var wg sync.WaitGroup
	for round := 0; round < 4; round++ {
		mm, _ := NewManager(ManagerConfig{Params: p, Channel: ChannelConfig{NoiseRate: 0.03},
			MasterSeed: int64(8000 + round)})
		wg.Add(1)
		go func(mm *Manager, round int) {
			defer wg.Done()
			rids := []string{fmt.Sprintf("r%d-a", round), fmt.Sprintf("r%d-b", round)}
			rs := mm.RunSessions(context.Background(), rids)
			for _, r := range rs {
				if r.Err != nil {
					t.Errorf("并发会话 %s 意外失败: %v", r.SessionID, r.Err)
				}
			}
		}(mm, round)
	}
	wg.Wait()

	keyByID := map[string][]byte{}
	for _, r := range results {
		if r.Err != nil {
			t.Errorf("会话 %s 不应失败: %v", r.SessionID, r.Err)
			continue
		}
		k, err := m.Store().Get(r.KeyID)
		if err != nil {
			t.Errorf("密钥 %s 取回失败: %v", r.KeyID, err)
			continue
		}
		for otherID, otherKey := range keyByID {
			if string(k.Key) == string(otherKey) {
				t.Fatalf("会话 %s 与 %s 产出了相同密钥，存在串扰", r.SessionID, otherID)
			}
		}
		keyByID[r.SessionID] = k.Key
	}
	if len(keyByID) != len(ids) {
		t.Fatalf("应有 %d 把独立密钥，实际 %d", len(ids), len(keyByID))
	}
	t.Logf("[结论] %d 个并发会话全部成功且密钥两两不同", len(ids))
}

// TestOneFailureDoesNotAffectOthers 并发批次中混入必然失败的会话：
// 失败会话不产出密钥，其它会话与既有库内容不受影响。
func TestOneFailureDoesNotAffectOthers(t *testing.T) {
	p := DefaultParams()
	// 高窃听 + 普通噪声，QBER 几乎必然超阈；先构造“好信道”管理器。
	good, err := NewManager(
		ManagerConfig{Params: p, Channel: ChannelConfig{NoiseRate: 0.02}, MasterSeed: 404},
	)
	if err != nil {
		t.Fatal(err)
	}
	// 先在 good 中放一把既有密钥。
	existingID, err := good.RunSession(context.Background(), "existing")
	if err != nil {
		t.Fatal(err)
	}

	// 将“坏信道管理器”和“好信道管理器”的会话并发交织，
	// 共享同一个 KeyStore / History，验证失败写入不会污染共享库。
	sharedStore := good.Store()
	sharedHist := good.History()
	// 构造一个共享库的坏管理器。
	badShared, err := NewManager(ManagerConfig{
		Params:     p,
		Channel:    ChannelConfig{NoiseRate: 0.05, EavesdropRate: 0.6},
		Store:      sharedStore,
		History:    sharedHist,
		MasterSeed: 505,
	})
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	var badErr error
	var goodNewID string
	wg.Add(2)
	go func() { defer wg.Done(); _, badErr = badShared.RunSession(context.Background(), "bad-1") }()
	go func() {
		defer wg.Done()
		goodNewID, err = good.RunSession(context.Background(), "good-new")
	}()
	wg.Wait()

	if badErr == nil || !IsFailure(badErr, ReasonEavesdropping) {
		t.Fatalf("坏信道会话应因窃听中止，实际: %v", badErr)
	}
	if err != nil {
		t.Fatalf("好信道会话不应受坏会话影响: %v", err)
	}
	if _, err := sharedStore.Get(existingID); err != nil {
		t.Fatalf("既有密钥应仍可用: %v", err)
	}
	if _, err := sharedStore.Get(goodNewID); err != nil {
		t.Fatalf("并发成功的新密钥应可用: %v", err)
	}
	if ids := sharedStore.IDs(); len(ids) != 2 {
		t.Fatalf("密钥库应有且仅有 2 把有效密钥（失败会话不得写入），实际 %d: %v", len(ids), ids)
	}
	t.Logf("[结论] 失败会话=%v；既有密钥与并发成功密钥均完好，库内共 %d 把", badErr, len(sharedStore.IDs()))
}

// TestKeyRevokeAndDestroy 撤销与销毁后密钥不得再被取出。
func TestKeyRevokeAndDestroy(t *testing.T) {
	p := DefaultParams()
	m := mustManager(t, 123, p, ChannelConfig{NoiseRate: 0.02})
	keyID, err := m.RunSession(context.Background(), "lifecycle")
	if err != nil {
		t.Fatal(err)
	}
	k, _ := m.Store().Get(keyID)
	t.Logf("[输入参数] keyID=%s len=%d state=%s", keyID, len(k.Key), k.State)

	if err := m.Store().Revoke(keyID); err != nil {
		t.Fatalf("撤销失败: %v", err)
	}
	if st, _ := m.Store().State(keyID); st != KeyRevoked {
		t.Fatalf("状态应为 revoked，实际 %s", st)
	}
	if _, err := m.Store().Get(keyID); err == nil {
		t.Fatal("撤销后 Get 必须失败")
	} else {
		t.Logf("[判定依据] 撤销后取回被拒绝: %v", err)
	}
	// 已撤销密钥可进一步销毁。
	if err := m.Store().Destroy(keyID); err != nil {
		t.Fatalf("销毁失败: %v", err)
	}
	if _, err := m.Store().Get(keyID); err == nil {
		t.Fatal("销毁后 Get 必须失败")
	}
	if st, _ := m.Store().State(keyID); st != KeyDestroyed {
		t.Fatalf("状态应为 destroyed，实际 %s", st)
	}
	// 终态不可逆：再次撤销应报错。
	if err := m.Store().Revoke(keyID); err == nil {
		t.Fatal("对已销毁密钥撤销必须报错")
	}
	t.Logf("[结论] 撤销/销毁后的密钥均无法取出，销毁为终态")
}

// TestFailedSessionNoHalfKey 中途失败（抽样后材料不足）时不残留半成品。
func TestFailedSessionNoHalfKey(t *testing.T) {
	p := DefaultParams()
	p.N = 16 // 极小批量：同基筛选后大概率不足以产出 32 字节密钥
	p.SampleFraction = 0.5
	m := mustManager(t, 1, p, ChannelConfig{})
	_, err := m.RunSession(context.Background(), "tiny")
	if err == nil {
		t.Fatal("极小批量应因材料不足或其它原因失败")
	}
	rec, _ := m.History().Get("tiny")
	logStats(t, "材料不足", rec.Stats)
	if !IsFailure(err, ReasonInsufficientBits) {
		t.Fatalf("应归类为 %q，实际: %v", ReasonInsufficientBits, err)
	}
	if len(m.Store().IDs()) != 0 {
		t.Fatalf("失败后密钥库应为空，实际 %v", m.Store().IDs())
	}
	if strings.Contains(fmt.Sprint(err), string(ReasonEavesdropping)) {
		t.Fatal("材料不足错误不得与窃听混淆")
	}
	t.Logf("[结论] 失败原因=%v，无半成品密钥入库", err)
}

// TestInvalidParamsRejected 非法参数被拒绝且原因可区分。
func TestInvalidParamsRejected(t *testing.T) {
	cases := []struct {
		name string
		p    Params
		ch   ChannelConfig
	}{
		{"阈值非法", Params{QBERThreshold: 1.5}, ChannelConfig{}},
		{"批量过小", Params{N: 2}, ChannelConfig{}},
		{"负噪声", Params{NoiseRate: -0.1}, ChannelConfig{NoiseRate: -0.1}},
		{"密钥长度为零", func() Params { p := DefaultParams(); p.KeyBytes = 0; return p }(), ChannelConfig{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := NewManager(ManagerConfig{Params: c.p, Channel: c.ch})
			if err == nil {
				t.Fatal("非法参数应被拒绝")
			}
			if !IsFailure(err, ReasonConfigInvalid) {
				t.Fatalf("应归类为 %q，实际: %v", ReasonConfigInvalid, err)
			}
			t.Logf("[输入参数] %+v channel=%+v => [结论] %v", c.p, c.ch, err)
		})
	}
}

// TestThresholdBoundary 验证阈值判定的严格性与噪声/窃听归类：
// 同一主种子下，略低于阈值成功、略高于阈值中止，且无窃听时归为信道质量。
func TestThresholdBoundary(t *testing.T) {
	p := DefaultParams()

	// 低于阈值：成功（该种子/会话ID下 QBER≈0.1471）。
	low := mustManager(t, 1, p, ChannelConfig{NoiseRate: 0.14})
	lowID, err := low.RunSession(context.Background(), "boundary-low")
	if err != nil {
		t.Fatalf("QBER 低于阈值时应成功: %v", err)
	}
	rLow, _ := low.History().Get("boundary-low")
	logStats(t, "阈值下", rLow.Stats)
	if rLow.Stats.QBER >= p.QBERThreshold {
		t.Fatalf("前置数据不成立: QBER=%.4f 应 < %.4f", rLow.Stats.QBER, p.QBERThreshold)
	}
	if _, err := low.Store().Get(lowID); err != nil {
		t.Fatalf("成功密钥应可取回: %v", err)
	}

	// 高于阈值：中止，无密钥，原因信道质量（该种子/会话ID下 QBER≈0.1644）。
	high := mustManager(t, 1, p, ChannelConfig{NoiseRate: 0.20})
	_, err = high.RunSession(context.Background(), "boundary-high")
	if err == nil {
		t.Fatal("QBER 高于阈值时必须中止")
	}
	rHigh, _ := high.History().Get("boundary-high")
	logStats(t, "阈值上", rHigh.Stats)
	if rHigh.Stats.QBER <= p.QBERThreshold {
		t.Fatalf("前置数据不成立: QBER=%.4f 应 > %.4f", rHigh.Stats.QBER, p.QBERThreshold)
	}
	if !IsFailure(err, ReasonChannelQuality) {
		t.Fatalf("应归类信道质量: %v", err)
	}
	if len(high.Store().IDs()) != 0 {
		t.Fatal("中止后密钥库必须为空")
	}
	t.Logf("[结论] 阈值 %.2f 判定正确：QBER=%.4f 成功 / QBER=%.4f 中止",
		p.QBERThreshold, rLow.Stats.QBER, rHigh.Stats.QBER)
}
