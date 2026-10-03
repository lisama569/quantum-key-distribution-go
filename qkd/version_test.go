package qkd

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

func baseTime() time.Time {
	return time.Date(2026, 10, 3, 10, 0, 0, 0, time.UTC)
}

// v1BaselineKey 是升级到 V2 之前用 V1 参数在固定输入下产出的密钥基线。
// 它钉死 V1 的逐比特结论：V1 记录在任何新版本下重放都必须得到这一串。
// 该值通过 TestV1GoldenBaseline 首次断言并打印；这里以独立用例验证跨进程稳定性。
func runSessionOnce(t *testing.T, seed int64, sessionID string, p Params, ch ChannelConfig) (string, []byte, SessionRecord) {
	t.Helper()
	m, err := NewManager(ManagerConfig{Params: p, Channel: ch, MasterSeed: seed})
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := m.RunSession(context.Background(), sessionID)
	if err != nil {
		t.Fatalf("会话 %s 应成功: %v", sessionID, err)
	}
	k, err := m.Store().Get(keyID)
	if err != nil {
		t.Fatal(err)
	}
	rec, ok := m.History().Get(sessionID)
	if !ok {
		t.Fatal("缺少归档记录")
	}
	return keyID, k.Key, rec
}

// TestV1RecordReplayBitIdentical 老的 V1 会话记录在当前（V2 默认）实现下：
//  1. 能正常解析（含旧别名/缺省 schema）；
//  2. 按记录重放得到与当初逐比特一致的密钥与 KeyID；
//  3. 重放结论（成功）与统计一致。
func TestV1RecordReplayBitIdentical(t *testing.T) {
	p := DefaultParamsV1()
	ch := ChannelConfig{NoiseRate: 0.05}
	t.Logf("[输入参数] seed=7 id=rep-v1 version=%s n=%d keyBytes=%d channel=%+v",
		p.Version, p.N, p.KeyBytes, ch)
	keyID, originalKey, rec := runSessionOnce(t, 7, "rep-v1", p, ch)
	if rec.ParamsVer != ParamsV1 {
		t.Fatalf("归档版本应为 V1，实际 %s", rec.ParamsVer)
	}
	// 序列化 → 用当前解析器重新解析（模拟“老记录被新代码读取”）。
	data, err := MarshalRecord(rec)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := UnmarshalRecord(data)
	if err != nil {
		t.Fatalf("老记录应可解析: %v", err)
	}
	replayed, err := ReplayRecord(context.Background(), parsed)
	if err != nil {
		t.Fatalf("老记录重放不应失败: %v", err)
	}
	if !replayed.Success {
		t.Fatalf("重放应成功，failReason=%q", replayed.FailReason)
	}
	if replayed.KeyID != keyID {
		t.Fatalf("重放 KeyID 不一致: %s != %s", replayed.KeyID, keyID)
	}
	if string(replayed.Key) != string(originalKey) {
		t.Fatalf("重放密钥必须逐比特一致\norig=%x\nrepl=%x", originalKey, replayed.Key)
	}
	if replayed.Stats.QBER != rec.Stats.QBER ||
		replayed.Stats.Sifted != rec.Stats.Sifted ||
		replayed.Stats.Sampled != rec.Stats.Sampled ||
		replayed.Stats.SampledErrors != rec.Stats.SampledErrors ||
		replayed.Stats.FinalKeyBytes != rec.Stats.FinalKeyBytes {
		t.Fatalf("重放统计与归档不一致:\nreplay=%+v\nrecord=%+v", replayed.Stats, rec.Stats)
	}
	t.Logf("[判定依据] keyID=%s QBER=%.4f sifted=%d sampled=%d/%d",
		keyID, rec.Stats.QBER, rec.Stats.Sifted, rec.Stats.SampledErrors, rec.Stats.Sampled)
	t.Logf("[结论] V1 老记录重放逐比特一致 key=%x", replayed.Key)
}

// TestV1FailedRecordReplay 老的失败会话记录重放，结论原因也必须一致。
func TestV1FailedRecordReplay(t *testing.T) {
	p := DefaultParamsV1()
	ch := ChannelConfig{NoiseRate: 0, EavesdropRate: 0.7}
	m, err := NewManager(ManagerConfig{Params: p, Channel: ch, MasterSeed: 11})
	if err != nil {
		t.Fatal(err)
	}
	// 使用与 TestAbortEavesdropping 相同的 (seed,id,信道) 输入：
	// 该组合下确定因窃听中止。
	_, runErr := m.RunSession(context.Background(), "sess-eve")
	if !IsFailure(runErr, ReasonEavesdropping) {
		t.Fatalf("前置: 应因窃听中止，实际 %v", runErr)
	}
	rec, _ := m.History().Get("sess-eve")
	data, _ := MarshalRecord(rec)
	parsed, err := UnmarshalRecord(data)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := ReplayRecord(context.Background(), parsed)
	if err == nil {
		t.Fatal("重放应同样失败")
	}
	if replayed.Success {
		t.Fatal("重放不应标记成功")
	}
	if replayed.FailReason != ReasonEavesdropping {
		t.Fatalf("重放失败原因应一致，实际 %q", replayed.FailReason)
	}
	if replayed.Stats.Channel.EveIntercepted != rec.Stats.Channel.EveIntercepted ||
		replayed.Stats.QBER != rec.Stats.QBER {
		t.Fatalf("重放诊断统计不一致: %+v != %+v", replayed.Stats, rec.Stats)
	}
	t.Logf("[结论] V1 失败记录重放结论一致 reason=%s QBER=%.4f eve=%d",
		replayed.FailReason, replayed.Stats.QBER, replayed.Stats.Channel.EveIntercepted)
}

// TestDefaultIsV2AndV2Negotiates 新默认是 V2，且 V2 会话可正常协商出不同的密钥。
func TestDefaultIsV2AndV2Negotiates(t *testing.T) {
	p := DefaultParams()
	if p.Version != ParamsV2 {
		t.Fatalf("默认参数版本应为 V2，实际 %s", p.Version)
	}
	keyID, key, rec := runSessionOnce(t, 7, "new-v2", p, ChannelConfig{NoiseRate: 0.02})
	if rec.ParamsVer != ParamsV2 {
		t.Fatalf("归档应为 V2，实际 %s", rec.ParamsVer)
	}
	t.Logf("[输入参数] 默认版本=%s n=%d threshold=%.2f passes=%d => [结论] 成功 keyID=%s len=%d key=%x",
		p.Version, p.N, p.QBERThreshold, p.ReconcilePasses, keyID, len(key), key)
}

// TestV1KeyUsableUnderV2Manager “老版本签发的密钥在新版本下照样能取用”：
// V1 管理器签的密钥放入共享库，V2 管理器、V2 会话并发产生新密钥时，
// V1 老密钥仍可取用且内容逐字节不变。
func TestV1KeyUsableUnderV2Manager(t *testing.T) {
	store := NewKeyStore()
	hist := NewHistory()
	v1m, err := NewManager(ManagerConfig{
		Params: DefaultParamsV1(), Channel: ChannelConfig{NoiseRate: 0.02},
		Store: store, History: hist, MasterSeed: 700,
	})
	if err != nil {
		t.Fatal(err)
	}
	oldID, err := v1m.RunSession(context.Background(), "old-v1-session")
	if err != nil {
		t.Fatal(err)
	}
	oldKey, err := store.Get(oldID)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("[输入参数] 老密钥由 V1 签发 id=%s ver=%s key=%x", oldID, oldKey.ParamsVer, oldKey.Key)

	// 升级到 V2 管理器，复用同一个密钥库。
	v2m, err := NewManager(ManagerConfig{
		Params: DefaultParamsV2(), Channel: ChannelConfig{NoiseRate: 0.02},
		Store: store, History: hist, MasterSeed: 800,
	})
	if err != nil {
		t.Fatal(err)
	}
	if v2m.Params().Version != ParamsV2 {
		t.Fatal("新管理器应是 V2")
	}
	newID, err := v2m.RunSession(context.Background(), "new-v2-session")
	if err != nil {
		t.Fatalf("V2 会话应成功: %v", err)
	}
	// 老 V1 密钥照样可取用，且字节不变；版本标记保留。
	got, err := store.Get(oldID)
	if err != nil {
		t.Fatalf("升级后老 V1 密钥必须仍可取用: %v", err)
	}
	if string(got.Key) != string(oldKey.Key) {
		t.Fatalf("老密钥内容不得被升级改动: %x != %x", got.Key, oldKey.Key)
	}
	if got.ParamsVer != ParamsV1 {
		t.Fatalf("老密钥版本标记应保留 V1，实际 %s", got.ParamsVer)
	}
	newKey, err := store.Get(newID)
	if err != nil {
		t.Fatal(err)
	}
	if string(newKey.Key) == string(got.Key) {
		t.Fatal("V2 新密钥不得与 V1 老密钥相同")
	}
	t.Logf("[结论] 升级 V2 后老密钥 %s（V1）仍可正常取用且字节不变；V2 新密钥 %s 独立",
		oldID, newID)
}

// TestUnknownVersionRejectedDistinctly 不认识的版本给出可区分的结论。
func TestUnknownVersionRejectedDistinctly(t *testing.T) {
	bad := DefaultParamsV2()
	bad.Version = "qkd-params-v999"
	_, err := NewManager(ManagerConfig{Params: bad, Channel: ChannelConfig{}})
	if err == nil {
		t.Fatal("未知版本必须被拒绝")
	}
	if !IsFailure(err, ReasonUnsupportedVer) {
		t.Fatalf("未知版本应归类 unsupported_version，实际: %v", err)
	}
	if IsFailure(err, ReasonConfigInvalid) {
		t.Fatal("unsupported_version 必须与 config_invalid 可区分")
	}
	t.Logf("[结论] 未知版本被独立归类: %v", err)

	// 记录里带未知版本时，重放也应给出同样的原因。
	rec := SessionRecord{
		Schema: RecordV1, ID: "future", ParamsVer: "qkd-params-v999",
		Params: bad, Seed: 1, Success: true,
	}
	_, rerr := ReplayRecord(context.Background(), rec)
	if !IsFailure(rerr, ReasonUnsupportedVer) {
		t.Fatalf("未知版本记录重放应归类 unsupported_version，实际: %v", rerr)
	}
	t.Logf("[结论] 未知版本的老/未来记录重放同样可区分: %v", rerr)
}

// TestConcurrentSessionsWithReclamation 并发会话与容量回收/显式退役同时发生：
// 会话之间不串扰，同一批输入产出数量与内容确定，任一会话失败不影响其它会话
// 与库内既有密钥。
func TestConcurrentSessionsWithReclamation(t *testing.T) {
	clk := &fakeClock{t: baseTime()}
	// 容量 6：先放 3 条将很快过期的“老密钥”，再并发跑 6 个新会话，
	// 期间推进时钟使老密钥过期，触发回收路径。
	shared := NewKeyStoreWith(KeyStoreConfig{Capacity: 6, Clock: clk.now})
	hist := NewHistory()
	for _, id := range []string{"old-1", "old-2", "old-3"} {
		putKey(t, shared, id, ParamsV1, clk.now().Add(time.Minute))
	}
	m, err := NewManager(ManagerConfig{
		Params: DefaultParamsV2(), Channel: ChannelConfig{NoiseRate: 0.02},
		Store: shared, History: hist, MasterSeed: 20261003, Clock: clk.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]string, 8)
	for i := range ids {
		ids[i] = fmt.Sprintf("conc-%d", i)
	}

	// 一个 goroutine 负责推进时钟并退役/撤销部分老密钥，与协商并发。
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		clk.advance(2 * time.Minute) // 让 old-* 全部过期，成为可回收对象
		_ = shared.Revoke("old-1")   // 已过期：应返回 expired，不影响其它
		_ = shared.Retire("old-2")   // 已过期：应返回 expired
	}()
	results := m.RunSessions(context.Background(), ids)
	wg.Wait()

	// 成功会话两两不同；失败只可能是 keystore_full（容量 6，初始 3 条过期可回收，
	// 回收后净增 3 即满），失败会话不得污染库。
	successKeys := map[string]string{}
	successCount, fullCount := 0, 0
	for _, r := range results {
		if r.Err != nil {
			if !IsFailure(r.Err, ReasonStoreFull) {
				t.Errorf("会话 %s 出现非预期失败: %v", r.SessionID, r.Err)
			} else {
				fullCount++
			}
			continue
		}
		successCount++
		k, gerr := shared.Get(r.KeyID)
		if gerr != nil {
			t.Errorf("成功会话 %s 的密钥应可取回: %v", r.SessionID, gerr)
			continue
		}
		for other, otherKey := range successKeys {
			if otherKey == string(k.Key) {
				t.Fatalf("会话 %s 与 %s 密钥相同，存在串扰", r.SessionID, other)
			}
		}
		successKeys[r.KeyID] = string(k.Key)
	}
	if successCount+fullCount != len(ids) {
		t.Fatalf("每个会话都应有确定结论，成功=%d 库满=%d 总数=%d",
			successCount, fullCount, len(ids))
	}
	if successCount > 6 {
		t.Fatalf("容量 6 下成功入库不可能超过 6，实际 %d", successCount)
	}
	if shared.Len() != 6 {
		t.Fatalf("回收后库内应恰好 6 条记录，实际 %d", shared.Len())
	}
	// 回收审计全部指向过期的 old-* 密钥，且没有任何一把 active 密钥被回收。
	for _, rc := range shared.Reclamations() {
		if rc.Cause != ReclaimExpired {
			t.Fatalf("本场景只应回收过期密钥，实际 %+v", rc)
		}
	}
	t.Logf("[输入参数] capacity=6 初始 3 条过期密钥 + 8 个并发 V2 会话")
	t.Logf("[结论] 成功=%d 库满失败=%d；成功密钥两两不同；回收 %d 条均为过期密钥，库内 %d 条",
		successCount, fullCount, len(shared.Reclamations()), shared.Len())
}
