package qkd

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

// TestConcurrentSessionsWithReclaim 高并发下同时发生会话签发与回收/退役：
//   - 容量受限迫使大量签发触发回收或 store_full，两种结局都必须自洽；
//   - 会话间密钥不重复；同一成功会话不重复产出；
//   - 回收只动失效/退役密钥，活动密钥即使因容量失败也保持可用；
//   - 任一失败不影响其它会话与库内既有密钥。
func TestConcurrentSessionsWithReclaim(t *testing.T) {
	base := time.Date(2026, 10, 3, 20, 0, 0, 0, time.UTC)
	var now time.Time = base
	var clockMu sync.Mutex
	nowFunc := func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return now
	}
	store := NewKeyStoreWith(KeyStoreConfig{Capacity: 12, Now: nowFunc})
	m, err := NewManager(ManagerConfig{
		Params: DefaultParams(), Channel: ChannelConfig{NoiseRate: 0.02},
		Store: store, MasterSeed: 424242, Now: nowFunc, KeyTTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	const n = 40
	ids := make([]string, n)
	for i := range ids {
		ids[i] = fmt.Sprintf("cc-%02d", i)
	}

	var wg sync.WaitGroup
	// 签发者：并发跑两批（第二批复用第一批 ID，应全部 session_reused，
	// 且绝不会因此产生第二把密钥）。
	issued := make(chan string, n)
	wg.Add(1)
	go func() {
		defer wg.Done()
		rs := m.RunSessions(context.Background(), ids)
		for _, r := range rs {
			if r.Err == nil {
				issued <- r.KeyID
			}
		}
		close(issued)
	}()

	// 退役者：反复尝试退役随机出现的密钥，制造持续回收压力。
	wg.Add(1)
	go func() {
		defer wg.Done()
		for k := 0; k < 200; k++ {
			for _, id := range store.IDs() {
				// 一半概率退役；Retire 对并发中已消失的条目报错也属正常。
				_ = store.Retire(id)
			}
		}
	}()

	// 时间推进者：让带 TTL 的密钥陆续过期，制造另一类回收来源。
	wg.Add(1)
	go func() {
		defer wg.Done()
		for d := 0; d < 30; d++ {
			clockMu.Lock()
			now = now.Add(6 * time.Minute) // 30*6m = 3h > TTL
			clockMu.Unlock()
			time.Sleep(time.Millisecond)
		}
	}()

	// 盘点者：只读并发，确保无竞态。
	wg.Add(1)
	go func() {
		defer wg.Done()
		for k := 0; k < 200; k++ {
			_ = store.IDs()
			_ = store.Len()
			_ = store.ReclaimLog()
		}
	}()

	issuedIDs := map[string]bool{}
	for id := range issued {
		if issuedIDs[id] {
			t.Fatalf("同一密钥 ID 被签发两次: %s", id)
		}
		issuedIDs[id] = true
	}
	wg.Wait()

	// 所有曾签发的密钥只有三种合规去向：仍可正常取用；已失效但仍在库
	// （expired/retired/revoked/destroyed）；已被容量回收（not_found 且审计可查）。
	// 绝不能出现“活动密钥被回收”或“消失但无审计”。
	var live, deadInStore, reclaimed int
	audit := map[string]bool{}
	for _, ev := range store.ReclaimLog() {
		audit[ev.KeyID] = true
		if ev.StateBefore == KeyActive {
			t.Fatalf("活动密钥被回收: %+v", ev)
		}
	}
	for id := range issuedIDs {
		if _, err := store.Get(id); err != nil {
			switch {
			case IsFailure(err, ReasonKeyNotFound):
				if !audit[id] {
					t.Fatalf("密钥 %s 消失但回收审计无记录", id)
				}
				reclaimed++
			case IsFailure(err, ReasonKeyExpired), IsFailure(err, ReasonKeyRetired),
				IsFailure(err, ReasonKeyRevoked), IsFailure(err, ReasonKeyDestroyed):
				deadInStore++
			default:
				t.Fatalf("已签发密钥出现未预期结论: %v", err)
			}
		} else {
			live++
		}
	}
	if live+deadInStore+reclaimed != len(issuedIDs) {
		t.Fatalf("签发去向对不上: live=%d dead=%d reclaimed=%d issued=%d",
			live, deadInStore, reclaimed, len(issuedIDs))
	}

	// 第二批：同一批会话 ID 重放。
	// 已真正签发过的会话必须 session_reused；当初因 store_full 未签发的会话
	// 允许重试：要么再次 store_full，要么在腾出空间后补发同一确定性密钥。
	dup := m.RunSessions(context.Background(), ids)
	for _, r := range dup {
		// 依据签发密钥集合判断该会话第一轮是否真正入库。
		deterministicID := KeyID(r.SessionID, m.Params().Version, m.sessionSeed(r.SessionID))
		wasIssued := issuedIDs[deterministicID]
		if wasIssued {
			if r.Err == nil || !IsFailure(r.Err, ReasonSessionReused) {
				t.Fatalf("已签发会话 %s 必须 session_reused，实际 key=%s err=%v",
					r.SessionID, r.KeyID, r.Err)
			}
			continue
		}
		if r.Err != nil && !IsFailure(r.Err, ReasonStoreFull) {
			t.Fatalf("未签发会话 %s 重试只应 store_full/成功，实际 %v", r.SessionID, r.Err)
		}
		if r.Err == nil && r.KeyID != deterministicID {
			t.Fatalf("补发会话 %s 的密钥 ID 必须确定一致", r.SessionID)
		}
	}
	t.Logf("[结论] 签发=%d（存活可取=%d，失效在库=%d，合规回收=%d，审计=%d 条）；"+
		"已签发会话重复执行全部 session_reused，未签发会话重试结论自洽；活动密钥从未被回收",
		len(issuedIDs), live, deadInStore, reclaimed, len(store.ReclaimLog()))
}
