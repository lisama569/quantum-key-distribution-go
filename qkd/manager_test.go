package qkd

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestConcurrentIsolation runs several sessions in parallel: some healthy,
// some eavesdropped/aborted. It verifies that successful sessions produce
// pairwise different keys, failures never poison the store or other
// sessions, and the store ends up containing exactly the successful keys.
func TestConcurrentIsolation(t *testing.T) {
	mgr := NewManager(NewSeededRand(999), testLogger{t})
	base, _ := DefaultParameters(ConfigV1)

	const n = 12
	var wg sync.WaitGroup
	results := make([]error, n)
	keys := make([][]byte, n)
	var wgMu sync.Mutex

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			p := base
			id := "conc-" + string(rune('a'+i))
			// Every third session is adversarial and must abort.
			if i%3 == 2 {
				p.Eavesdrop = true
			}
			ch := mgr.StartSession(id, p, uint64(i)*7919+1)
			res := <-ch
			wgMu.Lock()
			results[i] = res.Err
			if res.Err == nil {
				keys[i] = append([]byte(nil), res.Key.Secret...)
			}
			wgMu.Unlock()
		}(i)
	}
	wg.Wait()

	successCount, failCount := 0, 0
	seen := map[string]bool{}
	for i, err := range results {
		if err != nil {
			failCount++
			pe, ok := AsProtocolError(err)
			if !ok || pe.Code != FailureEavesdrop {
				t.Fatalf("session %d: expected eavesdrop abort, got %v", i, err)
			}
			// Failed session record carries no key id.
			rec, ok := mgr.Records().Get("conc-" + string(rune('a'+i)))
			if !ok || rec.Success || rec.KeyID != "" {
				t.Fatalf("failed session %d record must exist with no key", i)
			}
			continue
		}
		successCount++
		if len(keys[i]) != base.FinalKeyLength {
			t.Fatalf("session %d key length %d", i, len(keys[i]))
		}
		ks := string(keys[i])
		if seen[ks] {
			t.Fatalf("session %d produced a duplicate key — material cross-talk", i)
		}
		seen[ks] = true
	}
	t.Logf("concurrent result: %d succeeded, %d failed, %d distinct keys",
		successCount, failCount, len(seen))

	// Store must contain exactly the successful keys and remain intact.
	infos := mgr.Keys().List()
	if len(infos) != successCount {
		t.Fatalf("store has %d keys, want %d (failures must not corrupt store)",
			len(infos), successCount)
	}
	for _, info := range infos {
		if info.State != KeyActive {
			t.Fatalf("unexpected key state %s", info.State)
		}
		if _, err := mgr.Keys().Get(info.ID); err != nil {
			t.Fatalf("successful key %s not retrievable: %v", info.ID, err)
		}
	}
	if len(mgr.Records().All()) != n {
		t.Fatalf("records = %d, want %d (every session recorded)", len(mgr.Records().All()), n)
	}
}

// TestFailureDoesNotAffectOthers verifies that a failing session leaves
// pre-existing keys untouched and that a later healthy session still works.
func TestFailureDoesNotAffectOthers(t *testing.T) {
	mgr := NewManager(NewSeededRand(5), testLogger{t})
	p, _ := DefaultParameters(ConfigV1)

	k1, err := mgr.RunSession(context.Background(), "good-1", p, 11)
	if err != nil {
		t.Fatalf("good-1: %v", err)
	}
	bad := p
	bad.NoiseRate = 0.30
	if _, err := mgr.RunSession(context.Background(), "bad-1", bad, 22); err == nil {
		t.Fatal("bad-1 should abort")
	} else {
		pe, _ := AsProtocolError(err)
		t.Logf("bad-1 classified as %q: %s", pe.Code, pe.Message)
	}
	k3, err := mgr.RunSession(context.Background(), "good-2", p, 33)
	if err != nil {
		t.Fatalf("good-2 after failure: %v", err)
	}

	if string(k1.Secret) == string(k3.Secret) {
		t.Fatal("distinct sessions produced identical keys")
	}
	// The earlier key is still fully accessible and unchanged.
	stored, err := mgr.Keys().Get(k1.ID)
	if err != nil {
		t.Fatalf("pre-existing key lost after another session failed: %v", err)
	}
	if string(stored.Secret) != string(k1.Secret) {
		t.Fatal("pre-existing key material was modified")
	}
	t.Logf("store isolation verified: %d keys present after interleaved failure",
		len(mgr.Keys().List()))
}

// TestDestroyedKeyInaccessible end-to-end: succeed, destroy, then confirm
// retrieval is denied and the manager/record distinguish the state.
func TestDestroyedKeyInaccessible(t *testing.T) {
	mgr := NewManager(NewSeededRand(5), testLogger{t})
	p, _ := DefaultParameters(ConfigV1)
	k, err := mgr.RunSession(context.Background(), "life-1", p, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.Keys().Get(k.ID); err != nil {
		t.Fatalf("key should be active: %v", err)
	}
	if err := mgr.Keys().Destroy(k.ID, time.Now()); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if _, err := mgr.Keys().Get(k.ID); err == nil {
		t.Fatal("destroyed key must be inaccessible")
	} else {
		assertCode(t, err, FailureKeyDestroyed)
	}
	// The success record itself is still present and parseable.
	rec, ok := mgr.Records().Get("life-1")
	if !ok || !rec.Success {
		t.Fatal("historical success record missing")
	}
	if !strings.HasPrefix(rec.KeyID, "key-") {
		t.Fatalf("record key id wrong: %q", rec.KeyID)
	}
}

// TestDuplicateSessionIDRejected ensures two registrations cannot collide.
func TestDuplicateSessionIDRejected(t *testing.T) {
	mgr := NewManager(NewSeededRand(5), nil)
	p, _ := DefaultParameters(ConfigV1)
	ch := mgr.StartSession("dup", p, 1)
	<-ch // let it finish
	_, err := mgr.RunSession(context.Background(), "dup", p, 2)
	assertCode(t, err, FailureSessionReused)
}
