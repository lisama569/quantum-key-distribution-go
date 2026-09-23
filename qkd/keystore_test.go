package qkd

import (
	"bytes"
	"testing"
	"time"
)

// TestKeyStoreLifecycle covers query, defensive copy, revocation and
// destruction semantics, including that revoked/destroyed material can never
// be retrieved again.
func TestKeyStoreLifecycle(t *testing.T) {
	st := NewKeyStore()
	now := time.Date(2026, 9, 23, 10, 0, 0, 0, time.UTC)
	orig := []byte{1, 2, 3, 4}
	k := KeyMaterial{ID: "k1", Secret: orig, Version: ConfigV1, SessionID: "s1", CreatedAt: now}
	if err := st.Put(k); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// Active retrieval succeeds and returns an independent copy.
	got, err := st.Get("k1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got.Secret, orig) {
		t.Fatalf("secret mismatch")
	}
	got.Secret[0] = 0xFF
	got2, _ := st.Get("k1")
	if got2.Secret[0] != 1 {
		t.Fatalf("Get did not return a defensive copy")
	}
	if len(st.List()) != 1 || st.List()[0].Length != 4 {
		t.Fatalf("List metadata wrong: %+v", st.List())
	}

	// Unknown id.
	if _, err := st.Get("missing"); err == nil {
		t.Fatal("expected FailureKeyNotFound")
	} else {
		assertCode(t, err, FailureKeyNotFound)
	}

	// Revocation blocks retrieval with a distinct code.
	if err := st.Revoke("k1", now.Add(time.Minute)); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, err := st.Get("k1"); err == nil {
		t.Fatal("revoked key must not be retrievable")
	} else {
		assertCode(t, err, FailureKeyRevoked)
	}
	t.Logf("revoked key access correctly rejected; state=%s", st.List()[0].State)

	// Destroy wipes material; afterwards the id maps to a distinct
	// destroyed error and the stored length is zero.
	if err := st.Destroy("k1", now.Add(2*time.Minute)); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if _, err := st.Get("k1"); err == nil {
		t.Fatal("destroyed key must not be retrievable")
	} else {
		assertCode(t, err, FailureKeyDestroyed)
	}
	info := st.List()[0]
	if info.State != KeyDestroyed || info.Length != 0 {
		t.Fatalf("destroyed metadata wrong: %+v", info)
	}
	// Destroy is idempotent.
	if err := st.Destroy("k1", now); err != nil {
		t.Fatalf("idempotent Destroy: %v", err)
	}
	t.Logf("destroyed key access correctly rejected; bytes wiped and length=%d", info.Length)
}

// TestStoreRejectsEmpty ensures no half-finished/empty key can enter the
// store, and duplicate IDs fail.
func TestStoreRejectsEmpty(t *testing.T) {
	st := NewKeyStore()
	if err := st.Put(KeyMaterial{ID: "x"}); err == nil {
		t.Fatal("empty secret must be rejected")
	}
	km := KeyMaterial{ID: "x", Secret: []byte{1}}
	if err := st.Put(km); err != nil {
		t.Fatal(err)
	}
	if err := st.Put(km); err == nil {
		t.Fatal("duplicate id must be rejected")
	}
}
