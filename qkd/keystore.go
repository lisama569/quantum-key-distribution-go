package qkd

import (
	"fmt"
	"sync"
	"time"
)

// KeyState is the lifecycle state of a stored key.
type KeyState string

const (
	// KeyActive can be retrieved and used.
	KeyActive KeyState = "active"
	// KeyRevoked is administratively revoked and must not be returned.
	KeyRevoked KeyState = "revoked"
	// KeyDestroyed has had its material wiped irreversibly.
	KeyDestroyed KeyState = "destroyed"
)

// KeyMaterial is one produced secret key with its lifecycle metadata.
type KeyMaterial struct {
	ID          string
	Secret      []byte
	State       KeyState
	Version     ConfigVersion
	SessionID   string
	CreatedAt   time.Time
	RevokedAt   time.Time
	DestroyedAt time.Time
}

// cloneBytes returns a defensive copy of b.
func cloneBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

// wipe overwrites b with zeros so destroyed material cannot linger.
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// KeyStore is the concurrency-safe key lifecycle manager. Keys are kept in
// memory only; Destroy overwrites the secret bytes before unlinking them.
type KeyStore struct {
	mu sync.Mutex
	// keys keeps an entry even after destruction so Destroy is idempotent
	// and a destroyed ID is distinguishable from a never-seen one.
	keys map[string]*KeyMaterial
}

// NewKeyStore creates an empty store.
func NewKeyStore() *KeyStore {
	return &KeyStore{keys: map[string]*KeyMaterial{}}
}

// Put stores a freshly produced key. Storing an existing ID is an error.
func (s *KeyStore) Put(k KeyMaterial) error {
	if k.ID == "" {
		return NewError(FailureBadParameters, "key id must not be empty")
	}
	if len(k.Secret) == 0 {
		return NewError(FailureBadParameters, "refusing to store an empty key")
	}
	if k.State == "" {
		k.State = KeyActive
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.keys[k.ID]; exists {
		return NewError(FailureBadParameters,
			fmt.Sprintf("key id %q already exists", k.ID))
	}
	stored := k
	stored.Secret = cloneBytes(k.Secret)
	s.keys[k.ID] = &stored
	return nil
}

// Get returns a defensive copy of an active key. Revoked or destroyed keys
// are rejected with typed errors, unknown IDs return FailureKeyNotFound.
func (s *KeyStore) Get(id string) (KeyMaterial, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.keys[id]
	if !ok {
		return KeyMaterial{}, NewError(FailureKeyNotFound,
			fmt.Sprintf("no key with id %q", id))
	}
	switch k.State {
	case KeyRevoked:
		return KeyMaterial{}, NewError(FailureKeyRevoked,
			fmt.Sprintf("key %q was revoked at %s", id, k.RevokedAt.Format(time.RFC3339Nano)))
	case KeyDestroyed:
		return KeyMaterial{}, NewError(FailureKeyDestroyed,
			fmt.Sprintf("key %q was destroyed at %s", id, k.DestroyedAt.Format(time.RFC3339Nano)))
	}
	out := *k
	out.Secret = cloneBytes(k.Secret)
	return out, nil
}

// Revoke marks an active (or destroyed-no-op) key revoked.
func (s *KeyStore) Revoke(id string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.keys[id]
	if !ok {
		return NewError(FailureKeyNotFound, fmt.Sprintf("no key with id %q", id))
	}
	if k.State == KeyDestroyed {
		return NewError(FailureKeyDestroyed,
			fmt.Sprintf("cannot revoke destroyed key %q", id))
	}
	if at.IsZero() {
		at = time.Now()
	}
	k.State = KeyRevoked
	k.RevokedAt = at
	return nil
}

// Destroy wipes and unlinks a key's secret regardless of prior state. It is
// idempotent: destroying an unknown ID is an error, destroying an already
// destroyed key succeeds.
func (s *KeyStore) Destroy(id string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.keys[id]
	if !ok {
		return NewError(FailureKeyNotFound, fmt.Sprintf("no key with id %q", id))
	}
	if at.IsZero() {
		at = time.Now()
	}
	if k.State != KeyDestroyed {
		wipe(k.Secret)
		k.Secret = nil
		k.State = KeyDestroyed
		k.DestroyedAt = at
		k.RevokedAt = time.Time{}
	}
	return nil
}

// KeyInfo is non-secret metadata returned by List.
type KeyInfo struct {
	ID        string
	State     KeyState
	Version   ConfigVersion
	SessionID string
	Length    int
}

// List returns metadata (never secret bytes) for all stored keys.
func (s *KeyStore) List() []KeyInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]KeyInfo, 0, len(s.keys))
	for _, k := range s.keys {
		out = append(out, KeyInfo{
			ID:        k.ID,
			State:     k.State,
			Version:   k.Version,
			SessionID: k.SessionID,
			Length:    len(k.Secret),
		})
	}
	return out
}
