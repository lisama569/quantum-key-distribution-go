package qkd

import (
	"context"
	"fmt"
	"sync"
)

// Manager runs multiple QKD sessions concurrently with strict isolation:
// each session derives its own random streams from a unique per-session
// seed, keys land in a mutex-protected store, and a failure in one session
// never affects another session or any existing key material.
type Manager struct {
	mu       sync.Mutex
	keys     *KeyStore
	records  *RecordBook
	sessions map[string]*Session
	baseRand Rand
	log      Logger
}

// NewManager creates a manager with a root deterministic source. Every
// session receives a child stream derived from its own id and salt, so
// concurrent sessions never share random prefixes or key material.
func NewManager(root Rand, log Logger) *Manager {
	if root == nil {
		root = NewSeededRand(0)
	}
	return &Manager{
		keys:     NewKeyStore(),
		records:  NewRecordBook(),
		sessions: map[string]*Session{},
		baseRand: root,
		log:      log,
	}
}

// sessionSeed derives a dedicated 64-bit seed for a session from the root
// source, the session id and the caller-provided salt.
func (m *Manager) sessionSeed(id string, salt uint64) Rand {
	child := m.baseRand.Seed("session:" + id)
	// Fold in the salt by two draws XOR a constant so different salts split
	// streams while remaining deterministic.
	v := child.Uint64() ^ salt ^ 0x517b4b6400000000
	return NewSeededRand(v)
}

// StartSession registers and runs a session asynchronously with the given
// parameters and per-session seed salt. The returned channel emits exactly
// one result and is then closed.
func (m *Manager) StartSession(id string, p Parameters, seedSalt uint64) <-chan SessionResult {
	out := make(chan SessionResult, 1)
	if _, err := m.register(id, p, seedSalt); err != nil {
		out <- SessionResult{SessionID: id, Err: err}
		close(out)
		return out
	}
	go func() {
		m.mu.Lock()
		sess := m.sessions[id]
		m.mu.Unlock()
		key, err := sess.Run(context.Background())
		out <- SessionResult{SessionID: id, Key: key, Err: err}
		close(out)
	}()
	return out
}

// register creates a session with its isolated seed and the manager's
// finish hook. Duplicate ids are rejected.
func (m *Manager) register(id string, p Parameters, salt uint64) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if id == "" {
		return nil, NewError(FailureBadParameters, "session id must not be empty")
	}
	if _, exists := m.sessions[id]; exists {
		return nil, NewError(FailureSessionReused,
			fmt.Sprintf("session id %q is already registered", id))
	}
	rng := m.sessionSeed(id, salt)
	sess := NewSession(id, p, rng,
		WithLogger(m.log),
		withFinishHook(m.onFinish),
	)
	m.sessions[id] = sess
	return sess, nil
}

// onFinish is the single point where a terminal session affects shared
// state. The record is always appended (success or failure); the key is
// stored only on success. A storage error never removes existing keys.
func (m *Manager) onFinish(rec SessionRecord, key KeyMaterial) {
	m.records.append(rec)
	if rec.Success && key.ID != "" && len(key.Secret) > 0 {
		if err := m.keys.Put(key); err != nil {
			// Put only fails on duplicate id; the deterministic id makes
			// this unreachable for distinct sessions with distinct ids.
			m.logFn("session %s key store failure: %v", rec.SessionID, err)
		}
	}
}

func (m *Manager) logFn(format string, args ...any) {
	if m.log != nil {
		m.log.Logf(format, args...)
	}
}

// RunSession runs one session synchronously and waits for its result.
func (m *Manager) RunSession(ctx context.Context, id string, p Parameters, seedSalt uint64) (KeyMaterial, error) {
	if err := ctx.Err(); err != nil {
		return KeyMaterial{}, NewError(FailureAborted, err.Error())
	}
	sess, err := m.register(id, p, seedSalt)
	if err != nil {
		return KeyMaterial{}, err
	}
	return sess.Run(ctx)
}

// SessionResult is the single terminal output of a managed session.
type SessionResult struct {
	SessionID string
	Key       KeyMaterial
	Err       error
}

// Keys exposes the managed key store (for query/revoke/destroy).
func (m *Manager) Keys() *KeyStore { return m.keys }

// Records exposes the managed record book.
func (m *Manager) Records() *RecordBook { return m.records }

// Session looks up a registered session by ID.
func (m *Manager) Session(id string) (*Session, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	return s, ok
}
