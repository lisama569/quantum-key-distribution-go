package qkd

import "sync"

// KeyState 表示密钥生命周期状态。
type KeyState string

const (
	KeyActive    KeyState = "active"
	KeyRevoked   KeyState = "revoked"
	KeyDestroyed KeyState = "destroyed"
)

// StoredKey 为密钥库中一条受生命周期管理的密钥。
// Key 字节仅在 Active 状态可取回；撤销/销毁后被清零。
type StoredKey struct {
	ID        string
	Key       []byte
	State     KeyState
	ParamsVer ParamsVersion
}

// KeyStore 是线程安全的本地密钥库。
// 并发会话可能同时写入，故所有访问均由互斥锁保护；
// 返回密钥时返回字节副本，调用方无法借由切片别名改动库内材料。
type KeyStore struct {
	mu   sync.Mutex
	keys map[string]*StoredKey
}

// NewKeyStore 构造空密钥库。
func NewKeyStore() *KeyStore {
	return &KeyStore{keys: map[string]*StoredKey{}}
}

// Put 存入一条新密钥（ID 冲突时报错，已有内容不受影响）。
func (s *KeyStore) Put(k StoredKey) error {
	if k.ID == "" {
		return fail(ReasonConfigInvalid, "key id must not be empty")
	}
	if len(k.Key) == 0 {
		return fail(ReasonConfigInvalid, "key material must not be empty")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.keys[k.ID]; exists {
		return fail(ReasonSessionReused, "key id %q already exists", k.ID)
	}
	cp := make([]byte, len(k.Key))
	copy(cp, k.Key)
	if k.State == "" {
		k.State = KeyActive
	}
	s.keys[k.ID] = &StoredKey{ID: k.ID, Key: cp, State: k.State, ParamsVer: k.ParamsVer}
	return nil
}

// Get 按 ID 取回 Active 密钥的副本；
// 不存在、已撤销或已销毁均返回错误，且不返回任何字节。
func (s *KeyStore) Get(id string) (StoredKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.keys[id]
	if !ok {
		return StoredKey{}, fail(ReasonSessionAborted, "key %q not found", id)
	}
	switch k.State {
	case KeyRevoked:
		return StoredKey{}, fail(ReasonSessionAborted, "key %q has been revoked", id)
	case KeyDestroyed:
		return StoredKey{}, fail(ReasonSessionAborted, "key %q has been destroyed", id)
	}
	cp := make([]byte, len(k.Key))
	copy(cp, k.Key)
	return StoredKey{ID: k.ID, Key: cp, State: k.State, ParamsVer: k.ParamsVer}, nil
}

// Revoke 将密钥标记为已撤销并清除其字节（不可再 Get）。
// 重复撤销幂等；对已销毁密钥调用返回错误。
func (s *KeyStore) Revoke(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.keys[id]
	if !ok {
		return fail(ReasonSessionAborted, "key %q not found", id)
	}
	if k.State == KeyDestroyed {
		return fail(ReasonSessionAborted, "cannot revoke destroyed key %q", id)
	}
	wipe(k.Key)
	k.Key = nil
	k.State = KeyRevoked
	return nil
}

// Destroy 将密钥标记为已销毁并清除其字节。销毁为终态，不可逆。
func (s *KeyStore) Destroy(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.keys[id]
	if !ok {
		return fail(ReasonSessionAborted, "key %q not found", id)
	}
	wipe(k.Key)
	k.Key = nil
	k.State = KeyDestroyed
	return nil
}

// State 查询密钥状态；不存在返回错误。
func (s *KeyStore) State(id string) (KeyState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.keys[id]
	if !ok {
		return "", fail(ReasonSessionAborted, "key %q not found", id)
	}
	return k.State, nil
}

// IDs 返回当前全部密钥 ID（顺序未定义，仅用于盘点）。
func (s *KeyStore) IDs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.keys))
	for id := range s.keys {
		out = append(out, id)
	}
	return out
}

// wipe 清零字节切片，确保失败/撤销/销毁路径不残留半成品材料。
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
