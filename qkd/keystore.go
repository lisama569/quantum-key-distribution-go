package qkd

import (
	"sort"
	"sync"
	"time"
)

// KeyState 表示密钥生命周期状态。
type KeyState string

const (
	// KeyActive：在有效期内，可正常 Get 取用。
	KeyActive KeyState = "active"
	// KeyExpired：超过 NotAfter 有效期，不可取用（惰性判定，不可恢复）。
	KeyExpired KeyState = "expired"
	// KeyRetired：被显式提前退役，不可取用（不可恢复）。
	KeyRetired KeyState = "retired"
	// KeyRevoked：被撤销，不可取用（不可恢复）。
	KeyRevoked KeyState = "revoked"
	// KeyDestroyed：被销毁的终态，不可取用，任何操作都无法使其复活。
	KeyDestroyed KeyState = "destroyed"
)

// StoredKey 为密钥库中一条受生命周期管理的密钥。
// Key 字节仅在 Active 状态可取回；过期/退役/撤销/销毁后被清零。
type StoredKey struct {
	ID        string
	Key       []byte
	State     KeyState
	ParamsVer ParamsVersion
	// NotAfter 为有效期截止时刻；当前时间到达或超过该时刻即视为过期。
	// 零值表示长期有效（不过期）。
	NotAfter time.Time
	// InactiveAt 记录密钥离开 active 的时刻（过期时取 NotAfter），
	// 用于容量回收时“最早失效优先”的确定性排序。零值表示仍 active。
	InactiveAt time.Time
	// CreatedAt 为入库时刻。
	CreatedAt time.Time
}

// reclaimable 报告该状态是否允许在容量压力下被回收。
func (s KeyState) reclaimable() bool {
	switch s {
	case KeyExpired, KeyRetired, KeyRevoked, KeyDestroyed:
		return true
	}
	return false
}

// ReclaimReason 记录一次容量回收是依据密钥的哪类失效状态执行的。
type ReclaimReason string

const (
	ReclaimExpired   ReclaimReason = "expired"
	ReclaimRetired   ReclaimReason = "retired"
	ReclaimRevoked   ReclaimReason = "revoked"
	ReclaimDestroyed ReclaimReason = "destroyed"
)

// ReclaimEvent 是一条容量回收审计记录：回收了哪把密钥、为什么、什么时候。
type ReclaimEvent struct {
	KeyID       string        `json:"key_id"`
	ParamsVer   ParamsVersion `json:"params_ver"`
	Reason      ReclaimReason `json:"reason"`
	StateBefore KeyState      `json:"state_before"`
	// InactiveAt 为被回收密钥离开 active 的时刻。
	InactiveAt  time.Time `json:"inactive_at"`
	ReclaimedAt time.Time `json:"reclaimed_at"`
}

// KeyStoreConfig 为密钥库配置。
type KeyStoreConfig struct {
	// Capacity 为按条数计算的容量上限；<=0 表示不限制（默认行为）。
	Capacity int
	// Now 注入时钟，便于测试确定性地驱动“到期”；nil 时使用 time.Now。
	Now func() time.Time
}

// KeyStore 是线程安全的本地密钥库。
// 并发会话可能同时写入，故所有访问均由互斥锁保护；
// 返回密钥时返回字节副本，调用方无法借由切片别名改动库内材料。
//
// 容量回收策略：容量到达上限时，只允许回收 expired/retired/revoked/
// destroyed 的密钥（最早失效优先），绝不回收仍在有效期内的 active 密钥；
// 若没有任何可回收密钥，则本次写入以 store_full 明确失败，已有内容不变。
// 每次回收都留下可查询的 ReclaimEvent 审计记录。
type KeyStore struct {
	mu       sync.Mutex
	keys     map[string]*StoredKey
	capacity int
	now      func() time.Time
	audit    []ReclaimEvent
}

// NewKeyStore 构造无容量上限的空密钥库。
func NewKeyStore() *KeyStore {
	return NewKeyStoreWith(KeyStoreConfig{})
}

// NewKeyStoreWith 按配置构造密钥库（可设容量上限与注入时钟）。
func NewKeyStoreWith(cfg KeyStoreConfig) *KeyStore {
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &KeyStore{keys: map[string]*StoredKey{}, capacity: cfg.Capacity, now: now}
}

// Capacity 返回容量上限；<=0 表示不限制。
func (s *KeyStore) Capacity() int { return s.capacity }

// Len 返回当前条目数（含已失效但尚未回收的墓碑条目）。
func (s *KeyStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.keys)
}

// Put 存入一条新密钥（ID 冲突时报错，已有内容不受影响）。
//
// 若容量已满，先尝试回收一把失效/退役密钥（最早失效优先）；
// 没有可回收密钥时返回 store_full，绝不覆盖或挤掉 active 密钥。
func (s *KeyStore) Put(k StoredKey) error {
	if k.ID == "" {
		return fail(ReasonConfigInvalid, "key id must not be empty")
	}
	if len(k.Key) == 0 {
		return fail(ReasonConfigInvalid, "key material must not be empty")
	}
	if !k.NotAfter.IsZero() && !s.now().Before(k.NotAfter) {
		return fail(ReasonConfigInvalid, "cannot store key %q that is already expired", k.ID)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.keys[k.ID]; exists {
		return fail(ReasonSessionReused, "key id %q already exists", k.ID)
	}
	now := s.now()
	if s.capacity > 0 {
		for len(s.keys) >= s.capacity {
			if !s.reclaimOneLocked(now) {
				return fail(ReasonStoreFull,
					"key store is at capacity %d and no expired/retired/revoked/destroyed key is reclaimable",
					s.capacity)
			}
		}
	}
	cp := make([]byte, len(k.Key))
	copy(cp, k.Key)
	state := k.State
	if state == "" {
		state = KeyActive
	}
	if state != KeyActive {
		return fail(ReasonConfigInvalid, "new key %q must be stored in active state, got %q", k.ID, state)
	}
	created := k.CreatedAt
	if created.IsZero() {
		created = now
	}
	s.keys[k.ID] = &StoredKey{
		ID:        k.ID,
		Key:       cp,
		State:     KeyActive,
		ParamsVer: k.ParamsVer,
		NotAfter:  k.NotAfter,
		CreatedAt: created,
	}
	return nil
}

// reclaimOneLocked 回收一把可回收密钥（最早失效优先，其次按 ID 确定序）。
// 没有可回收密钥时返回 false，且不改动任何内容。
func (s *KeyStore) reclaimOneLocked(now time.Time) bool {
	var victim *StoredKey
	for _, k := range s.keys {
		st := s.effectiveStateLocked(k, now)
		if !st.reclaimable() {
			continue
		}
		if victim == nil || k.InactiveAt.Before(victim.InactiveAt) ||
			(k.InactiveAt.Equal(victim.InactiveAt) && k.ID < victim.ID) {
			victim = k
		}
	}
	if victim == nil {
		return false
	}
	st := victim.State
	ev := ReclaimEvent{
		KeyID:       victim.ID,
		ParamsVer:   victim.ParamsVer,
		Reason:      reclaimReasonFor(st),
		StateBefore: st,
		InactiveAt:  victim.InactiveAt,
		ReclaimedAt: now,
	}
	if victim.Key != nil {
		wipe(victim.Key)
	}
	delete(s.keys, victim.ID)
	s.audit = append(s.audit, ev)
	return true
}

func reclaimReasonFor(st KeyState) ReclaimReason {
	switch st {
	case KeyExpired:
		return ReclaimExpired
	case KeyRetired:
		return ReclaimRetired
	case KeyRevoked:
		return ReclaimRevoked
	default:
		return ReclaimDestroyed
	}
}

// ReclaimLog 返回容量回收审计记录的副本（按发生顺序）。
func (s *KeyStore) ReclaimLog() []ReclaimEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]ReclaimEvent, len(s.audit))
	copy(out, s.audit)
	return out
}

// effectiveStateLocked 对 active 密钥做到期惰性判定：
// 当前时间到达/超过 NotAfter 时转入 expired 并清零材料。
// 已离开 active 的密钥状态具有粘性，任何回收/升级都不能使其复活。
func (s *KeyStore) effectiveStateLocked(k *StoredKey, now time.Time) KeyState {
	if k.State == KeyActive && !k.NotAfter.IsZero() && !now.Before(k.NotAfter) {
		wipe(k.Key)
		k.Key = nil
		k.State = KeyExpired
		k.InactiveAt = k.NotAfter
	}
	return k.State
}

// classifiedLocked 返回密钥当前有效状态，并将状态映射为对应的取用失败原因。
func classifiedError(id string, st KeyState) error {
	switch st {
	case KeyExpired:
		return fail(ReasonKeyExpired, "key %q has expired", id)
	case KeyRetired:
		return fail(ReasonKeyRetired, "key %q has been retired", id)
	case KeyRevoked:
		return fail(ReasonKeyRevoked, "key %q has been revoked", id)
	case KeyDestroyed:
		return fail(ReasonKeyDestroyed, "key %q has been destroyed", id)
	default:
		return fail(ReasonSessionAborted, "key %q is not usable: %s", id, st)
	}
}

// Get 按 ID 取回 Active 密钥的副本；
// 不存在 / 已过期 / 已退役 / 已撤销 / 已销毁分别返回互相可区分的错误原因，
// 任何失败都不返回字节。
func (s *KeyStore) Get(id string) (StoredKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.keys[id]
	if !ok {
		return StoredKey{}, fail(ReasonKeyNotFound, "key %q not found", id)
	}
	if st := s.effectiveStateLocked(k, s.now()); st != KeyActive {
		return StoredKey{}, classifiedError(id, st)
	}
	cp := make([]byte, len(k.Key))
	copy(cp, k.Key)
	return StoredKey{
		ID: k.ID, Key: cp, State: KeyActive, ParamsVer: k.ParamsVer,
		NotAfter: k.NotAfter, InactiveAt: k.InactiveAt, CreatedAt: k.CreatedAt,
	}, nil
}

// Retire 将仍在有效期内的密钥显式提前退役并清零字节（不可再 Get）。
// 重复退役幂等；对已过期/已撤销/已销毁密钥调用返回可区分的错误。
func (s *KeyStore) Retire(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.keys[id]
	if !ok {
		return fail(ReasonKeyNotFound, "key %q not found", id)
	}
	now := s.now()
	switch s.effectiveStateLocked(k, now) {
	case KeyActive:
		wipe(k.Key)
		k.Key = nil
		k.State = KeyRetired
		k.InactiveAt = now
		return nil
	case KeyRetired:
		return nil
	case KeyExpired:
		return classifiedError(id, KeyExpired)
	case KeyRevoked:
		return classifiedError(id, KeyRevoked)
	default:
		return classifiedError(id, KeyDestroyed)
	}
}

// Revoke 将密钥标记为已撤销并清除其字节（不可再 Get）。
// 重复撤销幂等；已过期/已退役/已销毁密钥的状态具有粘性，各自返回可区分错误。
func (s *KeyStore) Revoke(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.keys[id]
	if !ok {
		return fail(ReasonKeyNotFound, "key %q not found", id)
	}
	now := s.now()
	switch s.effectiveStateLocked(k, now) {
	case KeyActive, KeyRetired:
		wipe(k.Key)
		k.Key = nil
		k.State = KeyRevoked
		if k.InactiveAt.IsZero() {
			k.InactiveAt = now
		}
		return nil
	case KeyRevoked:
		return nil
	case KeyExpired:
		return classifiedError(id, KeyExpired)
	default:
		return classifiedError(id, KeyDestroyed)
	}
}

// Destroy 将密钥标记为已销毁并清除其字节。销毁为终态，不可逆；重复销毁幂等。
// 过期/退役/撤销状态下仍可销毁（销毁是最后的合规处置）。
func (s *KeyStore) Destroy(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.keys[id]
	if !ok {
		return fail(ReasonKeyNotFound, "key %q not found", id)
	}
	if k.State == KeyDestroyed {
		return nil
	}
	now := s.now()
	s.effectiveStateLocked(k, now)
	wipe(k.Key)
	k.Key = nil
	k.State = KeyDestroyed
	if k.InactiveAt.IsZero() {
		k.InactiveAt = now
	}
	return nil
}

// State 查询密钥状态（会对到期密钥做惰性状态迁移）；不存在返回 key_not_found。
func (s *KeyStore) State(id string) (KeyState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.keys[id]
	if !ok {
		return "", fail(ReasonKeyNotFound, "key %q not found", id)
	}
	return s.effectiveStateLocked(k, s.now()), nil
}

// IDs 返回当前全部密钥 ID（含尚未被回收的失效条目；顺序未定义，仅用于盘点）。
func (s *KeyStore) IDs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.keys))
	for id := range s.keys {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// wipe 清零字节切片，确保失败/撤销/销毁路径不残留半成品材料。
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
