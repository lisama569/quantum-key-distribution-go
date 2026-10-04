package qkd

import (
	"sort"
	"sync"
	"time"
)

// KeyState 表示密钥生命周期状态。
type KeyState string

const (
	// KeyActive：在有效期内可正常取用。
	KeyActive KeyState = "active"
	// KeyRetired：被显式提前退役（记录留存可审计，可被容量回收），不可取用。
	KeyRetired KeyState = "retired"
	// KeyExpired：超过有效期（惰性判定并物化），不可取用，可被容量回收。
	KeyExpired KeyState = "expired"
	// KeyRevoked：被撤销并清零字节，不可取用，可被容量回收。
	KeyRevoked KeyState = "revoked"
	// KeyDestroyed：被销毁的终态，不可逆，不可取用，可被容量回收。
	KeyDestroyed KeyState = "destroyed"
)

// StoredKey 为密钥库中一条受生命周期管理的密钥。
// Key 字节仅在 Active 且未过期状态可取回；退役/过期/撤销/销毁后被清零。
type StoredKey struct {
	ID        string
	Key       []byte
	State     KeyState
	ParamsVer ParamsVersion
	// CreatedAt 为入库时间（时钟取自库配置）。
	CreatedAt time.Time
	// ExpiresAt 为有效期截止时刻；零值表示不过期（长期有效直至显式退役/撤销/销毁）。
	ExpiresAt time.Time
}

// KeyStore 是线程安全的本地密钥库。
// 并发会话可能同时写入，故所有访问均由互斥锁保护；
// 返回密钥时返回字节副本，调用方无法借由切片别名改动库内材料。
//
// 容量上限见 KeyStoreConfig.Capacity：库满后 Put 只允许回收
// “已过期 / 已退役 / 已撤销 / 已销毁”的密钥腾出空间，绝不覆盖仍可
// 正常取用的 Active 密钥；无空间可回收时以 keystore_full 明确失败。
//
// 被回收删除的密钥不会“消失得无影无踪”：其不可用结论以墓碑形式永久留存
// （tombstones，只记状态不记字节，不占容量）。因此回收/版本升级等任何
// 腾挪都不可能让同一 ID 重新以 active 入库（Put 直接按原终态拒绝），
// Get 也仍能区分它当初是 expired/retired/revoked/destroyed 中的哪一种。
type KeyStore struct {
	mu         sync.Mutex
	keys       map[string]*StoredKey
	tombstones map[string]KeyState
	sessions   map[string]sessionIssue
	capacity   int
	now        func() time.Time
	reclog     []ReclamationRecord
}

// sessionIssue 记录“某个会话已成功签发过密钥”这一永久结论：
// 只要会话成功过一次，无论其密钥后来被回收/退役/撤销/到期/销毁，
// 该登记都保留，同一会话永远不可能再产出第二把密钥。
type sessionIssue struct {
	KeyID     string
	ParamsVer ParamsVersion
}

// ReclamationCause 说明一条密钥被容量回收的直接原因。
type ReclamationCause string

const (
	ReclaimExpired   ReclamationCause = "expired"
	ReclaimRetired   ReclamationCause = "retired"
	ReclaimRevoked   ReclamationCause = "revoked"
	ReclaimDestroyed ReclamationCause = "destroyed"
)

// reclaimableStates 列出允许被容量回收的状态。
// 绝不在其中的 active 密钥永远不会被回收/覆盖。
var reclaimableStates = map[KeyState]ReclamationCause{
	KeyExpired:   ReclaimExpired,
	KeyRetired:   ReclaimRetired,
	KeyRevoked:   ReclaimRevoked,
	KeyDestroyed: ReclaimDestroyed,
}

// ReclamationRecord 是一条容量回收审计记录：回收了谁、为什么、什么时候，
// 以及为哪条新密钥腾出空间。记录只追加、不改写，可随时查询。
type ReclamationRecord struct {
	KeyID        string           `json:"key_id"`
	State        KeyState         `json:"state"`
	Cause        ReclamationCause `json:"cause"`
	ParamsVer    ParamsVersion    `json:"params_ver"`
	CreatedAt    time.Time        `json:"created_at"`
	ExpiresAt    time.Time        `json:"expires_at,omitempty"`
	ReclaimedAt  time.Time        `json:"reclaimed_at"`
	ReplacedByID string           `json:"replaced_by_id"`
	Reason       string           `json:"reason"`
}

// KeyStoreConfig 为密钥库配置。
type KeyStoreConfig struct {
	// Capacity 为按条数计的容量上限；<=0 表示不限制。
	Capacity int
	// Clock 为库判定有效期/记录时间戳所用时钟；nil 时使用 time.Now。
	// 测试可注入固定/可控时钟以验证到期行为。
	Clock func() time.Time
}

// NewKeyStore 构造无容量上限的空密钥库（等价于 NewKeyStoreWith(零配置)）。
func NewKeyStore() *KeyStore {
	return NewKeyStoreWith(KeyStoreConfig{})
}

// NewKeyStoreWith 按配置构造密钥库（容量上限与时钟可注入）。
func NewKeyStoreWith(cfg KeyStoreConfig) *KeyStore {
	clock := cfg.Clock
	if clock == nil {
		clock = time.Now
	}
	return &KeyStore{
		keys:       map[string]*StoredKey{},
		tombstones: map[string]KeyState{},
		sessions:   map[string]sessionIssue{},
		capacity:   cfg.Capacity,
		now:        clock,
	}
}

// Cap 返回容量上限（<=0 表示不限）。
func (s *KeyStore) Cap() int { return s.capacity }

// Len 返回当前留存条数（含已过期/退役/撤销/销毁但尚未被回收的记录）。
// 已回收的 ID 只留墓碑，不计入条数、不占容量。
func (s *KeyStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.keys)
}

// Tombstone 查询一个已被回收删除的 ID 留下的不可用结论。
// 第二个返回值为 false 表示该 ID 从未入库、或记录仍在库中（未被回收）。
func (s *KeyStore) Tombstone(id string) (KeyState, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.tombstones[id]
	return st, ok
}

// Put 存入一条新密钥（ID 冲突时报错，已有内容不受影响）。
//
// 若 ExpiresAt 已早于当前时间则拒绝（config_invalid）；State 为空时归一为
// active；显式给出的非 active 态也接受（此时不留存字节）。
func (s *KeyStore) Put(k StoredKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.putLocked(k)
}

// putLocked 为 Put 的持锁实现，供 Put 与 IssueSession 复用；调用方必须持有 s.mu。
func (s *KeyStore) putLocked(k StoredKey) error {
	if k.ID == "" {
		return fail(ReasonConfigInvalid, "key id must not be empty")
	}
	if len(k.Key) == 0 {
		return fail(ReasonConfigInvalid, "key material must not be empty")
	}
	// 已被回收删除的 ID 留有墓碑：该密钥此前已进入不可用状态，回收/腾挪/
	// 版本升级都不允许它以任何状态（尤其 active）重新入库“复活”。
	if st, buried := s.tombstones[k.ID]; buried {
		return terminalFailure(st, k.ID, "cannot put key %q: it was previously reclaimed as %s and can never be usable again")
	}
	if _, exists := s.keys[k.ID]; exists {
		return fail(ReasonSessionReused, "key id %q already exists", k.ID)
	}
	now := s.now()
	if k.CreatedAt.IsZero() {
		k.CreatedAt = now
	}
	if k.State == "" {
		k.State = KeyActive
	}
	if !k.ExpiresAt.IsZero() && !k.ExpiresAt.After(now) {
		return fail(ReasonConfigInvalid, "key %q already expired at %s", k.ID, k.ExpiresAt)
	}
	// 容量上限：库满时只允许回收“已失效/已退役”的密钥为新密钥腾位，
	// 绝不丢弃仍可正常取用的 active 密钥；腾不出空间则明确失败。
	if s.capacity > 0 && len(s.keys) >= s.capacity {
		if err := s.evictOneLocked(k.ID, now); err != nil {
			return err
		}
	}
	cp := make([]byte, len(k.Key))
	copy(cp, k.Key)
	stored := &StoredKey{
		ID:        k.ID,
		Key:       cp,
		State:     k.State,
		ParamsVer: k.ParamsVer,
		CreatedAt: k.CreatedAt,
		ExpiresAt: k.ExpiresAt,
	}
	// 非 active 入库不留存字节。
	if stored.State != KeyActive {
		wipe(stored.Key)
		stored.Key = nil
	}
	s.keys[k.ID] = stored
	return nil
}

// IssueSession 原子地完成“会话去重检查 + 密钥入库”，这是会话签发幂等性的
// 唯一入口：
//
//   - 同一 sessionID 只要成功签发过一次，登记就永久保留。此后无论其密钥
//     是被容量回收、退役、撤销、到期还是销毁，再以该会话签发都会以
//     session_reused 明确失败（返回信息带当初的 KeyID），绝不产出第二把；
//   - 去重检查、容量回收与入库在同一把互斥锁内完成，因此多个管理器/多
//     goroutine 并发签发同一会话时，恰有一个成功，其余全部 session_reused，
//     不会出现检查与入库之间的竞态窗口；
//   - 首次签发若因库满（keystore_full）等失败，会话登记不会写入（本次
//     未成功），库内容保持不变，也不留半成品。
func (s *KeyStore) IssueSession(sessionID string, k StoredKey) error {
	if sessionID == "" {
		return fail(ReasonConfigInvalid, "session id must not be empty")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if prev, ok := s.sessions[sessionID]; ok {
		return fail(ReasonSessionReused,
			"session %q already issued key %q; a session can produce at most one key for its lifetime (even after reclamation/retirement/revocation/expiry/destruction)",
			sessionID, prev.KeyID)
	}
	if err := s.putLocked(k); err != nil {
		return err
	}
	// 入库成功后才落会话登记；二者同锁，对外表现为一次原子提交。
	s.sessions[sessionID] = sessionIssue{KeyID: k.ID, ParamsVer: k.ParamsVer}
	return nil
}

// IssuedSession 返回某会话此前成功签发的密钥 ID 与参数版本。
// 第二个返回值为 false 表示该会话从未成功签发过（密钥可能入库失败、
// 协商中止，或会话 ID 根本不存在）。该登记不会因密钥被回收而移除。
func (s *KeyStore) IssuedSession(sessionID string) (keyID string, ver ParamsVersion, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	prev, exists := s.sessions[sessionID]
	if !exists {
		return "", "", false
	}
	return prev.KeyID, prev.ParamsVer, true
}

// IssuedSessions 返回全部“已成功签发过密钥”的会话 ID（字典序，供盘点/测试）。
func (s *KeyStore) IssuedSessions() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.sessions))
	for id := range s.sessions {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// Get 按 ID 取回“仍在有效期内的 Active 密钥”的副本；
// 不存在 / 已过期 / 已退役 / 已撤销 / 已销毁各自返回互不相同的 FailureReason，
// 且一律不返回任何字节。
func (s *KeyStore) Get(id string) (StoredKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.keys[id]
	if !ok {
		// 记录已被回收：若留有墓碑，按它当初进入不可用的具体原因失败，
		// 而不是笼统的 not_found——不可用的种类必须一直可区分。
		if st, buried := s.tombstones[id]; buried {
			return StoredKey{}, terminalFailure(st, id,
				"key %q is permanently unusable (reclaimed while %s)")
		}
		return StoredKey{}, fail(ReasonKeyNotFound, "key %q not found", id)
	}
	if err := s.materializeExpiryLocked(k); err != nil {
		return StoredKey{}, err
	}
	switch k.State {
	case KeyExpired:
		return StoredKey{}, fail(ReasonKeyExpired, "key %q has expired at %s", id, k.ExpiresAt)
	case KeyRetired:
		return StoredKey{}, fail(ReasonKeyRetired, "key %q has been retired", id)
	case KeyRevoked:
		return StoredKey{}, fail(ReasonKeyRevoked, "key %q has been revoked", id)
	case KeyDestroyed:
		return StoredKey{}, fail(ReasonKeyDestroyed, "key %q has been destroyed", id)
	}
	cp := make([]byte, len(k.Key))
	copy(cp, k.Key)
	return StoredKey{
		ID: k.ID, Key: cp, State: k.State, ParamsVer: k.ParamsVer,
		CreatedAt: k.CreatedAt, ExpiresAt: k.ExpiresAt,
	}, nil
}

// Retire 将密钥显式提前退役并清零字节。退役不是销毁：记录留存以供审计，
// 并可作为容量回收对象。重复退役幂等；对已撤销/已销毁/已过期密钥调用报错
// （这些为终态，退役不可能让它们恢复，也不能覆盖既有结论）。
func (s *KeyStore) Retire(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.keys[id]
	if !ok {
		if _, buried := s.tombstones[id]; buried {
			return s.tombstoneFailureLocked(id, "retire")
		}
		return fail(ReasonKeyNotFound, "key %q not found", id)
	}
	if err := s.materializeExpiryLocked(k); err != nil {
		return err
	}
	switch k.State {
	case KeyRetired:
		return nil // 幂等
	case KeyRevoked:
		return fail(ReasonKeyRevoked, "cannot retire revoked key %q", id)
	case KeyDestroyed:
		return fail(ReasonKeyDestroyed, "cannot retire destroyed key %q", id)
	case KeyExpired:
		return fail(ReasonKeyExpired, "cannot retire expired key %q", id)
	}
	wipe(k.Key)
	k.Key = nil
	k.State = KeyRetired
	return nil
}

// Revoke 将密钥标记为已撤销并清除其字节（不可再 Get）。
// 重复撤销幂等；已退役密钥允许升级为撤销；对已销毁/已过期密钥调用返回错误。
func (s *KeyStore) Revoke(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.keys[id]
	if !ok {
		if st, buried := s.tombstones[id]; buried {
			if st == KeyRevoked {
				return nil // 记录已作为撤销态被回收，重复撤销幂等
			}
			return s.tombstoneFailureLocked(id, "revoke")
		}
		return fail(ReasonKeyNotFound, "key %q not found", id)
	}
	if err := s.materializeExpiryLocked(k); err != nil {
		return err
	}
	switch k.State {
	case KeyRevoked:
		return nil // 幂等
	case KeyDestroyed:
		return fail(ReasonKeyDestroyed, "cannot revoke destroyed key %q", id)
	case KeyExpired:
		return fail(ReasonKeyExpired, "cannot revoke expired key %q", id)
	}
	wipe(k.Key)
	k.Key = nil
	k.State = KeyRevoked
	return nil
}

// Destroy 将密钥标记为已销毁并清除其字节。销毁为终态，不可逆：
// 此后容量回收/版本升级等任何操作都不可能使其恢复可用。重复销毁幂等。
func (s *KeyStore) Destroy(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.keys[id]
	if !ok {
		if st, buried := s.tombstones[id]; buried {
			if st == KeyDestroyed {
				return nil // 记录已作为销毁态被回收，重复销毁幂等
			}
			return s.tombstoneFailureLocked(id, "destroy")
		}
		return fail(ReasonKeyNotFound, "key %q not found", id)
	}
	if k.State == KeyDestroyed {
		return nil
	}
	wipe(k.Key)
	k.Key = nil
	k.State = KeyDestroyed
	return nil
}

// State 查询密钥状态（会先把已到期的 active 密钥物化为 expired）；不存在返回错误。
func (s *KeyStore) State(id string) (KeyState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.keys[id]
	if !ok {
		// 已回收但留有墓碑：状态结论（expired/retired/revoked/destroyed）仍可查询。
		if st, buried := s.tombstones[id]; buried {
			return st, nil
		}
		return "", fail(ReasonKeyNotFound, "key %q not found", id)
	}
	_ = s.materializeExpiryLocked(k)
	return k.State, nil
}

// materializeExpiryLocked 把“已过 ExpiresAt 但状态仍为 active”的密钥
// 就地物化为 expired 并清零字节；若已物化则返回 expired 错误。
// 调用方必须持有 s.mu。
func (s *KeyStore) materializeExpiryLocked(k *StoredKey) error {
	if k.State == KeyActive && !k.ExpiresAt.IsZero() && !k.ExpiresAt.After(s.now()) {
		wipe(k.Key)
		k.Key = nil
		k.State = KeyExpired
	}
	if k.State == KeyExpired {
		return fail(ReasonKeyExpired, "key %q has expired at %s", k.ID, k.ExpiresAt)
	}
	return nil
}

// terminalReason 把一个不可用状态映射为其专属、可互相区分的取用失败原因。
func terminalReason(st KeyState) FailureReason {
	switch st {
	case KeyExpired:
		return ReasonKeyExpired
	case KeyRetired:
		return ReasonKeyRetired
	case KeyRevoked:
		return ReasonKeyRevoked
	default: // KeyDestroyed
		return ReasonKeyDestroyed
	}
}

// terminalFailure 按不可用状态构造带原因的错误（format 必须含两个 %s/%v 占位：id、state）。
func terminalFailure(st KeyState, id, format string) error {
	return fail(terminalReason(st), format, id, st)
}

// tombstoneFailureLocked 返回墓碑对应的取用失败错误；调用方必须持有 s.mu。
func (s *KeyStore) tombstoneFailureLocked(id, action string) error {
	st := s.tombstones[id]
	return fail(terminalReason(st), "cannot %s key %q: it was reclaimed as %s and is permanently unusable", action, id, st)
}

// evictOneLocked 在库满时回收一条密钥为新入库密钥 replacedByID 腾位。
//
// 回收策略（确定性，便于复现与审计）：
//   - 先把所有到期但尚未物化的 active 密钥物化为 expired（物化即清零）；
//   - 候选只可能是 expired/retired/revoked/destroyed，active 永不入选；
//   - 优先级 destroyed > expired > retired > revoked（销毁记录信息价值最低，
//     撤销结论次之，退役记录最可能仍被调用方引用）；
//   - 同优先级按最早到期时间、再按最早入库时间、最后按 ID 字典序，全部确定。
//
// 没有任何可回收密钥时，返回 keystore_full，本次签发失败，库内容保持不变。
func (s *KeyStore) evictOneLocked(replacedByID string, now time.Time) error {
	// 先统一物化到期密钥。
	for _, k := range s.keys {
		if k.State == KeyActive && !k.ExpiresAt.IsZero() && !k.ExpiresAt.After(now) {
			wipe(k.Key)
			k.Key = nil
			k.State = KeyExpired
		}
	}
	var victim *StoredKey
	var victimRank int
	rankOf := func(c ReclamationCause) int {
		switch c {
		case ReclaimDestroyed:
			return 0
		case ReclaimExpired:
			return 1
		case ReclaimRetired:
			return 2
		default: // revoked
			return 3
		}
	}
	earlier := func(a, b time.Time, af, bf time.Time, aid, bid string) bool {
		if !a.Equal(b) {
			return a.Before(b)
		}
		if !af.Equal(bf) {
			return af.Before(bf)
		}
		return aid < bid
	}
	for _, k := range s.keys {
		cause, ok := reclaimableStates[k.State]
		if !ok {
			continue // active 永不回收
		}
		rank := rankOf(cause)
		if victim == nil || rank < victimRank ||
			(rank == victimRank && earlier(k.ExpiresAt, victim.ExpiresAt, k.CreatedAt, victim.CreatedAt, k.ID, victim.ID)) {
			victim, victimRank = k, rank
		}
	}
	if victim == nil {
		return fail(ReasonStoreFull,
			"keystore at capacity %d: all %d keys are active and none can be reclaimed (refusing to evict valid key for %q)",
			s.capacity, len(s.keys), replacedByID)
	}
	cause := reclaimableStates[victim.State]
	rec := ReclamationRecord{
		KeyID:        victim.ID,
		State:        victim.State,
		Cause:        cause,
		ParamsVer:    victim.ParamsVer,
		CreatedAt:    victim.CreatedAt,
		ExpiresAt:    victim.ExpiresAt,
		ReclaimedAt:  now,
		ReplacedByID: replacedByID,
		Reason:       "keystore at capacity; reclaimed a non-usable key to make room",
	}
	// 删除记录，但把“它为何不可用”的结论落为墓碑永久留存：
	// 回收只腾位，绝不抹掉不可用结论，同 ID 之后不可能复活。
	s.tombstones[victim.ID] = victim.State
	delete(s.keys, victim.ID)
	s.reclog = append(s.reclog, rec)
	return nil
}

// Reclamations 返回到目前为止的全部容量回收审计记录（按回收发生顺序）。
func (s *KeyStore) Reclamations() []ReclamationRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]ReclamationRecord, len(s.reclog))
	copy(out, s.reclog)
	return out
}

// ReclaimableCount 返回当前“可被容量回收”的密钥条数（已过期/退役/撤销/销毁）。
func (s *KeyStore) ReclaimableCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	n := 0
	for _, k := range s.keys {
		if k.State == KeyActive && !k.ExpiresAt.IsZero() && !k.ExpiresAt.After(now) {
			n++
			continue
		}
		if _, ok := reclaimableStates[k.State]; ok {
			n++
		}
	}
	return n
}

// IDs 返回当前全部密钥 ID（字典序，保证输出确定，仅用于盘点）。
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

// Snapshot 返回当前全部密钥的元数据副本（不含任何密钥字节；字节仅在
// Active 时存在且不会被本方法带出），按 ID 字典序排列，供盘点与测试。
func (s *KeyStore) Snapshot() []StoredKey {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]StoredKey, 0, len(s.keys))
	for _, k := range s.keys {
		_ = s.materializeExpiryLocked(k)
		out = append(out, StoredKey{
			ID:        k.ID,
			State:     k.State,
			ParamsVer: k.ParamsVer,
			CreatedAt: k.CreatedAt,
			ExpiresAt: k.ExpiresAt,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// wipe 清零字节切片，确保失败/撤销/销毁路径不残留半成品材料。
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
