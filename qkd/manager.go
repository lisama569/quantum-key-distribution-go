package qkd

import (
	"context"
	"sync"
	"time"
)

// ManagerConfig 为会话管理器配置。
type ManagerConfig struct {
	Params     Params        // 会话参数（版本化）
	Channel    ChannelConfig // 信道模型配置（同时写入 Params 以便归档自洽）
	Store      *KeyStore     // 密钥库（nil 时按 StoreCapacity/Clock 内部新建）
	History    *History      // 会话归档（nil 时内部新建）
	MasterSeed int64         // 主种子：按会话标识域隔离派生子随机源
	// StoreCapacity 为内部新建密钥库的条数上限（<=0 不限制）；
	// 显式提供 Store 时本字段被忽略。
	StoreCapacity int
	// KeyTTL 为新签发密钥的有效期；<=0 表示不过期（只能显式退役/撤销/销毁）。
	KeyTTL time.Duration
	// Clock 为管理器与内部新建密钥库使用的时钟；nil 时用 time.Now。
	// 注入可控时钟便于测试到期与容量回收行为。
	Clock func() time.Time
}

// Manager 管理多个并发会话与密钥入库，保证会话间密钥材料零共享。
type Manager struct {
	cfg ManagerConfig
}

// NewManager 构造管理器（填充默认值并校验参数）。
func NewManager(cfg ManagerConfig) (*Manager, error) {
	p := cfg.Params.withDefaults()
	// 信道配置与参数内的噪声/窃听字段保持一致，以 Params 为单一事实来源。
	p.NoiseRate = cfg.Channel.NoiseRate
	p.EavesdropRate = cfg.Channel.EavesdropRate
	if err := p.Validate(); err != nil {
		return nil, err
	}
	cfg.Params = p
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	if cfg.Store == nil {
		cfg.Store = NewKeyStoreWith(KeyStoreConfig{Capacity: cfg.StoreCapacity, Clock: cfg.Clock})
	}
	if cfg.History == nil {
		cfg.History = NewHistory()
	}
	return &Manager{cfg: cfg}, nil
}

// Store 返回管理器使用的密钥库。
func (m *Manager) Store() *KeyStore { return m.cfg.Store }

// History 返回管理器使用的会话归档。
func (m *Manager) History() *History { return m.cfg.History }

// Params 返回管理器使用的（归一化）参数快照。
func (m *Manager) Params() Params { return m.cfg.Params }

// sessionSeed 以主种子和会话标识派生该会话专属种子。
// 相同 (masterSeed, sessionID) 永远得到相同会话（可复现）；
// 不同 sessionID 得到互不相关的随机流（隔离）。
func (m *Manager) sessionSeed(sessionID string) int64 {
	return deriveSeed(m.cfg.MasterSeed, "session:"+sessionID, 0)
}

// RunSession 执行单个会话；成功则把密钥入库并归档，失败仅归档失败记录，
// 绝不写入任何半成品密钥。
//
// 会话签发是幂等的：同一 sessionID 在该密钥库内至多成功签发一次。预检与
// 最终入库都经由 KeyStore 的会话登记判定——即便密钥后来被容量回收、退役、
// 撤销、到期或销毁，登记仍在，重跑同一会话只会得到 session_reused；
// 参数版本升级后（派生出不同 KeyID）也同样被会话级登记拦下。
func (m *Manager) RunSession(ctx context.Context, sessionID string) (string, error) {
	seed := m.sessionSeed(sessionID)
	// 快速预检：已成功签发过的会话不再消耗一次协商。
	// 这只是优化路径；并发下的权威判定在 Store.IssueSession 的原子提交中。
	if keyID, _, ok := m.cfg.Store.IssuedSession(sessionID); ok {
		err := fail(ReasonSessionReused,
			"session %q already issued key %q and can never issue again", sessionID, keyID)
		m.cfg.History.Add(SessionRecord{
			Schema:     RecordV1,
			ID:         sessionID,
			ParamsVer:  m.cfg.Params.Version,
			Params:     m.cfg.Params,
			Seed:       seed,
			Channel:    m.cfg.Channel,
			Success:    false,
			FailReason: ReasonSessionReused,
		})
		return "", err
	}
	sess, err := NewSession(SessionConfig{
		ID:     sessionID,
		Params: m.cfg.Params,
		Rand:   NewSeededRand(seed),
	})
	if err != nil {
		failReason := FailureReason(ReasonConfigInvalid)
		if pe, ok := err.(*ProtocolError); ok {
			failReason = pe.Reason
		}
		m.cfg.History.Add(SessionRecord{
			Schema:     RecordV1,
			ID:         sessionID,
			ParamsVer:  m.cfg.Params.Version,
			Params:     m.cfg.Params,
			Seed:       seed,
			Channel:    m.cfg.Channel,
			Success:    false,
			FailReason: failReason,
		})
		return "", err
	}
	key, runErr := sess.Run(ctx)
	rec := SessionRecord{
		Schema:    RecordV1,
		ID:        sessionID,
		ParamsVer: m.cfg.Params.Version,
		Params:    m.cfg.Params,
		Seed:      seed,
		Channel:   m.cfg.Channel,
		Stats:     sess.Stats(),
	}
	if runErr != nil {
		rec.Success = false
		if pe, ok := runErr.(*ProtocolError); ok {
			rec.FailReason = pe.Reason
		} else {
			rec.FailReason = ReasonSessionAborted
		}
		m.cfg.History.Add(rec)
		return "", runErr
	}
	keyID := KeyID(sessionID, m.cfg.Params.Version, seed)
	stored := StoredKey{
		ID:        keyID,
		Key:       key,
		State:     KeyActive,
		ParamsVer: m.cfg.Params.Version,
	}
	if m.cfg.KeyTTL > 0 {
		stored.ExpiresAt = m.cfg.Clock().Add(m.cfg.KeyTTL)
	}
	// 原子提交：会话去重登记 + 密钥入库（含容量回收）在同一把锁内完成。
	// 即便预检之后、提交之前有另一个管理器/goroutine 抢先签发了同一会话，
	// 这里也会以 session_reused 失败而不会写入第二把密钥。
	if putErr := m.cfg.Store.IssueSession(sessionID, stored); putErr != nil {
		// 入库失败（容量满无法回收 / ID 冲突等）不允许密钥游离在外。
		// 保留库给出的可区分原因（keystore_full / session_reused 等）。
		wipe(key)
		rec.Success = false
		if pe, ok := putErr.(*ProtocolError); ok {
			rec.FailReason = pe.Reason
		} else {
			rec.FailReason = ReasonSessionAborted
		}
		m.cfg.History.Add(rec)
		return "", putErr
	}
	wipe(key) // 入库持有独立副本，清掉本地这份。
	rec.Success = true
	rec.KeyID = keyID
	rec.KeyBytes = len(key)
	m.cfg.History.Add(rec)
	return keyID, nil
}

// RunSessions 并发执行多个会话。
//
// 每个会话使用独立派生的随机源与独立的 Session 对象，密钥材料不共享；
// 任一会话失败既不会取消其它会话，也不会改动密钥库既有内容。
// 返回切片与 sessionIDs 一一对应。
func (m *Manager) RunSessions(ctx context.Context, sessionIDs []string) []SessionResult {
	results := make([]SessionResult, len(sessionIDs))
	var wg sync.WaitGroup
	for i, id := range sessionIDs {
		wg.Add(1)
		go func(i int, id string) {
			defer wg.Done()
			keyID, err := m.RunSession(ctx, id)
			results[i] = SessionResult{SessionID: id, KeyID: keyID, Err: err}
		}(i, id)
	}
	wg.Wait()
	return results
}

// SessionResult 为并发批量执行中单会话的结果。
type SessionResult struct {
	SessionID string
	KeyID     string
	Err       error
}
