package qkd

import (
	"context"
	"sync"
	"time"
)

// ManagerConfig 为会话管理器配置。
type ManagerConfig struct {
	Params     Params         // 会话参数（版本化）；零值时取当前默认（v2）
	Channel    ChannelConfig  // 信道模型配置（同时写入 Params 以便归档自洽）
	Store      *KeyStore      // 密钥库（nil 时按 StoreCfg 内部新建）
	StoreCfg   KeyStoreConfig // Store 为 nil 时用于构造密钥库（容量上限/时钟）
	History    *History       // 会话归档（nil 时内部新建）
	MasterSeed int64          // 主种子：按会话标识域隔离派生子随机源
	// KeyTTL 为新签发密钥的有效期；<=0 表示长期有效（不过期）。
	KeyTTL time.Duration
	// Now 注入管理器时钟（与 StoreCfg.Now 保持一致）；nil 时使用 time.Now。
	Now func() time.Time
}

// Manager 管理多个并发会话与密钥入库，保证会话间密钥材料零共享。
type Manager struct {
	cfg ManagerConfig
	now func() time.Time
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
	now := cfg.Now
	if now == nil {
		now = cfg.StoreCfg.Now
	}
	if now == nil {
		now = time.Now
	}
	cfg.Now = now
	cfg.StoreCfg.Now = now
	if cfg.Store == nil {
		cfg.Store = NewKeyStoreWith(cfg.StoreCfg)
	}
	if cfg.History == nil {
		cfg.History = NewHistory()
	}
	return &Manager{cfg: cfg, now: now}, nil
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

// alreadyIssuedLocked 判断该会话 ID 是否已经成功产出并入库过密钥。
// 同一成功会话绝不允许第二次产出密钥（即便旧密钥后来被容量回收也不行）；
// 仅失败过的会话允许重试。
func (m *Manager) alreadyIssued(sessionID string) bool {
	if prev, ok := m.cfg.History.Get(sessionID); ok && prev.Success && prev.Issued {
		return true
	}
	return false
}

// RunSession 执行单个会话；成功则把密钥入库并归档，失败仅归档失败记录，
// 绝不写入任何半成品密钥。
//
// 容量已满且无失效/退役密钥可回收时，入库明确失败（store_full），
// 本次协商密钥随即清零，库内任何既有密钥都不受影响。
func (m *Manager) RunSession(ctx context.Context, sessionID string) (string, error) {
	if sessionID == "" {
		err := fail(ReasonConfigInvalid, "session id must not be empty")
		return "", err
	}
	if m.alreadyIssued(sessionID) {
		err := fail(ReasonSessionReused, "session %q has already issued a key", sessionID)
		return "", err
	}
	seed := m.sessionSeed(sessionID)
	sess, err := NewSession(SessionConfig{
		ID:     sessionID,
		Params: m.cfg.Params,
		Rand:   NewSeededRand(seed),
	})
	if err != nil {
		m.cfg.History.Add(SessionRecord{
			Schema:     RecordV1,
			ID:         sessionID,
			ParamsVer:  m.cfg.Params.Version,
			Params:     m.cfg.Params,
			Seed:       seed,
			Channel:    m.cfg.Channel,
			Success:    false,
			FailReason: ReasonConfigInvalid,
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
	issuedAt := m.now()
	var notAfter time.Time
	if m.cfg.KeyTTL > 0 {
		notAfter = issuedAt.Add(m.cfg.KeyTTL)
	}
	putErr := m.cfg.Store.Put(StoredKey{
		ID:        keyID,
		Key:       key,
		State:     KeyActive,
		ParamsVer: m.cfg.Params.Version,
		NotAfter:  notAfter,
		CreatedAt: issuedAt,
	})
	if putErr != nil {
		// 入库失败（容量满 / ID 冲突）：协议虽协商成功，但密钥绝不允许游离在外。
		// 记为失败归档（issued=false），key_id 保留备查；该会话未产出密钥，
		// 因此允许后续重试，重放归档也会得到“失败”这一与事实相符的结论。
		wipe(key)
		rec.Success = false
		rec.Issued = false
		rec.KeyID = keyID
		rec.KeyBytes = len(key)
		rec.FailReason = failReasonOf(putErr, ReasonSessionReused)
		m.cfg.History.Add(rec)
		return "", putErr
	}
	wipe(key) // 入库持有独立副本，清掉本地这份。
	rec.Success = true
	rec.Issued = true
	rec.KeyID = keyID
	rec.KeyBytes = len(key) // 注意：key 已清零，长度仍保留为记录值。
	rec.IssuedAt = issuedAt
	rec.NotAfter = notAfter
	m.cfg.History.Add(rec)
	return keyID, nil
}

// failReasonOf 提取本包错误原因，缺省回退到 fallback。
func failReasonOf(err error, fallback FailureReason) FailureReason {
	if pe, ok := err.(*ProtocolError); ok {
		return pe.Reason
	}
	return fallback
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
