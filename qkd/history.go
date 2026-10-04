package qkd

import (
	"encoding/json"
	"sort"
	"sync"
)

// RecordSchemaVersion 是会话归档记录自身的格式版本，
// 与协议参数版本 ParamsVersion 正交：参数版本描述“怎么协商”，
// 记录格式版本描述“怎么序列化”，解析时两者都保留。
type RecordSchemaVersion string

const (
	// RecordV1：初始记录格式。
	RecordV1 RecordSchemaVersion = "qkd-record-v1"
)

// SessionRecord 是一次会话（成功或失败）的可复现归档。
// JSON 字段名保持稳定；未来新增字段只能追加，并在解析时兼容缺省。
type SessionRecord struct {
	Schema     RecordSchemaVersion `json:"schema"`
	ID         string              `json:"id"`
	ParamsVer  ParamsVersion       `json:"params_ver"`
	Params     Params              `json:"params"`
	Seed       int64               `json:"seed"`
	Channel    ChannelConfig       `json:"channel"`
	Success    bool                `json:"success"`
	KeyID      string              `json:"key_id,omitempty"`
	KeyBytes   int                 `json:"key_bytes,omitempty"`
	FailReason FailureReason       `json:"fail_reason,omitempty"`
	Stats      SessionStats        `json:"stats"`
}

// History 保存历史会话记录，线程安全，支持按版本解析旧记录。
//
// 除普通归档外，History 还维护一份只追加的“已成功签发登记表” issued：
// 任一会话 ID 一旦成功产出过密钥即永久登记，与该密钥之后是否被容量回收、
// 退役、撤销、销毁或到期清除完全无关，也不受参数版本升级影响。管理器据此
// 保证“同一会话至多签发一把密钥”。
type History struct {
	mu      sync.RWMutex
	records map[string]SessionRecord
	issued  map[string]SessionRecord
}

// NewHistory 构造空历史。
func NewHistory() *History {
	return &History{records: map[string]SessionRecord{}, issued: map[string]SessionRecord{}}
}

// Add 追加（或覆盖）一条会话记录。
//
// 已存在“成功签发”记录时，后续任何记录都不得覆盖它：失败归档不能抹掉
// 一次既成的成功（成功结论与会话幂等保证永久成立）。失败记录之间可以覆盖，
// 成功记录也可以覆盖此前的失败记录。
func (h *History) Add(r SessionRecord) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if old, ok := h.issued[r.ID]; ok {
		h.records[r.ID] = old
		return
	}
	if r.Success {
		h.issued[r.ID] = r
	}
	h.records[r.ID] = r
}

// MarkIssued 登记一次成功签发（只追加）：同时写入签发登记表与普通归档。
// 若该会话此前已成功签发过，则什么都不做并返回 false——成功结论不可重复、
// 不可覆盖。首次登记返回 true。
func (h *History) MarkIssued(r SessionRecord) bool {
	r.Success = true
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.issued[r.ID]; ok {
		return false
	}
	h.issued[r.ID] = r
	h.records[r.ID] = r
	return true
}

// IsIssued 返回该会话是否曾经成功签发过密钥；一旦为 true 即永久为 true，
// 与其密钥当前是 active、已回收、退役、撤销、销毁还是过期均无关。
func (h *History) IsIssued(sessionID string) (SessionRecord, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	r, ok := h.issued[sessionID]
	return r, ok
}

// Get 按会话 ID 取记录。
func (h *History) Get(sessionID string) (SessionRecord, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	r, ok := h.records[sessionID]
	return r, ok
}

// List 返回全部记录（按会话 ID 排序，保证输出确定）。
func (h *History) List() []SessionRecord {
	h.mu.RLock()
	out := make([]SessionRecord, 0, len(h.records))
	for _, r := range h.records {
		out = append(out, r)
	}
	h.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// legacyRecord 描述早期/更宽松的字段命名，用于向后兼容解析。
// 新代码写出始终使用 SessionRecord 的规范字段。
type legacyRecord struct {
	Schema        string          `json:"schema"`
	ID            string          `json:"id"`
	ParamsVer     string          `json:"params_ver"`
	ParamsVersion string          `json:"params_version"` // 旧别名
	Params        json.RawMessage `json:"params"`
	Seed          int64           `json:"seed"`
	Channel       ChannelConfig   `json:"channel"`
	Success       bool            `json:"success"`
	KeyID         string          `json:"key_id"`
	KeyBytes      int             `json:"key_bytes"`
	FailReason    string          `json:"fail_reason"`
	AbortReason   string          `json:"abort_reason"` // 旧别名
	Stats         json.RawMessage `json:"stats"`
}

// UnmarshalJSON 解析记录并兼容历史格式：
//   - 缺省 schema 时归一为 RecordV1；
//   - 接受旧字段别名 params_version / abort_reason；
//   - 未知字段一律忽略，保证新版本可读旧记录。
func (r *SessionRecord) UnmarshalJSON(data []byte) error {
	var l legacyRecord
	if err := json.Unmarshal(data, &l); err != nil {
		return err
	}
	r.Schema = RecordSchemaVersion(l.Schema)
	if r.Schema == "" {
		r.Schema = RecordV1
	}
	r.ID = l.ID
	r.ParamsVer = ParamsVersion(l.ParamsVer)
	if r.ParamsVer == "" {
		r.ParamsVer = ParamsVersion(l.ParamsVersion)
	}
	if r.ParamsVer == "" {
		r.ParamsVer = ParamsV1
	}
	if len(l.Params) > 0 {
		if err := json.Unmarshal(l.Params, &r.Params); err != nil {
			return err
		}
	}
	if r.Params.Version == "" {
		r.Params.Version = r.ParamsVer
	}
	r.Seed = l.Seed
	r.Channel = l.Channel
	r.Success = l.Success
	r.KeyID = l.KeyID
	r.KeyBytes = l.KeyBytes
	r.FailReason = FailureReason(l.FailReason)
	if r.FailReason == "" {
		r.FailReason = FailureReason(l.AbortReason)
	}
	if len(l.Stats) > 0 {
		if err := json.Unmarshal(l.Stats, &r.Stats); err != nil {
			return err
		}
	}
	return nil
}

// MarshalRecord 将一条会话记录序列化为规范 JSON（始终带最新 schema）。
func MarshalRecord(r SessionRecord) ([]byte, error) {
	if r.Schema == "" {
		r.Schema = RecordV1
	}
	return json.Marshal(r)
}

// UnmarshalRecord 解析 JSON 会话记录，自动兼容历史格式（见 UnmarshalJSON）。
func UnmarshalRecord(data []byte) (SessionRecord, error) {
	var r SessionRecord
	if err := json.Unmarshal(data, &r); err != nil {
		return SessionRecord{}, fail(ReasonConfigInvalid, "malformed session record: %v", err)
	}
	return r, nil
}
