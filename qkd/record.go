package qkd

import (
	"bytes"
	"encoding/json"
	"sync"
	"time"
)

// RecordSchemaVersion is the serialization schema of a session record.
// Old records remain parseable by newer code (unknown fields ignored,
// missing fields defaulted).
type RecordSchemaVersion string

const (
	// RecordV1 is the initial record schema.
	RecordV1 RecordSchemaVersion = "qkd-record/v1"
)

// SessionPhase labels how far a session progressed.
type SessionPhase string

const (
	PhaseCreated   SessionPhase = "created"
	PhaseQuantum   SessionPhase = "quantum"
	PhaseSifted    SessionPhase = "sifted"
	PhaseEstimated SessionPhase = "estimated"
	PhaseCorrected SessionPhase = "corrected"
	PhaseAmplified SessionPhase = "amplified"
	PhaseSucceeded SessionPhase = "succeeded"
	PhaseFailed    SessionPhase = "failed"
)

// SessionRecord is the versioned audit trail of one session. It never
// contains the final secret, only lengths/statistics.
type SessionRecord struct {
	Schema    RecordSchemaVersion `json:"schema"`
	SessionID string              `json:"session_id"`
	Params    Parameters          `json:"params"`
	StartedAt time.Time           `json:"started_at"`
	EndedAt   time.Time           `json:"ended_at"`
	Phase     SessionPhase        `json:"phase"`

	Success bool        `json:"success"`
	Failure FailureCode `json:"failure,omitempty"`
	Reason  string      `json:"reason,omitempty"`

	Stats SessionStats `json:"stats"`

	// KeyID is empty for failed sessions (no half-finished key exists).
	KeyID string `json:"key_id,omitempty"`
}

// SessionStats holds the explainable measurements of a session.
type SessionStats struct {
	PhotonsSent        int     `json:"photons_sent"`
	SiftedBits         int     `json:"sifted_bits"`
	SampleBits         int     `json:"sample_bits"`
	SampleErrors       int     `json:"sample_errors"`
	QBER               float64 `json:"qber"`
	NoiseFlips         int     `json:"noise_flips"`
	EavesdropTouches   int     `json:"eavesdrop_touches"`
	EavesdropPositions []int   `json:"eavesdrop_positions,omitempty"`
	CorrectedBits      int     `json:"corrected_bits"`
	CorrectionRounds   int     `json:"correction_rounds"`
	ResidualErrors     int     `json:"residual_errors"`
	PrivacyLeakageBits int     `json:"privacy_leakage_bits"`
	FinalKeyBytes      int     `json:"final_key_bytes"`
}

// RecordBook stores historical session records, concurrency-safe.
type RecordBook struct {
	mu      sync.Mutex
	order   []string
	records map[string]SessionRecord
}

// NewRecordBook creates an empty record book.
func NewRecordBook() *RecordBook {
	return &RecordBook{records: map[string]SessionRecord{}}
}

// append records a terminal session record.
func (b *RecordBook) append(r SessionRecord) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, exists := b.records[r.SessionID]; !exists {
		b.order = append(b.order, r.SessionID)
	}
	b.records[r.SessionID] = r
}

// Get returns the record of a session.
func (b *RecordBook) Get(sessionID string) (SessionRecord, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	r, ok := b.records[sessionID]
	return r, ok
}

// All returns all stored records in insertion order.
func (b *RecordBook) All() []SessionRecord {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]SessionRecord, 0, len(b.order))
	for _, id := range b.order {
		out = append(out, b.records[id])
	}
	return out
}

// Marshal serializes the record under the current schema.
func (r SessionRecord) Marshal() ([]byte, error) {
	if r.Schema == "" {
		r.Schema = RecordV1
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(r); err != nil {
		return nil, NewError(FailureBadParameters, "marshal record: "+err.Error())
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// ParseRecord decodes a JSON record. Records written under older schemas are
// accepted; unknown fields are ignored and missing parameter fields are
// filled from the version defaults.
func ParseRecord(data []byte) (SessionRecord, error) {
	var r SessionRecord
	dec := json.NewDecoder(bytes.NewReader(data))
	// Ignore fields introduced by future schemas.
	if err := dec.Decode(&r); err != nil {
		return SessionRecord{}, NewError(FailureBadParameters,
			"parse record: "+err.Error())
	}
	if r.Schema == "" {
		r.Schema = RecordV1
	}
	// Backward compatibility: an old record whose params carry a known
	// version is filled with that version's defaults for any field that
	// did not exist when it was written (zero value => default).
	if r.Params.Version != "" {
		if def, err := DefaultParameters(r.Params.Version); err == nil {
			r.Params = fillZeroDefaults(r.Params, def)
		}
	}
	return r, nil
}

// fillZeroDefaults replaces zero-valued fields of p with the default taken
// from def, while preserving every value explicitly present in p.
func fillZeroDefaults(p, def Parameters) Parameters {
	if p.PhotonCount == 0 {
		p.PhotonCount = def.PhotonCount
	}
	if p.SampleFraction == 0 {
		p.SampleFraction = def.SampleFraction
	}
	if p.QBERThreshold == 0 {
		p.QBERThreshold = def.QBERThreshold
	}
	if p.CorrectPasses == 0 {
		p.CorrectPasses = def.CorrectPasses
	}
	if p.FinalKeyLength == 0 {
		p.FinalKeyLength = def.FinalKeyLength
	}
	// NoiseRate 0 is a valid explicit value; we only default when the
	// record predates the field. Since v1 always carried it, leave as-is.
	return p
}
