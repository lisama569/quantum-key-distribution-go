package qkd

import (
	"strings"
	"testing"
)

// TestRecordRoundTrip covers marshal/parse of a terminal record.
func TestRecordRoundTrip(t *testing.T) {
	p, _ := DefaultParameters(ConfigV1)
	s := NewSession("rec-1", p, NewSeededRand(42), WithLogger(testLogger{t}))
	if _, err := s.Run(nilCtx()); err != nil {
		t.Fatal(err)
	}
	rec := s.Record()
	data, err := rec.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	back, err := ParseRecord(data)
	if err != nil {
		t.Fatal(err)
	}
	if back.SessionID != rec.SessionID || back.Stats.FinalKeyBytes != rec.Stats.FinalKeyBytes ||
		back.Params.FinalKeyLength != p.FinalKeyLength {
		t.Fatalf("round-trip mismatch:\n%+v\n%+v", back, rec)
	}
}

// TestRecordBackwardCompatible parses a hand-written record that mimics an
// older schema: missing newer fields are defaulted, unknown future fields
// are ignored, and the record stays readable.
func TestRecordBackwardCompatible(t *testing.T) {
	old := `{
		"schema":"qkd-record/v1",
		"session_id":"legacy",
		"params":{"version":"qkd-bb84/v1","photon_count":2048},
		"phase":"failed",
		"success":false,
		"failure":"qber_threshold_exceeded",
		"reason":"historical failure",
		"future_unknown_field":{"x":123},
		"stats":{"photons_sent":2048,"qber":0.18}
	}`
	rec, err := ParseRecord([]byte(old))
	if err != nil {
		t.Fatalf("legacy record must parse under new code: %v", err)
	}
	if rec.Params.QBERThreshold != 0.15 || rec.Params.FinalKeyLength != 32 ||
		rec.Params.CorrectPasses != 3 {
		t.Fatalf("missing parameter fields not defaulted: %+v", rec.Params)
	}
	if rec.Failure != FailureQBER {
		t.Fatalf("failure code lost: %q", rec.Failure)
	}
	t.Logf("legacy record parsed; defaulted params: threshold=%.2f finalKeyBytes=%d passes=%d",
		rec.Params.QBERThreshold, rec.Params.FinalKeyLength, rec.Params.CorrectPasses)
}

// TestRecordBookOrdering verifies insertion-order retrieval and isolation.
func TestRecordBookOrdering(t *testing.T) {
	b := NewRecordBook()
	b.append(SessionRecord{Schema: RecordV1, SessionID: "a"})
	b.append(SessionRecord{Schema: RecordV1, SessionID: "b"})
	all := b.All()
	if len(all) != 2 || all[0].SessionID != "a" || all[1].SessionID != "b" {
		t.Fatalf("ordering wrong: %+v", all)
	}
	if _, ok := b.Get("zzz"); ok {
		t.Fatal("unknown id should be absent")
	}
}

// TestRecordContainsNoSecret ensures serialized records never leak key bytes.
func TestRecordContainsNoSecret(t *testing.T) {
	p, _ := DefaultParameters(ConfigV1)
	s := NewSession("rec-secret", p, NewSeededRand(42))
	k, err := s.Run(nilCtx())
	if err != nil {
		t.Fatal(err)
	}
	data, _ := s.Record().Marshal()
	if jsonContains(data, k.Secret) {
		t.Fatal("record serialization leaked key material")
	}
}

func jsonContains(data, sub []byte) bool {
	// Raw key bytes must never appear in the JSON encoding of the record.
	return strings.Contains(string(data), string(sub))
}
