package qkd

import (
	"context"
	"fmt"
	"testing"
)

// testLogger prints input parameters and decision basis into the test log.
type testLogger struct {
	t *testing.T
}

func (l testLogger) Logf(format string, args ...any) {
	l.t.Logf(format, args...)
}

func paramsFor(t *testing.T, v ConfigVersion) Parameters {
	t.Helper()
	p, err := DefaultParameters(v)
	if err != nil {
		t.Fatalf("DefaultParameters(%s): %v", v, err)
	}
	t.Logf("input params version=%s photonCount=%d sampleFraction=%.2f qberThreshold=%.4f noiseRate=%.4f eavesdrop=%v finalKeyLength=%d",
		p.Version, p.PhotonCount, p.SampleFraction, p.QBERThreshold, p.NoiseRate, p.Eavesdrop, p.FinalKeyLength)
	return p
}

func assertCode(t *testing.T, err error, want FailureCode) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error code %q, got nil", want)
	}
	pe, ok := AsProtocolError(err)
	if !ok {
		t.Fatalf("expected *ProtocolError, got %T: %v", err, err)
	}
	if pe.Code != want {
		t.Fatalf("expected code %q, got %q (%s)", want, pe.Code, pe.Message)
	}
	t.Logf("correctly classified failure code=%q basis=%s", pe.Code, pe.Message)
}

// TestSuccessfulNegotiation covers the normal end-to-end negotiation: both
// parties derive identical, fixed-length keys and the session records
// success without exposing internals.
func TestSuccessfulNegotiation(t *testing.T) {
	p := paramsFor(t, ConfigV1)
	s := NewSession("ok-1", p, NewSeededRand(42), WithLogger(testLogger{t}))

	key, err := s.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(key.Secret) != p.FinalKeyLength {
		t.Fatalf("key length = %d, want %d", len(key.Secret), p.FinalKeyLength)
	}
	if s.State() != StateSucceeded {
		t.Fatalf("state = %s, want succeeded", s.State())
	}
	rec := s.Record()
	if !rec.Success || rec.KeyID != key.ID {
		t.Fatalf("record inconsistent: success=%v keyID=%q want %q",
			rec.Success, rec.KeyID, key.ID)
	}
	// Alice and Bob agree: independent privacy amplification succeeded and
	// verification hashes matched (logged reconcile/amplify phases).
	if rec.Stats.ResidualErrors != 0 {
		t.Fatalf("residual errors %d, want 0", rec.Stats.ResidualErrors)
	}
	if rec.Stats.QBER > p.QBERThreshold {
		t.Fatalf("QBER %.4f exceeded threshold %.4f on success path",
			rec.Stats.QBER, p.QBERThreshold)
	}
	t.Logf("decision basis: QBER=%.4f <= threshold=%.4f -> proceed; finalKeyBytes=%d keyID=%s",
		rec.Stats.QBER, p.QBERThreshold, rec.Stats.FinalKeyBytes, key.ID)
}

// TestReproducible confirms the injected deterministic source makes identical
// inputs reproduce the identical key and record, under both config versions.
func TestReproducible(t *testing.T) {
	for _, v := range []ConfigVersion{ConfigV1, ConfigV2} {
		v := v
		t.Run(string(v), func(t *testing.T) {
			p := paramsFor(t, v)
			run := func() ([]byte, SessionStats) {
				s := NewSession("rep-"+string(v), p, NewSeededRand(123), WithLogger(testLogger{t}))
				k, err := s.Run(context.Background())
				if err != nil {
					t.Fatalf("Run: %v", err)
				}
				return append([]byte(nil), k.Secret...), s.Record().Stats
			}
			k1, st1 := run()
			k2, st2 := run()
			if string(k1) != string(k2) {
				t.Fatalf("non-reproducible key:\n%x\n%x", k1, k2)
			}
			if !statsEqual(st1, st2) {
				t.Fatalf("non-reproducible stats:\n%+v\n%+v", st1, st2)
			}
			t.Logf("reproduced %d-byte key for %s (%x...)", len(k1), v, k1[:4])
		})
	}
}

// TestNoiseThresholdAbort covers abort due to channel noise with no
// adversary: the failure must classify as QBER, not eavesdropping.
func TestNoiseThresholdAbort(t *testing.T) {
	p := paramsFor(t, ConfigV1)
	p.NoiseRate = 0.25
	s := NewSession("noise-1", p, NewSeededRand(7), WithLogger(testLogger{t}))
	_, err := s.Run(context.Background())
	assertCode(t, err, FailureQBER)

	rec := s.Record()
	if rec.Success || rec.KeyID != "" {
		t.Fatalf("failed session must not carry a key: success=%v keyID=%q",
			rec.Success, rec.KeyID)
	}
	if rec.Stats.EavesdropTouches != 0 {
		t.Fatalf("noise abort must show zero eavesdrop touches, got %d",
			rec.Stats.EavesdropTouches)
	}
	t.Logf("no half-finished key remains; session state=%s", s.State())
}

// TestEavesdropAbort covers intercept-resend detection: with the adversary
// present and QBER over threshold, the code must distinguish eavesdropping
// from ordinary noise.
func TestEavesdropAbort(t *testing.T) {
	p := paramsFor(t, ConfigV1)
	p.Eavesdrop = true
	s := NewSession("eve-1", p, NewSeededRand(7), WithLogger(testLogger{t}))
	_, err := s.Run(context.Background())
	assertCode(t, err, FailureEavesdrop)
	rec := s.Record()
	if rec.Stats.EavesdropTouches == 0 {
		t.Fatalf("expected recorded adversary interactions")
	}
	if rec.Success || rec.KeyID != "" {
		t.Fatalf("eavesdropped session must not yield a key")
	}
}

// TestFailureCodesDistinct proves noise and eavesdropping failures with very
// similar measured QBER still resolve to different codes.
func TestFailureCodesDistinct(t *testing.T) {
	noise := paramsFor(t, ConfigV1)
	noise.NoiseRate = 0.25
	sn := NewSession("dist-noise", noise, NewSeededRand(7))
	_, errN := sn.Run(context.Background())

	eve := paramsFor(t, ConfigV1)
	eve.Eavesdrop = true
	se := NewSession("dist-eve", eve, NewSeededRand(7))
	_, errE := se.Run(context.Background())

	cn, _ := AsProtocolError(errN)
	ce, _ := AsProtocolError(errE)
	if cn.Code == ce.Code {
		t.Fatalf("failure codes not distinguishable: both %q", cn.Code)
	}
	t.Logf("distinct codes verified: noise=%q eavesdrop=%q", cn.Code, ce.Code)
}

// TestSessionCannotReuseKey enforces one session -> at most one key.
func TestSessionCannotReuseKey(t *testing.T) {
	p := paramsFor(t, ConfigV1)
	s := NewSession("reuse-1", p, NewSeededRand(1), WithLogger(testLogger{t}))
	if _, err := s.Run(context.Background()); err != nil {
		t.Fatalf("first Run: %v", err)
	}
	_, err := s.Run(context.Background())
	assertCode(t, err, FailureSessionReused)
}

// TestBadParameters exercises version/range validation classification.
func TestBadParameters(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Parameters)
	}{
		{"unknown version", func(p *Parameters) { p.Version = "nope/v9" }},
		{"too few photons", func(p *Parameters) { p.PhotonCount = 8 }},
		{"bad sample fraction", func(p *Parameters) { p.SampleFraction = 1.5 }},
		{"bad threshold", func(p *Parameters) { p.QBERThreshold = -0.1 }},
		{"zero passes", func(p *Parameters) { p.CorrectPasses = 0 }},
		{"zero key length", func(p *Parameters) { p.FinalKeyLength = 0 }},
		{"noise out of range", func(p *Parameters) { p.NoiseRate = 2 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, _ := DefaultParameters(ConfigV1)
			tc.mut(&p)
			t.Logf("input params under test: %+v", p)
			s := NewSession("bad-"+tc.name, p, NewSeededRand(1))
			_, err := s.Run(context.Background())
			assertCode(t, err, FailureBadParameters)
			if s.Record().Success || s.Record().KeyID != "" {
				t.Fatalf("invalid params must not produce a key")
			}
		})
	}
}

// TestUnknownConfigVersion checks direct lookup.
func TestUnknownConfigVersion(t *testing.T) {
	if _, err := DefaultParameters("bogus"); err == nil {
		t.Fatal("expected error for unknown version")
	} else if pe, _ := AsProtocolError(err); pe.Code != FailureBadParameters {
		t.Fatalf("code = %q", pe.Code)
	}
}

func ExampleSession() {
	p, _ := DefaultParameters(ConfigV1)
	s := NewSession("doc", p, NewSeededRand(42))
	key, err := s.Run(context.Background())
	if err != nil {
		fmt.Println("aborted:", err)
		return
	}
	fmt.Println(len(key.Secret))
	// Output: 32
}

// statsEqual compares statistics including the eavesdrop position slice.
func statsEqual(a, b SessionStats) bool {
	if a.PhotonsSent != b.PhotonsSent || a.SiftedBits != b.SiftedBits ||
		a.SampleBits != b.SampleBits || a.SampleErrors != b.SampleErrors ||
		a.QBER != b.QBER || a.NoiseFlips != b.NoiseFlips ||
		a.EavesdropTouches != b.EavesdropTouches ||
		a.CorrectedBits != b.CorrectedBits || a.CorrectionRounds != b.CorrectionRounds ||
		a.ResidualErrors != b.ResidualErrors || a.PrivacyLeakageBits != b.PrivacyLeakageBits ||
		a.FinalKeyBytes != b.FinalKeyBytes {
		return false
	}
	if len(a.EavesdropPositions) != len(b.EavesdropPositions) {
		return false
	}
	for i := range a.EavesdropPositions {
		if a.EavesdropPositions[i] != b.EavesdropPositions[i] {
			return false
		}
	}
	return true
}
