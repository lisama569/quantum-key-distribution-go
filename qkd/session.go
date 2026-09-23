package qkd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// SessionState is the lifecycle state of a session.
type SessionState string

const (
	StateCreated   SessionState = "created"
	StateRunning   SessionState = "running"
	StateSucceeded SessionState = "succeeded"
	StateFailed    SessionState = "failed"
)

// Logger receives structured step logs. Tests use it to print inputs and
// decision basis; nil disables logging.
type Logger interface {
	Logf(format string, args ...any)
}

// discardLogger is used when no logger was injected.
type discardLogger struct{}

func (discardLogger) Logf(string, ...any) {}

// Session is one end-to-end BB84 negotiation between Alice and Bob over a
// local channel. A session yields at most one key: once terminal it can
// never produce another.
type Session struct {
	mu sync.Mutex

	id       string
	params   Parameters
	rootRand Rand
	channel  *Channel

	aliceRand Rand
	bobRand   Rand
	log       Logger
	now       func() time.Time

	state   SessionState
	phase   SessionPhase
	stats   SessionStats
	record  SessionRecord
	keyID   string
	secret  []byte
	failure *ProtocolError

	// onFinish is invoked once at the terminal transition (used by the
	// Manager to persist record and key atomically w.r.t. the store).
	onFinish func(SessionRecord, KeyMaterial)
}

// SessionOption configures a session at creation.
type SessionOption func(*Session)

// WithLogger attaches a step logger.
func WithLogger(l Logger) SessionOption {
	return func(s *Session) {
		if l != nil {
			s.log = l
		}
	}
}

// WithClock injects a deterministic clock.
func WithClock(now func() time.Time) SessionOption {
	return func(s *Session) {
		if now != nil {
			s.now = now
		}
	}
}

// withFinishHook is used by the Manager to persist records and keys at
// terminal time.
func withFinishHook(h func(SessionRecord, KeyMaterial)) SessionOption {
	return func(s *Session) { s.onFinish = h }
}

// NewSession constructs a session from versioned parameters and one root
// deterministic source. Per-role and channel streams are derived from the
// session id so distinct sessions never share a stream prefix or material.
func NewSession(id string, p Parameters, root Rand, opts ...SessionOption) *Session {
	s := &Session{
		id:       id,
		params:   p,
		rootRand: root,
		state:    StateCreated,
		phase:    PhaseCreated,
		log:      discardLogger{},
		now:      time.Now,
	}
	for _, o := range opts {
		o(s)
	}
	// Derive independent labelled streams from the root.
	if root != nil {
		s.aliceRand = root.Seed("alice:" + id)
		s.bobRand = root.Seed("bob:" + id)
		noiseRand := root.Seed("noise:" + id)
		var eveRand Rand
		if p.Eavesdrop {
			eveRand = root.Seed("eve:" + id)
		}
		s.channel = NewChannel(p, noiseRand, eveRand)
	}
	s.record = SessionRecord{
		Schema:    RecordV1,
		SessionID: id,
		Params:    p,
		Phase:     PhaseCreated,
	}
	return s
}

// ID returns the session identifier.
func (s *Session) ID() string { return s.id }

// State returns the current lifecycle state.
func (s *Session) State() SessionState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

// Record returns the terminal (or current) session record.
func (s *Session) Record() SessionRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.record
}

// Run executes the full protocol: quantum transfer, basis sifting, QBER
// estimation, information reconciliation and privacy amplification. It is
// safe to call once; a second call fails with FailureSessionReused.
//
// On success the derived key has exactly Params.FinalKeyLength bytes and is
// returned (and handed to the finish hook). On failure no key material is
// exposed and a typed *ProtocolError explains the cause.
func (s *Session) Run(ctx context.Context) (KeyMaterial, error) {
	s.mu.Lock()
	if s.state != StateCreated {
		s.mu.Unlock()
		return KeyMaterial{}, NewError(FailureSessionReused,
			fmt.Sprintf("session %q already in terminal/running state %q", s.id, s.state))
	}
	s.state = StateRunning
	s.phase = PhaseQuantum
	s.record.StartedAt = s.now()
	s.mu.Unlock()

	s.log.Logf("[session=%s] RUN start version=%s photons=%d sampleFraction=%.3f qberThreshold=%.4f noiseRate=%.4f eavesdrop=%v finalKeyBytes=%d",
		s.id, s.params.Version, s.params.PhotonCount, s.params.SampleFraction,
		s.params.QBERThreshold, s.params.NoiseRate, s.params.Eavesdrop, s.params.FinalKeyLength)

	// Parameter validation is performed at run time so the failure lands in
	// the session record rather than as an untracked constructor error.
	if err := s.params.Validate(); err != nil {
		return KeyMaterial{}, s.terminateFail(err)
	}
	if s.rootRand == nil || s.channel == nil {
		return KeyMaterial{}, s.terminateFail(NewError(FailureBadParameters,
			"session requires a non-nil deterministic random source"))
	}

	// failf aborts, wipes intermediates and terminalizes the record.
	failf := func(code FailureCode, format string, args ...any) (KeyMaterial, error) {
		return KeyMaterial{}, s.terminateFail(NewError(code, fmt.Sprintf(format, args...)))
	}

	// Phase 1: quantum transfer.
	var aBits, bBits []Bit
	var aBases, bBases []Basis
	aBits, aBases, bBits, bBases = s.runQuantum(ctx)

	// Phase 2: basis sifting.
	if err := ctx.Err(); err != nil {
		return failf(FailureAborted, "canceled before sifting: %v", err)
	}
	siftedA, siftedB, origPos, ok := s.runSift(ctx, aBits, aBases, bBits, bBases)
	if !ok {
		return KeyMaterial{}, s.failure // runSift already terminalized
	}

	// Phase 3: QBER estimation on a sacrificed sample.
	if err := ctx.Err(); err != nil {
		return failf(FailureAborted, "canceled before estimation: %v", err)
	}
	keyA, keyB, keyPos, proceed := s.runEstimate(ctx, siftedA, siftedB, origPos)
	if !proceed {
		return KeyMaterial{}, s.failure
	}

	// Phase 4: information reconciliation on the remaining bits.
	if err := ctx.Err(); err != nil {
		return failf(FailureAborted, "canceled before reconciliation: %v", err)
	}
	recA, recB, leakage, proceed := s.runReconcile(ctx, keyA, keyB, keyPos)
	if !proceed {
		return KeyMaterial{}, s.failure
	}

	// Phase 5: privacy amplification -> fixed-length secret.
	if err := ctx.Err(); err != nil {
		return failf(FailureAborted, "canceled before privacy amplification: %v", err)
	}
	secret, err := s.runAmplify(ctx, recA, recB, leakage)
	if err != nil {
		wipe(secret)
		return KeyMaterial{}, s.terminateFail(err)
	}

	// Success: finalize exactly one key.
	key := KeyMaterial{
		ID:        s.deriveKeyID(secret),
		Secret:    secret,
		State:     KeyActive,
		Version:   s.params.Version,
		SessionID: s.id,
		CreatedAt: s.now(),
	}
	s.keyID = key.ID
	s.secret = cloneBytes(secret)
	s.stats.FinalKeyBytes = len(secret)

	s.mu.Lock()
	s.state = StateSucceeded
	s.phase = PhaseSucceeded
	s.record = s.buildRecord(true, FailureNone, "")
	s.mu.Unlock()

	s.log.Logf("[session=%s] SUCCESS keyID=%s finalKeyBytes=%d", s.id, key.ID, len(secret))
	if s.onFinish != nil {
		s.onFinish(s.record, key)
	}
	// Wipe the session's internal copy: the caller owns the returned key;
	// a store (if attached) holds its own copy.
	wipe(s.secret)
	s.secret = nil
	return key, nil
}

// runQuantum generates photons on Alice's side, lets Bob measure each over
// the local channel, and returns both parties' raw bits and bases.
func (s *Session) runQuantum(ctx context.Context) ([]Bit, []Basis, []Bit, []Basis) {
	n := s.params.PhotonCount
	aBits := make([]Bit, n)
	aBases := make([]Basis, n)
	bBits := make([]Bit, n)
	bBases := make([]Basis, n)
	for i := 0; i < n; i++ {
		if ctx.Err() != nil {
			break
		}
		aBits[i] = Bit(s.aliceRand.Intn(2))
		aBases[i] = Basis(s.aliceRand.Intn(2))
		bBases[i] = Basis(s.bobRand.Intn(2))
		d := s.channel.transmit(i, Photon{Bit: aBits[i], Basis: aBases[i]}, bBases[i])
		bBits[i] = d.Bit
	}
	cs := s.channel.stats()
	s.stats.PhotonsSent = cs.Sent
	s.stats.NoiseFlips = cs.NoiseFlips
	s.stats.EavesdropTouches = cs.EavesdropTouches
	ev := s.channel.eavesdropEvents()
	positions := make([]int, 0, len(ev))
	for _, e := range ev {
		positions = append(positions, e.Position)
	}
	s.stats.EavesdropPositions = positions
	s.phase = PhaseQuantum
	s.log.Logf("[session=%s] quantum: sent=%d noiseFlips=%d eavesdropTouches=%d",
		s.id, cs.Sent, cs.NoiseFlips, cs.EavesdropTouches)
	return aBits, aBases, bBits, bBases
}

// runSift keeps positions whose bases agree (public basis comparison).
func (s *Session) runSift(ctx context.Context, aBits []Bit, aBases []Basis, bBits []Bit, bBases []Basis) ([]Bit, []Bit, []int, bool) {
	sA := make([]Bit, 0, len(aBits)/2+1)
	sB := make([]Bit, 0, len(aBits)/2+1)
	orig := make([]int, 0, len(aBits)/2+1)
	for i := range aBits {
		if ctx.Err() != nil {
			break
		}
		if aBases[i] == bBases[i] {
			sA = append(sA, aBits[i])
			sB = append(sB, bBits[i])
			orig = append(orig, i)
		}
	}
	s.stats.SiftedBits = len(sA)
	s.phase = PhaseSifted
	s.log.Logf("[session=%s] sift: siftedBits=%d (basis matches %.1f%%)",
		s.id, len(sA), 100*float64(len(sA))/float64(s.stats.PhotonsSent))

	sampleCount := int(float64(len(sA)) * s.params.SampleFraction)
	needAfterSample := s.params.FinalKeyLength * 8
	if len(sA) < minSiftedBits || sampleCount < minSampleBits || len(sA)-sampleCount < needAfterSample {
		s.terminateFail(NewError(FailureSiftedKeyTooShort, fmt.Sprintf(
			"sifted bits %d insufficient: need >=%d total, >=%d sample bits and >=%d post-sample bits",
			len(sA), minSiftedBits, minSampleBits, needAfterSample)))
		return nil, nil, nil, false
	}
	return sA, sB, orig, true
}

// runEstimate sacrifices a deterministic prefix of the sifted key to measure
// QBER, then applies the channel-quality / eavesdropping decision rules.
// The remaining bits become the reconciliation input.
func (s *Session) runEstimate(ctx context.Context, sA, sB []Bit, origPos []int) ([]Bit, []Bit, []int, bool) {
	sampleCount := int(float64(len(sA)) * s.params.SampleFraction)
	errs := countDiffs(sA[:sampleCount], sB[:sampleCount])
	qber := float64(errs) / float64(sampleCount)
	s.stats.SampleBits = sampleCount
	s.stats.SampleErrors = errs
	s.stats.QBER = qber

	// Count adversary interactions landing inside the sacrificed sample
	// (only those can causally explain observed sample errors).
	sampleOrig := map[int]struct{}{}
	for i := 0; i < sampleCount; i++ {
		sampleOrig[origPos[i]] = struct{}{}
	}
	eveInSample := 0
	for _, e := range s.channel.eavesdropEvents() {
		if _, ok := sampleOrig[e.Position]; ok {
			eveInSample++
		}
	}
	s.phase = PhaseEstimated
	s.log.Logf("[session=%s] estimate: sampleBits=%d sampleErrors=%d QBER=%.4f threshold=%.4f eavesdropTouchesInSample=%d rule=abort_if_QBER_>_threshold",
		s.id, sampleCount, errs, qber, s.params.QBERThreshold, eveInSample)

	if qber > s.params.QBERThreshold {
		if eveInSample > 0 {
			s.terminateFail(NewError(FailureEavesdrop, fmt.Sprintf(
				"QBER %.4f > threshold %.4f with %d adversary interactions in the sample; intercept-resend eavesdropping detected (%d of %d sample bits wrong)",
				qber, s.params.QBERThreshold, eveInSample, errs, sampleCount)))
			return nil, nil, nil, false
		}
		s.terminateFail(NewError(FailureQBER, fmt.Sprintf(
			"QBER %.4f > threshold %.4f: channel quality too low (%d of %d sample bits wrong, noiseFlips total=%d)",
			qber, s.params.QBERThreshold, errs, sampleCount, s.stats.NoiseFlips)))
		return nil, nil, nil, false
	}
	keyA := append([]Bit(nil), sA[sampleCount:]...)
	keyB := append([]Bit(nil), sB[sampleCount:]...)
	keyOrig := append([]int(nil), origPos[sampleCount:]...)
	return keyA, keyB, keyOrig, true
}

// runReconcile performs public parity-based error correction on the remaining
// bits and verifies agreement. It also computes the privacy-amplification
// leakage budget: disclosed parity bits plus one bit per adversary
// interaction landing in the key portion.
func (s *Session) runReconcile(ctx context.Context, keyA, keyB []Bit, keyOrig []int) ([]Bit, []Bit, int, bool) {
	res, err := reconcile(keyA, keyB, s.params.CorrectPasses)
	if err != nil {
		s.terminateFail(err)
		return nil, nil, 0, false
	}
	s.stats.CorrectedBits = len(res.flips)
	s.stats.CorrectionRounds = res.rounds
	s.stats.ResidualErrors = countDiffs(keyA, keyB)

	ha := hashBits("qkd-verify", keyA)
	hb := hashBits("qkd-verify", keyB)
	if ha != hb {
		s.terminateFail(NewError(FailureVerifyMismatch,
			"post-reconciliation verification digests differ"))
		return nil, nil, 0, false
	}

	keySet := map[int]struct{}{}
	for _, p := range keyOrig {
		keySet[p] = struct{}{}
	}
	eveLeak := 0
	for _, e := range s.channel.eavesdropEvents() {
		if _, ok := keySet[e.Position]; ok {
			eveLeak++
		}
	}
	leakage := res.disclosedBits + eveLeak
	s.stats.PrivacyLeakageBits = leakage
	s.phase = PhaseCorrected
	_ = ctx
	s.log.Logf("[session=%s] reconcile: flips=%d rounds=%d residualErrors=%d disclosedParityBits=%d eavesdropLeakageBits=%d totalLeakage=%d verified=true",
		s.id, len(res.flips), res.rounds, s.stats.ResidualErrors, res.disclosedBits, eveLeak, leakage)
	return keyA, keyB, leakage, true
}

// runAmplify derives the fixed-length final key and confirms both parties
// derive the identical result independently.
func (s *Session) runAmplify(ctx context.Context, recA, recB []Bit, leakage int) ([]byte, error) {
	seed := s.id + "|" + string(s.params.Version)
	secret, err := privacyAmplify(seed, recA, leakage, s.params.FinalKeyLength)
	if err != nil {
		return nil, err
	}
	peer, err := privacyAmplify(seed, recB, leakage, s.params.FinalKeyLength)
	if err != nil {
		return nil, err
	}
	if string(peer) != string(secret) {
		wipe(peer)
		return nil, NewError(FailureVerifyMismatch,
			"privacy amplification produced divergent keys")
	}
	wipe(peer)
	s.phase = PhaseAmplified
	_ = ctx
	s.log.Logf("[session=%s] amplify: reconciledBits=%d leakageBits=%d finalKeyBytes=%d",
		s.id, len(recA), leakage, len(secret))
	return secret, nil
}

// terminateFail moves the session to its failed terminal state, wipes any
// retained secret and records the reason. No key is exposed.
func (s *Session) terminateFail(err error) error {
	pe, ok := AsProtocolError(err)
	if !ok {
		pe = NewError(FailureAborted, err.Error())
	}
	s.mu.Lock()
	wipe(s.secret)
	s.secret = nil
	s.keyID = ""
	s.state = StateFailed
	s.phase = PhaseFailed
	s.failure = pe
	s.record = s.buildRecord(false, pe.Code, pe.Message)
	rec := s.record
	s.mu.Unlock()

	s.log.Logf("[session=%s] FAILURE code=%s reason=%s", s.id, pe.Code, pe.Message)
	if s.onFinish != nil {
		s.onFinish(rec, KeyMaterial{})
	}
	return pe
}

// buildRecord assembles the audit record from current state.
func (s *Session) buildRecord(success bool, code FailureCode, reason string) SessionRecord {
	now := s.now()
	started := s.record.StartedAt
	if started.IsZero() {
		started = now
	}
	phase := s.phase
	if success {
		phase = PhaseSucceeded
	} else {
		phase = PhaseFailed
	}
	return SessionRecord{
		Schema:    RecordV1,
		SessionID: s.id,
		Params:    s.params,
		StartedAt: started,
		EndedAt:   now,
		Phase:     phase,
		Success:   success,
		Failure:   code,
		Reason:    reason,
		Stats:     s.stats,
		KeyID:     s.keyID,
	}
}

// deriveKeyID binds the key id to the session, parameter version and the
// derived material. It is deterministic, so re-running a session with the
// same inputs reproduces both the key and its id.
func (s *Session) deriveKeyID(secret []byte) string {
	h := sha256.New()
	h.Write([]byte("qkd-key-id"))
	h.Write([]byte{0})
	h.Write([]byte(s.id))
	h.Write([]byte{0})
	h.Write([]byte(s.params.Version))
	h.Write(secret)
	sum := h.Sum(nil)
	return "key-" + hex.EncodeToString(sum[:16])
}

// minSiftedBits / minSampleBits guard against statistically meaningless runs.
const (
	minSiftedBits = 32
	minSampleBits = 8
)
