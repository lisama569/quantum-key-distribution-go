package qkd

// Basis is a BB84 measurement basis.
type Basis uint8

const (
	// BasisRect is the rectilinear basis {|0>,|1>}.
	BasisRect Basis = 0
	// BasisDiag is the diagonal basis {|+>,|->}.
	BasisDiag Basis = 1
)

// Bit is a classical bit.
type Bit uint8

// Photon is one transmitted qubit, described classically for the local
// simulation by the encoded bit and the basis Alice used.
type Photon struct {
	Bit   Bit
	Basis Basis
}

// Detection is what Bob records when a photon reaches a detector.
type Detection struct {
	Bit   Bit
	Basis Basis
}

// EavesdropEvent marks one position at which the adversary interacted with
// the channel (intercept-resend). The session record keeps the positions so
// conclusions are explainable.
type EavesdropEvent struct {
	Position      int
	MeasuredBasis Basis
	// Disturbed is true when Eve used a basis different from Alice's,
	// i.e. her resent photon can introduce errors at Bob.
	Disturbed bool
}

// ChannelStat captures channel-level observations accumulated during the
// quantum phase.
type ChannelStat struct {
	Sent             int
	NoiseFlips       int
	EavesdropTouches int
}

// Channel is the local, deterministic model of the quantum link between
// Alice and Bob. Noise flips and adversary actions are driven by injected
// Rand instances, which guarantees reproducible runs.
type Channel struct {
	noiseRate float64
	eavesdrop bool
	rng       Rand // channel noise source
	eveRNG    Rand // adversary source (nil when eavesdrop=false)
	stat      ChannelStat
	events    []EavesdropEvent
}

// NewChannel builds the channel model from parameters and injected sources.
// eveRNG may be nil when eavesdropping is disabled.
func NewChannel(p Parameters, noiseRand Rand, eveRand Rand) *Channel {
	return &Channel{
		noiseRate: p.NoiseRate,
		eavesdrop: p.Eavesdrop,
		rng:       noiseRand,
		eveRNG:    eveRand,
	}
}

// transmit models one photon travelling Alice -> [Eve] -> [noise] -> Bob.
//
// Intercept-resend: Eve measures in her own random basis, obtaining a
// classical bit, and resends a photon in that basis. Bob then measures in
// bobBasis. Matching bases with no eavesdropper reproduce Alice's bit
// exactly; a basis mismatch at Eve disturbs the state and yields a random
// result (50% error when Bob's basis agrees with Alice's). Finally,
// intrinsic channel noise flips the detected bit independently with
// probability NoiseRate.
func (c *Channel) transmit(position int, sent Photon, bobBasis Basis) Detection {
	bit := sent.Bit
	basis := sent.Basis

	if c.eavesdrop && c.eveRNG != nil {
		eveBasis := Basis(c.eveRNG.Intn(2))
		// Eve measures: same basis -> true bit; different basis -> random.
		got := sent.Bit
		if eveBasis != sent.Basis {
			got = Bit(c.eveRNG.Intn(2))
		}
		// Eve resends the collapsed photon (got in eveBasis).
		bit = got
		basis = eveBasis
		c.stat.EavesdropTouches++
		c.events = append(c.events, EavesdropEvent{
			Position:      position,
			MeasuredBasis: eveBasis,
			Disturbed:     eveBasis != sent.Basis,
		})
	}

	// Bob measures the arriving photon.
	det := Detection{Basis: bobBasis}
	if bobBasis == basis {
		det.Bit = bit
	} else {
		// Basis mismatch: Bob projects onto a random eigenstate.
		det.Bit = Bit(c.rng.Intn(2))
	}

	// Intrinsic channel noise: independent bit flip.
	if c.noiseRate > 0 && c.rng.Float64() < c.noiseRate {
		det.Bit ^= 1
		c.stat.NoiseFlips++
	}

	c.stat.Sent++
	return det
}

// stats returns the accumulated channel statistics.
func (c *Channel) stats() ChannelStat { return c.stat }

// eavesdropEvents returns the recorded adversary interactions.
func (c *Channel) eavesdropEvents() []EavesdropEvent {
	out := make([]EavesdropEvent, len(c.events))
	copy(out, c.events)
	return out
}
