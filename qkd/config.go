package qkd

import "fmt"

// ConfigVersion identifies a versioned set of session parameters.
type ConfigVersion string

const (
	// ConfigV1 is the first parameter version (2048 photons, 15% QBER
	// threshold, 32-byte key).
	ConfigV1 ConfigVersion = "qkd-bb84/v1"
	// ConfigV2 is the newer parameter version (4096 photons, tighter 11%
	// threshold, 64-byte key).
	ConfigV2 ConfigVersion = "qkd-bb84/v2"
)

// Parameters holds the versioned parameters governing a session.
//
// The JSON tags make historical session records forward/backward
// parseable: unknown fields added by newer versions are ignored by old
// parsers, and old records gain default values when loaded by new code.
type Parameters struct {
	// Version identifies the parameter set. Never empty in a valid config.
	Version ConfigVersion `json:"version"`

	// PhotonCount is the number of qubits Alice sends in the quantum phase.
	PhotonCount int `json:"photon_count"`

	// SampleFraction is the fraction of sifted bits sacrificed to estimate
	// the quantum bit error rate, in (0,1).
	SampleFraction float64 `json:"sample_fraction"`

	// QBERThreshold aborts the session (FailureQBER) when the measured
	// error rate is strictly greater than this value, in [0,1].
	QBERThreshold float64 `json:"qber_threshold"`

	// CorrectPasses bounds information-reconciliation effort.
	CorrectPasses int `json:"correct_passes"`

	// FinalKeyLength is the deterministic key length in bytes produced by
	// privacy amplification.
	FinalKeyLength int `json:"final_key_length"`

	// NoiseRate is the local channel model's intrinsic bit-flip
	// probability in [0,1], applied independently of eavesdropping.
	NoiseRate float64 `json:"noise_rate"`

	// Eavesdrop enables the intercept-resend adversary in the channel.
	Eavesdrop bool `json:"eavesdrop"`
}

// DefaultParameters returns the built-in parameters for a known version.
// Unknown versions yield FailureBadParameters.
func DefaultParameters(version ConfigVersion) (Parameters, error) {
	f, ok := configRegistry[version]
	if !ok {
		return Parameters{}, NewError(FailureBadParameters,
			fmt.Sprintf("unknown parameter version %q", version))
	}
	return f(), nil
}

// Validate checks version support and field ranges.
func (p Parameters) Validate() error {
	if _, ok := configRegistry[p.Version]; !ok {
		return NewError(FailureBadParameters,
			fmt.Sprintf("unknown parameter version %q", p.Version))
	}
	if p.PhotonCount < minPhotons {
		return NewError(FailureBadParameters,
			fmt.Sprintf("photon_count %d below minimum %d", p.PhotonCount, minPhotons))
	}
	if p.SampleFraction <= 0 || p.SampleFraction >= 1 {
		return NewError(FailureBadParameters,
			fmt.Sprintf("sample_fraction %v must be within (0,1)", p.SampleFraction))
	}
	if p.QBERThreshold < 0 || p.QBERThreshold > 1 {
		return NewError(FailureBadParameters,
			fmt.Sprintf("qber_threshold %v must be within [0,1]", p.QBERThreshold))
	}
	if p.CorrectPasses < 1 {
		return NewError(FailureBadParameters,
			fmt.Sprintf("correct_passes %d must be >= 1", p.CorrectPasses))
	}
	if p.FinalKeyLength < 1 {
		return NewError(FailureBadParameters,
			fmt.Sprintf("final_key_length %d must be >= 1 byte", p.FinalKeyLength))
	}
	if p.NoiseRate < 0 || p.NoiseRate > 1 {
		return NewError(FailureBadParameters,
			fmt.Sprintf("noise_rate %v must be within [0,1]", p.NoiseRate))
	}
	return nil
}

// minPhotons is the smallest supported quantum-phase length; smaller values
// do not leave enough sifted bits for a meaningful error estimate.
const minPhotons = 64

// configRegistry maps versions to their default constructors.
var configRegistry = map[ConfigVersion]func() Parameters{
	ConfigV1: func() Parameters {
		return Parameters{
			Version:        ConfigV1,
			PhotonCount:    2048,
			SampleFraction: 0.20,
			QBERThreshold:  0.15,
			CorrectPasses:  3,
			FinalKeyLength: 32,
			NoiseRate:      0.02,
			Eavesdrop:      false,
		}
	},
	ConfigV2: func() Parameters {
		return Parameters{
			Version:        ConfigV2,
			PhotonCount:    4096,
			SampleFraction: 0.25,
			QBERThreshold:  0.11,
			CorrectPasses:  3,
			FinalKeyLength: 64,
			NoiseRate:      0.02,
			Eavesdrop:      false,
		}
	},
}
