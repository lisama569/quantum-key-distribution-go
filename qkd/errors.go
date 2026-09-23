// Package qkd implements a fully local, deterministic simulation of a
// BB84-based quantum key distribution session protocol.
//
// No external services or real quantum hardware are required: the quantum
// channel, the random source and both protocol parties are simulated
// in-process. Randomness is injected so that results are reproducible.
package qkd

import "errors"

// FailureCode classifies why a session did not yield a key. Every abort has
// a distinct, stable code so callers can distinguish failure causes.
type FailureCode string

const (
	// FailureNone is the zero value: no failure occurred.
	FailureNone FailureCode = ""

	// FailureBadParameters means the session parameters are invalid
	// (unknown version or out-of-range fields).
	FailureBadParameters FailureCode = "bad_parameters"

	// FailureAborted means the session was explicitly aborted by a party
	// before completion.
	FailureAborted FailureCode = "aborted"

	// FailureQBER means the measured quantum bit error rate exceeded the
	// configured threshold; the channel is considered too noisy or
	// tampered with and no key is produced.
	FailureQBER FailureCode = "qber_threshold_exceeded"

	// FailureEavesdrop means eavesdropping was detected by the channel
	// model (an intercept-resend attack was observed).
	FailureEavesdrop FailureCode = "eavesdropping_detected"

	// FailureSiftedKeyTooShort means too few bits survived basis sifting
	// to estimate the error rate / derive a key.
	FailureSiftedKeyTooShort FailureCode = "sifted_key_too_short"

	// FailureReconcileFailed means information reconciliation could not
	// correct all errors within the configured effort.
	FailureReconcileFailed FailureCode = "reconciliation_failed"

	// FailureVerifyMismatch means the post-correction hash comparison
	// showed the parties still disagree.
	FailureVerifyMismatch FailureCode = "verification_mismatch"

	// FailurePrivacyAmplification means the final key length could not be
	// reached after accounting for leaked information.
	FailurePrivacyAmplification FailureCode = "privacy_amplification_failed"

	// FailureSessionReused means a session was asked to produce a key more
	// than once (or re-run after terminal state).
	FailureSessionReused FailureCode = "session_reused"

	// FailureKeyNotFound means the requested key ID does not exist in the
	// store (or was never stored).
	FailureKeyNotFound FailureCode = "key_not_found"

	// FailureKeyRevoked means the key exists but has been revoked.
	FailureKeyRevoked FailureCode = "key_revoked"

	// FailureKeyDestroyed means the key material has been irreversibly
	// destroyed.
	FailureKeyDestroyed FailureCode = "key_destroyed"
)

// ProtocolError is the typed error returned across the package. The Code
// field allows programmatic discrimination of failure reasons.
type ProtocolError struct {
	// Code is the stable failure classification.
	Code FailureCode
	// Message is a human readable explanation including the measured
	// quantities that led to the decision.
	Message string
}

func (e *ProtocolError) Error() string {
	if e == nil {
		return ""
	}
	return string(e.Code) + ": " + e.Message
}

// NewError builds a ProtocolError with the given code and message.
func NewError(code FailureCode, message string) *ProtocolError {
	return &ProtocolError{Code: code, Message: message}
}

// AsProtocolError extracts a *ProtocolError from err, if present.
func AsProtocolError(err error) (*ProtocolError, bool) {
	var pe *ProtocolError
	if errors.As(err, &pe) {
		return pe, true
	}
	return nil, false
}
