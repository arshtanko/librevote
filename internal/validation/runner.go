package validation

import (
	"context"
	"errors"
	"fmt"
	"time"

	"librevote/internal/domain"
)

const (
	// ValidatorVersionEnvelopeRunner identifies the envelope-only runner rules.
	ValidatorVersionEnvelopeRunner = "envelope-runner-v1"
)

var (
	ErrRunnerConfigStore            = errors.New("validation store is required")
	ErrRunnerConfigDomainValidator  = errors.New("domain validator is required")
	ErrRunnerConfigValidatorVersion = errors.New("validator_version is required")
	ErrRunnerOutcomeObjectID        = errors.New("domain validator returned mismatched object_id")
)

// EnvelopeOutcomeStore is the storage behavior required by Runner.
type EnvelopeOutcomeStore interface {
	PersistEnvelopeValidationOutcome(context.Context, domain.ObjectEnvelope, Outcome, PersistenceInput) (PersistenceResult, error)
}

// DomainValidator runs stages after envelope validation and returns the object status.
type DomainValidator interface {
	ValidateDomain(context.Context, domain.ObjectEnvelope) (Outcome, error)
}

// PersistenceInput carries local metadata for durable validation records.
type PersistenceInput struct {
	ValidatorVersion string
	SeenAt           int64
	CheckedAt        int64
}

// PersistenceResult reports storage effects without exposing storage internals.
type PersistenceResult struct {
	Inserted        bool
	Updated         bool
	Duplicate       bool
	Reacquired      bool
	InvalidRecorded bool
}

// RunnerConfig wires deterministic envelope validation to local storage.
type RunnerConfig struct {
	Envelope         EnvelopeConfig
	Store            EnvelopeOutcomeStore
	DomainValidator  DomainValidator
	ValidatorVersion string
	Now              func() time.Time
}

// Runner consumes ObjectEnvelope values, validates the implemented envelope
// stage, and persists the local outcome.
type Runner struct {
	envelope         EnvelopeConfig
	store            EnvelopeOutcomeStore
	domainValidator  DomainValidator
	validatorVersion string
	now              func() time.Time
}

// RunnerResult contains both validation and persistence effects for callers.
type RunnerResult struct {
	EnvelopeAccepted bool
	Outcome          Outcome
	Persistence      PersistenceResult
}

// NewRunner validates configuration and returns an envelope validation runner.
func NewRunner(cfg RunnerConfig) (*Runner, error) {
	if cfg.Store == nil {
		return nil, ErrRunnerConfigStore
	}
	if cfg.DomainValidator == nil {
		return nil, ErrRunnerConfigDomainValidator
	}
	if cfg.ValidatorVersion == "" {
		return nil, ErrRunnerConfigValidatorVersion
	}
	if cfg.Envelope.NetworkID == "" {
		return nil, ErrEnvelopeConfigNetworkID
	}
	if cfg.Envelope.ProtocolVersion == "" {
		return nil, ErrEnvelopeConfigProtocolVersion
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	if cfg.Envelope.Now == nil {
		cfg.Envelope.Now = now
	}

	return &Runner{
		envelope:         cfg.Envelope,
		store:            cfg.Store,
		domainValidator:  cfg.DomainValidator,
		validatorVersion: cfg.ValidatorVersion,
		now:              now,
	}, nil
}

// IngestAndValidate validates envelope deterministically, delegates later
// validation stages, and persists the local outcome. It does not implement
// revalidation, conflict resolution, network publication, or tally recomputation.
func (r *Runner) IngestAndValidate(ctx context.Context, envelope domain.ObjectEnvelope) (RunnerResult, error) {
	if r == nil || r.store == nil {
		return RunnerResult{}, ErrRunnerConfigStore
	}
	if r.domainValidator == nil {
		return RunnerResult{}, ErrRunnerConfigDomainValidator
	}
	if r.validatorVersion == "" {
		return RunnerResult{}, ErrRunnerConfigValidatorVersion
	}

	envelopeResult, err := ValidateEnvelope(envelope, r.envelope)
	if err != nil {
		return RunnerResult{}, err
	}
	outcome := envelopeResult.Outcome
	if envelopeResult.Accepted {
		outcome, err = r.domainValidator.ValidateDomain(ctx, envelope)
		if err != nil {
			return RunnerResult{}, err
		}
		if outcome.ObjectID != envelope.ObjectID {
			return RunnerResult{}, ErrRunnerOutcomeObjectID
		}
	}
	if outcome.ObjectID == "" {
		return RunnerResult{}, fmt.Errorf("cannot persist validation outcome without object_id")
	}

	nowMillis := r.now().UnixMilli()
	persisted, err := r.store.PersistEnvelopeValidationOutcome(ctx, envelope, outcome, PersistenceInput{
		ValidatorVersion: r.validatorVersion,
		SeenAt:           nowMillis,
		CheckedAt:        nowMillis,
	})
	if err != nil {
		return RunnerResult{}, err
	}

	return RunnerResult{
		EnvelopeAccepted: envelopeResult.Accepted,
		Outcome:          outcome,
		Persistence:      persisted,
	}, nil
}
