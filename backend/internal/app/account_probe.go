package app

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"time"

	accountapp "github.com/chenyme/grok2api/backend/internal/application/account"
	"github.com/chenyme/grok2api/backend/internal/application/accountprobe"
	clientkeyapp "github.com/chenyme/grok2api/backend/internal/application/clientkey"
	"github.com/chenyme/grok2api/backend/internal/application/gateway"
	accountdomain "github.com/chenyme/grok2api/backend/internal/domain/account"
	"github.com/chenyme/grok2api/backend/internal/infra/config"
)

// accountProbeConfigPath resolves where panel edits are stored. The quality
// guard directory is reused when configured because it is already the directory
// the deployment mounts for runtime state; otherwise state falls back to the
// process working directory.
func accountProbeConfigPath(qualityGuardDirectory string) string {
	if directory := strings.TrimSpace(qualityGuardDirectory); directory != "" {
		return filepath.Join(directory, "account-probe.json")
	}
	return filepath.Join(".", "data", "account-probe.json")
}

// accountProbeConfig maps the yaml block onto the runtime configuration. The
// server-managed identity is the default funding key, so enabling the feature in
// yaml is enough to make automatic cycles work without picking a Client Key.
func accountProbeConfig(value config.AccountProbeConfig, identityID uint64) accountprobe.Config {
	cfg := accountprobe.Config{
		Enabled:             value.Enabled,
		Interval:            value.Interval.Value(),
		ChunkSize:           value.ChunkSize,
		Workers:             value.Workers,
		Model:               value.Model,
		Prompt:              value.Prompt,
		MaxOutputTokens:     value.MaxOutputTokens,
		ClientKeyID:         identityID,
		EarlyStopOnThinking: true,
		EarlyStopDelayMS:    int(value.EarlyStopDelay.Value() / time.Millisecond),
		Cooldown:            value.Cooldown.Value(),
		AutoDisable:         value.AutoDisable,
	}
	// Early stop is on unless explicitly turned off: it is the only thing
	// keeping a healthy account from spending the full reply budget just to
	// prove that it thinks.
	if value.EarlyStopOnThinking != nil {
		cfg.EarlyStopOnThinking = *value.EarlyStopOnThinking
	}
	return cfg
}

// accountProbeAdapter bridges the gateway account probe into the scheduling
// service, and applies the missing-thinking penalty through the account service
// so probe-driven and request-driven punishments stay identical.
type accountProbeAdapter struct {
	gateway  *gateway.Service
	accounts *accountapp.Service
	keys     *clientkeyapp.Service

	identityMu sync.Mutex
	identityID uint64
}

func newAccountProbeAdapter(gatewayService *gateway.Service, accounts *accountapp.Service, keys *clientkeyapp.Service) *accountProbeAdapter {
	return &accountProbeAdapter{gateway: gatewayService, accounts: accounts, keys: keys}
}

// ResolveAccountProbeIdentity implements accountprobe.IdentityResolver.
//
// It asks the client key service for the server-managed identity, creating it on
// demand, so the operator can enable the feature from the panel at any time.
// The result is cached: the identity is stable for the life of the process, and
// re-resolving would issue a needless write on every probe run.
func (a *accountProbeAdapter) ResolveAccountProbeIdentity(ctx context.Context) (uint64, error) {
	a.identityMu.Lock()
	defer a.identityMu.Unlock()
	if a.identityID != 0 {
		return a.identityID, nil
	}
	key, err := a.keys.EnsureQualityGuardIdentity(ctx, true)
	if err != nil {
		return 0, err
	}
	a.identityID = key.ID
	return key.ID, nil
}

// ProbeAccount implements accountprobe.Prober.
func (a *accountProbeAdapter) ProbeAccount(ctx context.Context, input accountprobe.ProbeInput) (accountprobe.ProbeResult, error) {
	return a.probe(ctx, input)
}

// probe retries once after re-enabling the internal identity.
//
// The identity is shared with the egress quality guard and startup sets its
// enabled flag from the two feature switches. Enabling the probe from the panel
// after a boot where both were off therefore leaves the key disabled, and every
// probe would fail with a disabled-key error until the next restart.
func (a *accountProbeAdapter) probe(ctx context.Context, input accountprobe.ProbeInput) (accountprobe.ProbeResult, error) {
	call := func(clientKeyID uint64) (gateway.AccountProbeResult, error) {
		return a.gateway.ProbeAccount(ctx, gateway.AccountProbeInput{
			AccountID:           input.AccountID,
			ClientKeyID:         clientKeyID,
			Model:               input.Model,
			Mode:                input.Mode,
			Prompt:              input.Prompt,
			MaxOutputTokens:     input.MaxOutputTokens,
			EarlyStopOnThinking: input.EarlyStopOnThinking,
			EarlyStopDelayMS:    input.EarlyStopDelayMS,
		})
	}
	result, err := call(input.ClientKeyID)
	if err != nil && errors.Is(err, gateway.ErrAccountProbeKeyUnavailable) {
		key, ensureErr := a.keys.EnsureQualityGuardIdentity(ctx, true)
		if ensureErr == nil {
			a.identityMu.Lock()
			a.identityID = key.ID
			a.identityMu.Unlock()
			result, err = call(key.ID)
		}
	}
	if err != nil {
		return accountprobe.ProbeResult{}, err
	}
	return accountprobe.ProbeResult{
		AccountID:           result.AccountID,
		AccountName:         result.AccountName,
		Email:               result.Email,
		Verdict:             result.Verdict,
		Reason:              result.Reason,
		StatusCode:          result.StatusCode,
		HasThinking:         result.HasThinking,
		ReasoningBytes:      result.ReasoningBytes,
		ReasoningDeltaBytes: result.ReasoningDeltaBytes,
		EncryptedBytes:      result.EncryptedBytes,
		EncryptionFloor:     result.EncryptionFloor,
		ReasoningRatio:      result.ReasoningRatio,
		FirstVisibleMS:      result.FirstVisibleMS,
		Mode:                result.Mode,
		ToolCallOK:          result.ToolCallOK,
		ToolName:            result.ToolName,
		ToolArgs:            result.ToolArgs,
		OutputTokens:        result.OutputTokens,
		ReasoningTokens:     result.ReasoningTokens,
		VisibleChars:        result.VisibleChars,
		FirstTokenMS:        result.FirstTokenMS,
		DurationMS:          result.DurationMS,
		GenerationMS:        result.GenerationMS,
		OutputTPS:           result.OutputTPS,
		EgressNodeID:        result.EgressNodeID,
		EgressNodeName:      result.EgressNodeName,
		EarlyStop:           result.EarlyStop,
		Model:               result.Model,
		Error:               result.Error,
		ProbedAt:            result.ProbedAt,
	}, nil
}

// CoolAccountForMissingThinking implements accountprobe.Penalizer.
func (a *accountProbeAdapter) CoolAccountForMissingThinking(ctx context.Context, accountID uint64, cooldown time.Duration, autoDisable bool) error {
	return a.accounts.ApplyMissingThinkingPenalty(ctx, accountID, cooldown, autoDisable)
}

// ListProbeCandidates implements accountprobe.AccountLister.
//
// The status filter uses the account service's own vocabulary ("active" means
// enabled). A filter value it does not recognise makes List fail outright, which
// would silently disable every automatic cycle, so a rejected filter is retried
// without it rather than leaving the sweep permanently dead.
func (a *accountProbeAdapter) ListProbeCandidates(ctx context.Context, page, pageSize int) ([]accountdomain.Credential, int64, error) {
	if pageSize <= 0 {
		pageSize = accountprobe.DefaultChunkSize
	}
	if page < 1 {
		page = 1
	}
	filter := accountapp.ListFilter{Provider: string(accountdomain.ProviderBuild), Status: "active"}
	views, total, err := a.accounts.List(ctx, page, pageSize, "", filter)
	if errors.Is(err, accountapp.ErrInvalidFilter) {
		filter.Status = ""
		views, total, err = a.accounts.List(ctx, page, pageSize, "", filter)
	}
	if err != nil {
		return nil, 0, err
	}
	values := make([]accountdomain.Credential, 0, len(views))
	for _, view := range views {
		if view.Credential.Provider != accountdomain.ProviderBuild || !view.Credential.Enabled {
			continue
		}
		values = append(values, view.Credential)
	}
	return values, total, nil
}
