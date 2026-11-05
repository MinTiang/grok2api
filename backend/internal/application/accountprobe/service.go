// Package accountprobe runs scheduled and manual short-stream quality probes
// against individual Build accounts and applies the missing-thinking penalty
// when an account answers without streaming any reasoning.
//
// The probe itself lives in the gateway: it must reuse the normal inference path
// so that every account is observed through the egress it is actually bound to.
// This package only owns scheduling, concurrency, verdict bookkeeping and the
// penalty hand-off.
package accountprobe

import (
	"context"
	"errors"
	"log/slog"
	"runtime/debug"
	"sync"
	"time"

	accountdomain "github.com/chenyme/grok2api/backend/internal/domain/account"
	"github.com/chenyme/grok2api/backend/internal/pkg/batch"
)

const (
	// DefaultChunkSize bounds how many accounts one automatic cycle probes.
	DefaultChunkSize = 50
	// DefaultInterval is how often the automatic cycle runs.
	DefaultInterval = 6 * time.Hour
	// defaultWorkers keeps concurrency low on purpose. Registration-side tooling
	// reports that probing too aggressively looks like bot traffic, and the whole
	// point of the probe is to avoid triggering risk control.
	defaultWorkers = 2
	// defaultCooldown mirrors the request-path missing-thinking cooldown so both
	// entry points punish a degraded account identically.
	defaultCooldown = 12 * time.Hour
	// defaultModel is the Build model used when the operator leaves it empty.
	defaultModel = "grok-4.6"
	// defaultMode stays on thinking. Tool mode is implemented but not trustworthy yet:
	// measured upstream honours tool_choice=required only about half the time,
	// regardless of account quality, so its verdicts are noise.
	// The capability the probe tests by default is:
	// harder signal than reasoning volume: it is visible the moment the call lands.
	defaultMode = AccountProbeModeThinking
	// probeTimeout bounds one account's whole probe, including its samples and the
	// gap between them. Five thinking samples of 20-30s plus gaps need more than
	// the single-sample budget this used to be.
	probeTimeout = 300 * time.Second
	// penaltyTimeout bounds the account write that follows a degraded verdict.
	penaltyTimeout = 10 * time.Second
	// maxRecentResults bounds the in-memory result ring used by the panel.
	maxRecentResults = 500
	// accountProbeToolSamples is how many independent calls a tool-mode verdict is
	// built from. A single sample is not trustworthy: measured on one account it
	// returned a complete call, then prose, then a call again, because the model
	// does not follow tool_choice=required deterministically.
	accountProbeThinkingSamples   = 5
	accountProbeThinkingMajority  = 3
	accountProbeThinkingSampleGap = 5 * time.Second
	accountProbeToolSamples       = 5
	// accountProbeToolMajority is how many of those samples must carry a complete
	// call before the account counts as able to call tools.
	accountProbeToolMajority = 4
	// accountProbeToolSampleGap spaces the samples so they do not collide on the
	// same account slot.
	accountProbeToolSampleGap = 3 * time.Second
)

// Probe modes. They test different capabilities and are never mixed: tool mode
// asks whether the account can actually invoke a function, thinking mode asks
// whether the reply carried a real reasoning trace.
const (
	AccountProbeModeTool     = "tool"
	AccountProbeModeThinking = "thinking"
)

// Verdicts reported by the gateway probe.
const (
	VerdictHealthy = "healthy"
	VerdictHard    = "hard"
	VerdictRisk    = "risk"
	VerdictError   = "error"
)

// Prober executes one account probe. The gateway implements this.
type Prober interface {
	ProbeAccount(ctx context.Context, input ProbeInput) (ProbeResult, error)
}

// PersistedConfig is the on-disk form of the panel-editable configuration.
//
// It exists so an operator's panel changes survive a restart. Pointer fields
// let a stored document omit a value without forcing it to a zero that would
// erase an intentional `false`.
type PersistedConfig struct {
	Enabled             *bool   `json:"enabled,omitempty"`
	IntervalHours       *int    `json:"intervalHours,omitempty"`
	ChunkSize           *int    `json:"chunkSize,omitempty"`
	Workers             *int    `json:"workers,omitempty"`
	Model               *string `json:"model,omitempty"`
	Mode                *string `json:"mode,omitempty"`
	Prompt              *string `json:"prompt,omitempty"`
	MaxOutputTokens     *int    `json:"maxOutputTokens,omitempty"`
	EarlyStopOnThinking *bool   `json:"earlyStopOnThinking,omitempty"`
	EarlyStopDelayMS    *int    `json:"earlyStopDelayMs,omitempty"`
	CooldownHours       *int    `json:"cooldownHours,omitempty"`
	AutoDisable         *bool   `json:"autoDisable,omitempty"`
}

// Apply overlays the persisted values onto a configuration.
func (p PersistedConfig) Apply(cfg Config) Config {
	if p.Enabled != nil {
		cfg.Enabled = *p.Enabled
	}
	if p.IntervalHours != nil && *p.IntervalHours > 0 {
		cfg.Interval = time.Duration(*p.IntervalHours) * time.Hour
	}
	if p.ChunkSize != nil && *p.ChunkSize > 0 {
		cfg.ChunkSize = *p.ChunkSize
	}
	if p.Workers != nil && *p.Workers > 0 {
		cfg.Workers = *p.Workers
	}
	if p.Model != nil && *p.Model != "" {
		cfg.Model = *p.Model
	}
	if p.Mode != nil && *p.Mode != "" {
		cfg.Mode = *p.Mode
	}
	if p.Prompt != nil {
		cfg.Prompt = *p.Prompt
	}
	if p.MaxOutputTokens != nil && *p.MaxOutputTokens > 0 {
		cfg.MaxOutputTokens = *p.MaxOutputTokens
	}
	if p.EarlyStopOnThinking != nil {
		cfg.EarlyStopOnThinking = *p.EarlyStopOnThinking
	}
	if p.EarlyStopDelayMS != nil && *p.EarlyStopDelayMS > 0 {
		cfg.EarlyStopDelayMS = *p.EarlyStopDelayMS
	}
	if p.CooldownHours != nil && *p.CooldownHours > 0 {
		cfg.Cooldown = time.Duration(*p.CooldownHours) * time.Hour
	}
	if p.AutoDisable != nil {
		cfg.AutoDisable = *p.AutoDisable
	}
	return cfg
}

// FromConfig projects a configuration onto its persisted form.
func FromConfig(cfg Config) PersistedConfig {
	hours := int(cfg.Interval / time.Hour)
	cooldownHours := int(cfg.Cooldown / time.Hour)
	return PersistedConfig{
		Enabled:             &cfg.Enabled,
		IntervalHours:       &hours,
		ChunkSize:           &cfg.ChunkSize,
		Workers:             &cfg.Workers,
		Model:               &cfg.Model,
		Mode:                &cfg.Mode,
		Prompt:              &cfg.Prompt,
		MaxOutputTokens:     &cfg.MaxOutputTokens,
		EarlyStopOnThinking: &cfg.EarlyStopOnThinking,
		EarlyStopDelayMS:    &cfg.EarlyStopDelayMS,
		CooldownHours:       &cooldownHours,
		AutoDisable:         &cfg.AutoDisable,
	}
}

// ProbeInput is the gateway-facing probe request.
type ProbeInput struct {
	AccountID           uint64
	ClientKeyID         uint64
	Model               string
	Prompt              string
	MaxOutputTokens     int
	Mode                string
	EarlyStopOnThinking bool
	EarlyStopDelayMS    int
}

// ProbeResult is the gateway-facing probe outcome.
type ProbeResult struct {
	AccountID           uint64
	AccountName         string
	Email               string
	Verdict             string
	Reason              string
	StatusCode          int
	HasThinking         bool
	ReasoningBytes      int
	ReasoningDeltaBytes int
	EncryptedBytes      int
	EncryptionFloor     int64
	ReasoningRatio      float64
	FirstVisibleMS      int64
	AnswerExcerpt       string
	Mode                string
	ToolCallOK          bool
	ToolName            string
	ToolArgs            string
	OutputTokens        int64
	ReasoningTokens     int64
	VisibleChars        int
	FirstTokenMS        int64
	DurationMS          int64
	GenerationMS        int64
	OutputTPS           float64
	EgressNodeID        uint64
	EgressNodeName      string
	EarlyStop           bool
	Model               string
	Error               string
	ProbedAt            time.Time
}

// Penalizer applies the missing-thinking penalty to one account.
type Penalizer interface {
	CoolAccountForMissingThinking(ctx context.Context, accountID uint64, cooldown time.Duration, autoDisable bool) error
}

// AccountLister enumerates candidate accounts for automatic cycles.
type AccountLister interface {
	// ListProbeCandidates returns one page of Build accounts eligible for a
	// probe. Pagination is part of the contract: automatic cycles advance a
	// cursor so that every account is eventually probed instead of only the
	// first page.
	ListProbeCandidates(ctx context.Context, page, pageSize int) (values []accountdomain.Credential, total int64, err error)
}

// IdentityResolver returns the server-managed Client Key that funds probes.
//
// The key is created lazily by the clientkey service, so resolving it at probe
// time (rather than only at startup) lets the operator switch the feature on
// from the panel without restarting the process.
type IdentityResolver interface {
	ResolveAccountProbeIdentity(ctx context.Context) (uint64, error)
}

// Config is the runtime configuration of the probe feature.
type Config struct {
	Enabled             bool
	Interval            time.Duration
	ChunkSize           int
	Workers             int
	Model               string
	Mode                string
	Prompt              string
	MaxOutputTokens     int
	ClientKeyID         uint64
	EarlyStopOnThinking bool
	EarlyStopDelayMS    int
	Cooldown            time.Duration
	AutoDisable         bool
}

// ResultView is one panel-facing probe row.
type ResultView struct {
	AccountID           uint64    `json:"accountId"`
	AccountName         string    `json:"accountName"`
	Email               string    `json:"email"`
	Verdict             string    `json:"verdict"`
	Reason              string    `json:"reason"`
	StatusCode          int       `json:"statusCode"`
	HasThinking         bool      `json:"hasThinking"`
	ReasoningBytes      int       `json:"reasoningBytes"`
	ReasoningDeltaBytes int       `json:"reasoningDeltaBytes"`
	EncryptedBytes      int       `json:"encryptedBytes"`
	EncryptionFloor     int64     `json:"encryptionFloor"`
	ReasoningRatio      float64   `json:"reasoningRatio"`
	FirstVisibleMS      int64     `json:"firstVisibleMs"`
	AnswerExcerpt       string    `json:"answerExcerpt,omitempty"`
	Mode                string    `json:"mode,omitempty"`
	ToolCallOK          bool      `json:"toolCallOk"`
	ToolName            string    `json:"toolName,omitempty"`
	ToolArgs            string    `json:"toolArgs,omitempty"`
	OutputTokens        int64     `json:"outputTokens"`
	ReasoningTokens     int64     `json:"reasoningTokens"`
	VisibleChars        int       `json:"visibleChars"`
	FirstTokenMS        int64     `json:"firstTokenMs"`
	DurationMS          int64     `json:"durationMs"`
	OutputTPS           float64   `json:"outputTps"`
	EgressNodeID        uint64    `json:"egressNodeId"`
	EgressNodeName      string    `json:"egressNodeName"`
	EarlyStop           bool      `json:"earlyStop"`
	Model               string    `json:"model"`
	Error               string    `json:"error,omitempty"`
	Penalized           bool      `json:"penalized"`
	ProbedAt            time.Time `json:"probedAt"`
}

// RunView reports one batch (manual or automatic) execution.
type RunView struct {
	ID         string       `json:"id"`
	Trigger    string       `json:"trigger"`
	StartedAt  time.Time    `json:"startedAt"`
	FinishedAt *time.Time   `json:"finishedAt,omitempty"`
	Total      int          `json:"total"`
	Done       int          `json:"done"`
	Healthy    int          `json:"healthy"`
	Hard       int          `json:"hard"`
	Risk       int          `json:"risk"`
	Errors     int          `json:"errors"`
	Penalized  int          `json:"penalized"`
	Running    bool         `json:"running"`
	LastError  string       `json:"lastError,omitempty"`
	Results    []ResultView `json:"results"`
}

// Service owns probe scheduling and result history.
type Service struct {
	logger    *slog.Logger
	prober    Prober
	penalizer Penalizer
	accounts  AccountLister
	identity  IdentityResolver
	pool      *batch.Pool

	mu      sync.RWMutex
	cfg     Config
	runs    map[string]*RunView
	order   []string
	recent  []ResultView
	running bool
	cancel  context.CancelFunc
	// cursorPage is the next page the automatic sweep will read. It lives in
	// memory only: a restart simply restarts the rotation, which is harmless
	// because a full cycle is a sweep rather than a checkpointed job.
	cursorPage int
	store      *configStore
}

// NewService builds the probe service.
func NewService(logger *slog.Logger, prober Prober, penalizer Penalizer, accounts AccountLister) *Service {
	return &Service{
		logger:    logger,
		prober:    prober,
		penalizer: penalizer,
		accounts:  accounts,
		pool:      batch.NewPool(defaultWorkers),
		cfg:       normalizeConfig(Config{}),
		runs:      make(map[string]*RunView),
	}
}

// SetIdentityResolver wires the lazy Client Key resolver.
func (s *Service) SetIdentityResolver(value IdentityResolver) {
	s.identity = value
}

// SetConfigStore wires the on-disk configuration file and applies whatever was
// persisted there.
//
// Precedence is deliberate: yaml supplies the starting point and the saved panel
// file overlays it, so an operator's panel change survives a restart. The
// consequence is that editing yaml alone will not undo a panel change — the
// panel is the live source of truth once it has been used, and the file has to
// be removed to hand control back to yaml.
func (s *Service) SetConfigStore(path string) error {
	s.store = newConfigStore(path)
	if path == "" {
		return nil
	}
	value, found, err := s.store.Load()
	if err != nil {
		return err
	}
	if !found {
		return nil
	}
	s.UpdateConfig(value.Apply(s.Config()))
	return nil
}

// SaveConfig applies a panel change and persists it.
//
// The file is written before the running configuration is swapped, so a disk
// failure leaves the service on its previous settings. Applying first and then
// failing to persist would show the operator an error while silently running
// the new values until the next restart.
func (s *Service) SaveConfig(value PersistedConfig) error {
	cfg := normalizeConfig(value.Apply(s.Config()))
	if err := s.store.Save(FromConfig(cfg)); err != nil {
		return err
	}
	s.UpdateConfig(cfg)
	return nil
}

// resolveClientKey fills in the funding key when the caller did not configure one.
func (s *Service) resolveClientKey(ctx context.Context, cfg Config) (Config, error) {
	if cfg.ClientKeyID != 0 {
		return cfg, nil
	}
	if s.identity == nil {
		s.logger.Warn("account_probe_identity_missing", "reason", "resolver_not_wired")
		return cfg, nil
	}
	id, err := s.identity.ResolveAccountProbeIdentity(ctx)
	if err != nil {
		return cfg, err
	}
	s.logger.Info("account_probe_identity_resolved", "client_key_id", id)
	cfg.ClientKeyID = id
	return cfg, nil
}

func normalizeConfig(value Config) Config {
	if value.Interval <= 0 {
		value.Interval = DefaultInterval
	}
	if value.ChunkSize <= 0 {
		value.ChunkSize = DefaultChunkSize
	}
	if value.Workers <= 0 {
		value.Workers = defaultWorkers
	}
	if value.Model == "" {
		value.Model = defaultModel
	}
	if value.Mode == "" {
		value.Mode = defaultMode
	}
	if value.MaxOutputTokens <= 0 {
		// Reasoning draws from the same budget as the visible answer, so this has
		// to be loose enough that thinking is not cut off before it streams.
		value.MaxOutputTokens = 512
	}
	if value.Cooldown <= 0 {
		value.Cooldown = defaultCooldown
	}
	if value.EarlyStopDelayMS <= 0 {
		value.EarlyStopDelayMS = 800
	}
	return value
}

// Config returns the current configuration.
func (s *Service) Config() Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg
}

// UpdateConfig replaces the configuration and resizes the worker pool.
func (s *Service) UpdateConfig(value Config) {
	normalized := normalizeConfig(value)
	s.mu.Lock()
	s.cfg = normalized
	s.mu.Unlock()
	if normalized.Workers > 0 {
		s.pool.UpdateLimit(normalized.Workers)
	}
}

// Run drives automatic cycles until the context is cancelled.
func (s *Service) Run(ctx context.Context) {
	timer := time.NewTimer(s.nextDelay())
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			s.safeAutomaticCycle(ctx)
			timer.Reset(s.nextDelay())
		}
	}
}

// safeAutomaticCycle keeps one failed cycle from killing the scheduler. This
// loop owns the only goroutine that ever starts automatic runs, so a panic here
// would silently stop all future sweeps.
func (s *Service) safeAutomaticCycle(ctx context.Context) {
	defer func() {
		if recovered := recover(); recovered != nil {
			s.logger.Error("account_probe_cycle_panic", "panic", recovered, "stack", string(debug.Stack()))
		}
	}()
	s.runAutomaticCycle(ctx)
}

func (s *Service) nextDelay() time.Duration {
	cfg := s.Config()
	if cfg.Interval <= 0 {
		return DefaultInterval
	}
	return cfg.Interval
}

func (s *Service) runAutomaticCycle(ctx context.Context) {
	cfg := s.Config()
	if !cfg.Enabled {
		return
	}
	resolved, err := s.resolveClientKey(ctx, cfg)
	if err != nil {
		s.logger.Error("account_probe_identity_failed", "error", err)
		return
	}
	cfg = resolved
	if cfg.ClientKeyID == 0 {
		s.logger.Warn("account_probe_skipped", "reason", "client_key_not_configured")
		return
	}
	// Automatic cycles walk the account list page by page. Without a cursor the
	// first page would be re-probed every cycle and the rest of the pool would
	// never be checked, which defeats the point of a rotating full sweep.
	page := s.nextCursorPage()
	candidates, total, err := s.accounts.ListProbeCandidates(ctx, page, cfg.ChunkSize)
	if err != nil {
		s.logger.Error("account_probe_candidates_failed", "error", err, "page", page)
		return
	}
	if len(candidates) == 0 && page > 1 {
		// Past the end of the list: restart the sweep from the first page.
		page = 1
		candidates, total, err = s.accounts.ListProbeCandidates(ctx, page, cfg.ChunkSize)
		if err != nil {
			s.logger.Error("account_probe_candidates_failed", "error", err, "page", page)
			return
		}
	}
	if len(candidates) == 0 {
		return
	}
	ids := make([]uint64, 0, len(candidates))
	for _, candidate := range candidates {
		ids = append(ids, candidate.ID)
	}
	// The cursor only advances once the batch is actually accepted. Advancing it
	// first would permanently skip this page whenever a manual run happens to be
	// in flight, silently leaving those accounts unprobed forever.
	if _, err := s.Start(ctx, "auto", ids); err != nil {
		s.logger.Warn("account_probe_auto_skipped", "error", err, "page", page)
		return
	}
	s.recordCursorPage(page + 1)
	s.logger.Info("account_probe_cycle_start", "page", page, "chunk", len(candidates), "total", total)
}

// nextCursorPage reports the page the next automatic cycle should probe.
func (s *Service) nextCursorPage() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.cursorPage < 1 {
		return 1
	}
	return s.cursorPage
}

func (s *Service) recordCursorPage(page int) {
	s.mu.Lock()
	s.cursorPage = page
	s.mu.Unlock()
}

// Start launches a probe batch and returns immediately.
func (s *Service) Start(ctx context.Context, trigger string, accountIDs []uint64) (RunView, error) {
	cfg := s.Config()
	if len(accountIDs) == 0 {
		return RunView{}, errors.New("请选择至少一个账号")
	}
	resolved, err := s.resolveClientKey(ctx, cfg)
	if err != nil {
		return RunView{}, err
	}
	cfg = resolved
	if cfg.ClientKeyID == 0 {
		return RunView{}, errors.New("尚未配置短测使用的 Client Key")
	}

	runID := trigger + "-" + time.Now().UTC().Format("20060102T150405.000000")
	run := &RunView{
		ID: runID, Trigger: trigger, StartedAt: time.Now().UTC(),
		Total: len(accountIDs), Running: true, Results: make([]ResultView, 0, len(accountIDs)),
	}
	s.mu.Lock()
	// The run flag is checked and claimed under the same lock: a manual trigger
	// and an automatic cycle can arrive together, and a check outside the lock
	// would let both start and clobber the cancel handle.
	if s.running {
		s.mu.Unlock()
		return RunView{}, errors.New("已有短测任务正在运行")
	}
	s.runs[runID] = run
	s.order = append([]string{runID}, s.order...)
	if len(s.order) > 20 {
		for _, dropped := range s.order[20:] {
			delete(s.runs, dropped)
		}
		s.order = s.order[:20]
	}
	// Take the snapshot while still holding the lock and before the worker
	// starts mutating the shared run record.
	snapshot := *run
	snapshot.Results = copyResults(run.Results)
	s.running = true
	probeCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	s.cancel = cancel
	s.mu.Unlock()

	go s.execute(probeCtx, runID, cfg, accountIDs)
	return snapshot, nil
}

func (s *Service) execute(ctx context.Context, runID string, cfg Config, accountIDs []uint64) {
	defer func() {
		if recovered := recover(); recovered != nil {
			s.logger.Error("account_probe_run_panic", "run_id", runID, "panic", recovered, "stack", string(debug.Stack()))
		}
		s.mu.Lock()
		s.running = false
		if s.cancel != nil {
			s.cancel = nil
		}
		if run := s.runs[runID]; run != nil {
			now := time.Now().UTC()
			run.FinishedAt = &now
			run.Running = false
		}
		s.mu.Unlock()
	}()

	// One dispatcher feeds a bounded queue and a fixed worker count drains it.
	// Spawning a goroutine per account would put the whole pool into blocked
	// goroutines on a large account list, and a stop would have to unwind them
	// all before the run could finish.
	queue := make(chan uint64)
	var wg sync.WaitGroup
	if len(accountIDs) == 0 {
		// No workers would ever drain the queue, so the dispatch loop below would
		// block forever. Start rejects an empty batch, but keep this defensive.
		return
	}
	workerCount := cfg.Workers
	if workerCount <= 0 {
		workerCount = defaultWorkers
	}
	if workerCount > len(accountIDs) {
		workerCount = len(accountIDs)
	}
	for index := 0; index < workerCount; index++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// A panic here runs on a background goroutine, where gin.Recovery
			// cannot reach it. Without this the whole process exits and Docker
			// restarts the container, which is what makes the panel drop out
			// mid-run instead of reporting a failed probe.
			defer func() {
				if recovered := recover(); recovered != nil {
					s.logger.Error("account_probe_worker_panic", "run_id", runID, "panic", recovered, "stack", string(debug.Stack()))
				}
			}()
			for accountID := range queue {
				if ctx.Err() != nil {
					return
				}
				id := accountID
				_ = s.pool.Do(ctx, func(workCtx context.Context) error {
					s.probeOne(workCtx, runID, cfg, id)
					return nil
				})
			}
		}()
	}
	for _, accountID := range accountIDs {
		if ctx.Err() != nil {
			break
		}
		select {
		case queue <- accountID:
		case <-ctx.Done():
		}
	}
	close(queue)
	wg.Wait()
}

// sampleThinkingMode probes several times and decides by majority.
//
// A single thinking sample is not trustworthy because the degradation is
// transient. Measured on one fleet, the same account produced an encrypted
// payload of 4.79 bytes per claimed reasoning token on one run and 1.76 on the
// next, so a one-shot verdict flips between healthy and degraded from minute to
// minute. The ratio itself is a sound measurement of that moment; what is unstable
// is the account. Majority over several samples is what turns it into a property.
func (s *Service) sampleThinkingMode(ctx context.Context, input ProbeInput, accountID uint64) ProbeResult {
	var best ProbeResult
	var lastError ProbeResult
	degraded, healthy, responded := 0, 0, 0
	for sample := 0; sample < accountProbeThinkingSamples; sample++ {
		if sample > 0 {
			select {
			case <-ctx.Done():
			case <-time.After(accountProbeThinkingSampleGap):
			}
			if ctx.Err() != nil {
				break
			}
		}
		result, err := s.prober.ProbeAccount(ctx, input)
		if err != nil || result.Verdict == VerdictError {
			// A pinned account can still be refused while its previous slot is
			// being released, so give one failed sample a second chance before it
			// counts as a dead attempt.
			if ctx.Err() == nil {
				select {
				case <-ctx.Done():
				case <-time.After(accountProbeThinkingSampleGap):
				}
				if retryResult, retryErr := s.prober.ProbeAccount(ctx, input); retryErr == nil {
					result, err = retryResult, nil
				}
			}
		}
		if err != nil {
			lastError = ProbeResult{AccountID: accountID, Verdict: VerdictError, Reason: "probe_failed", Error: err.Error()}
			continue
		}
		if result.Reason == "account_disabled" {
			return result
		}
		if result.Verdict == VerdictError {
			lastError = result
			continue
		}
		responded++
		if result.Verdict == VerdictHard {
			degraded++
		} else {
			healthy++
		}
		// Keep the most recent sample so the row carries a real ratio.
		best = result
		if degraded >= accountProbeThinkingMajority || healthy >= accountProbeThinkingMajority {
			break
		}
		// Stop once neither side can still reach a majority.
		if accountProbeThinkingSamples-responded < accountProbeThinkingMajority-max(degraded, healthy) {
			break
		}
	}
	switch {
	case degraded >= accountProbeThinkingMajority:
		best.Verdict = VerdictHard
		best.Reason = "thinking_missing"
		best.HasThinking = false
	case healthy >= accountProbeThinkingMajority:
		best.Verdict = VerdictHealthy
		best.Reason = "thinking_present"
		best.HasThinking = true
	case responded > 0:
		// No majority: a single sample is not enough to act on, and cooling on a
		// coin flip would punish healthy accounts half the time.
		return ProbeResult{AccountID: accountID, Verdict: VerdictError, Reason: "probe_inconclusive", Error: "多次采样结果不一致，本次不判定"}
	case lastError.Verdict != "":
		return lastError
	default:
		return ProbeResult{AccountID: accountID, Verdict: VerdictError, Reason: "probe_failed", Error: "多次采样均未拿到响应"}
	}
	s.logger.Info("account_probe_sampled", "account_id", accountID, "mode", "thinking", "degraded", degraded, "healthy", healthy, "verdict", best.Verdict)
	return best
}

// sampleToolMode runs the probe several times and decides by majority.
//
// Tool mode cannot rely on a single call. Measured on one account, three
// consecutive samples returned a complete call, then prose, then a complete call
// again, because the model does not honour tool_choice=required deterministically.
// Majority voting turns that noise into a stable verdict; the extra samples are
// short requests, and the loop stops as soon as the outcome is settled.
func (s *Service) sampleToolMode(ctx context.Context, input ProbeInput, accountID uint64) ProbeResult {
	var best ProbeResult
	var lastError ProbeResult
	okCount, responded := 0, 0
	for sample := 0; sample < accountProbeToolSamples; sample++ {
		if sample > 0 {
			select {
			case <-ctx.Done():
			case <-time.After(accountProbeToolSampleGap):
			}
			if ctx.Err() != nil {
				break
			}
		}
		result, err := s.prober.ProbeAccount(ctx, input)
		if err != nil {
			s.logger.Warn("account_probe_sample_failed", "account_id", accountID, "sample", sample+1, "error", err)
			continue
		}
		if result.Reason == "account_disabled" {
			return result
		}
		// A failed request says nothing about tool capability. Counting it as a
		// missing call is what made an upstream 403 look like a degraded account.
		if result.Verdict == VerdictError {
			lastError = result
			continue
		}
		responded++
		if result.ToolCallOK {
			okCount++
			// Keep a successful sample: it carries the arguments worth showing.
			if !best.ToolCallOK {
				best = result
			}
		} else if best.Verdict == "" || best.Verdict == VerdictHealthy {
			// Keep the first genuine failure so the verdict can name the mode.
			best = result
		}
		if okCount >= accountProbeToolMajority {
			break
		}
		// Stop once the majority is arithmetically impossible.
		if responded-okCount > accountProbeToolSamples-accountProbeToolMajority {
			break
		}
	}
	switch {
	case okCount >= accountProbeToolMajority:
		best.Verdict = VerdictHealthy
		best.Reason = "tool_call_ok"
		best.ToolCallOK = true
	case responded > 0:
		// The account answered but never completed the tool loop. Keep the specific
		// failure from the samples instead of flattening every case to "missing":
		// wrong tool, ungrounded answer and incomplete arguments need different
		// responses from an operator.
		best.Verdict = VerdictHard
		if best.Reason == "" || best.Reason == "tool_call_ok" {
			best.Reason = "tool_call_missing"
		}
		best.ToolCallOK = false
	case lastError.Verdict != "":
		// Every attempt failed at the transport level; keep that verdict and error.
		return lastError
	default:
		return ProbeResult{AccountID: accountID, Verdict: VerdictError, Reason: "probe_failed", Error: "多次采样均未拿到响应"}
	}
	s.logger.Info("account_probe_sampled", "account_id", accountID, "ok", okCount, "responded", responded, "verdict", best.Verdict)
	return best
}

func (s *Service) probeOne(ctx context.Context, runID string, cfg Config, accountID uint64) {
	// Keep a single bad probe from taking down its worker: the run must still
	// report a verdict for this account and continue with the rest.
	defer func() {
		if recovered := recover(); recovered != nil {
			s.logger.Error("account_probe_panic", "run_id", runID, "account_id", accountID, "panic", recovered, "stack", string(debug.Stack()))
			s.recordResult(runID, ResultView{
				AccountID: accountID, Verdict: VerdictError, Reason: "probe_panic",
				Error: "短测过程中发生内部错误", ProbedAt: time.Now().UTC(),
			})
		}
	}()

	probeCtx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()

	input := ProbeInput{
		AccountID: accountID, ClientKeyID: cfg.ClientKeyID, Model: cfg.Model, Mode: cfg.Mode, Prompt: cfg.Prompt,
		MaxOutputTokens: cfg.MaxOutputTokens, EarlyStopOnThinking: cfg.EarlyStopOnThinking,
		EarlyStopDelayMS: cfg.EarlyStopDelayMS,
	}
	var result ProbeResult
	var err error
	if cfg.Mode == AccountProbeModeTool {
		result = s.sampleToolMode(probeCtx, input, accountID)
	} else {
		result = s.sampleThinkingMode(probeCtx, input, accountID)
	}
	view := ResultView{
		AccountID: accountID, ProbedAt: time.Now().UTC(),
	}
	if err != nil {
		view.Verdict = VerdictError
		view.Reason = "probe_failed"
		view.Error = err.Error()
	} else {
		view = ResultView{
			AccountID: result.AccountID, AccountName: result.AccountName, Email: result.Email,
			Verdict: result.Verdict, Reason: result.Reason, StatusCode: result.StatusCode,
			HasThinking: result.HasThinking, ReasoningBytes: result.ReasoningBytes,
			ReasoningDeltaBytes: result.ReasoningDeltaBytes, EncryptedBytes: result.EncryptedBytes,
			EncryptionFloor: result.EncryptionFloor, ReasoningRatio: result.ReasoningRatio,
			FirstVisibleMS: result.FirstVisibleMS, AnswerExcerpt: result.AnswerExcerpt,
			Mode: result.Mode, ToolCallOK: result.ToolCallOK,
			ToolName: result.ToolName, ToolArgs: result.ToolArgs,
			OutputTokens: result.OutputTokens, ReasoningTokens: result.ReasoningTokens,
			VisibleChars: result.VisibleChars, FirstTokenMS: result.FirstTokenMS,
			DurationMS: result.DurationMS, OutputTPS: result.OutputTPS,
			EgressNodeID: result.EgressNodeID, EgressNodeName: result.EgressNodeName,
			EarlyStop: result.EarlyStop, Model: result.Model, Error: result.Error,
			ProbedAt: result.ProbedAt,
		}
	}

	// An operator stop must not swallow a verdict that was already decided: the
	// penalty has to land even when the surrounding context was cancelled after
	// the probe finished.
	if view.Verdict == VerdictHard && s.penalizer != nil {
		penaltyCtx, cancelPenalty := context.WithTimeout(context.WithoutCancel(ctx), penaltyTimeout)
		penaltyErr := s.penalizer.CoolAccountForMissingThinking(penaltyCtx, accountID, cfg.Cooldown, cfg.AutoDisable)
		cancelPenalty()
		if penaltyErr != nil {
			s.logger.Error("account_probe_penalty_failed", "account_id", accountID, "error", penaltyErr)
		} else {
			view.Penalized = true
		}
	}

	// A panic below must still leave a row behind, so record before logging.
	s.recordResult(runID, view)

	s.logger.Info("account_probe_done",
		"account_id", accountID, "verdict", view.Verdict, "reason", view.Reason,
		"mode", view.Mode, "tool_call_ok", view.ToolCallOK, "tool_name", view.ToolName,
		"has_thinking", view.HasThinking, "reasoning_bytes", view.ReasoningBytes, "ratio", view.ReasoningRatio,
		"output_tokens", view.OutputTokens, "first_visible_ms", view.FirstVisibleMS, "answer", view.AnswerExcerpt,
		"early_stop", view.EarlyStop, "penalized", view.Penalized)
}

// recordResult appends one probe outcome to the run counters and the recent
// history. It is the single write path so the panic handler cannot drift.
func (s *Service) recordResult(runID string, view ResultView) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if run := s.runs[runID]; run != nil {
		run.Done++
		run.Results = append(run.Results, view)
		switch view.Verdict {
		case VerdictHealthy:
			run.Healthy++
		case VerdictHard:
			run.Hard++
		case VerdictRisk:
			run.Risk++
		default:
			run.Errors++
		}
		if view.Penalized {
			run.Penalized++
		}
	}
	s.recent = append(s.recent, view)
	if len(s.recent) > maxRecentResults {
		s.recent = s.recent[len(s.recent)-maxRecentResults:]
	}
}

// copyResults clones a result slice for handing to a caller.
//
// A nil slice would marshal to JSON null, and the panel validates `results` as an
// array, so a run that has not finished yet would fail to decode on the client
// even though the batch started fine.
func copyResults(values []ResultView) []ResultView {
	out := make([]ResultView, len(values))
	copy(out, values)
	return out
}

func (s *Service) run(runID string) *RunView {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.runs[runID]
}

// Runs returns recent runs, newest first.
func (s *Service) Runs() []RunView {
	s.mu.RLock()
	defer s.mu.RUnlock()
	values := make([]RunView, 0, len(s.order))
	for _, id := range s.order {
		run, ok := s.runs[id]
		if !ok {
			continue
		}
		// Results is appended under the write lock while a batch runs, so hand
		// callers their own backing array instead of aliasing it.
		snapshot := *run
		snapshot.Results = copyResults(run.Results)
		values = append(values, snapshot)
	}
	return values
}

// RecentResults returns the most recent probe rows.
func (s *Service) RecentResults() []ResultView {
	s.mu.RLock()
	defer s.mu.RUnlock()
	values := make([]ResultView, len(s.recent))
	copy(values, s.recent)
	return values
}

// Stop cancels a running batch.
func (s *Service) Stop() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel == nil {
		return false
	}
	s.cancel()
	s.cancel = nil
	return true
}
