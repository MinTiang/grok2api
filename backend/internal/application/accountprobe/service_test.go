package accountprobe

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	accountdomain "github.com/chenyme/grok2api/backend/internal/domain/account"
)

type fakeLister struct {
	mu     sync.Mutex
	pages  []int
	total  int64
	byPage map[int][]accountdomain.Credential
}

func (f *fakeLister) ListProbeCandidates(_ context.Context, page, _ int) ([]accountdomain.Credential, int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pages = append(f.pages, page)
	return f.byPage[page], f.total, nil
}

// TestCursorAdvancesAcrossCycles is the regression guard for the original bug:
// automatic cycles used to request page 1 forever, so an account pool larger
// than one chunk was only ever probed at the front.
func TestCursorAdvancesAcrossCycles(t *testing.T) {
	lister := &fakeLister{
		total: 12,
		byPage: map[int][]accountdomain.Credential{
			1: {{ID: 1}, {ID: 2}},
			2: {{ID: 3}, {ID: 4}},
			3: {{ID: 5}, {ID: 6}},
		},
	}
	service := NewService(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil, lister)
	service.UpdateConfig(Config{Enabled: true, ClientKeyID: 1, ChunkSize: 2})

	// Start would need a real prober; drive the cursor directly so the test
	// stays focused on page rotation.
	for cycle := 0; cycle < 5; cycle++ {
		page := service.nextCursorPage()
		values, _, err := lister.ListProbeCandidates(context.Background(), page, 2)
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if len(values) == 0 {
			service.recordCursorPage(1)
			continue
		}
		service.recordCursorPage(page + 1)
	}

	got := lister.pages
	// Page 4 is empty, which is what makes the sweep wrap back to page 1.
	want := []int{1, 2, 3, 4, 1}
	if len(got) != len(want) {
		t.Fatalf("pages = %v, want %v", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("pages = %v, want %v", got, want)
		}
	}
}

// TestCursorDoesNotAdvanceWhenBatchRejected is the regression guard for a silent
// hole: the cursor used to advance before Start was attempted, so a page that was
// skipped because another run held the slot was never probed again.
func TestCursorDoesNotAdvanceWhenBatchRejected(t *testing.T) {
	lister := &fakeLister{
		total: 3,
		byPage: map[int][]accountdomain.Credential{
			3: {{ID: 30}},
		},
	}
	service := NewService(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil, lister)
	service.UpdateConfig(Config{Enabled: true, ClientKeyID: 1, ChunkSize: 1})

	// Occupy the service so the next Start is rejected.
	if _, err := service.Start(context.Background(), "manual", []uint64{1}); err != nil {
		t.Fatalf("first start: %v", err)
	}
	service.recordCursorPage(3)

	service.runAutomaticCycle(context.Background())

	if got := service.nextCursorPage(); got != 3 {
		t.Fatalf("cursor after rejected cycle = %d, want 3 (must not advance)", got)
	}
	service.Stop()
}

// TestStartRejectsConcurrentBatch covers the check-then-act race: two callers
// arriving together must not both launch a run.
func TestStartRejectsConcurrentBatch(t *testing.T) {
	lister := &fakeLister{}
	service := NewService(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil, lister)
	service.UpdateConfig(Config{Enabled: true, ClientKeyID: 1, ChunkSize: 1})

	var wg sync.WaitGroup
	started := make(chan struct{}, 2)
	for index := 0; index < 2; index++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := service.Start(context.Background(), "manual", []uint64{1}); err == nil {
				started <- struct{}{}
			}
		}()
	}
	wg.Wait()
	close(started)

	count := 0
	for range started {
		count++
	}
	if count != 1 {
		t.Fatalf("accepted runs = %d, want exactly 1", count)
	}
	service.Stop()
}

// TestPersistedConfigRoundTrip guards panel edits surviving a restart.
func TestPersistedConfigRoundTrip(t *testing.T) {
	original := Config{
		Enabled: true, Interval: 3 * time.Hour, ChunkSize: 77, Workers: 4,
		Model: "grok-4.6", Prompt: "hi", MaxOutputTokens: 32,
		EarlyStopOnThinking: false, EarlyStopDelayMS: 500,
		Cooldown: 6 * time.Hour, AutoDisable: true,
	}
	restored := FromConfig(original).Apply(Config{})
	if restored.Enabled != original.Enabled || restored.Interval != original.Interval ||
		restored.ChunkSize != original.ChunkSize || restored.Workers != original.Workers ||
		restored.Model != original.Model || restored.Prompt != original.Prompt ||
		restored.MaxOutputTokens != original.MaxOutputTokens ||
		restored.EarlyStopOnThinking != original.EarlyStopOnThinking ||
		restored.EarlyStopDelayMS != original.EarlyStopDelayMS ||
		restored.Cooldown != original.Cooldown || restored.AutoDisable != original.AutoDisable {
		t.Fatalf("round trip lost values: %#v", restored)
	}
}

// TestConfigStorePersistsToDisk verifies the file really survives a reload.
func TestConfigStorePersistsToDisk(t *testing.T) {
	path := t.TempDir() + "/account-probe.json"
	store := newConfigStore(path)
	enabled := true
	chunk := 9
	if err := store.Save(PersistedConfig{Enabled: &enabled, ChunkSize: &chunk}); err != nil {
		t.Fatalf("save: %v", err)
	}
	value, found, err := newConfigStore(path).Load()
	if err != nil || !found {
		t.Fatalf("load: found=%v err=%v", found, err)
	}
	if value.Enabled == nil || !*value.Enabled || value.ChunkSize == nil || *value.ChunkSize != 9 {
		t.Fatalf("unexpected persisted value: %#v", value)
	}
}

// TestPersistedFalseIsNotTreatedAsUnset ensures an explicit `false` survives,
// which the earlier bool-based config could not express.
func TestPersistedFalseIsNotTreatedAsUnset(t *testing.T) {
	disabled := false
	cfg := PersistedConfig{EarlyStopOnThinking: &disabled}.Apply(Config{EarlyStopOnThinking: true})
	if cfg.EarlyStopOnThinking {
		t.Fatal("explicit false must override the default")
	}
}

// TestRatioSummaryCalibration pins what the self-check reports. The threshold is
// coupled to the prompt, so this is what tells an operator the two bands still
// separate - or that they have collapsed and the number is meaningless.
func TestRatioSummaryCalibration(t *testing.T) {
	build := func(threshold float64, ratios ...float64) *Service {
		s := &Service{cfg: normalizeConfig(Config{RatioThreshold: threshold})}
		for _, ratio := range ratios {
			s.recent = append(s.recent, ResultView{ReasoningRatio: ratio, Verdict: VerdictHealthy})
		}
		return s
	}

	t.Run("separated bands recommend the midpoint", func(t *testing.T) {
		s := build(3.8, 1.97, 2.03, 2.16, 2.33, 5.00, 5.07, 5.11, 5.54)
		got := s.RatioSummary()
		if !got.Calibrated {
			t.Fatalf("expected calibrated, got warning %q", got.Warning)
		}
		if got.Degraded != 4 || got.Healthy != 4 {
			t.Fatalf("counts = %d/%d, want 4/4", got.Degraded, got.Healthy)
		}
		if got.DegradedMax != 2.33 || got.HealthyMin != 5 {
			t.Fatalf("edges = %v/%v, want 2.33/5", got.DegradedMax, got.HealthyMin)
		}
		if got.Recommended != 3.67 {
			t.Fatalf("recommended = %v, want 3.67", got.Recommended)
		}
	})

	t.Run("overlapping bands warn instead of pretending", func(t *testing.T) {
		s := build(3.0, 2.9, 2.95, 3.0, 3.05, 3.1, 3.2)
		got := s.RatioSummary()
		if got.Calibrated {
			t.Fatal("expected overlap to be reported as uncalibrated")
		}
		if got.Warning == "" {
			t.Fatal("expected a warning when the bands overlap")
		}
	})

	t.Run("too few samples is not a calibration", func(t *testing.T) {
		s := build(3.0, 1.8, 5.0)
		got := s.RatioSummary()
		if got.Calibrated {
			t.Fatal("two rows are not enough to calibrate")
		}
		if got.Samples != 2 {
			t.Fatalf("samples = %d, want 2", got.Samples)
		}
	})

	t.Run("threshold far from the gap is flagged", func(t *testing.T) {
		s := build(3.0, 1.97, 2.03, 2.16, 5, 5.07, 5.11)
		got := s.RatioSummary()
		if !got.Calibrated || got.Warning == "" {
			t.Fatalf("expected a nudging warning, got calibrated=%v warning=%q", got.Calibrated, got.Warning)
		}
	})
}
