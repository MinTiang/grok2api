package account

import (
	"context"
	"encoding/base64"
	"path/filepath"
	"testing"
	"time"

	accountdomain "github.com/chenyme/grok2api/backend/internal/domain/account"
	"github.com/chenyme/grok2api/backend/internal/infra/persistence/relational"
	"github.com/chenyme/grok2api/backend/internal/infra/runtime/memory"
	"github.com/chenyme/grok2api/backend/internal/infra/security"
)

// newProbePenaltyService builds the smallest service able to exercise
// ApplyMissingThinkingPenalty against a real repository.
func newProbePenaltyService(t *testing.T) (*Service, *relational.AccountRepository, context.Context, time.Time) {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	database, err := relational.OpenSQLite(ctx, filepath.Join(t.TempDir(), "account-probe-penalty.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	if err := database.InitializeSchema(ctx); err != nil {
		t.Fatal(err)
	}
	cipher, err := security.NewCipher(base64.StdEncoding.EncodeToString(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	repo := relational.NewAccountRepository(database)
	service := NewService(repo, nil, nil, memory.NewStickyStore(), nil, cipher, nil)
	service.now = func() time.Time { return now }
	return service, repo, ctx, now
}

func createProbeAccount(t *testing.T, repo *relational.AccountRepository, ctx context.Context) uint64 {
	t.Helper()
	cipher, err := security.NewCipher(base64.StdEncoding.EncodeToString(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	token, err := cipher.Encrypt("probe-token")
	if err != nil {
		t.Fatal(err)
	}
	value, _, err := repo.UpsertByIdentity(ctx, accountdomain.Credential{
		Provider: accountdomain.ProviderBuild, AuthType: accountdomain.AuthTypeOAuth, Name: "probe-penalty",
		SourceKey: "probe-penalty-1", EncryptedAccessToken: token, Enabled: true, AuthStatus: accountdomain.AuthStatusActive,
	})
	if err != nil {
		t.Fatal(err)
	}
	return value.ID
}

// TestProbePenaltyCoolsThenDisables mirrors the two-strike contract the feature
// promises: the first miss cools for the configured window, and the next miss
// after that cooldown disables the account outright.
func TestProbePenaltyCoolsThenDisables(t *testing.T) {
	service, repo, ctx, now := newProbePenaltyService(t)
	id := createProbeAccount(t, repo, ctx)

	if err := service.ApplyMissingThinkingPenalty(ctx, id, 12*time.Hour, false); err != nil {
		t.Fatalf("first penalty: %v", err)
	}
	first, err := repo.Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if first.LastError != accountdomain.LastErrorMissingThinking {
		t.Fatalf("first strike marker = %q, want %q", first.LastError, accountdomain.LastErrorMissingThinking)
	}
	if first.CooldownUntil == nil || !first.CooldownUntil.Equal(now.Add(12*time.Hour)) {
		t.Fatalf("first strike cooldown = %v, want %v", first.CooldownUntil, now.Add(12*time.Hour))
	}
	if !first.Enabled {
		t.Fatal("first strike must keep the account enabled")
	}

	// While still cooling, a repeat miss is a no-op: it must not silently consume
	// the second strike before the cooldown actually elapsed.
	if err := service.ApplyMissingThinkingPenalty(ctx, id, 12*time.Hour, false); err != nil {
		t.Fatalf("repeat penalty while cooling: %v", err)
	}
	repeat, err := repo.Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if !repeat.Enabled {
		t.Fatal("a miss during an active cooldown must not disable the account")
	}

	// Once the cooldown elapsed, the next miss escalates to disabled.
	service.now = func() time.Time { return now.Add(13 * time.Hour) }
	if err := service.ApplyMissingThinkingPenalty(ctx, id, 12*time.Hour, false); err != nil {
		t.Fatalf("second penalty: %v", err)
	}
	second, err := repo.Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if second.Enabled {
		t.Fatal("second strike after the cooldown must disable the account")
	}
	if second.LastError != accountdomain.LastErrorMissingThinkingDisabled {
		t.Fatalf("second strike marker = %q, want %q", second.LastError, accountdomain.LastErrorMissingThinkingDisabled)
	}
	if second.CooldownUntil != nil {
		t.Fatalf("disabled account must not keep a cooldown, got %v", second.CooldownUntil)
	}
}

// TestProbePenaltyAutoDisableOnFirstMiss covers the explicit autoDisable option.
func TestProbePenaltyAutoDisableOnFirstMiss(t *testing.T) {
	service, repo, ctx, _ := newProbePenaltyService(t)
	id := createProbeAccount(t, repo, ctx)

	if err := service.ApplyMissingThinkingPenalty(ctx, id, 12*time.Hour, true); err != nil {
		t.Fatalf("penalty: %v", err)
	}
	value, err := repo.Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if value.Enabled {
		t.Fatal("autoDisable must disable on the first miss")
	}
	if value.LastError != accountdomain.LastErrorMissingThinkingDisabled {
		t.Fatalf("marker = %q, want %q", value.LastError, accountdomain.LastErrorMissingThinkingDisabled)
	}
}

// TestProbePenaltyZeroCooldownUsesDefault guards the fallback when the caller
// passes an unset duration.
func TestProbePenaltyZeroCooldownUsesDefault(t *testing.T) {
	service, repo, ctx, now := newProbePenaltyService(t)
	id := createProbeAccount(t, repo, ctx)

	if err := service.ApplyMissingThinkingPenalty(ctx, id, 0, false); err != nil {
		t.Fatalf("penalty: %v", err)
	}
	value, err := repo.Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if value.CooldownUntil == nil {
		t.Fatal("expected a cooldown")
	}
	if !value.CooldownUntil.Equal(now.Add(12 * time.Hour)) {
		t.Fatalf("cooldown = %v, want default 12h from %v", value.CooldownUntil, now)
	}
}
