package app

import (
	"testing"

	accountapp "github.com/chenyme/grok2api/backend/internal/application/account"
	accountdomain "github.com/chenyme/grok2api/backend/internal/domain/account"
)

// TestProbeListFilterIsAccepted is the regression guard for a silent failure: an
// unrecognised status value makes the account service reject the whole filter,
// which killed every automatic cycle while manual runs kept working, so nothing
// looked broken from the panel.
func TestProbeListFilterIsAccepted(t *testing.T) {
	filter := accountapp.ListFilter{
		Provider: string(accountdomain.ProviderBuild),
		Status:   "active",
	}
	if !accountdomain.Provider(filter.Provider).IsValid() {
		t.Fatalf("probe provider %q must be a valid provider", filter.Provider)
	}
	allowed := map[string]bool{
		"": true, "active": true, "disabled": true, "reauthRequired": true,
		"cooldown": true, "waitingReset": true, "probing": true,
	}
	if !allowed[filter.Status] {
		t.Fatalf("probe status %q is rejected by the account service; automatic cycles would never list accounts", filter.Status)
	}
}
