package web

import (
	"context"
	"fmt"

	"github.com/chenyme/grok2api/backend/internal/domain/account"
	"github.com/chenyme/grok2api/backend/internal/infra/provider"
	"github.com/chenyme/grok2api/backend/internal/infra/provider/sessionidentity"
)

// CheckConsoleEligibility 在 Web→Console 同步前通过 RSC 首页账号快照校验资格：
// 仅 cursorMerged=true 且未被上游限制的 SSO 允许创建 Console 授权。
func (a *Adapter) CheckConsoleEligibility(ctx context.Context, credential account.Credential) error {
	if credential.Provider != account.ProviderWeb || credential.AuthType != account.AuthTypeSSO {
		return fmt.Errorf("仅 Grok Web SSO 账号需要 Console 资格校验")
	}
	user, err := sessionidentity.FetchRSCUser(ctx, a.config().BaseURL, credential, a.egress, a.cipher)
	if err != nil {
		return err
	}
	return sessionidentity.CheckRSCConsoleEligibility(user)
}

var _ provider.ConsoleEligibilityAdapter = (*Adapter)(nil)
