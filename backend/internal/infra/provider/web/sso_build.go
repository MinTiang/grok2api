package web

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	accountdomain "github.com/chenyme/grok2api/backend/internal/domain/account"
	egressdomain "github.com/chenyme/grok2api/backend/internal/domain/egress"
	"github.com/chenyme/grok2api/backend/internal/infra/config"
	infraegress "github.com/chenyme/grok2api/backend/internal/infra/egress"
	"github.com/chenyme/grok2api/backend/internal/infra/provider"
	"github.com/chenyme/grok2api/backend/internal/infra/security"
	"golang.org/x/net/html"
)

const (
	ssoBuildClientID = "b1a00492-073a-47ea-816f-4c329264a828"
	ssoBuildScope    = "openid profile email offline_access grok-cli:access api:access conversations:read conversations:write"
	// ssoBuildPKCEScope 是 PKCE 授权流程使用的最小 scope（实测可用集）：Build/CLI
	// 上游只需要 grok-cli:access + api:access；conversations:* 由 Web SSO cookie
	// 承担，不随 Build 凭据申请。
	ssoBuildPKCEScope = "openid profile email offline_access grok-cli:access api:access"
	ssoDeviceURL      = "https://auth.x.ai/oauth2/device/code"
	ssoVerifyURL      = "https://auth.x.ai/oauth2/device/verify"
	ssoApproveURL     = "https://auth.x.ai/oauth2/device/approve"
	ssoAuthorizeURL   = "https://auth.x.ai/oauth2/authorize"
	ssoTokenURL       = "https://auth.x.ai/oauth2/token"
	// ssoBuildRedirectURI 是 Grok CLI 注册的 loopback 回调地址。授权码只从 302 的
	// Location 中解析，该地址本身不会被请求。
	ssoBuildRedirectURI = "http://127.0.0.1:56121/callback"
	maxAuthBody         = 2 << 20
)

// ssoBuildDeviceFallback 控制 PKCE 主路径失败后是否再尝试 device flow。默认开启：
// 若上游恢复 device flow 或转而拦截 PKCE，兜底仍可完成转换；置为 false 可省去一次
// 注定失败的请求。
var ssoBuildDeviceFallback = true

type ssoBuildHTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

type ssoBuildFlow struct {
	client    ssoBuildHTTPClient
	userAgent string
	cookies   map[string]string
}

func (a *Adapter) ConvertToBuild(ctx context.Context, credential accountdomain.Credential) (provider.CredentialSeed, error) {
	if credential.Provider != accountdomain.ProviderWeb || credential.AuthType != accountdomain.AuthTypeSSO {
		return provider.CredentialSeed{}, fmt.Errorf("仅 Grok Web SSO 账号支持转换")
	}
	token, err := a.cipher.Decrypt(credential.EncryptedAccessToken)
	if err != nil {
		return provider.CredentialSeed{}, fmt.Errorf("解密 Grok Web SSO: %w", err)
	}
	token = normalizeSSOToken(token)
	if token == "" {
		return provider.CredentialSeed{}, provider.ErrUnauthorized
	}
	lease, err := a.egress.AcquireCredential(ctx, egressdomain.ScopeWeb, credential)
	if err != nil {
		return provider.CredentialSeed{}, err
	}
	defer lease.Release()
	requestCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	flow := &ssoBuildFlow{
		client: lease, userAgent: lease.UserAgent,
		cookies: ssoBuildCookies(token, lease.CFCookies),
	}
	seed, err := flow.convert(requestCtx, credential)
	if err != nil {
		a.egress.Feedback(context.WithoutCancel(ctx), lease.NodeID, conversionStatus(err), err)
		return provider.CredentialSeed{}, err
	}
	a.egress.Feedback(context.WithoutCancel(ctx), lease.NodeID, http.StatusOK, nil)
	return seed, nil
}

// convert 先走 PKCE 主路径，失败且非明确的授权拒绝时再用 device flow 兜底。
// 2026-10 起 device flow 的 approve 被 Cloudflare 永久拦截：该端点要求只有 consent
// 页面脚本才能产出的浏览器令牌，补充任何请求头都返回 403「We could not verify this
// browser」。PKCE 提交的是 consent 页面上真实存在的跨站表单，具备完整浏览器导航
// 语义即可通过，因此成为主路径。
func (f *ssoBuildFlow) convert(ctx context.Context, credential accountdomain.Credential) (provider.CredentialSeed, error) {
	seed, err := f.convertPKCE(ctx, credential)
	if err == nil {
		return seed, nil
	}
	if !ssoBuildDeviceFallback || errors.Is(err, provider.ErrUnauthorized) || errors.Is(err, provider.ErrAuthorizationDenied) {
		return provider.CredentialSeed{}, err
	}
	if fallbackSeed, fallbackErr := f.convertDeviceFlow(ctx, credential); fallbackErr == nil {
		return fallbackSeed, nil
	}
	return provider.CredentialSeed{}, err
}

// convertPKCE 通过 authorization code + PKCE 流程换取 Build token（当前唯一可用的
// 协议路径）。流程：GET /oauth2/authorize（已带 sso/sso-rw cookie，303 跳同意页）
// → 解析同意页隐藏表单 → POST /oauth2/authorize 提交同意（需完整浏览器导航头）
// → 302 到 loopback 带 code → POST /oauth2/token 用 code_verifier 换 token。
//
// 与 device flow 的关键差异：整个流程没有任何被 CF 标记的可疑状态变更端点，POST
// 的是页面上真实存在的跨站表单，因此能通过 Cloudflare 校验。
func (f *ssoBuildFlow) convertPKCE(ctx context.Context, credential accountdomain.Credential) (provider.CredentialSeed, error) {
	verifier, err := randomB64URL(64)
	if err != nil {
		return provider.CredentialSeed{}, err
	}
	challenge := sha256.Sum256([]byte(verifier))
	state, err := randomB64URL(16)
	if err != nil {
		return provider.CredentialSeed{}, err
	}
	authorizeQuery := url.Values{
		"response_type":         {"code"},
		"client_id":             {ssoBuildClientID},
		"redirect_uri":          {ssoBuildRedirectURI},
		"scope":                 {ssoBuildPKCEScope},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(challenge[:])},
		"code_challenge_method": {"S256"},
		"state":                 {state},
	}
	// GET 本身不触发 CF 校验，正常 303 → accounts.x.ai 的同意页
	status, finalURL, body, err := f.do(ctx, http.MethodGet, ssoAuthorizeURL+"?"+authorizeQuery.Encode(), nil)
	if err != nil {
		return provider.CredentialSeed{}, err
	}
	if ssoDeviceRedirectState(finalURL) == "sign-in" {
		return provider.CredentialSeed{}, provider.ErrUnauthorized
	}
	if status < 200 || status >= 300 {
		return provider.CredentialSeed{}, fmt.Errorf("SSO PKCE 获取同意页失败: %w", conversionHTTPError{status: status})
	}
	form := parseConsentFormFields(body)
	if form == nil {
		// 常见于 SSO 失效被踢回登录页（无重定向直接 200）或返回挑战页
		return provider.CredentialSeed{}, fmt.Errorf("SSO PKCE 转换失败：未获取到同意页表单（SSO 可能已失效）")
	}
	form.Set("action", "allow")

	code, err := f.submitConsent(ctx, finalURL, form, state)
	if err != nil {
		return provider.CredentialSeed{}, err
	}
	token, err := f.exchangePKCECode(ctx, code, verifier)
	if err != nil {
		return provider.CredentialSeed{}, err
	}
	return buildCredentialSeed(token, credential), nil
}

// submitConsent 以浏览器跨站表单语义提交同意页。请求头逐档增强：403 表示 CF 判为
// 非浏览器导航，换更完整的档位重试而不是「参数错误」；成功时 302 的 Location 指向
// loopback 回调，仅从中解析授权码，绝不发起请求。
func (f *ssoBuildFlow) submitConsent(ctx context.Context, consentPageURL string, form url.Values, state string) (string, error) {
	referer := consentReferer(consentPageURL)
	lastStatus := 0
	for _, headers := range navigationHeaderTiers(f.userAgent) {
		status, location, _, err := f.postAuthorizeNoFollow(ctx, form, headers, referer)
		if err != nil {
			return "", err
		}
		lastStatus = status
		if status == http.StatusForbidden {
			continue
		}
		code, returnedState, ok := extractAuthorizationCode(location)
		if !ok {
			// 3xx 但没有 code（带 error=）或其它状态码：换档位重试也不会有改善
			return "", fmt.Errorf("SSO PKCE 提交同意失败: %w", conversionHTTPError{status: status})
		}
		if returnedState != state {
			return "", fmt.Errorf("SSO PKCE 提交同意失败：state 校验不一致")
		}
		return code, nil
	}
	return "", fmt.Errorf("SSO PKCE 提交同意失败：浏览器导航头全部被拒绝: %w", conversionHTTPError{status: lastStatus})
}

// postAuthorizeNoFollow 提交同意表单但不跟随重定向：成功时 302 的 Location 指向
// loopback 回调（只解析不请求），因此不经过通用重定向处理。
func (f *ssoBuildFlow) postAuthorizeNoFollow(ctx context.Context, form url.Values, headers map[string]string, referer string) (int, string, []byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, ssoAuthorizeURL, strings.NewReader(form.Encode()))
	if err != nil {
		return 0, "", nil, err
	}
	request.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
	request.Header.Set("Cookie", f.cookieHeader())
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	request.Header.Set("Referer", referer)
	response, err := f.client.Do(request)
	if err != nil {
		return 0, "", nil, err
	}
	f.captureCookies(response)
	data, readErr := io.ReadAll(io.LimitReader(response.Body, maxAuthBody+1))
	_ = response.Body.Close()
	if readErr != nil {
		return response.StatusCode, "", nil, readErr
	}
	if len(data) > maxAuthBody {
		return response.StatusCode, "", nil, fmt.Errorf("xAI OAuth 响应超过 2 MiB")
	}
	return response.StatusCode, strings.TrimSpace(response.Header.Get("Location")), data, nil
}

// exchangePKCECode 用授权码 + code_verifier 换取 token。
func (f *ssoBuildFlow) exchangePKCECode(ctx context.Context, code, verifier string) (ssoBuildToken, error) {
	status, _, body, err := f.doWithFollowHeaders(ctx, http.MethodPost, ssoTokenURL, url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {ssoBuildClientID},
		"code":          {code},
		"redirect_uri":  {ssoBuildRedirectURI},
		"code_verifier": {verifier},
	}, true, map[string]string{
		"x-grok-client-version": config.RecommendedBuildClientVersion,
		"x-grok-client-surface": "web",
	})
	if err != nil {
		return ssoBuildToken{}, err
	}
	var payload struct {
		AccessToken      string `json:"access_token"`
		RefreshToken     string `json:"refresh_token"`
		IDToken          string `json:"id_token"`
		ExpiresIn        int    `json:"expires_in"`
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return ssoBuildToken{}, fmt.Errorf("解析 xAI OAuth Token: %w", err)
	}
	if payload.AccessToken == "" {
		return ssoBuildToken{}, fmt.Errorf("xAI OAuth Token 失败 (%s): %w", firstValue(payload.ErrorDescription, payload.Error, strconv.Itoa(status)), conversionHTTPError{status: status})
	}
	if payload.ExpiresIn <= 0 {
		payload.ExpiresIn = 3600
	}
	return ssoBuildToken{AccessToken: payload.AccessToken, RefreshToken: payload.RefreshToken, IDToken: payload.IDToken, ExpiresAt: time.Now().UTC().Add(time.Duration(payload.ExpiresIn) * time.Second)}, nil
}

// navigationHeaderTiers 构建逐档增强的浏览器导航请求头。实测差异很明确：仅
// Content-Type 必然 403 挑战页；补齐 Origin/Referer/UA/Accept/Sec-Fetch-* 的完整
// 导航语义即可通过。UA 使用 Lease 的真实 UA 以匹配出口的 TLS 指纹 profile；client
// hints 的 Chrome 大版本从 UA 推导，推导不出时省略。Accept-Encoding 交由出口
// 客户端自行协商，不在此设置。
func navigationHeaderTiers(userAgent string) []map[string]string {
	base := map[string]string{
		"User-Agent":                userAgent,
		"Accept-Language":           "en-US,en;q=0.9",
		"Origin":                    "https://accounts.x.ai",
		"Sec-Fetch-Dest":            "document",
		"Sec-Fetch-Mode":            "navigate",
		"Sec-Fetch-Site":            "same-origin",
		"Sec-Fetch-User":            "?1",
		"Upgrade-Insecure-Requests": "1",
	}
	tier2 := cloneHeaders(base)
	tier2["Cache-Control"] = "max-age=0"
	for key, value := range chromeClientHints(userAgent) {
		tier2[key] = value
	}
	tier3 := cloneHeaders(tier2)
	tier3["DNT"] = "1"
	tier3["Priority"] = "u=0, i"
	return []map[string]string{base, tier2, tier3}
}

func cloneHeaders(headers map[string]string) map[string]string {
	clone := make(map[string]string, len(headers))
	for key, value := range headers {
		clone[key] = value
	}
	return clone
}

// chromeClientHints 从 UA 推导 sec-ch-ua 客户端提示；UA 不含 Chrome 版本时返回 nil。
func chromeClientHints(userAgent string) map[string]string {
	match := chromeMajorPattern.FindStringSubmatch(strings.TrimSpace(userAgent))
	if len(match) != 2 {
		return nil
	}
	major := match[1]
	hints := map[string]string{
		"sec-ch-ua":          fmt.Sprintf(`"Not=A?Brand";v="99", "Google Chrome";v="%s", "Chromium";v="%s"`, major, major),
		"sec-ch-ua-mobile":   "?0",
		"sec-ch-ua-platform": `"Windows"`,
	}
	switch {
	case strings.Contains(userAgent, "Windows"):
		hints["sec-ch-ua-platform"] = `"Windows"`
	case strings.Contains(userAgent, "Macintosh"), strings.Contains(userAgent, "Mac OS"):
		hints["sec-ch-ua-platform"] = `"macOS"`
	case strings.Contains(userAgent, "Android"):
		hints["sec-ch-ua-platform"] = `"Android"`
		hints["sec-ch-ua-mobile"] = "?1"
	case strings.Contains(userAgent, "iPhone"), strings.Contains(userAgent, "iPad"):
		hints["sec-ch-ua-platform"] = `"iOS"`
		hints["sec-ch-ua-mobile"] = "?1"
	case strings.Contains(userAgent, "Linux"), strings.Contains(userAgent, "X11"):
		hints["sec-ch-ua-platform"] = `"Linux"`
	}
	return hints
}

var chromeMajorPattern = regexp.MustCompile(`(?i)Chrome/(\d+)`)

// parseConsentFormFields 从同意页解析待提交的表单隐藏字段。只收 hidden input：
// 页面里还有搜索框等无关 input，混进来会被上游拒绝。缺 client_id/redirect_uri
// 说明拿到的不是同意页（可能是挑战页或登录页）。
func parseConsentFormFields(body []byte) url.Values {
	form := url.Values{}
	tokenizer := html.NewTokenizer(bytes.NewReader(body))
	for {
		tokenType := tokenizer.Next()
		if tokenType == html.ErrorToken {
			break
		}
		if tokenType != html.StartTagToken && tokenType != html.SelfClosingTagToken {
			continue
		}
		token := tokenizer.Token()
		if !strings.EqualFold(token.Data, "input") {
			continue
		}
		var name, value, inputType string
		for _, attribute := range token.Attr {
			switch strings.ToLower(attribute.Key) {
			case "name":
				name = attribute.Val
			case "value":
				value = attribute.Val
			case "type":
				inputType = attribute.Val
			}
		}
		if name == "" || !strings.EqualFold(inputType, "hidden") {
			continue
		}
		form.Set(name, value)
	}
	if form.Get("client_id") == "" || form.Get("redirect_uri") == "" {
		return nil
	}
	return form
}

// extractAuthorizationCode 从回调 Location 中解析授权码与回传的 state。
func extractAuthorizationCode(location string) (string, string, bool) {
	parsed, err := url.Parse(strings.TrimSpace(location))
	if err != nil {
		return "", "", false
	}
	query := parsed.Query()
	code := strings.TrimSpace(query.Get("code"))
	if code == "" {
		return "", "", false
	}
	return code, query.Get("state"), true
}

// consentReferer 返回不带 query 的同意页地址：Origin 是固定值，Referer 若带上
// ?response_type=... 会与其语义冲突，更像伪造。
func consentReferer(pageURL string) string {
	parsed, err := url.Parse(pageURL)
	if err != nil || parsed.Host == "" {
		return "https://accounts.x.ai/oauth2/consent"
	}
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String()
}

func randomB64URL(byteLen int) (string, error) {
	buf := make([]byte, byteLen)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("生成 PKCE 随机数失败: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// buildCredentialSeed 由 token 响应构造 Build 凭据种子，两条转换路径共用。
func buildCredentialSeed(token ssoBuildToken, credential accountdomain.Credential) provider.CredentialSeed {
	claims := decodeBuildClaims(firstValue(token.IDToken, token.AccessToken))
	userID := claimString(claims, "sub")
	email := claimString(claims, "email")
	teamID := claimString(claims, "team_id")
	name := strings.TrimSpace(credential.Name)
	if name == "" {
		name = "Grok Web account"
	}
	return provider.CredentialSeed{
		Provider: accountdomain.ProviderBuild, AuthType: accountdomain.AuthTypeOAuth,
		Name: firstValue(email, name+" Build", userID, "Grok Build account"), Email: email, UserID: userID, TeamID: teamID,
		SourceKey: "sso-build:" + security.HashToken(token.AccessToken), OIDCClientID: ssoBuildClientID,
		AccessToken: token.AccessToken, RefreshToken: token.RefreshToken, ExpiresAt: token.ExpiresAt,
	}
}

// convertDeviceFlow 是 device flow 兜底路径：device/code → verify → approve（需
// consent_token 防伪令牌）→ 轮询 token。
func (f *ssoBuildFlow) convertDeviceFlow(ctx context.Context, credential accountdomain.Credential) (provider.CredentialSeed, error) {
	form := url.Values{"client_id": {ssoBuildClientID}, "scope": {ssoBuildScope}}
	status, _, body, err := f.do(ctx, http.MethodPost, ssoDeviceURL, form)
	if err != nil {
		return provider.CredentialSeed{}, err
	}
	if status < 200 || status >= 300 {
		return provider.CredentialSeed{}, fmt.Errorf("xAI Device Flow 启动失败: %w", conversionHTTPError{status: status})
	}
	var device struct {
		DeviceCode string `json:"device_code"`
		UserCode   string `json:"user_code"`
		Interval   int    `json:"interval"`
		ExpiresIn  int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &device); err != nil {
		return provider.CredentialSeed{}, fmt.Errorf("解析 xAI Device Flow: %w", err)
	}
	if device.DeviceCode == "" || device.UserCode == "" {
		return provider.CredentialSeed{}, fmt.Errorf("xAI Device Flow 返回字段不完整")
	}
	if device.Interval <= 0 {
		device.Interval = 5
	}
	if device.ExpiresIn <= 0 {
		device.ExpiresIn = 1800
	}

	// verify → consent。xAI 2025-09 起在 device 授权流程加入防伪令牌：consent 页面内嵌一个
	// 一次性 consent_token（ES256 JWT，typ=consent+jwt），approve 必须回传它，否则返回
	// 403「Request could not be verified」。因此这里不能只看 3xx 的状态路径，还要取到
	// consent 页面来解析该令牌。
	status, finalURL, verifyBody, err := f.doWithFollow(ctx, http.MethodPost, ssoVerifyURL, url.Values{"user_code": {device.UserCode}}, false)
	if err != nil {
		return provider.CredentialSeed{}, err
	}
	if status == http.StatusUnauthorized {
		return provider.CredentialSeed{}, provider.ErrUnauthorized
	}
	if status < 200 || status >= 400 {
		return provider.CredentialSeed{}, fmt.Errorf("SSO 自动验证 Device Flow 失败: %w", conversionHTTPError{status: status})
	}
	if redirectState := ssoDeviceRedirectState(finalURL); redirectState != "consent" {
		if redirectState == "sign-in" {
			return provider.CredentialSeed{}, provider.ErrUnauthorized
		}
		return provider.CredentialSeed{}, fmt.Errorf("SSO 自动验证 Device Flow 失败")
	}
	consentPageURL := finalURL

	// verify 以 3xx 跳转到 consent 时响应体为空，需要 GET consent 页面本身来解析 consent_token。
	consentToken := extractConsentToken(verifyBody)
	consentUserCode := extractConsentInput(verifyBody, "user_code")
	if consentToken == "" {
		consentStatus, _, consentBody, cerr := f.do(ctx, http.MethodGet, consentPageURL, nil)
		if cerr != nil {
			return provider.CredentialSeed{}, fmt.Errorf("获取 xAI consent 页面失败: %w", cerr)
		}
		if consentStatus < 200 || consentStatus >= 300 {
			return provider.CredentialSeed{}, fmt.Errorf("获取 xAI consent 页面失败: %w", conversionHTTPError{status: consentStatus})
		}
		consentToken = extractConsentToken(consentBody)
		consentUserCode = extractConsentInput(consentBody, "user_code")
	}
	if !consentTokenMatchesDevice(consentToken, device.DeviceCode) && !consentTokenMatchesUserCode(consentToken, consentUserCode, device.UserCode, time.Now()) {
		return provider.CredentialSeed{}, fmt.Errorf("SSO 自动批准 Device Flow 失败：未获取 consent_token")
	}

	status, finalURL, approveBody, err := f.doWithFollowHeaders(ctx, http.MethodPost, ssoApproveURL, url.Values{
		"user_code": {device.UserCode}, "action": {"allow"}, "principal_type": {"User"}, "principal_id": {""},
		"consent_token": {consentToken},
	}, false, map[string]string{
		"Origin":                    "https://accounts.x.ai",
		"Referer":                   consentPageURL,
		"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"Sec-Fetch-Dest":            "document",
		"Sec-Fetch-Mode":            "navigate",
		"Sec-Fetch-Site":            "same-site",
		"Sec-Fetch-User":            "?1",
		"Upgrade-Insecure-Requests": "1",
	})
	if err != nil {
		return provider.CredentialSeed{}, err
	}
	if status == http.StatusForbidden && isBrowserVerificationRequired(approveBody) {
		// Observed 2026-10-20: approve now demands a Castle browser token that only
		// the consent page's script can produce. Not an SSO failure.
		return provider.CredentialSeed{}, fmt.Errorf("%w: xAI 要求浏览器校验后才能批准授权，请改用 Device OAuth 在浏览器中手动完成", errBrowserVerificationRequired)
	}
	if status < 200 || status >= 400 {
		return provider.CredentialSeed{}, fmt.Errorf("SSO 自动批准 Device Flow 失败: %w", conversionHTTPError{status: status})
	}
	if redirectState := ssoDeviceRedirectState(finalURL); redirectState != "done" {
		if redirectState == "sign-in" {
			return provider.CredentialSeed{}, provider.ErrUnauthorized
		}
		return provider.CredentialSeed{}, fmt.Errorf("SSO 自动批准 Device Flow 失败")
	}

	token, err := f.pollToken(ctx, device.DeviceCode, time.Duration(device.Interval)*time.Second, time.Duration(device.ExpiresIn)*time.Second)
	if err != nil {
		return provider.CredentialSeed{}, err
	}
	return buildCredentialSeed(token, credential), nil
}

type ssoBuildToken struct {
	AccessToken  string
	RefreshToken string
	IDToken      string
	ExpiresAt    time.Time
}

func (f *ssoBuildFlow) pollToken(ctx context.Context, deviceCode string, interval, expiresIn time.Duration) (ssoBuildToken, error) {
	if interval < time.Second {
		interval = time.Second
	}
	deadline := time.Now().Add(min(expiresIn, 75*time.Second))
	for time.Now().Before(deadline) {
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ssoBuildToken{}, ctx.Err()
		case <-timer.C:
		}
		status, _, body, err := f.do(ctx, http.MethodPost, ssoTokenURL, url.Values{
			"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}, "client_id": {ssoBuildClientID}, "device_code": {deviceCode},
		})
		if err != nil {
			return ssoBuildToken{}, err
		}
		var payload struct {
			AccessToken      string `json:"access_token"`
			RefreshToken     string `json:"refresh_token"`
			IDToken          string `json:"id_token"`
			ExpiresIn        int    `json:"expires_in"`
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			return ssoBuildToken{}, fmt.Errorf("解析 xAI OAuth Token: %w", err)
		}
		if status >= 200 && status < 300 && payload.AccessToken != "" {
			if payload.ExpiresIn <= 0 {
				payload.ExpiresIn = 3600
			}
			return ssoBuildToken{AccessToken: payload.AccessToken, RefreshToken: payload.RefreshToken, IDToken: payload.IDToken, ExpiresAt: time.Now().UTC().Add(time.Duration(payload.ExpiresIn) * time.Second)}, nil
		}
		switch payload.Error {
		case "authorization_pending":
			continue
		case "slow_down":
			interval += 5 * time.Second
			continue
		case "access_denied", "expired_token":
			return ssoBuildToken{}, provider.ErrAuthorizationDenied
		default:
			if status >= 400 {
				return ssoBuildToken{}, fmt.Errorf("xAI OAuth Token 失败 (%s): %w", firstValue(payload.ErrorDescription, payload.Error), conversionHTTPError{status: status})
			}
			return ssoBuildToken{}, fmt.Errorf("xAI OAuth Token 失败: %s", firstValue(payload.ErrorDescription, payload.Error, strconv.Itoa(status)))
		}
	}
	return ssoBuildToken{}, fmt.Errorf("xAI Device Flow 轮询超时")
}

func (f *ssoBuildFlow) do(ctx context.Context, method, endpoint string, form url.Values) (int, string, []byte, error) {
	return f.doWithFollow(ctx, method, endpoint, form, true)
}

// doWithFollow 在 follow=false 时遇到 3xx 直接返回状态码与解析后的 Location 作为 finalURL，
// 用于重定向目标域会被 Cloudflare 拦截（accounts.x.ai）的请求。
func (f *ssoBuildFlow) doWithFollow(ctx context.Context, method, endpoint string, form url.Values, follow bool) (int, string, []byte, error) {
	return f.doWithFollowHeaders(ctx, method, endpoint, form, follow, nil)
}

func (f *ssoBuildFlow) doWithFollowHeaders(ctx context.Context, method, endpoint string, form url.Values, follow bool, extraHeaders map[string]string) (int, string, []byte, error) {
	if !safeXAIURL(endpoint) {
		return 0, "", nil, fmt.Errorf("xAI OAuth URL 不安全")
	}
	currentURL := endpoint
	currentMethod := method
	currentForm := form
	for redirects := 0; redirects <= 8; redirects++ {
		var body io.Reader
		if currentForm != nil {
			body = strings.NewReader(currentForm.Encode())
		}
		request, err := http.NewRequestWithContext(ctx, currentMethod, currentURL, body)
		if err != nil {
			return 0, "", nil, err
		}
		request.Header.Set("Accept", "application/json, text/html;q=0.9, */*;q=0.8")
		request.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
		request.Header.Set("User-Agent", f.userAgent)
		request.Header.Set("Cookie", f.cookieHeader())
		if currentMethod == http.MethodGet && ssoDeviceRedirectState(currentURL) == "consent" {
			request.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
			request.Header.Set("Referer", "https://auth.x.ai/")
			request.Header.Set("Sec-Fetch-Dest", "document")
			request.Header.Set("Sec-Fetch-Mode", "navigate")
			request.Header.Set("Sec-Fetch-Site", "same-site")
			request.Header.Set("Upgrade-Insecure-Requests", "1")
		}
		for key, value := range extraHeaders {
			request.Header.Set(key, value)
		}
		if currentForm != nil {
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		response, err := f.client.Do(request)
		if err != nil {
			return 0, "", nil, err
		}
		f.captureCookies(response)
		data, readErr := io.ReadAll(io.LimitReader(response.Body, maxAuthBody+1))
		_ = response.Body.Close()
		if readErr != nil {
			return response.StatusCode, currentURL, nil, readErr
		}
		if len(data) > maxAuthBody {
			return response.StatusCode, currentURL, nil, fmt.Errorf("xAI OAuth 响应超过 2 MiB")
		}
		if response.StatusCode < 300 || response.StatusCode > 399 {
			return response.StatusCode, currentURL, data, nil
		}
		location := strings.TrimSpace(response.Header.Get("Location"))
		if location == "" {
			return response.StatusCode, currentURL, data, fmt.Errorf("xAI OAuth 重定向缺少 Location")
		}
		base, _ := url.Parse(currentURL)
		next, err := url.Parse(location)
		if err != nil {
			return response.StatusCode, currentURL, data, err
		}
		currentURL = base.ResolveReference(next).String()
		if !safeXAIURL(currentURL) {
			return response.StatusCode, currentURL, data, fmt.Errorf("xAI OAuth 重定向到非受信域名")
		}
		if !follow {
			return response.StatusCode, currentURL, data, nil
		}
		if response.StatusCode == http.StatusSeeOther || ((response.StatusCode == http.StatusMovedPermanently || response.StatusCode == http.StatusFound) && currentMethod != http.MethodGet && currentMethod != http.MethodHead) {
			currentMethod = http.MethodGet
			currentForm = nil
		}
	}
	return 0, currentURL, nil, fmt.Errorf("xAI OAuth 重定向次数过多")
}

func (f *ssoBuildFlow) captureCookies(response *http.Response) {
	for _, cookie := range response.Cookies() {
		name := strings.TrimSpace(cookie.Name)
		value := strings.TrimSpace(cookie.Value)
		if name == "" || len(name) > 128 || len(value) > 16384 || strings.ContainsAny(name+value, "\r\n\x00") {
			continue
		}
		if cookie.MaxAge < 0 {
			delete(f.cookies, name)
			continue
		}
		f.cookies[name] = value
	}
}

func ssoDeviceRedirectState(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil || !safeXAIURL(raw) {
		return ""
	}
	path := strings.TrimRight(parsed.EscapedPath(), "/")
	switch path {
	// /oauth2/consent 是 PKCE 授权流程的同意页；device flow 的同意页带 device 前缀
	case "/oauth2/device/consent", "/oauth2/consent":
		return "consent"
	case "/oauth2/device/done":
		return "done"
	case "/sign-in", "/sign-up":
		return "sign-in"
	default:
		return ""
	}
}

func (f *ssoBuildFlow) cookieHeader() string {
	keys := make([]string, 0, len(f.cookies))
	for key := range f.cookies {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+f.cookies[key])
	}
	return strings.Join(parts, "; ")
}

func ssoBuildCookies(token, cloudflareCookies string) map[string]string {
	cookies := make(map[string]string)
	for _, part := range strings.Split(infraegress.BuildSSOCookie(token, cloudflareCookies), ";") {
		name, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok && name != "" {
			cookies[name] = value
		}
	}
	return cookies
}

func safeXAIURL(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Hostname() == "" {
		return false
	}
	host := strings.ToLower(parsed.Hostname())
	return host == "x.ai" || strings.HasSuffix(host, ".x.ai")
}

func normalizeSSOToken(value string) string {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(strings.ToLower(value), "sso=") {
		value = strings.TrimSpace(value[len("sso="):])
	}
	if token, _, found := strings.Cut(value, ";"); found {
		value = strings.TrimSpace(token)
	}
	return strings.NewReplacer("\r", "", "\n", "", "\x00", "").Replace(value)
}

var (
	consentTokenJSONRe = regexp.MustCompile(`(?i)\\?["']?(?:consentToken|consent_token)\\?["']?\s*[:=]\s*\\?["'](eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\\?["']`)
)

// extractConsentToken 从 consent 页面 HTML 中解析一次性 consent_token：
// 优先取表单隐藏字段 name="consent_token"，回退到 RSC/JSON 里的 consentToken。
func extractConsentToken(body []byte) string {
	tokenizer := html.NewTokenizer(strings.NewReader(string(body)))
	for {
		tokenType := tokenizer.Next()
		if tokenType == html.ErrorToken {
			break
		}
		if tokenType != html.StartTagToken && tokenType != html.SelfClosingTagToken {
			continue
		}
		token := tokenizer.Token()
		if !strings.EqualFold(token.Data, "input") {
			continue
		}
		var name, value string
		for _, attribute := range token.Attr {
			switch strings.ToLower(attribute.Key) {
			case "name":
				name = attribute.Val
			case "value":
				value = attribute.Val
			}
		}
		if strings.EqualFold(name, "consent_token") && value != "" {
			return value
		}
	}
	if m := consentTokenJSONRe.FindSubmatch(body); m != nil {
		return string(m[1])
	}
	return ""
}

// consentTokenMatchesUserCode binds a consent token to this device request
// when its dc claim is a server-side authorization id (observed 2026-10-20:
// a UUID unrelated to device_code). The consent form echoes our user_code, so
// the token is accepted only from that form, with the consent audience and an
// unexpired exp.
func consentTokenMatchesUserCode(token, pageUserCode, userCode string, now time.Time) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[2] == "" || userCode == "" || !strings.EqualFold(strings.TrimSpace(pageUserCode), userCode) {
		return false
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	var head struct {
		Typ string `json:"typ"`
	}
	if json.Unmarshal(header, &head) != nil || !strings.EqualFold(head.Typ, "consent+jwt") {
		return false
	}
	claims := decodeBuildClaims(token)
	if claimString(claims, "aud") != "consent" || claimString(claims, "dc") == "" {
		return false
	}
	exp, _ := claims["exp"].(float64)
	return exp > 0 && time.Unix(int64(exp), 0).After(now)
}

// extractConsentInput returns the value of a hidden input on the consent form.
func extractConsentInput(body []byte, field string) string {
	tokenizer := html.NewTokenizer(strings.NewReader(string(body)))
	for {
		tokenType := tokenizer.Next()
		if tokenType == html.ErrorToken {
			return ""
		}
		if tokenType != html.StartTagToken && tokenType != html.SelfClosingTagToken {
			continue
		}
		token := tokenizer.Token()
		if !strings.EqualFold(token.Data, "input") {
			continue
		}
		var name, value string
		for _, attribute := range token.Attr {
			switch strings.ToLower(attribute.Key) {
			case "name":
				name = attribute.Val
			case "value":
				value = attribute.Val
			}
		}
		if strings.EqualFold(name, field) {
			return value
		}
	}
}

func consentTokenMatchesDevice(token, deviceCode string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[2] == "" {
		return false
	}
	return claimString(decodeBuildClaims(token), "dc") == deviceCode && deviceCode != ""
}

func decodeBuildClaims(token string) map[string]any {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return nil
	}
	data, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}
	var claims map[string]any
	if json.Unmarshal(data, &claims) != nil {
		return nil
	}
	return claims
}

func claimString(claims map[string]any, key string) string {
	value, _ := claims[key].(string)
	return strings.TrimSpace(value)
}

func firstValue(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}

// errBrowserVerificationRequired reports that xAI refused the automated
// device approval because it requires an interactive browser check.
var errBrowserVerificationRequired = errors.New("xAI device approval requires browser verification")

func isBrowserVerificationRequired(body []byte) bool {
	text := strings.ToLower(string(body))
	return strings.Contains(text, "could not verify this browser") || strings.Contains(text, "request could not be verified")
}

type conversionHTTPError struct{ status int }

func (e conversionHTTPError) Error() string { return fmt.Sprintf("xAI OAuth HTTP %d", e.status) }

func conversionStatus(err error) int {
	var statusErr conversionHTTPError
	if errors.As(err, &statusErr) {
		return statusErr.status
	}
	if errors.Is(err, provider.ErrUnauthorized) {
		return http.StatusUnauthorized
	}
	return 0
}

var _ provider.BuildCredentialConverter = (*Adapter)(nil)
var _ ssoBuildHTTPClient = (*infraegress.Lease)(nil)
