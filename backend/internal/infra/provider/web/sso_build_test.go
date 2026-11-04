package web

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	accountdomain "github.com/chenyme/grok2api/backend/internal/domain/account"
	"github.com/chenyme/grok2api/backend/internal/infra/config"
	"github.com/chenyme/grok2api/backend/internal/infra/provider"
)

type scriptedSSOClient struct {
	responses []*http.Response
	requests  []*http.Request
}

func (c *scriptedSSOClient) Do(request *http.Request) (*http.Response, error) {
	c.requests = append(c.requests, request)
	response := c.responses[0]
	c.responses = c.responses[1:]
	return response, nil
}

// dynamicSSOClient 按请求内容动态应答，用于需要回显生成态参数（如 PKCE state）的流程。
type dynamicSSOClient struct {
	requests []*http.Request
	respond  func(request *http.Request) *http.Response
}

func (c *dynamicSSOClient) Do(request *http.Request) (*http.Response, error) {
	c.requests = append(c.requests, request)
	return c.respond(request), nil
}

func redirectResponse(status int, location string) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{"Location": []string{location}}, Body: io.NopCloser(strings.NewReader(""))}
}

func statusResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body))}
}

func htmlResponse(body string) *http.Response {
	return statusResponse(http.StatusOK, body)
}

func TestSSOBuildFlowFollowsOnlyTrustedXAIHTTPSRedirects(t *testing.T) {
	client := &scriptedSSOClient{responses: []*http.Response{
		{StatusCode: http.StatusFound, Header: http.Header{"Location": []string{"https://auth.x.ai/next"}, "Set-Cookie": []string{"session=abc; Path=/; Secure"}}, Body: io.NopCloser(strings.NewReader(""))},
		{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("ok"))},
	}}
	flow := &ssoBuildFlow{client: client, userAgent: "test-agent", cookies: map[string]string{"sso": "secret"}}
	status, finalURL, body, err := flow.do(context.Background(), http.MethodGet, ssoDeviceURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	if status != http.StatusOK || finalURL != "https://auth.x.ai/next" || string(body) != "ok" {
		t.Fatalf("response = %d %s %q", status, finalURL, body)
	}
	if len(client.requests) != 2 || client.requests[1].Header.Get("User-Agent") != "test-agent" {
		t.Fatalf("requests = %#v", client.requests)
	}
	cookie := client.requests[1].Header.Get("Cookie")
	if !strings.Contains(cookie, "sso=secret") || !strings.Contains(cookie, "session=abc") {
		t.Fatalf("redirect cookies = %q", cookie)
	}

	unsafe := &scriptedSSOClient{responses: []*http.Response{{StatusCode: http.StatusFound, Header: http.Header{"Location": []string{"https://example.com/steal"}}, Body: io.NopCloser(strings.NewReader(""))}}}
	flow = &ssoBuildFlow{client: unsafe, userAgent: "test-agent", cookies: map[string]string{"sso": "secret"}}
	if _, _, _, err := flow.do(context.Background(), http.MethodGet, ssoDeviceURL, nil); err == nil {
		t.Fatal("unsafe redirect was accepted")
	}
}

func TestSSOBuildFlowMapsDeadSSOToUnauthorized(t *testing.T) {
	client := &scriptedSSOClient{responses: []*http.Response{
		{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(
			`{"device_code":"dc","user_code":"uc","interval":1,"expires_in":1800}`))},
		{StatusCode: http.StatusSeeOther, Header: http.Header{"Location": []string{"https://accounts.x.ai/sign-in"}}, Body: io.NopCloser(strings.NewReader(""))},
	}}
	flow := &ssoBuildFlow{client: client, userAgent: "lease-agent", cookies: map[string]string{"sso": "dead"}}
	_, err := flow.convertDeviceFlow(context.Background(), fakeCredential())
	if !errors.Is(err, provider.ErrUnauthorized) {
		t.Fatalf("err = %v, want ErrUnauthorized", err)
	}
	if len(client.requests) != 2 {
		t.Fatalf("requests = %d, want 2 (device, verify)", len(client.requests))
	}
}

func TestSSOBuildFlowConvertsEndToEndWithConsentToken(t *testing.T) {
	client := &scriptedSSOClient{responses: []*http.Response{
		{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(
			`{"device_code":"dc","user_code":"uc","interval":1,"expires_in":1800}`))},
		{StatusCode: http.StatusSeeOther, Header: http.Header{"Location": []string{"https://accounts.x.ai/oauth2/device/consent"}}, Body: io.NopCloser(strings.NewReader(""))},
		{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(
			`<form method="post"><input value="eyJhbGciOiJFUzI1NiJ9.eyJkYyI6ImRjIn0.sig" type="hidden" name="consent_token"></form>`))},
		{StatusCode: http.StatusSeeOther, Header: http.Header{"Location": []string{"https://accounts.x.ai/oauth2/device/done"}}, Body: io.NopCloser(strings.NewReader(""))},
		{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(
			`{"access_token":"access","refresh_token":"refresh","expires_in":3600}`))},
	}}
	flow := &ssoBuildFlow{client: client, userAgent: "lease-agent", cookies: ssoBuildCookies("live", "cf_clearance=clearance")}
	seed, err := flow.convertDeviceFlow(context.Background(), fakeCredential())
	if err != nil {
		t.Fatal(err)
	}
	if seed.AccessToken != "access" || seed.RefreshToken != "refresh" || len(client.requests) != 5 {
		t.Fatalf("seed=%#v requests=%d", seed, len(client.requests))
	}
	hosts := []string{"auth.x.ai", "auth.x.ai", "accounts.x.ai", "auth.x.ai", "auth.x.ai"}
	for index, request := range client.requests {
		if request.URL.Hostname() != hosts[index] {
			t.Fatalf("device flow visited unexpected host %q", request.URL.Hostname())
		}
	}
	if client.requests[3].URL.RawQuery != "" {
		t.Fatalf("approve must post a form body, got query %q", client.requests[3].URL.RawQuery)
	}
	approve := client.requests[3]
	if approve.Method != http.MethodPost {
		t.Fatalf("approve method = %q, want POST", approve.Method)
	}
	wantHeaders := map[string]string{
		"Origin":                    "https://accounts.x.ai",
		"Referer":                   "https://accounts.x.ai/oauth2/device/consent",
		"Sec-Fetch-Dest":            "document",
		"Sec-Fetch-Mode":            "navigate",
		"Sec-Fetch-Site":            "same-site",
		"Sec-Fetch-User":            "?1",
		"Upgrade-Insecure-Requests": "1",
	}
	for name, want := range wantHeaders {
		if got := approve.Header.Get(name); got != want {
			t.Errorf("approve %s = %q, want %q", name, got, want)
		}
	}
	consentCookie := client.requests[2].Header.Get("Cookie")
	if !strings.Contains(consentCookie, "sso=live") || !strings.Contains(consentCookie, "cf_clearance=clearance") {
		t.Fatalf("consent request cookies = %q", consentCookie)
	}
	if client.requests[2].Header.Get("Sec-Fetch-Mode") != "navigate" || client.requests[2].Header.Get("Sec-Fetch-Dest") != "document" {
		t.Fatalf("consent request is missing navigation headers: %#v", client.requests[2].Header)
	}
	body, err := io.ReadAll(client.requests[3].Body)
	if err != nil {
		t.Fatal(err)
	}
	approveForm, err := url.ParseQuery(string(body))
	if err != nil {
		t.Fatal(err)
	}
	if approveForm.Get("consent_token") != "eyJhbGciOiJFUzI1NiJ9.eyJkYyI6ImRjIn0.sig" {
		t.Fatalf("approve form missing consent_token: %q", approveForm.Get("consent_token"))
	}
}

func TestSSOBuildFlowVerifyDoesNotFollowRedirect(t *testing.T) {
	client := &scriptedSSOClient{responses: []*http.Response{
		{StatusCode: http.StatusSeeOther, Header: http.Header{"Location": []string{"https://accounts.x.ai/oauth2/device/consent"}}, Body: io.NopCloser(strings.NewReader("verify response"))},
	}}
	flow := &ssoBuildFlow{client: client, userAgent: "lease-agent", cookies: map[string]string{"sso": "live"}}
	status, finalURL, body, err := flow.doWithFollow(context.Background(), http.MethodPost, ssoVerifyURL, url.Values{"user_code": {"uc"}}, false)
	if err != nil {
		t.Fatal(err)
	}
	if status != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", status)
	}
	if finalURL != "https://accounts.x.ai/oauth2/device/consent" {
		t.Fatalf("finalURL = %q", finalURL)
	}
	if len(client.requests) != 1 {
		t.Fatalf("redirect must not be followed, requests = %d", len(client.requests))
	}
	if string(body) != "verify response" {
		t.Fatalf("redirect response body = %q", body)
	}
}

func TestSSODeviceRedirectStateRequiresExactTrustedPath(t *testing.T) {
	tests := map[string]string{
		"https://accounts.x.ai/oauth2/device/consent":           "consent",
		"https://accounts.x.ai/oauth2/device/done/":             "done",
		"https://accounts.x.ai/sign-in?returnTo=%2Foauth2":      "sign-in",
		"https://accounts.x.ai/other?next=consent":              "",
		"https://accounts.x.ai/oauth2/device/consent-untrusted": "",
		"https://example.com/oauth2/device/consent":             "",
	}
	for raw, wanted := range tests {
		if actual := ssoDeviceRedirectState(raw); actual != wanted {
			t.Fatalf("ssoDeviceRedirectState(%q)=%q want=%q", raw, actual, wanted)
		}
	}
}

func fakeCredential() accountdomain.Credential { return accountdomain.Credential{} }

func TestExtractConsentToken(t *testing.T) {
	form := []byte(`<input value="eyJhbGciOiJFUzI1NiJ9.a.b" type="hidden" name="consent_token">`)
	if token := extractConsentToken(form); token != "eyJhbGciOiJFUzI1NiJ9.a.b" {
		t.Fatalf("form token = %q", token)
	}
	jsonPayload := []byte(`{"consentToken":"eyJhbGciOiJFUzI1NiJ9.c.d","other":1}`)
	if token := extractConsentToken(jsonPayload); token != "eyJhbGciOiJFUzI1NiJ9.c.d" {
		t.Fatalf("json token = %q", token)
	}
	rscPayload := []byte(`{\"consentToken\":\"eyJhbGciOiJFUzI1NiJ9.e.f\"}`)
	if token := extractConsentToken(rscPayload); token != "eyJhbGciOiJFUzI1NiJ9.e.f" {
		t.Fatalf("escaped RSC token = %q", token)
	}
	if token := extractConsentToken([]byte("<html>nothing</html>")); token != "" {
		t.Fatalf("unexpected token = %q", token)
	}
}

func TestConsentTokenMustMatchDeviceCode(t *testing.T) {
	token := "eyJhbGciOiJFUzI1NiJ9.eyJkYyI6ImRjIn0.sig"
	if !consentTokenMatchesDevice(token, "dc") {
		t.Fatal("consent token for current device code was rejected")
	}
	if consentTokenMatchesDevice(token, "other-device") {
		t.Fatal("consent token for a different device code was accepted")
	}
	if consentTokenMatchesDevice("not-a-jwt", "dc") {
		t.Fatal("malformed consent token was accepted")
	}
}

func TestSSOBuildCookiesCarrySanitizedCloudflareClearance(t *testing.T) {
	cookies := ssoBuildCookies("sso-token", "cf_clearance=clearance; __cf_bm=bm; sso=attacker")
	if cookies["sso"] != "sso-token" || cookies["sso-rw"] != "sso-token" {
		t.Fatalf("SSO cookies = %#v", cookies)
	}
	if cookies["cf_clearance"] != "clearance" || cookies["__cf_bm"] != "bm" {
		t.Fatalf("Cloudflare cookies = %#v", cookies)
	}
}

func TestSSOBuildConversionSanitizesTokenAndURLs(t *testing.T) {
	if token := normalizeSSOToken("sso=token-value; x-userid=drop"); token != "token-value" {
		t.Fatalf("token = %q", token)
	}
	for _, value := range []string{"https://accounts.x.ai/", "https://auth.x.ai/oauth2/device/code"} {
		if !safeXAIURL(value) {
			t.Fatalf("trusted URL rejected: %s", value)
		}
	}
	for _, value := range []string{"http://auth.x.ai/", "https://x.ai.example.com/", "https://user@auth.x.ai/"} {
		if safeXAIURL(value) {
			t.Fatalf("unsafe URL accepted: %s", value)
		}
	}
}

// TestConsentTokenBoundByUserCode mirrors the live consent page (2026-10-20):
// self-closing hidden inputs and a dc claim that is a server-side UUID.
func TestConsentTokenBoundByUserCode(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"consent+jwt","alg":"ES256","kid":"k"}`))
	exp := time.Now().Add(5 * time.Minute).Unix()
	claims := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"dc":"0b7c6f0e-1111-4222-8333-444455556666","aud":"consent","exp":%d}`, exp)))
	token := header + "." + claims + ".sig"
	page := []byte(`<form><input type="hidden" name="user_code" value="5C3A-S5Y7"/><input type="hidden" name="principal_type" value="User"/><input type="hidden" name="consent_token" value="` + token + `"/></form>`)
	if got := extractConsentToken(page); got != token {
		t.Fatalf("self-closing consent_token = %q", got)
	}
	pageUserCode := extractConsentInput(page, "user_code")
	if !consentTokenMatchesUserCode(token, pageUserCode, "5C3A-S5Y7", time.Now()) {
		t.Fatal("consent token bound to our user_code was rejected")
	}
	if consentTokenMatchesUserCode(token, pageUserCode, "ZZZZ-ZZZZ", time.Now()) {
		t.Fatal("consent page for another user_code was accepted")
	}
	if consentTokenMatchesUserCode(token, pageUserCode, "5C3A-S5Y7", time.Now().Add(time.Hour)) {
		t.Fatal("expired consent token was accepted")
	}
	plain := base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"JWT","alg":"ES256"}`)) + "." + claims + ".sig"
	if consentTokenMatchesUserCode(plain, pageUserCode, "5C3A-S5Y7", time.Now()) {
		t.Fatal("non-consent JWT was accepted")
	}
}

func TestBrowserVerificationRequiredBody(t *testing.T) {
	live := []byte(`<h1>Request could not be verified</h1><p>We could not verify this browser. Allow scripts and turn off ad or tracker blockers for this site, then enter the code again.</p>`)
	if !isBrowserVerificationRequired(live) {
		t.Fatal("live Castle rejection not recognized")
	}
	if isBrowserVerificationRequired([]byte(`{"error":"access_denied"}`)) {
		t.Fatal("ordinary 403 misclassified as browser verification")
	}
}

func pkceConsentHTML(state string) string {
	return `<form method="post" action="https://auth.x.ai/oauth2/authorize">` +
		`<input type="hidden" name="client_id" value="` + ssoBuildClientID + `"/>` +
		`<input type="hidden" name="redirect_uri" value="` + ssoBuildRedirectURI + `"/>` +
		`<input type="hidden" name="response_type" value="code"/>` +
		`<input type="hidden" name="state" value="` + state + `"/>` +
		`<input type="text" name="q" value="decoy-search-box"/>` +
		`</form>`
}

func pkceIDToken() string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claims := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"user-1","email":"u@example.com"}`))
	return header + "." + claims + ".sig"
}

func TestSSOBuildPKCEConvertsEndToEnd(t *testing.T) {
	client := &dynamicSSOClient{}
	client.respond = func(request *http.Request) *http.Response {
		state := client.requests[0].URL.Query().Get("state")
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/oauth2/authorize":
			return redirectResponse(http.StatusSeeOther, "https://accounts.x.ai/oauth2/consent?response_type=code&state="+url.QueryEscape(state))
		case request.URL.Hostname() == "accounts.x.ai":
			return htmlResponse(pkceConsentHTML(request.URL.Query().Get("state")))
		case request.Method == http.MethodPost && request.URL.Path == "/oauth2/authorize":
			return redirectResponse(http.StatusFound, "http://127.0.0.1:56121/callback?code=pkce-code&state="+url.QueryEscape(state))
		default:
			return htmlResponse(`{"access_token":"pkce-access","refresh_token":"pkce-refresh","id_token":"` + pkceIDToken() + `","expires_in":3600}`)
		}
	}
	flow := &ssoBuildFlow{client: client, userAgent: "lease-agent", cookies: ssoBuildCookies("live", "cf_clearance=clearance")}
	seed, err := flow.convert(context.Background(), fakeCredential())
	if err != nil {
		t.Fatal(err)
	}
	if seed.AccessToken != "pkce-access" || seed.RefreshToken != "pkce-refresh" {
		t.Fatalf("seed = %#v", seed)
	}
	if seed.Provider != accountdomain.ProviderBuild || seed.AuthType != accountdomain.AuthTypeOAuth {
		t.Fatalf("seed provider/auth = %v/%v", seed.Provider, seed.AuthType)
	}
	if seed.Email != "u@example.com" || seed.UserID != "user-1" {
		t.Fatalf("seed identity = %q/%q", seed.Email, seed.UserID)
	}

	hosts := []string{"auth.x.ai", "accounts.x.ai", "auth.x.ai", "auth.x.ai"}
	if len(client.requests) != len(hosts) {
		t.Fatalf("requests = %d, want %d", len(client.requests), len(hosts))
	}
	for index, host := range hosts {
		if client.requests[index].URL.Hostname() != host {
			t.Fatalf("request %d visited %q, want %q (loopback must never be requested)", index, client.requests[index].URL.Hostname(), host)
		}
	}

	authorizeQuery := client.requests[0].URL.Query()
	if authorizeQuery.Get("response_type") != "code" || authorizeQuery.Get("client_id") != ssoBuildClientID {
		t.Fatalf("authorize query = %#v", authorizeQuery)
	}
	if authorizeQuery.Get("redirect_uri") != ssoBuildRedirectURI || authorizeQuery.Get("scope") != ssoBuildPKCEScope {
		t.Fatalf("authorize query = %#v", authorizeQuery)
	}
	if authorizeQuery.Get("code_challenge_method") != "S256" {
		t.Fatalf("authorize query = %#v", authorizeQuery)
	}

	consent := client.requests[1]
	if consent.Header.Get("Sec-Fetch-Mode") != "navigate" || consent.Header.Get("Sec-Fetch-Dest") != "document" {
		t.Fatalf("consent GET is missing navigation headers: %#v", consent.Header)
	}
	cookie := consent.Header.Get("Cookie")
	if !strings.Contains(cookie, "sso=live") || !strings.Contains(cookie, "sso-rw=live") || !strings.Contains(cookie, "cf_clearance=clearance") {
		t.Fatalf("consent cookies = %q", cookie)
	}

	submit := client.requests[2]
	wantHeaders := map[string]string{
		"Origin":                    "https://accounts.x.ai",
		"Referer":                   "https://accounts.x.ai/oauth2/consent",
		"Sec-Fetch-Dest":            "document",
		"Sec-Fetch-Mode":            "navigate",
		"Sec-Fetch-Site":            "same-origin",
		"Sec-Fetch-User":            "?1",
		"Upgrade-Insecure-Requests": "1",
	}
	for name, want := range wantHeaders {
		if got := submit.Header.Get(name); got != want {
			t.Errorf("submit %s = %q, want %q", name, got, want)
		}
	}
	submitBody, err := io.ReadAll(submit.Body)
	if err != nil {
		t.Fatal(err)
	}
	submitForm, err := url.ParseQuery(string(submitBody))
	if err != nil {
		t.Fatal(err)
	}
	if submitForm.Get("action") != "allow" || submitForm.Get("client_id") != ssoBuildClientID {
		t.Fatalf("submit form = %#v", submitForm)
	}
	if submitForm.Get("state") != authorizeQuery.Get("state") {
		t.Fatalf("submit form must echo consent page state: %#v", submitForm)
	}
	if submitForm.Has("q") {
		t.Fatalf("non-hidden inputs must not be submitted: %#v", submitForm)
	}

	exchange := client.requests[3]
	if exchange.Header.Get("x-grok-client-version") != config.RecommendedBuildClientVersion || exchange.Header.Get("x-grok-client-surface") != "web" {
		t.Fatalf("token exchange headers = %#v", exchange.Header)
	}
	exchangeBody, err := io.ReadAll(exchange.Body)
	if err != nil {
		t.Fatal(err)
	}
	exchangeForm, err := url.ParseQuery(string(exchangeBody))
	if err != nil {
		t.Fatal(err)
	}
	if exchangeForm.Get("grant_type") != "authorization_code" || exchangeForm.Get("code") != "pkce-code" || exchangeForm.Get("redirect_uri") != ssoBuildRedirectURI {
		t.Fatalf("exchange form = %#v", exchangeForm)
	}
	challenge := sha256.Sum256([]byte(exchangeForm.Get("code_verifier")))
	if authorizeQuery.Get("code_challenge") != base64.RawURLEncoding.EncodeToString(challenge[:]) {
		t.Fatalf("code_challenge does not match S256(code_verifier)")
	}
}

func TestSSOBuildPKCEMapsSignInToUnauthorizedWithoutFallback(t *testing.T) {
	client := &scriptedSSOClient{responses: []*http.Response{
		redirectResponse(http.StatusSeeOther, "https://accounts.x.ai/sign-in"),
		htmlResponse("<html>sign in</html>"),
	}}
	flow := &ssoBuildFlow{client: client, userAgent: "lease-agent", cookies: map[string]string{"sso": "dead"}}
	_, err := flow.convert(context.Background(), fakeCredential())
	if !errors.Is(err, provider.ErrUnauthorized) {
		t.Fatalf("err = %v, want ErrUnauthorized", err)
	}
	if len(client.requests) != 2 {
		t.Fatalf("requests = %d, want 2 (dead SSO must not trigger device fallback)", len(client.requests))
	}
}

func TestSSOBuildPKCERetriesNavigationHeadersOn403(t *testing.T) {
	posts := 0
	client := &dynamicSSOClient{}
	client.respond = func(request *http.Request) *http.Response {
		state := client.requests[0].URL.Query().Get("state")
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/oauth2/authorize":
			return redirectResponse(http.StatusSeeOther, "https://accounts.x.ai/oauth2/consent?state="+url.QueryEscape(state))
		case request.URL.Hostname() == "accounts.x.ai":
			return htmlResponse(pkceConsentHTML(request.URL.Query().Get("state")))
		case request.Method == http.MethodPost && request.URL.Path == "/oauth2/authorize":
			posts++
			if posts == 1 {
				return statusResponse(http.StatusForbidden, "<html>We could not verify this browser</html>")
			}
			return redirectResponse(http.StatusFound, "http://127.0.0.1:56121/callback?code=pkce-code&state="+url.QueryEscape(state))
		default:
			return htmlResponse(`{"access_token":"pkce-access","expires_in":3600}`)
		}
	}
	flow := &ssoBuildFlow{client: client, userAgent: "lease-agent", cookies: map[string]string{"sso": "live"}}
	seed, err := flow.convert(context.Background(), fakeCredential())
	if err != nil {
		t.Fatal(err)
	}
	if seed.AccessToken != "pkce-access" || posts != 2 {
		t.Fatalf("seed = %#v posts = %d", seed, posts)
	}
	var tierUserAgents []string
	var tierCacheControls []string
	for _, request := range client.requests {
		if request.Method == http.MethodPost && request.URL.Path == "/oauth2/authorize" {
			tierUserAgents = append(tierUserAgents, request.Header.Get("User-Agent"))
			tierCacheControls = append(tierCacheControls, request.Header.Get("Cache-Control"))
		}
	}
	if len(tierCacheControls) != 2 || tierCacheControls[0] != "" || tierCacheControls[1] != "max-age=0" {
		t.Fatalf("navigation header tiers = %q", tierCacheControls)
	}
	if tierUserAgents[0] != "lease-agent" || tierUserAgents[1] != "lease-agent" {
		t.Fatalf("tier user agents = %q", tierUserAgents)
	}
}

func TestSSOBuildPKCEStateMismatchFails(t *testing.T) {
	client := &dynamicSSOClient{}
	client.respond = func(request *http.Request) *http.Response {
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/oauth2/authorize":
			return redirectResponse(http.StatusSeeOther, "https://accounts.x.ai/oauth2/consent")
		case request.URL.Hostname() == "accounts.x.ai":
			return htmlResponse(pkceConsentHTML(""))
		case request.Method == http.MethodPost && request.URL.Path == "/oauth2/authorize":
			return redirectResponse(http.StatusFound, "http://127.0.0.1:56121/callback?code=pkce-code&state=tampered")
		default:
			t.Fatal("token exchange must not run after state mismatch")
			return nil
		}
	}
	flow := &ssoBuildFlow{client: client, userAgent: "lease-agent", cookies: map[string]string{"sso": "live"}}
	if _, err := flow.convertPKCE(context.Background(), fakeCredential()); err == nil || !strings.Contains(err.Error(), "state") {
		t.Fatalf("err = %v, want state mismatch failure", err)
	}
}

func TestSSOBuildPKCEMissingConsentFormFails(t *testing.T) {
	client := &scriptedSSOClient{responses: []*http.Response{
		redirectResponse(http.StatusSeeOther, "https://accounts.x.ai/oauth2/consent"),
		htmlResponse(`<form><input type="text" name="q" value="search"/></form>`),
	}}
	flow := &ssoBuildFlow{client: client, userAgent: "lease-agent", cookies: map[string]string{"sso": "live"}}
	_, err := flow.convertPKCE(context.Background(), fakeCredential())
	if err == nil || !strings.Contains(err.Error(), "同意页表单") {
		t.Fatalf("err = %v, want missing consent form failure", err)
	}
}

func TestSSOBuildConvertFallsBackToDeviceFlow(t *testing.T) {
	client := &scriptedSSOClient{responses: []*http.Response{
		statusResponse(http.StatusInternalServerError, "pkce upstream down"),
		{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(
			`{"device_code":"dc","user_code":"uc","interval":1,"expires_in":1800}`))},
		redirectResponse(http.StatusSeeOther, "https://accounts.x.ai/oauth2/device/consent"),
		htmlResponse(`<form method="post"><input value="eyJhbGciOiJFUzI1NiJ9.eyJkYyI6ImRjIn0.sig" type="hidden" name="consent_token"></form>`),
		redirectResponse(http.StatusSeeOther, "https://accounts.x.ai/oauth2/device/done"),
		htmlResponse(`{"access_token":"device-access","refresh_token":"device-refresh","expires_in":3600}`),
	}}
	flow := &ssoBuildFlow{client: client, userAgent: "lease-agent", cookies: ssoBuildCookies("live", "")}
	seed, err := flow.convert(context.Background(), fakeCredential())
	if err != nil {
		t.Fatal(err)
	}
	if seed.AccessToken != "device-access" || seed.RefreshToken != "device-refresh" {
		t.Fatalf("seed = %#v", seed)
	}
	if len(client.requests) != 6 {
		t.Fatalf("requests = %d, want 6 (pkce failure + full device flow)", len(client.requests))
	}
}
