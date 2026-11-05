package gateway

import "testing"

// TestClassifyAccountProbeResult pins the core contract: the verdict comes from
// streamed thinking only. TPS and token counts are diagnostics.
func TestClassifyAccountProbeResult(t *testing.T) {
	cases := []struct {
		name    string
		result  AccountProbeResult
		verdict string
		reason  string
	}{
		{
			name:    "thinking present is healthy even at absurd tps",
			result:  AccountProbeResult{HasThinking: true, ReasoningBytes: 128, VisibleChars: 4, OutputTokens: 64, OutputTPS: 5000},
			verdict: AccountProbeHealthy,
			reason:  "thinking_present",
		},
		{
			name:    "reply without thinking is hard regardless of tps",
			result:  AccountProbeResult{HasThinking: false, VisibleChars: 40, OutputTokens: 48, OutputTPS: 12},
			verdict: AccountProbeHard,
			reason:  "thinking_missing",
		},
		{
			name:    "reported reasoning tokens alone never count as thinking",
			result:  AccountProbeResult{HasThinking: false, ReasoningBytes: 0, ReasoningTokens: 900, VisibleChars: 12, OutputTokens: 40},
			verdict: AccountProbeHard,
			reason:  "thinking_missing",
		},
		{
			name:    "empty reply is an error, not a degraded account",
			result:  AccountProbeResult{HasThinking: false, VisibleChars: 0, OutputTokens: 0},
			verdict: AccountProbeError,
			reason:  "empty_reply",
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			verdict, reason := classifyAccountProbeResult(testCase.result)
			if verdict != testCase.verdict || reason != testCase.reason {
				t.Fatalf("got (%q, %q), want (%q, %q)", verdict, reason, testCase.verdict, testCase.reason)
			}
		})
	}
}

// TestIsAccountProbePenalizable ensures transport noise never cools an account.
func TestIsAccountProbePenalizable(t *testing.T) {
	for _, verdict := range []string{AccountProbeRisk, AccountProbeError, AccountProbeHealthy} {
		if IsAccountProbePenalizable(verdict) {
			t.Fatalf("verdict %q must not penalize the account", verdict)
		}
	}
	if !IsAccountProbePenalizable(AccountProbeHard) {
		t.Fatal("hard verdict must penalize the account")
	}
}

// TestClassifyAccountProbeFailure separates account-level refusal from
// infrastructure failure, because only the former may touch account state.
func TestClassifyAccountProbeFailure(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{name: "401 is account risk", status: 401, want: AccountProbeRisk},
		{name: "403 is account risk", status: 403, want: AccountProbeRisk},
		{name: "429 is account risk", status: 429, want: AccountProbeRisk},
		{name: "permission-denied body is account risk", status: 400, body: `{"error":"permission-denied"}`, want: AccountProbeRisk},
		{name: "502 is transport noise", status: 502, want: AccountProbeError},
		{name: "proxy failure is transport noise", status: 407, want: AccountProbeError},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := classifyAccountProbeFailure(testCase.status, testCase.body); got != testCase.want {
				t.Fatalf("got %q, want %q", got, testCase.want)
			}
		})
	}
}
