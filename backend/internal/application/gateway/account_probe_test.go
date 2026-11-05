package gateway

import (
	"bufio"
	"strings"
	"testing"
)

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

// TestParseReasoningEvidenceComment covers the marker that actually decides the
// verdict. Chat deltas never carry reasoning on Build: the converter emits an
// empty start stub plus this byte count, so missing it makes every account look
// degraded.
func TestParseReasoningEvidenceComment(t *testing.T) {
	cases := []struct {
		line   string
		want   int
		wantOK bool
	}{
		{": grok2api-reasoning-evidence 512", 512, true},
		{": grok2api-reasoning-evidence   4096  ", 4096, true},
		{": grok2api-reasoning-start", 0, false},
		{": grok2api-reasoning-evidence", 0, false},
		{": grok2api-reasoning-evidence 0", 0, false},
		{": grok2api-reasoning-evidence abc", 0, false},
		{"data: {\"id\":\"x\"}", 0, false},
	}
	for _, testCase := range cases {
		got, ok := parseReasoningEvidenceComment(testCase.line)
		if ok != testCase.wantOK || got != testCase.want {
			t.Fatalf("parseReasoningEvidenceComment(%q) = (%d, %v), want (%d, %v)", testCase.line, got, ok, testCase.want, testCase.wantOK)
		}
	}
}

// TestProbeStreamMarkersDecideVerdict pins the distinction the probe relies on:
// the start stub alone is not proof of thinking (a degraded build still emits it),
// while an evidence line is. Chat deltas carry no reasoning on Build, so reading
// only delta.reasoning reported every account as degraded.
func TestProbeStreamMarkersDecideVerdict(t *testing.T) {
	healthyStream := strings.Join([]string{
		": grok2api-reasoning-start",
		"",
		": grok2api-reasoning-evidence 512",
		"",
		`data: {"id":"resp_1","choices":[{"delta":{"content":"63"}}]}`,
		"",
		"data: [DONE]",
		"",
	}, "\n")
	degradedStream := strings.Join([]string{
		": grok2api-reasoning-start",
		"",
		`data: {"id":"resp_2","choices":[{"delta":{"content":"63"}}]}`,
		"",
		"data: [DONE]",
		"",
	}, "\n")

	scan := func(stream string) int {
		reasoningBytes := 0
		scanner := bufio.NewScanner(strings.NewReader(stream))
		for scanner.Scan() {
			trimmed := strings.TrimSpace(scanner.Text())
			if reasoningBytes == 0 {
				if evidence, ok := parseReasoningEvidenceComment(trimmed); ok {
					reasoningBytes = evidence
				}
			}
		}
		return reasoningBytes
	}

	if got := scan(healthyStream); got != 512 {
		t.Fatalf("healthy stream reasoning bytes = %d, want 512", got)
	}
	if got := scan(degradedStream); got != 0 {
		t.Fatalf("degraded stream reasoning bytes = %d, want 0 (start stub is not proof)", got)
	}
}

// TestThinkingEvidenceRequiresPlaintextOrFloor pins how the two reasoning traces
// combine. A degraded account can still attach a short encrypted signature, so a
// non-zero encrypted length alone must not count as thinking.
func TestThinkingEvidenceRequiresPlaintextOrFloor(t *testing.T) {
	cases := []struct {
		name           string
		deltaBytes     int
		encryptedBytes int
		wantThinking   bool
	}{
		{"plaintext delta alone is conclusive", 40, 0, true},
		{"large encrypted payload counts", 0, 4096, true},
		{"encrypted at the floor counts", 0, accountProbeMinEncryptedBytes, true},
		{"short encrypted signature does not", 0, 120, false},
		{"start stub with nothing else does not", 0, 0, false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			hasThinking := testCase.deltaBytes > 0 || testCase.encryptedBytes >= accountProbeMinEncryptedBytes
			if hasThinking != testCase.wantThinking {
				t.Fatalf("hasThinking = %v, want %v", hasThinking, testCase.wantThinking)
			}
		})
	}
}
