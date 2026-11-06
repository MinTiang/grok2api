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

// TestThinkingEvidenceScalesWithClaimedReasoning pins the proportional rule.
// A degraded account reports many reasoning tokens while shipping a small
// encrypted stub, so the bar is max(256, reasoningTokens*4); a fixed floor let
// every stub through.
func TestThinkingEvidenceScalesWithClaimedReasoning(t *testing.T) {
	cases := []struct {
		name           string
		deltaBytes     int
		encryptedBytes int
		reasoningToks  int64
		wantThinking   bool
	}{
		{"plaintext delta alone is conclusive", 40, 0, 0, true},
		{"plaintext wins even with a tiny blob", 40, 10, 2000, true},
		{"no trace at all", 0, 0, 500, false},
		{"stub far below its own claim", 0, 1719, 897, false},
		{"stub below scaled floor", 0, 3030, 1743, false},
		{"payload meeting the scaled floor", 0, 8000, 2000, true},
		{"small claim only needs the minimum", 0, 300, 10, true},
		{"payload under the minimum", 0, 120, 0, false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			floor := encryptedThinkingFloor(accountProbeMinEncryptedBytes, accountProbeEncryptedBytesPerToken, testCase.reasoningToks)
			hasThinking := testCase.deltaBytes > 0 || int64(testCase.encryptedBytes) >= floor
			if hasThinking != testCase.wantThinking {
				t.Fatalf("hasThinking = %v, want %v (floor %d, encrypted %d)", hasThinking, testCase.wantThinking, floor, testCase.encryptedBytes)
			}
		})
	}
}

// TestEncryptionFloorCalibration pins the two calibrations that were measured on
// a live fleet. The clock puzzle separates healthy at 4.4-5.0 bytes per claimed
// reasoning token from degraded at 1.6-2.0, so 3.0 sits mid-gap. A short
// arithmetic prompt compresses both bands to 4.9-5.7 and 2.1-2.7, which is why
// the threshold has to travel with the prompt instead of being a constant.
func TestEncryptionFloorCalibration(t *testing.T) {
	cases := []struct {
		name     string
		perToken float64
		tokens   int64
		encBytes int
		want     bool
	}{
		{"clock prompt, healthy 4.5 ratio", 3, 2000, 9000, true},
		{"clock prompt, degraded 1.8 ratio", 3, 2000, 3600, false},
		{"clock prompt, degraded upper 2.0", 3, 2000, 4000, false},
		{"short prompt, healthy 5.0 ratio", 3.8, 300, 1500, true},
		{"short prompt, degraded 2.7 ratio", 3.8, 300, 810, false},
		{"zero tokens needs only the minimum", 3, 0, 260, true},
		{"zero tokens under the minimum", 3, 0, 100, false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			floor := accountProbeEncryptionFloor(testCase.perToken, testCase.tokens)
			got := int64(testCase.encBytes) >= floor
			if got != testCase.want {
				t.Fatalf("floor=%d encBytes=%d => %v, want %v", floor, testCase.encBytes, got, testCase.want)
			}
		})
	}
}

// TestEmptySuccessReplyIsDegraded pins the fix for the accounts that survived
// every sweep. Real traffic showed a 42% rate of 2xx responses carrying no tokens
// at all; classifying those as transport noise meant the worst accounts were the
// only ones never penalized.
func TestEmptySuccessReplyIsDegraded(t *testing.T) {
	cases := []struct {
		name       string
		statusCode int
		want       string
	}{
		{"200 with nothing in it", 200, AccountProbeHard},
		{"206 with nothing in it", 206, AccountProbeHard},
		{"500 with nothing in it", 500, AccountProbeError},
		{"502 with nothing in it", 502, AccountProbeError},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			result := AccountProbeResult{StatusCode: testCase.statusCode, VisibleChars: 0, OutputTokens: 0}
			got, reason := classifyAccountProbeResult(result)
			if got != testCase.want {
				t.Fatalf("verdict = %q (%s), want %q", got, reason, testCase.want)
			}
		})
	}

	// A reply with visible text but no reasoning is still the original case.
	result := AccountProbeResult{StatusCode: 200, VisibleChars: 40, OutputTokens: 48}
	if got, _ := classifyAccountProbeResult(result); got != AccountProbeHard {
		t.Fatalf("prose without reasoning = %q, want %q", got, AccountProbeHard)
	}
}

// TestReasoningStubWithoutAnswerIsDegraded pins the hole that let a badly broken
// account through. A degraded upstream emits a tiny reasoning stub and no answer
// at all; because HasThinking was tested first, that stub produced a healthy
// verdict. One such account had twenty-six empty replies in real traffic and
// passed every sweep.
func TestReasoningStubWithoutAnswerIsDegraded(t *testing.T) {
	stub := AccountProbeResult{
		StatusCode:     200,
		HasThinking:    true,
		ReasoningBytes: 20,
		VisibleChars:   0,
		OutputTokens:   0,
	}
	if got, reason := classifyAccountProbeResult(stub); got != AccountProbeHard || reason != "empty_reply" {
		t.Fatalf("reasoning stub with no answer = %q (%s), want hard/empty_reply", got, reason)
	}

	// Real thinking plus a real answer is still healthy.
	good := AccountProbeResult{
		StatusCode: 200, HasThinking: true, ReasoningBytes: 380, VisibleChars: 3, OutputTokens: 5,
	}
	if got, _ := classifyAccountProbeResult(good); got != AccountProbeHealthy {
		t.Fatalf("thinking with an answer = %q, want healthy", got)
	}

	// Thinking with an answer but no reasoning is still the ratio case.
	noReasoning := AccountProbeResult{StatusCode: 200, VisibleChars: 40, OutputTokens: 48}
	if got, _ := classifyAccountProbeResult(noReasoning); got != AccountProbeHard {
		t.Fatalf("prose without reasoning = %q, want hard", got)
	}
}
