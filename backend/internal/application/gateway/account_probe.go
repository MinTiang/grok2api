package gateway

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/chenyme/grok2api/backend/internal/domain/audit"
	infraegress "github.com/chenyme/grok2api/backend/internal/infra/egress"
	"github.com/chenyme/grok2api/backend/internal/infra/security"
)

// Account probe verdicts. They mirror the short-stream classifier used by
// external registration tooling: the only hard signal is whether the upstream
// actually streamed reasoning content.
const (
	AccountProbeHealthy = "healthy"
	AccountProbeHard    = "hard"
	AccountProbeRisk    = "risk"
	AccountProbeError   = "error"
)

// accountProbeMaxStreamBytes bounds the streamed reply. The probe stops as soon
// as reasoning appears, so this is only a safety net against a runaway upstream.
const accountProbeMaxStreamBytes = 1 << 20

// AccountProbeInput describes one manual or scheduled account quality probe.
type AccountProbeInput struct {
	AccountID uint64
	// ClientKeyID funds the probe request. It mirrors the egress quality probe
	// contract: the operator picks a key, and its billing/rate limits apply.
	ClientKeyID     uint64
	Model           string
	Prompt          string
	MaxOutputTokens int
	// EarlyStopOnThinking stops reading as soon as reasoning content arrives.
	// This is what keeps the probe cheap: a healthy account costs a handful of
	// reasoning tokens, and a degraded account is cut off at the reply cap.
	EarlyStopOnThinking bool
	// EarlyStopDelayMS delays the early stop after reasoning is first observed so
	// that partially streamed reasoning is not mistaken for a complete thought.
	EarlyStopDelayMS int
}

// AccountProbeResult reports one account probe outcome.
type AccountProbeResult struct {
	AccountID       uint64    `json:"accountId"`
	AccountName     string    `json:"accountName"`
	Email           string    `json:"email"`
	Verdict         string    `json:"verdict"`
	Reason          string    `json:"reason"`
	StatusCode      int       `json:"statusCode"`
	HasThinking     bool      `json:"hasThinking"`
	ReasoningBytes  int       `json:"reasoningBytes"`
	OutputTokens    int64     `json:"outputTokens"`
	ReasoningTokens int64     `json:"reasoningTokens"`
	VisibleChars    int       `json:"visibleChars"`
	FirstTokenMS    int64     `json:"firstTokenMs"`
	DurationMS      int64     `json:"durationMs"`
	GenerationMS    int64     `json:"generationMs"`
	OutputTPS       float64   `json:"outputTps"`
	EgressNodeID    uint64    `json:"egressNodeId"`
	EgressNodeName  string    `json:"egressNodeName"`
	EarlyStop       bool      `json:"earlyStop"`
	Model           string    `json:"model"`
	Error           string    `json:"error,omitempty"`
	ProbedAt        time.Time `json:"probedAt"`
}

// ProbeAccount runs one short streamed chat against a single pinned account.
//
// The probe deliberately reuses the normal inference path so the account is
// reached through the very egress it is bound to: an explicitly bound account
// must never be silently probed through another proxy, because a mismatched
// exit IP is itself a risk signal and would make the verdict meaningless.
func (s *Service) ProbeAccount(ctx context.Context, input AccountProbeInput) (AccountProbeResult, error) {
	if input.AccountID == 0 {
		return AccountProbeResult{}, errors.New("账号 ID 无效")
	}
	view, err := s.accounts.Get(ctx, input.AccountID)
	if err != nil {
		return AccountProbeResult{}, fmt.Errorf("读取待测账号: %w", err)
	}
	credential := view.Credential
	result := AccountProbeResult{
		AccountID:    credential.ID,
		AccountName:  credential.Name,
		Email:        credential.Email,
		EgressNodeID: credential.EgressNodeID,
		Model:        input.Model,
		ProbedAt:     time.Now().UTC(),
	}
	if !credential.Enabled {
		result.Verdict = AccountProbeError
		result.Reason = "account_disabled"
		result.Error = "账号已禁用，跳过短测"
		return result, nil
	}

	prompt := strings.TrimSpace(input.Prompt)
	if prompt == "" {
		prompt = defaultAccountProbePrompt
	}
	maxOutput := input.MaxOutputTokens
	if maxOutput <= 0 {
		maxOutput = defaultAccountProbeMaxOutputTokens
	}

	body, err := json.Marshal(map[string]any{
		"model":          input.Model,
		"messages":       []map[string]string{{"role": "user", "content": prompt}},
		"stream":         true,
		"stream_options": map[string]bool{"include_usage": true},
		"max_tokens":     maxOutput,
	})
	if err != nil {
		return result, err
	}

	key, err := s.clientKeys.Get(ctx, input.ClientKeyID)
	if err != nil {
		return result, fmt.Errorf("读取短测 Client Key: %w", err)
	}
	if !key.IsAvailable(time.Now().UTC()) {
		return result, errors.New("短测 Client Key 已禁用或过期")
	}
	publicModel, ok := qualityProbeBuildPublicModel(input.Model)
	if !ok {
		return result, fmt.Errorf("短测模型必须属于 Grok Build: %s", input.Model)
	}
	requestIDPart, err := security.NewOpaqueToken(12)
	if err != nil {
		return result, err
	}

	// WithQualityProbe does two things here, and both are intended.
	//
	// It keeps ambiguous egress failures out of credential health, so a flaky
	// proxy cannot mark a healthy account as broken just because it was probed.
	// It also lets the account's own bound node be used even while that node is
	// cooling or disabled — the alternative would be falling back to a different
	// proxy, which would observe a different exit IP than real traffic and make
	// the verdict meaningless. A genuinely broken node surfaces as an error
	// verdict, which never penalizes the account.
	probeCtx := infraegress.WithQualityProbe(ctx)
	startedAt := time.Now()
	answer, err := s.CreateChatCompletion(probeCtx, Input{
		RequestID: "probe_" + requestIDPart, ClientKey: key, PublicModel: publicModel, Body: body,
		Streaming: true, Operation: audit.OperationChat, ForcedAccountID: input.AccountID,
		accountProbe: true,
	})
	if err != nil {
		result.Verdict = AccountProbeError
		result.Reason = "request_failed"
		// A missing route is a configuration mistake, not an account problem, so
		// the message names the model and says where to fix it. The bare gateway
		// error would leave the operator guessing which model to configure.
		if errors.Is(err, ErrModelNotFound) {
			result.Error = fmt.Sprintf("模型 %q 没有可用的 Build 路由，请在模型页确认该模型的 provider 为 grok_build 且已启用，或在短测设置里改用已有的 Build 模型", input.Model)
		} else {
			result.Error = err.Error()
		}
		result.DurationMS = time.Since(startedAt).Milliseconds()
		return result, nil
	}
	defer answer.Body.Close()

	usage := Usage{}
	responseID := ""
	errorCode := ""
	defer func() { answer.Finalize(usage, responseID, errorCode) }()
	if answer.StatusCode < http.StatusOK || answer.StatusCode >= http.StatusMultipleChoices {
		result.StatusCode = answer.StatusCode
		detail, _ := io.ReadAll(io.LimitReader(answer.Body, 8<<10))
		errorCode = "account_probe_upstream_error"
		result.Verdict = classifyAccountProbeFailure(answer.StatusCode, string(detail))
		result.Reason = probeReasonForStatus(result.Verdict, answer.StatusCode)
		result.Error = strings.TrimSpace(string(detail))
		result.DurationMS = time.Since(startedAt).Milliseconds()
		return result, nil
	}
	result.StatusCode = answer.StatusCode

	var firstGeneratedAt time.Time
	var firstReasoningAt time.Time
	var visible strings.Builder
	reasoningBytes := 0
	totalBytes := 0
	earlyStop := false
	earlyStopDelay := time.Duration(input.EarlyStopDelayMS) * time.Millisecond
	if earlyStopDelay <= 0 {
		earlyStopDelay = defaultAccountProbeEarlyStopDelay
	}

	scanner := bufio.NewScanner(answer.Body)
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	for scanner.Scan() {
		line := scanner.Bytes()
		totalBytes += len(line) + 1
		if totalBytes > accountProbeMaxStreamBytes {
			errorCode = "account_probe_response_too_large"
			break
		}
		trimmed := strings.TrimSpace(string(line))
		if trimmed == ": grok2api-reasoning-start" {
			if firstGeneratedAt.IsZero() {
				firstGeneratedAt = time.Now()
				if answer.MarkFirstToken != nil {
					answer.MarkFirstToken()
				}
			}
			continue
		}
		if !strings.HasPrefix(trimmed, "data:") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(trimmed, "data:"))
		if payload == "[DONE]" {
			break
		}
		var event qualityProbeChatEvent
		if json.Unmarshal([]byte(payload), &event) != nil {
			continue
		}
		if responseID == "" {
			responseID = event.ID
		}
		if event.Usage != nil {
			usage.Reported = true
			usage.InputTokens = event.Usage.PromptTokens
			usage.OutputTokens = event.Usage.CompletionTokens
			usage.ReasoningTokens = event.Usage.CompletionTokensDetails.ReasoningTokens
			usage.TotalTokens = event.Usage.TotalTokens
			usage.ResponseModel = event.Model
		}
		for _, choice := range event.Choices {
			delta := choice.Delta
			if delta.Content != "" {
				visible.WriteString(delta.Content)
			}
			reasoning := delta.Reasoning + delta.ReasoningContent + delta.ThinkingContent
			if reasoning != "" {
				reasoningBytes += len(reasoning)
				if firstReasoningAt.IsZero() {
					firstReasoningAt = time.Now()
				}
			}
			if qualityProbeHasGeneratedDelta(delta.Content, delta.Reasoning, delta.ReasoningContent, delta.ThinkingContent) && firstGeneratedAt.IsZero() {
				firstGeneratedAt = time.Now()
				if answer.MarkFirstToken != nil {
					answer.MarkFirstToken()
				}
			}
		}
		// Stop as soon as reasoning is proven present. The remaining reply is
		// pure cost: the verdict is already decided.
		if input.EarlyStopOnThinking && !firstReasoningAt.IsZero() && time.Since(firstReasoningAt) >= earlyStopDelay {
			earlyStop = true
			break
		}
	}

	completedAt := time.Now()
	// Only streamed reasoning deltas prove thinking. usage.reasoning_tokens is
	// recorded for diagnostics but never promotes a verdict on its own.
	result.HasThinking = reasoningBytes > 0
	result.ReasoningBytes = reasoningBytes
	result.OutputTokens = usage.OutputTokens
	result.ReasoningTokens = usage.ReasoningTokens
	result.VisibleChars = len(visible.String())
	result.EarlyStop = earlyStop
	if !firstGeneratedAt.IsZero() {
		result.FirstTokenMS = firstGeneratedAt.Sub(startedAt).Milliseconds()
	}
	result.DurationMS = completedAt.Sub(startedAt).Milliseconds()
	if !firstGeneratedAt.IsZero() {
		result.GenerationMS = audit.GenerationWindowMS(result.FirstTokenMS, result.DurationMS, usage.ReasoningTokens)
		if result.GenerationMS < 1 {
			result.GenerationMS = 1
		}
		result.OutputTPS = qualityProbeOutputTokensPerSecond(usage.OutputTokens, usage.ReasoningTokens, result.DurationMS, result.FirstTokenMS)
	}

	result.Verdict, result.Reason = classifyAccountProbeResult(result)
	return result, nil
}

// classifyAccountProbeResult decides the verdict from thinking presence only.
//
// Usage.reasoning_tokens is not proof of thinking: degraded accounts report
// hundreds of reasoning tokens while the stream never carries reasoning deltas.
// The encrypted/payload thinking bytes are the only trustworthy evidence, so TPS
// is recorded for diagnostics and never decides the verdict.
func classifyAccountProbeResult(result AccountProbeResult) (string, string) {
	if result.HasThinking {
		return AccountProbeHealthy, "thinking_present"
	}
	if result.VisibleChars == 0 && result.OutputTokens == 0 {
		return AccountProbeError, "empty_reply"
	}
	return AccountProbeHard, "thinking_missing"
}

func classifyAccountProbeFailure(status int, body string) string {
	switch {
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return AccountProbeRisk
	case status == http.StatusTooManyRequests:
		return AccountProbeRisk
	}
	lower := strings.ToLower(body)
	for _, marker := range accountProbeRiskMarkers {
		if strings.Contains(lower, marker) {
			return AccountProbeRisk
		}
	}
	if status >= 500 {
		return AccountProbeError
	}
	return AccountProbeError
}

func probeReasonForStatus(verdict string, status int) string {
	if verdict == AccountProbeRisk {
		return fmt.Sprintf("upstream_%d", status)
	}
	return fmt.Sprintf("upstream_%d", status)
}

var accountProbeRiskMarkers = []string{
	"permission-denied",
	"permission denied",
	"forbidden",
	"unauthorized",
	"invalid token",
	"token expired",
	"no auth",
	"account suspended",
	"account banned",
}

const (
	defaultAccountProbePrompt          = "Think step by step. A clock shows 3:27. What is the smaller angle in degrees between the hour and minute hands, rounded to the nearest integer? Reply with only that integer on the first line and QUALITY_OK on the last line."
	defaultAccountProbeMaxOutputTokens = 48
	defaultAccountProbeEarlyStopDelay  = 800 * time.Millisecond
)

// IsAccountProbePenalizable reports whether a verdict should cool the account.
// Transport and upstream failures are infrastructure noise and never penalize
// the account; only a completed reply that carries no reasoning does.
func IsAccountProbePenalizable(verdict string) bool {
	return verdict == AccountProbeHard
}
