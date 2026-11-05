package gateway

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/chenyme/grok2api/backend/internal/domain/audit"
	"github.com/chenyme/grok2api/backend/internal/domain/clientkey"
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

// ErrAccountProbeKeyUnavailable reports that the internal identity funding the
// probe is disabled or expired. Callers re-enable it and retry once, because the
// shared identity's enabled flag is derived from the feature switches at startup
// and enabling the probe later would otherwise leave it switched off.
var ErrAccountProbeKeyUnavailable = errors.New("短测 Client Key 已禁用或过期")

// Account probe modes. They judge different capabilities and never overlap:
// tool mode asks whether the account can actually call a function, thinking mode
// asks whether the reply carried a real reasoning trace.
const (
	AccountProbeModeTool     = "tool"
	AccountProbeModeThinking = "thinking"
)

// AccountProbeInput describes one manual or scheduled account quality probe.
type AccountProbeInput struct {
	AccountID uint64
	// ClientKeyID funds the probe request. It mirrors the egress quality probe
	// contract: the operator picks a key, and its billing/rate limits apply.
	ClientKeyID     uint64
	Model           string
	Prompt          string
	MaxOutputTokens int
	// MinBytesPerToken is the encrypted-reasoning bytes required per claimed
	// reasoning token before a reply counts as having really thought. It is a
	// parameter rather than a constant because the right value depends on the
	// prompt: the clock puzzle separates at 3.0, while a short arithmetic prompt
	// compresses the degraded band up to 2.7 and needs about 4.0. Zero uses the
	// tuned default.
	MinBytesPerToken float64
	// Mode selects the capability under test. Empty means tool mode.
	Mode string
	// EarlyStopOnThinking stops reading as soon as reasoning evidence arrives.
	// It is kept because the wire format allows it, but on Build it never fires:
	// the encrypted-reasoning marker is emitted at the tail of the stream, after
	// the visible reply has already been sent, so every probe runs to completion.
	// Cost has to be controlled through chunk size and interval instead.
	EarlyStopOnThinking bool
	// EarlyStopDelayMS delays the early stop after reasoning is first observed so
	// that partially streamed reasoning is not mistaken for a complete thought.
	EarlyStopDelayMS int
}

// AccountProbeResult reports one account probe outcome.
type AccountProbeResult struct {
	AccountID      uint64 `json:"accountId"`
	AccountName    string `json:"accountName"`
	Email          string `json:"email"`
	Verdict        string `json:"verdict"`
	Reason         string `json:"reason"`
	StatusCode     int    `json:"statusCode"`
	HasThinking    bool   `json:"hasThinking"`
	ReasoningBytes int    `json:"reasoningBytes"`
	// ReasoningDeltaBytes counts plaintext reasoning deltas only, and
	// EncryptedBytes the encrypted-reasoning payload length. They are kept apart
	// because a degraded account can still ship an encrypted blob: the floor on
	// the encrypted side is what separates a real trace from a stub.
	ReasoningDeltaBytes int `json:"reasoningDeltaBytes"`
	EncryptedBytes      int `json:"encryptedBytes"`
	// FirstVisibleMS is when the first visible token arrived. Diagnostics only:
	// measured on real accounts, degraded ones delay their answer just as long as
	// healthy ones, so it cannot decide a verdict.
	FirstVisibleMS int64 `json:"firstVisibleMs"`
	// AnswerExcerpt is the start of the visible answer. The probe prompt has a
	// verifiable answer, so keeping the text lets answer quality be checked
	// against the ratio instead of assuming the ratio means anything on its own.
	AnswerExcerpt string `json:"answerExcerpt,omitempty"`
	// Tool mode outcome. ToolCallOK is the verdict signal: the model either invoked
	// the tool with complete arguments or it did not.
	Mode       string `json:"mode,omitempty"`
	ToolCallOK bool   `json:"toolCallOk"`
	ToolName   string `json:"toolName,omitempty"`
	ToolArgs   string `json:"toolArgs,omitempty"`
	// EncryptionFloor is the encrypted length this reply had to reach, derived
	// from its own claimed reasoning tokens. Surfacing it makes a rejection
	// explainable instead of a bare verdict.
	EncryptionFloor int64 `json:"encryptionFloor"`
	// ReasoningRatio is the measured bytes of encrypted reasoning per claimed
	// reasoning token. Healthy accounts sit at 4.46-4.94 and degraded ones at
	// 1.59-1.94, so this single number explains any verdict.
	ReasoningRatio  float64   `json:"reasoningRatio"`
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

	mode := normalizeAccountProbeMode(input.Mode)
	prompt := strings.TrimSpace(input.Prompt)
	if prompt == "" {
		if mode == AccountProbeModeTool {
			prompt = accountProbeToolPrompt
		} else {
			prompt = defaultAccountProbePrompt
		}
	}
	maxOutput := input.MaxOutputTokens
	// Reasoning draws from this budget, so a tiny cap would end the reply before
	// any reasoning streams and mislabel a healthy account. Clamp from below and
	// let early stop keep the real cost down.
	if maxOutput < accountProbeMinOutputTokens {
		maxOutput = defaultAccountProbeMaxOutputTokens
	}

	payload := map[string]any{
		"model":    input.Model,
		"messages": []map[string]string{{"role": "user", "content": prompt}},
		// The body flag has to agree with the Streaming option below: Build answers
		// a streamed request with SSE, which cannot be decoded as one JSON object.
		"stream":         mode != AccountProbeModeTool,
		"stream_options": map[string]bool{"include_usage": true},
		"max_tokens":     maxOutput,
	}
	if mode == AccountProbeModeTool {
		// "auto" is what makes the test meaningful. The capability being measured
		// is whether the account reaches for a tool at all when the task needs one;
		// forcing the call with "required" hides that, and measured upstream it also
		// honours the forced variant only about half the time.
		payload["tools"] = accountProbeTools()
		payload["tool_choice"] = "auto"
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return result, err
	}

	key, err := s.clientKeys.Get(ctx, input.ClientKeyID)
	if err != nil {
		return result, fmt.Errorf("读取短测 Client Key: %w", err)
	}
	if !key.IsAvailable(time.Now().UTC()) {
		return result, ErrAccountProbeKeyUnavailable
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
		// Tool mode is not streamed: measured on Build, a streamed tools request
		// yields no tool_calls at all, so the call is only observable in a complete
		// response. Thinking mode keeps streaming because its evidence arrives as
		// SSE comments.
		Streaming: mode != AccountProbeModeTool, Operation: audit.OperationChat,
		ForcedAccountID: input.AccountID, accountProbe: true,
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

	if mode == AccountProbeModeTool {
		payload, readErr := io.ReadAll(io.LimitReader(answer.Body, accountProbeMaxStreamBytes))
		result.DurationMS = time.Since(startedAt).Milliseconds()
		if readErr != nil {
			result.Verdict = AccountProbeError
			result.Reason = "read_failed"
			result.Error = readErr.Error()
			return result, nil
		}
		parsed, call := parseAccountProbeToolBody(result, payload)
		// A call on its own does not prove the account can use tools: measured on
		// this fleet almost every account emits one. What separates them is whether
		// the account can carry the tool result forward, so the grounded follow-up
		// decides the verdict.
		if parsed.ToolCallOK && call != nil {
			grounded, followErr, followTokens := s.probeToolFollowUp(probeCtx, key, publicModel, input.Model, prompt, *call, input.AccountID, maxOutput)
			parsed.OutputTokens += followTokens
			switch {
			case followErr != nil:
				parsed.Verdict = AccountProbeError
				parsed.Reason = "follow_up_failed"
				parsed.Error = followErr.Error()
				parsed.ToolCallOK = false
			case grounded:
				parsed.Verdict = AccountProbeHealthy
				parsed.Reason = "tool_call_ok"
			default:
				parsed.Verdict = AccountProbeHard
				parsed.Reason = "tool_call_ungrounded"
				parsed.ToolCallOK = false
			}
		}
		parsed.DurationMS = time.Since(startedAt).Milliseconds()
		return parsed, nil
	}

	var firstGeneratedAt time.Time
	var firstReasoningAt time.Time
	var visible strings.Builder
	reasoningDeltaBytes := 0
	encryptedBytes := 0
	var firstVisibleAt time.Time
	// FirstVisibleMS is recorded for diagnostics only. Measurement across real
	// accounts showed degraded ones hold their answer back just as long as healthy
	// ones, so this delay cannot decide a verdict and nothing stops early on it.
	// Tool mode needs these: the call arrives as fragments and its arguments are
	// what tell a real invocation from prose that merely mentions the tool.
	var toolName string
	var toolArgs strings.Builder
	toolComplete := false
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
		// Two markers matter. The start stub proves nothing on its own: a
		// degraded account emits it too, so it only anchors first-token timing.
		// The evidence line carries the encrypted-reasoning payload length.
		if trimmed == qualityReasoningSSEComment {
			if firstGeneratedAt.IsZero() {
				firstGeneratedAt = time.Now()
				if answer.MarkFirstToken != nil {
					answer.MarkFirstToken()
				}
			}
			continue
		}
		if evidence, ok := parseReasoningEvidenceComment(trimmed); ok {
			if evidence > encryptedBytes {
				encryptedBytes = evidence
			}
			if firstReasoningAt.IsZero() {
				firstReasoningAt = time.Now()
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
				if firstVisibleAt.IsZero() {
					firstVisibleAt = time.Now()
				}
				visible.WriteString(delta.Content)
			}
			// Plaintext reasoning deltas: the strongest signal, because a degraded
			// account ships none. Build reaches this path when the converter emits
			// reasoning_content for OperationChat.
			reasoning := delta.Reasoning + delta.ReasoningContent + delta.ThinkingContent
			if reasoning != "" {
				reasoningDeltaBytes += len(reasoning)
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
			// Tool mode: accumulate the invocation. Arguments stream in fragments,
			// so completeness is checked as they arrive.
			for _, call := range delta.ToolCalls {
				if call.Function.Name != "" {
					toolName = call.Function.Name
				}
				if call.Function.Arguments != "" {
					toolArgs.WriteString(call.Function.Arguments)
				}
			}
			if mode == AccountProbeModeTool && !toolComplete && toolName != "" {
				toolComplete = accountProbeToolCallComplete(toolName, toolArgs.String())
			}
		}
		// Tool mode decides as soon as the call is complete: the capability under
		// test is proven, and the rest of the stream is pure cost.
		if mode == AccountProbeModeTool && toolComplete {
			earlyStop = true
			break
		}
		// Fallback for a reply that only streams reasoning: wait for the delay
		// after reasoning appears so a partially streamed thought is not judged.
		if input.EarlyStopOnThinking && !firstReasoningAt.IsZero() && time.Since(firstReasoningAt) >= earlyStopDelay {
			earlyStop = true
			break
		}
	}

	completedAt := time.Now()
	// Plaintext reasoning deltas are conclusive. When the converter sends only
	// encrypted reasoning, the payload has to be proportional to the reasoning
	// tokens the reply claims: a degraded account reports hundreds of thinking
	// tokens while shipping a stub of a few hundred bytes, so no fixed floor can
	// separate the two. usage.reasoning_tokens still never decides on its own, it
	// only sets the bar encrypted content has to clear.
	result.ReasoningDeltaBytes = reasoningDeltaBytes
	result.EncryptedBytes = encryptedBytes
	result.ReasoningBytes = max(reasoningDeltaBytes, encryptedBytes)
	encryptionFloor := accountProbeEncryptionFloor(input.MinBytesPerToken, usage.ReasoningTokens)
	result.EncryptionFloor = encryptionFloor
	if usage.ReasoningTokens > 0 {
		result.ReasoningRatio = math.Round(float64(encryptedBytes)/float64(usage.ReasoningTokens)*100) / 100
	}
	result.HasThinking = reasoningDeltaBytes > 0 || int64(encryptedBytes) >= encryptionFloor
	result.OutputTokens = usage.OutputTokens
	result.ReasoningTokens = usage.ReasoningTokens
	answerText := visible.String()
	result.VisibleChars = len(answerText)
	result.AnswerExcerpt = truncateAccountProbeAnswer(answerText)
	result.EarlyStop = earlyStop
	if !firstVisibleAt.IsZero() {
		result.FirstVisibleMS = firstVisibleAt.Sub(startedAt).Milliseconds()
	}
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

	result.Mode = mode
	result.ToolCallOK = toolComplete
	result.ToolName = toolName
	result.ToolArgs = toolArgs.String()

	if mode == AccountProbeModeTool {
		// Tool mode judges one thing: did a forced call actually happen with usable
		// arguments. That is a capability signal, not a reasoning-volume estimate,
		// and it is available the moment the call lands.
		switch {
		case toolComplete:
			result.Verdict = AccountProbeHealthy
			result.Reason = "tool_call_ok"
		case toolName == "" && len(visible.String()) == 0 && usage.OutputTokens == 0:
			result.Verdict = AccountProbeError
			result.Reason = "empty_reply"
		case toolName == "":
			result.Verdict = AccountProbeHard
			result.Reason = "tool_call_missing"
		default:
			result.Verdict = AccountProbeHard
			result.Reason = "tool_call_incomplete"
		}
		return result, nil
	}

	// Thinking mode comes from the completed reply: the only signal that separates
	// a real trace from a stub is the encrypted payload measured against the
	// reasoning tokens the reply claims, and both arrive at the tail.
	result.Verdict, result.Reason = classifyAccountProbeResult(result)
	return result, nil
}

// classifyAccountProbeResult is the fallback for a stream that ended without ever
// producing a visible token, so the first-visible-token latency could not decide.
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
	defaultAccountProbePrompt = "Think step by step. A clock shows 3:27. What is the smaller angle in degrees between the hour and minute hands, rounded to the nearest integer? Reply with only that integer on the first line and QUALITY_OK on the last line."
	// A tight cap truncates the reply before the encrypted-reasoning marker is
	// emitted, which would make a healthy account look degraded. Note that Build
	// does not honour this as a real ceiling: probes with a cap of 48 still
	// produced 1300-3900 output tokens, because reasoning is not counted against
	// it. Treat it as a safety net for the visible reply, not a cost control.
	defaultAccountProbeMaxOutputTokens = 512
	defaultAccountProbeEarlyStopDelay  = 800 * time.Millisecond
	// Anything below this is treated as unset: reasoning needs room to stream
	// before the visible answer starts.
	accountProbeMinOutputTokens = 128
	// accountProbeAnswerExcerptBytes bounds the answer text kept for quality checks.
	accountProbeAnswerExcerptBytes = 160
	// Encrypted reasoning must scale with the reasoning tokens the reply claims,
	// or it is a stub. Calibrated on 38 measured rows: healthy accounts sit at
	// 4.46-4.94 bytes per claimed reasoning token, degraded ones at 1.59-1.94, a
	// 2.3x gap. A threshold of 3 sits mid-gap with over 1.0 of margin on both
	// sides; the previous value of 4 left only 0.46 above the healthy floor and
	// would misjudge a healthy account that dipped.
	accountProbeMinEncryptedBytes      = 256
	accountProbeEncryptedBytesPerToken = 3.0
	// accountProbeThinkingThreshold is the first-visible-token delay that counts
	// as evidence of thinking. A model that reasons emits its first visible token
	// well after this; a degraded account dumps the answer immediately. It is the
	// only verdict signal available while the stream is still open, so the probe
	// can decide and stop instead of paying for the whole reply.
	accountProbeThinkingThreshold = 3 * time.Second
	// accountProbeToolName is the function the tool-mode probe requires. The wrong
	// tools below are deliberately plausible, so reaching for the right one is a
	// real decision rather than the only option.
	accountProbeToolName = "get_stock_price"
	// accountProbeToolArg is the argument that must carry the subject of the task.
	accountProbeToolArg = "ticker"
	// accountProbeToolPrompt needs live data and names no tool. A degraded account
	// answers from memory or picks an unrelated tool, which is exactly what the
	// client-side symptom looks like.
	accountProbeToolPrompt = "What is the current share price of AAPL in USD? I need the real market price, so call a tool instead of guessing."
	// accountProbeToolFakePrice is the number the probe injects as the tool result.
	// A grounded answer can only quote it back, so its presence proves the account
	// carried the tool output forward instead of answering from memory.
	accountProbeToolFakePrice     = "187.42"
	accountProbeToolResultContent = "AAPL is trading at 187.42 USD right now."
)

// accountProbeTools is the tool schema the tool-mode probe offers.
//
// Four tools with similar shapes are offered on purpose. Measuring a single toy
// tool made every account look healthy: 29 of 30 called it correctly, so the test
// had no discriminating power. Forcing a choice between near-miss candidates is
// what turns this into a capability test.
func accountProbeTools() []map[string]any {
	tool := func(name, description string, properties map[string]any, required ...string) map[string]any {
		return map[string]any{
			"type": "function",
			"function": map[string]any{
				"name":        name,
				"description": description,
				"parameters": map[string]any{
					"type":       "object",
					"properties": properties,
					"required":   required,
				},
			},
		}
	}
	return []map[string]any{
		tool(accountProbeToolName, "Get the current market price of a stock",
			map[string]any{
				accountProbeToolArg: map[string]any{"type": "string", "description": "Stock ticker symbol, for example AAPL"},
				"currency":          map[string]any{"type": "string", "enum": []string{"USD", "EUR", "JPY"}},
			}, accountProbeToolArg, "currency"),
		tool("get_weather", "Get the current weather for a city",
			map[string]any{
				"city": map[string]any{"type": "string"},
				"unit": map[string]any{"type": "string", "enum": []string{"celsius", "fahrenheit"}},
			}, "city"),
		tool("search_web", "Search the web for a page matching a query",
			map[string]any{
				"query": map[string]any{"type": "string"},
			}, "query"),
		tool("send_email", "Send an email to a recipient",
			map[string]any{
				"to":      map[string]any{"type": "string"},
				"subject": map[string]any{"type": "string"},
			}, "to", "subject"),
	}
}

// accountProbeToolCallComplete reports whether the model reached for the right
// tool and passed the task subject through. Choosing a plausible but wrong tool,
// omitting the argument, or answering in prose all count as a miss: they are the
// same failure a real client sees when an account cannot drive tools.
func accountProbeToolCallComplete(name, args string) bool {
	if name != accountProbeToolName {
		return false
	}
	var parsed map[string]any
	if json.Unmarshal([]byte(args), &parsed) != nil {
		return false
	}
	ticker, ok := parsed[accountProbeToolArg].(string)
	if !ok || strings.TrimSpace(ticker) == "" {
		return false
	}
	// The subject has to survive into the argument, otherwise the call did not
	// actually carry the task.
	return strings.Contains(strings.ToUpper(ticker), "AAPL")
}

// probeToolFollowUp completes the tool loop and reports whether the final answer
// is grounded in the result the probe injected.
//
// This is the step that actually separates accounts here. Emitting a tool call is
// something nearly every account manages - 29 of 30 did, and adding near-miss
// candidate tools did not change that. Carrying the returned value into the answer
// is the part a degraded account skips, and it is the same failure a client sees
// when tools "do not work".
func (s *Service) probeToolFollowUp(ctx context.Context, key clientkey.Key, publicModel, model, prompt string, call qualityProbeToolCall, accountID uint64, maxOutput int) (bool, error, int64) {
	body, err := json.Marshal(map[string]any{
		"model":      model,
		"stream":     false,
		"max_tokens": maxOutput,
		"tools":      accountProbeTools(),
		"messages": []any{
			map[string]any{"role": "user", "content": prompt},
			map[string]any{
				"role":    "assistant",
				"content": "",
				"tool_calls": []any{map[string]any{
					"id":   call.ID,
					"type": "function",
					"function": map[string]any{
						"name":      call.Function.Name,
						"arguments": call.Function.Arguments,
					},
				}},
			},
			map[string]any{
				"role":         "tool",
				"tool_call_id": call.ID,
				"content":      accountProbeToolResultContent,
			},
		},
	})
	if err != nil {
		return false, err, 0
	}
	requestIDPart, err := security.NewOpaqueToken(12)
	if err != nil {
		return false, err, 0
	}
	answer, err := s.CreateChatCompletion(ctx, Input{
		RequestID: "probe_follow_" + requestIDPart, ClientKey: key, PublicModel: publicModel,
		Body: body, Streaming: false, Operation: audit.OperationChat,
		ForcedAccountID: accountID, accountProbe: true,
	})
	if err != nil {
		return false, err, 0
	}
	defer answer.Body.Close()
	payload, readErr := io.ReadAll(io.LimitReader(answer.Body, accountProbeMaxStreamBytes))
	if readErr != nil {
		return false, readErr, 0
	}
	if answer.StatusCode < http.StatusOK || answer.StatusCode >= http.StatusMultipleChoices {
		return false, fmt.Errorf("兜底轮上游返回 %d: %s", answer.StatusCode, strings.TrimSpace(string(payload))[:min(len(payload), 200)]), 0
	}
	var response struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Usage *struct {
			CompletionTokens int64 `json:"completion_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(payload, &response); err != nil {
		return false, fmt.Errorf("兜底轮响应解析失败: %w", err), 0
	}
	var tokens int64
	if response.Usage != nil {
		tokens = response.Usage.CompletionTokens
	}
	if len(response.Choices) == 0 {
		return false, errors.New("兜底轮没有返回内容"), tokens
	}
	// The injected number is the only place 187.42 can come from, so quoting it
	// proves the tool output reached the answer.
	return strings.Contains(response.Choices[0].Message.Content, accountProbeToolFakePrice), nil, tokens
}

// parseAccountProbeToolBody turns a complete Chat Completions response into a
// tool-mode verdict. Arguments are concatenated per index because the wire format
// splits them. The first call is returned so the caller can continue the loop.
func parseAccountProbeToolBody(result AccountProbeResult, payload []byte) (AccountProbeResult, *qualityProbeToolCall) {
	result.Mode = AccountProbeModeTool
	var response struct {
		Choices []struct {
			FinishReason string `json:"finish_reason"`
			Message      struct {
				Content   string                 `json:"content"`
				ToolCalls []qualityProbeToolCall `json:"tool_calls"`
			} `json:"message"`
		} `json:"choices"`
		Usage *struct {
			CompletionTokens        int64 `json:"completion_tokens"`
			CompletionTokensDetails struct {
				ReasoningTokens int64 `json:"reasoning_tokens"`
			} `json:"completion_tokens_details"`
		} `json:"usage"`
		Error *struct {
			Message string `json:"message"`
			Type    string `json:"type"`
			Code    string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(payload, &response); err != nil {
		result.Verdict = AccountProbeError
		result.Reason = "invalid_response"
		result.Error = "短测响应不是合法 JSON"
		return result, nil
	}
	if len(response.Choices) == 0 {
		// An error envelope is not a capability signal. Without this the empty
		// choices list was read as "no tool call" and a 403 became a degraded
		// verdict that penalized the account.
		result.Verdict = AccountProbeError
		result.Reason = "empty_reply"
		if response.Error != nil {
			result.Error = strings.TrimSpace(response.Error.Message)
			if code := strings.TrimSpace(response.Error.Code); code != "" {
				if result.Error == "" {
					result.Error = code
				} else {
					result.Error = code + ": " + result.Error
				}
			}
			result.Verdict = classifyAccountProbeFailure(0, result.Error)
			result.Reason = probeReasonForStatus(result.Verdict, 0)
		}
		return result, nil
	}
	choice := response.Choices[0]
	var name string
	var args strings.Builder
	for _, call := range choice.Message.ToolCalls {
		if call.Function.Name != "" {
			name = call.Function.Name
		}
		args.WriteString(call.Function.Arguments)
	}
	result.ToolName = name
	result.ToolArgs = args.String()
	result.ToolCallOK = accountProbeToolCallComplete(name, args.String())
	result.VisibleChars = len(choice.Message.Content)
	if response.Usage != nil {
		result.OutputTokens = response.Usage.CompletionTokens
		result.ReasoningTokens = response.Usage.CompletionTokensDetails.ReasoningTokens
	}
	switch {
	case result.ToolCallOK:
		result.Verdict = AccountProbeHealthy
		result.Reason = "tool_call_ok"
	case name == "" && result.VisibleChars == 0 && result.OutputTokens == 0:
		result.Verdict = AccountProbeError
		result.Reason = "empty_reply"
	case name == "":
		// Answered without reaching for any tool: the headline symptom.
		result.Verdict = AccountProbeHard
		result.Reason = "tool_call_missing"
	case name != accountProbeToolName:
		// Picked a plausible but wrong tool.
		result.Verdict = AccountProbeHard
		result.Reason = "tool_call_wrong"
	default:
		// Right tool, but the task subject did not survive into the arguments.
		result.Verdict = AccountProbeHard
		result.Reason = "tool_call_incomplete"
	}
	if !result.ToolCallOK || len(choice.Message.ToolCalls) == 0 {
		return result, nil
	}
	first := choice.Message.ToolCalls[0]
	if first.ID == "" {
		first.ID = "call_probe"
	}
	return result, &first
}

// normalizeAccountProbeMode keeps an unknown or empty mode on the tool default.
func normalizeAccountProbeMode(value string) string {
	if strings.TrimSpace(value) == AccountProbeModeThinking {
		return AccountProbeModeThinking
	}
	return AccountProbeModeTool
}

// accountProbeEncryptionFloor is the encrypted-reasoning payload a reply has to
// reach, given how many reasoning tokens it claims. Calibrated per prompt, since
// the degraded band shifts when the question changes.
func accountProbeEncryptionFloor(bytesPerToken float64, reasoningTokens int64) int64 {
	floor := int64(accountProbeMinEncryptedBytes)
	if bytesPerToken <= 0 {
		bytesPerToken = accountProbeEncryptedBytesPerToken
	}
	if reasoningTokens <= 0 {
		return floor
	}
	need := int64(float64(reasoningTokens) * bytesPerToken)
	if need > floor {
		return need
	}
	return floor
}

// truncateAccountProbeAnswer keeps a short, safe prefix of the visible answer.
// The probe prompt has a checkable answer, so this text is what lets answer
// quality be compared against the reasoning ratio afterwards.
func truncateAccountProbeAnswer(value string) string {
	trimmed := strings.TrimSpace(value)
	if len(trimmed) <= accountProbeAnswerExcerptBytes {
		return trimmed
	}
	cut := accountProbeAnswerExcerptBytes
	// Do not split a multi-byte rune.
	for cut > 0 && !utf8.RuneStart(trimmed[cut]) {
		cut--
	}
	return strings.TrimSpace(trimmed[:cut])
}

// IsAccountProbePenalizable reports whether a verdict should cool the account.
// Transport and upstream failures are infrastructure noise and never penalize
// the account; only a completed reply that carries no reasoning does.
func IsAccountProbePenalizable(verdict string) bool {
	return verdict == AccountProbeHard
}

// parseReasoningEvidenceComment reads the encrypted-reasoning byte count from the
// `: grok2api-reasoning-evidence <n>` SSE comment.
//
// The converter folds upstream reasoning into encrypted_content, so its length is
// the only measurable trace left after protocol conversion. A degraded account
// emits the start stub but never an evidence line.
func parseReasoningEvidenceComment(line string) (int, bool) {
	const prefix = qualityReasoningEvidenceSSEComment
	if !strings.HasPrefix(line, prefix) {
		return 0, false
	}
	raw := strings.TrimSpace(strings.TrimPrefix(line, prefix))
	if raw == "" {
		return 0, false
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value <= 0 {
		return 0, false
	}
	return value, true
}
