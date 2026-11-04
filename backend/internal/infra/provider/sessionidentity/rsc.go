package sessionidentity

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/chenyme/grok2api/backend/internal/domain/account"
	domainegress "github.com/chenyme/grok2api/backend/internal/domain/egress"
	infraegress "github.com/chenyme/grok2api/backend/internal/infra/egress"
	"github.com/chenyme/grok2api/backend/internal/infra/provider"
	"github.com/chenyme/grok2api/backend/internal/infra/security"
)

// RSC 首页（GET /?_rsc=<key>，头 RSC:1 / Accept: text/x-component）返回 Next.js
// flight 数据，其中 dehydrated TanStack Query 的 initialData.user 携带完整账号对象。
// 2026-11 实测（三个账号逐字段对比）：仅 cursorMerged=true 的账号可同步为 Console
// 授权，blockedReason 非 null 表示账号已被限制。飞行数据里账号对象可能以原始 JSON
// 内嵌，也可能作为 JSON 字符串内嵌（引号转义为 \"），两种形态都要支持。
const (
	rscResponseLimit = 512 << 10
	// rscUserSentinel 用于在 flight 文本中定位账号对象：该字段只在 user 对象出现。
	rscUserSentinel = "cursorMerged"
)

// RSCUser 是 RSC flight 数据中 initialData.user 的关键健康字段快照。
// 数值型字段保留原始 JSON 文本（SessionTierID 等），避免上游类型在
// 数字/字符串之间漂移时导致整体解析失败；门禁只依赖布尔与 blockedReason。
type RSCUser struct {
	CursorMerged              bool
	CursorLinked              bool
	BlockedReason             string // "" = null
	CanUseDebugTools          bool
	EmailConfirmed            bool
	SessionTierID             string
	ExperienceACLs            string
	TOSAcceptedVersion        string
	BirthDateChangesRemaining string
	CreateTime                string
	SignInMethod              string
	PersonalTeamID            string
	Email                     string
}

// FetchRSCUser 通过 Grok Web 会话拉取 RSC 首页并解析账号健康快照。
// 请求复用账号的 Web 出口、浏览器指纹、Cookie 与 Resin 身份（与身份同步一致）。
func FetchRSCUser(ctx context.Context, baseURL string, credential account.Credential, egress *infraegress.Manager, cipher *security.Cipher) (RSCUser, error) {
	if credential.AuthType != account.AuthTypeSSO || credential.Provider != account.ProviderWeb {
		return RSCUser{}, fmt.Errorf("仅 Grok Web SSO 账号支持 RSC 体检")
	}
	if egress == nil || cipher == nil {
		return RSCUser{}, fmt.Errorf("RSC 体检依赖未初始化")
	}
	token, err := cipher.Decrypt(credential.EncryptedAccessToken)
	if err != nil {
		return RSCUser{}, err
	}
	if strings.TrimSpace(token) == "" {
		return RSCUser{}, provider.ErrUnauthorized
	}
	lease, err := egress.AcquireCredential(ctx, domainegress.ScopeWeb, credential)
	if err != nil {
		return RSCUser{}, err
	}
	defer lease.Release()
	return FetchRSCUserWithLease(ctx, baseURL, token, lease, egress)
}

// FetchRSCUserWithLease 通过已选定的 Web 出口租约拉取 RSC 首页。
func FetchRSCUserWithLease(ctx context.Context, baseURL, token string, lease *infraegress.Lease, egress *infraegress.Manager) (RSCUser, error) {
	if lease == nil || egress == nil {
		return RSCUser{}, fmt.Errorf("RSC 体检租约未初始化")
	}
	if strings.TrimSpace(token) == "" {
		return RSCUser{}, provider.ErrUnauthorized
	}
	requestCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	origin := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, origin+"/?_rsc="+rscRouterKey(), nil)
	if err != nil {
		return RSCUser{}, err
	}
	header := browserHeaders(token, origin, lease)
	header.Set("Accept", "text/x-component")
	header.Set("RSC", "1")
	request.Header = header
	response, err := lease.Do(request)
	if err != nil {
		egress.FeedbackForScope(context.WithoutCancel(ctx), domainegress.ScopeWeb, lease.NodeID, 0, err)
		return RSCUser{}, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, rscResponseLimit+1))
	if err != nil {
		return RSCUser{}, err
	}
	if len(body) > rscResponseLimit {
		return RSCUser{}, fmt.Errorf("Grok RSC 响应超过安全上限")
	}
	egress.FeedbackForScope(context.WithoutCancel(ctx), domainegress.ScopeWeb, lease.NodeID, response.StatusCode, nil)
	if response.StatusCode == http.StatusUnauthorized {
		return RSCUser{}, provider.ErrUnauthorized
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return RSCUser{}, fmt.Errorf("Grok RSC 接口返回 %d", response.StatusCode)
	}
	return ParseRSCUser(body)
}

// CheckRSCConsoleEligibility 基于 RSC 账号快照判断能否同步为 Console 授权：
// blockedReason 非 null 直接判死；cursorMerged 必须为 true（cursorLinked=true 只说明
// Cursor 侧身份存在，未完成合并不代表可转换）。
func CheckRSCConsoleEligibility(user RSCUser) error {
	if blocked := strings.TrimSpace(user.BlockedReason); blocked != "" {
		return fmt.Errorf("%w: 账号已被限制（blockedReason=%s）", provider.ErrUnauthorized, blocked)
	}
	if !user.CursorMerged {
		return fmt.Errorf("%w: 该账号 Cursor 身份未合并（cursorMerged=false，cursorLinked=%t），仅已合并账号可同步到 Console",
			provider.ErrConsoleNotMerged, user.CursorLinked)
	}
	return nil
}

// ParseRSCUser 从 RSC flight 文本中解析账号健康快照。
func ParseRSCUser(body []byte) (RSCUser, error) {
	object, found := extractRSCUserObject(body)
	if !found {
		return RSCUser{}, fmt.Errorf("Grok RSC 数据中未找到账号对象（页面结构可能已变化）")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(object, &fields); err != nil {
		return RSCUser{}, fmt.Errorf("解析 Grok RSC 账号对象: %w", err)
	}
	merged, ok := rscBool(fields, "cursorMerged")
	if !ok {
		return RSCUser{}, fmt.Errorf("Grok RSC 账号对象缺少 cursorMerged 字段")
	}
	user := RSCUser{
		CursorMerged:              merged,
		CursorLinked:              rscBoolOrFalse(fields, "cursorLinked"),
		CanUseDebugTools:          rscBoolOrFalse(fields, "canUseDebugTools"),
		EmailConfirmed:            rscBoolOrFalse(fields, "emailConfirmed"),
		BlockedReason:             rscNullableString(fields, "blockedReason"),
		SessionTierID:             rscScalarString(fields, "sessionTierId"),
		ExperienceACLs:            rscScalarString(fields, "experienceAcls"),
		TOSAcceptedVersion:        rscScalarString(fields, "tosAcceptedVersion"),
		BirthDateChangesRemaining: rscScalarString(fields, "birthDateChangesRemaining"),
		CreateTime:                rscScalarString(fields, "createTime"),
		SignInMethod:              rscScalarString(fields, "signInMethod"),
		PersonalTeamID:            rscNullableString(fields, "personalTeamId"),
		Email:                     rscNullableString(fields, "email"),
	}
	return user, nil
}

// extractRSCUserObject 在 flight 文本中定位账号对象：原始 JSON 形态优先，其次
// 内嵌于 JSON 字符串的转义形态。候选对象必须能完整反序列化且包含 cursorMerged，
// 避免锚点在转义文本中误命中时提前失败。
func extractRSCUserObject(body []byte) ([]byte, bool) {
	modes := []struct {
		key     []byte
		escaped bool
	}{
		{[]byte(`"` + rscUserSentinel + `"`), false},
		{[]byte(`\"` + rscUserSentinel + `\"`), true},
	}
	for _, mode := range modes {
		for offset := 0; offset < len(body); {
			found := bytes.Index(body[offset:], mode.key)
			if found < 0 {
				break
			}
			index := offset + found
			offset = index + len(mode.key)
			object, ok := extractBalancedJSONObject(body, index, mode.escaped)
			if !ok {
				continue
			}
			if mode.escaped {
				object = unescapeRSCJSON(object)
			}
			var fields map[string]json.RawMessage
			if json.Unmarshal(object, &fields) != nil {
				continue
			}
			if _, present := fields[rscUserSentinel]; present {
				return object, true
			}
		}
	}
	return nil, false
}

// extractBalancedJSONObject 以 key 所在位置为锚点提取外层 JSON 对象。
// 先向左找对象起始「{」（跳过完整的字符串字面量），再向右做字符串感知的括号配对。
// escaped 模式下字符串以 \" 定界（对象内嵌于 JSON 字符串，仅引号与反斜杠被转义）。
func extractBalancedJSONObject(body []byte, keyIndex int, escaped bool) ([]byte, bool) {
	open := findEnclosingObjectStart(body, keyIndex, escaped)
	if open < 0 {
		return nil, false
	}
	depth := 0
	inString := false
	for index := open; index < len(body); index++ {
		char := body[index]
		if escaped {
			switch {
			case char == '\\' && index+1 < len(body) && body[index+1] == '"':
				inString = !inString
				index++
				continue
			case char == '\\' && index+1 < len(body):
				index++
				continue
			}
			if inString {
				continue
			}
			switch char {
			case '{':
				depth++
			case '}':
				depth--
				if depth == 0 {
					return body[open : index+1], true
				}
			}
			continue
		}
		switch {
		case inString && char == '\\':
			index++
		case char == '"':
			inString = !inString
		}
		if inString {
			continue
		}
		switch char {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return body[open : index+1], true
			}
		}
	}
	return nil, false
}

// findEnclosingObjectStart 从 key 位置向左扫描对象起始「{」：遇完整字符串字面量
// 整段跳过（其内部的括号不参与配对），遇「}」记一层待闭合深度。
func findEnclosingObjectStart(body []byte, keyIndex int, escaped bool) int {
	depth := 0
	for index := keyIndex - 1; index >= 0; index-- {
		char := body[index]
		if escaped {
			if char == '"' {
				// 外层转义后所有引号都以 \" 形态出现，直接按引号配对整段跳过。
				// （内层转义引号 \\\" 会破坏开闭交替，此形态在账号对象字段值中
				// 极罕见；即便误判，最终仍有 JSON 反序列化校验兜底。）
				start := index
				for start-1 >= 0 && body[start-1] == '\\' {
					start--
				}
				closer := start - 1
				for closer >= 0 && body[closer] != '"' {
					closer--
				}
				if closer < 0 {
					return -1
				}
				index = closer
				continue
			}
			switch char {
			case '}':
				depth++
			case '{':
				if depth == 0 {
					return index
				}
				depth--
			}
			continue
		}
		if char == '"' {
			// 向左找与本引号配对的另一个未转义引号，整段跳过
			closer := index - 1
			for closer >= 0 {
				if body[closer] == '"' {
					backslashes := 0
					for probe := closer - 1; probe >= 0 && body[probe] == '\\'; probe-- {
						backslashes++
					}
					if backslashes%2 == 0 {
						break
					}
					closer--
					continue
				}
				closer--
			}
			if closer < 0 {
				return -1
			}
			index = closer
			continue
		}
		switch char {
		case '}':
			depth++
		case '{':
			if depth == 0 {
				return index
			}
			depth--
		}
	}
	return -1
}

// unescapeRSCJSON 反转义内嵌于 JSON 字符串的 JSON 文本。
// strings.NewReplacer 单遍从左到右替换：\\ 先于 \" 消费，保证 \\\" → \" 正确。
func unescapeRSCJSON(value []byte) []byte {
	return []byte(strings.NewReplacer(`\\`, `\`, `\"`, `"`).Replace(string(value)))
}

func rscBool(fields map[string]json.RawMessage, key string) (bool, bool) {
	field, present := fields[key]
	if !present {
		return false, false
	}
	var value bool
	if json.Unmarshal(field, &value) != nil {
		return false, false
	}
	return value, true
}

func rscBoolOrFalse(fields map[string]json.RawMessage, key string) bool {
	value, _ := rscBool(fields, key)
	return value
}

// rscNullableString 返回字符串字段；null 或缺失返回 ""（与被限制状态区分靠门禁语义）。
func rscNullableString(fields map[string]json.RawMessage, key string) string {
	field, present := fields[key]
	if !present || string(field) == "null" {
		return ""
	}
	var value string
	if json.Unmarshal(field, &value) == nil {
		return strings.TrimSpace(value)
	}
	return ""
}

// rscScalarString 宽松读取标量字段：数字/字符串/布尔统一转为展示用文本，
// 缺失或 null 返回 ""，其它类型（数组/对象）保留原始 JSON 文本。
func rscScalarString(fields map[string]json.RawMessage, key string) string {
	field, present := fields[key]
	if !present || string(field) == "null" {
		return ""
	}
	var value any
	if json.Unmarshal(field, &value) != nil {
		return strings.TrimSpace(string(field))
	}
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(typed)
	default:
		return strings.TrimSpace(string(field))
	}
}

// rscRouterKey 生成 Next.js RSC 导航随机 key；随机源失败时退化为纳秒时间戳。
func rscRouterKey() string {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}
