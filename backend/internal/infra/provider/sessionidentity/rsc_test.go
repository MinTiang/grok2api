package sessionidentity

import (
	"errors"
	"strings"
	"testing"

	"github.com/chenyme/grok2api/backend/internal/infra/provider"
)

// rawRSCFlight 模拟 Next.js flight 文本：账号对象以原始 JSON 内嵌（T chunk），
// 且前面的 chunk 里存在带花括号的字符串值，验证括号配对不会被字符串内容干扰。
const rawRSCFlight = `0:{"meta":"ignore { } inside string","items":[]}` + "\n" +
	`3:T2048,[{"queryKey":["user"],"state":{"data":{"initialData":{"user":` +
	`{"id":"user-1","email":"user@example.com","name":"we{ird} name","cursorLinked":true,"cursorMerged":true,` +
	`"blockedReason":null,"sessionTierId":2,"experienceAcls":[],"canUseDebugTools":false,"emailConfirmed":true,` +
	`"tosAcceptedVersion":6,"birthDateChangesRemaining":0,"createTime":1790624118,"signInMethod":1,"personalTeamId":"team-1"}` +
	`}}}}]}`

func TestParseRSCUserFromRawFlight(t *testing.T) {
	user, err := ParseRSCUser([]byte(rawRSCFlight))
	if err != nil {
		t.Fatal(err)
	}
	if !user.CursorMerged || !user.CursorLinked || !user.EmailConfirmed {
		t.Fatalf("user = %#v", user)
	}
	if user.BlockedReason != "" || user.Email != "user@example.com" || user.PersonalTeamID != "team-1" {
		t.Fatalf("user = %#v", user)
	}
	if user.SessionTierID != "2" || user.CreateTime != "1790624118" || user.SignInMethod != "1" || user.TOSAcceptedVersion != "6" {
		t.Fatalf("scalar fields = %#v", user)
	}
	if err := CheckRSCConsoleEligibility(user); err != nil {
		t.Fatalf("merged account rejected: %v", err)
	}
}

// escapedRSCFlight 模拟账号对象内嵌于 JSON 字符串的形态（引号转义为 \"）。
const escapedRSCFlight = `5:T1024,{\"queries\":[{\"state\":{\"data\":{\"initialData\":{\"user\":` +
	`{\"id\":\"user-2\",\"email\":\"old@example.com\",\"cursorLinked\":true,\"cursorMerged\":false,` +
	`\"blockedReason\":null,\"sessionTierId\":2,\"experienceAcls\":[],\"personalTeamId\":\"team-2\"}` +
	`}}}}]}`

func TestParseRSCUserFromEscapedFlight(t *testing.T) {
	user, err := ParseRSCUser([]byte(escapedRSCFlight))
	if err != nil {
		t.Fatal(err)
	}
	if user.CursorMerged || !user.CursorLinked || user.Email != "old@example.com" || user.PersonalTeamID != "team-2" {
		t.Fatalf("user = %#v", user)
	}
	err = CheckRSCConsoleEligibility(user)
	if !errors.Is(err, provider.ErrConsoleNotMerged) {
		t.Fatalf("err = %v, want ErrConsoleNotMerged", err)
	}
}

func TestCheckRSCConsoleEligibility(t *testing.T) {
	if err := CheckRSCConsoleEligibility(RSCUser{CursorMerged: true}); err != nil {
		t.Fatalf("merged account rejected: %v", err)
	}
	if err := CheckRSCConsoleEligibility(RSCUser{CursorMerged: false, CursorLinked: true}); !errors.Is(err, provider.ErrConsoleNotMerged) {
		t.Fatalf("unmerged account err = %v, want ErrConsoleNotMerged", err)
	}
	if err := CheckRSCConsoleEligibility(RSCUser{CursorMerged: true, BlockedReason: "policy_violation"}); !errors.Is(err, provider.ErrUnauthorized) {
		t.Fatalf("blocked account err = %v, want ErrUnauthorized", err)
	}
	if err := CheckRSCConsoleEligibility(RSCUser{CursorMerged: true, BlockedReason: "  "}); err != nil {
		t.Fatalf("blank blockedReason must not block: %v", err)
	}
}

func TestParseRSCUserRejectsMalformedPayloads(t *testing.T) {
	if _, err := ParseRSCUser([]byte(`0:{"hello":"world"}`)); err == nil || !strings.Contains(err.Error(), "未找到账号对象") {
		t.Fatalf("missing user object err = %v", err)
	}
	// cursorMerged 存在但类型不是布尔：无法判定资格，必须报错而不是默认放行。
	typedWrong := `0:{"cursorMerged":"true","cursorLinked":true}`
	if _, err := ParseRSCUser([]byte(typedWrong)); err == nil || !strings.Contains(err.Error(), "cursorMerged") {
		t.Fatalf("non-boolean cursorMerged err = %v", err)
	}
}

func TestParseRSCUserIgnoresDecoyMentionsOutsideObjects(t *testing.T) {
	// 文本中先出现 key 的无关提及（非 JSON 对象内），解析器应跳过并继续寻找真实对象。
	body := `0:{"note":"cursorMerged appears in docs"}` + "\n" +
		`1:{"cursorMerged":false,"cursorLinked":false,"blockedReason":null}`
	user, err := ParseRSCUser([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if user.CursorMerged {
		t.Fatalf("user = %#v", user)
	}
}
