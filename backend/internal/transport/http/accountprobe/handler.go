// Package accountprobe exposes the manual trigger, run history and runtime
// configuration of the Build account quality probe to the admin console.
package accountprobe

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/chenyme/grok2api/backend/internal/application/accountprobe"
)

// Bounds on panel input. Probing is deliberately not allowed to be aggressive:
// a burst of probe traffic is itself the kind of pattern risk control reacts to,
// which is the opposite of what this feature is for.
const (
	maxChunkSize = 500
	maxWorkers   = 8
)

// Handler serves the account probe admin endpoints.
type Handler struct {
	service *accountprobe.Service
}

func NewHandler(service *accountprobe.Service) *Handler {
	return &Handler{service: service}
}

func (h *Handler) Register(router *gin.RouterGroup) {
	router.GET("/account-probe", h.status)
	router.PUT("/account-probe/config", h.updateConfig)
	router.POST("/account-probe/run", h.run)
	router.POST("/account-probe/stop", h.stop)
	router.GET("/account-probe/runs", h.runs)
}

type configRequest struct {
	Enabled             *bool   `json:"enabled"`
	IntervalHours       *int    `json:"intervalHours"`
	ChunkSize           *int    `json:"chunkSize"`
	Workers             *int    `json:"workers"`
	Model               *string `json:"model"`
	Mode                *string `json:"mode"`
	Prompt              *string `json:"prompt"`
	MaxOutputTokens     *int    `json:"maxOutputTokens"`
	EarlyStopOnThinking *bool   `json:"earlyStopOnThinking"`
	EarlyStopDelayMS    *int    `json:"earlyStopDelayMs"`
	CooldownHours       *int    `json:"cooldownHours"`
	AutoDisable         *bool   `json:"autoDisable"`
}

type runRequest struct {
	AccountIDs []uint64 `json:"accountIds"`
}

func (h *Handler) status(c *gin.Context) {
	cfg := h.service.Config()
	c.JSON(http.StatusOK, gin.H{"data": gin.H{
		"config": gin.H{
			"enabled":             cfg.Enabled,
			"intervalHours":       int(cfg.Interval / time.Hour),
			"chunkSize":           cfg.ChunkSize,
			"workers":             cfg.Workers,
			"model":               cfg.Model,
			"mode":                cfg.Mode,
			"prompt":              cfg.Prompt,
			"maxOutputTokens":     cfg.MaxOutputTokens,
			"clientKeyId":         cfg.ClientKeyID,
			"earlyStopOnThinking": cfg.EarlyStopOnThinking,
			"earlyStopDelayMs":    cfg.EarlyStopDelayMS,
			"cooldownHours":       int(cfg.Cooldown / time.Hour),
			"autoDisable":         cfg.AutoDisable,
		},
		"recent": h.service.RecentResults(),
		"runs":   h.service.Runs(),
	}})
}

func (h *Handler) updateConfig(c *gin.Context) {
	var request configRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": "invalidRequest", "message": "配置格式无效"}})
		return
	}
	// Only panel-editable fields are accepted. ClientKeyID is deliberately not
	// among them: the probe funds itself from the server-managed identity, and
	// letting the request point at an arbitrary key would let a panel save
	// redirect internal probe traffic onto a billable key.
	persisted := accountprobe.PersistedConfig{
		Enabled:             request.Enabled,
		IntervalHours:       request.IntervalHours,
		ChunkSize:           request.ChunkSize,
		Workers:             request.Workers,
		MaxOutputTokens:     request.MaxOutputTokens,
		EarlyStopOnThinking: request.EarlyStopOnThinking,
		EarlyStopDelayMS:    request.EarlyStopDelayMS,
		CooldownHours:       request.CooldownHours,
		AutoDisable:         request.AutoDisable,
	}
	if request.Model != nil {
		trimmed := strings.TrimSpace(*request.Model)
		persisted.Model = &trimmed
	}
	if request.Mode != nil {
		trimmed := strings.TrimSpace(*request.Mode)
		if trimmed != "" && trimmed != accountprobe.AccountProbeModeTool && trimmed != accountprobe.AccountProbeModeThinking {
			c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": "invalidRequest", "message": "短测模式必须是 tool 或 thinking"}})
			return
		}
		persisted.Mode = &trimmed
	}
	if request.Prompt != nil {
		trimmed := strings.TrimSpace(*request.Prompt)
		persisted.Prompt = &trimmed
	}
	if persisted.ChunkSize != nil && *persisted.ChunkSize > maxChunkSize {
		c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": "invalidRequest", "message": "每轮账号数超出上限"}})
		return
	}
	if persisted.Workers != nil && *persisted.Workers > maxWorkers {
		c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": "invalidRequest", "message": "并发数超出上限"}})
		return
	}
	if err := h.service.SaveConfig(persisted); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": gin.H{"code": "accountProbeSaveFailed", "message": "保存短测配置失败"}})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": gin.H{"ok": true}})
}

func (h *Handler) run(c *gin.Context) {
	var request runRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": "invalidRequest", "message": "请求格式无效"}})
		return
	}
	// Bound the batch: an unbounded list would let one request queue an
	// arbitrarily large sweep of upstream traffic.
	if len(request.AccountIDs) > maxChunkSize {
		c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": "invalidRequest", "message": "单次短测账号数超出上限"}})
		return
	}
	run, err := h.service.Start(c.Request.Context(), "manual", request.AccountIDs)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": "accountProbeRunFailed", "message": err.Error()}})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": run})
}

func (h *Handler) stop(c *gin.Context) {
	stopped := h.service.Stop()
	c.JSON(http.StatusOK, gin.H{"data": gin.H{"stopped": stopped}})
}

func (h *Handler) runs(c *gin.Context) {
	if raw := c.Query("limit"); raw != "" {
		if limit, err := strconv.Atoi(raw); err == nil && limit > 0 {
			values := h.service.Runs()
			if len(values) > limit {
				values = values[:limit]
			}
			c.JSON(http.StatusOK, gin.H{"data": values})
			return
		}
	}
	c.JSON(http.StatusOK, gin.H{"data": h.service.Runs()})
}
