import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Activity, Ban, FlaskConical, Play, RefreshCw, Square, TimerReset } from "lucide-react";
import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { listAccounts } from "@/features/accounts/accounts-api";
import { listModels } from "@/entities/model/model-api";
import { EmptyState, ErrorState } from "@/shared/components/data-state";
import { cn } from "@/shared/lib/cn";
import { formatCompactDateTime } from "@/shared/lib/format";

import {
  fetchAccountProbeStatus,
  runAccountProbe,
  stopAccountProbe,
  updateAccountProbeConfig,
  type AccountProbeConfig,
  type AccountProbeEditableConfig,
  type AccountProbeResult,
  type AccountProbeVerdict,
} from "./account-probe-api";

const verdictStyles: Record<AccountProbeVerdict, string> = {
  healthy: "bg-emerald-500/15 text-emerald-600 dark:text-emerald-400",
  hard: "bg-red-500/15 text-red-600 dark:text-red-400",
  risk: "bg-amber-500/15 text-amber-600 dark:text-amber-400",
  error: "bg-slate-500/15 text-slate-600 dark:text-slate-400",
};

const verdictLabels: Record<AccountProbeVerdict, string> = {
  healthy: "正常",
  hard: "降智",
  risk: "风控",
  error: "异常",
};

export function AccountProbePanel({ accountIds }: { accountIds?: number[] } = {}) {
  const { t, i18n } = useTranslation();
  const queryClient = useQueryClient();
  const [draft, setDraft] = useState<AccountProbeConfig | null>(null);
  const [selected, setSelected] = useState<Set<number>>(() => new Set());

  // The probe is Build-only, so the picker offers exactly the accounts the
  // backend would accept instead of every account in the pool. Note the field
  // names: `provider` selects Build/Web/Console, while `type` is the quota type
  // (free/paid/...). Passing a provider through `type` is rejected as an invalid
  // filter and leaves the picker empty.
  const accountsQuery = useQuery({
    queryKey: ["account-probe-candidates"],
    queryFn: () => listAccounts({ page: 1, pageSize: 200, provider: "grok_build", status: "active" }),
  });
  const candidates = accountsQuery.data?.items ?? [];
  const effectiveSelection = accountIds?.length ? accountIds : [...selected];

  // Only Build routes can stream reasoning, and the probe fails outright when the
  // configured model has no Build route. Listing the real options keeps the
  // operator from having to guess a model name.
  const modelsQuery = useQuery({
    queryKey: ["account-probe-models"],
    queryFn: () => listModels({ page: 1, pageSize: 200, provider: "grok_build", status: "" }),
  });
  const buildModels = useMemo(
    () => (modelsQuery.data?.items ?? []).filter((item) => item.enabled && item.available),
    [modelsQuery.data],
  );

  const query = useQuery({
    queryKey: ["account-probe-status"],
    queryFn: fetchAccountProbeStatus,
    // A running batch only becomes visible through polling, so keep a modest
    // interval whenever anything is still in flight.
    refetchInterval: (query) => (query.state.data?.runs?.some((run) => run.running) ? 2000 : false),
  });

  // `draft` only holds user edits. The rendered config falls back to the server
  // value, which removes the need to seed state from an effect and keeps the form
  // in sync whenever a refetch lands.
  const saveMutation = useMutation({
    mutationFn: (input: AccountProbeConfig) => {
      // clientKeyId is server-managed; drop it so the panel can never submit it.
      const editable: AccountProbeEditableConfig = {
        enabled: input.enabled,
        intervalHours: input.intervalHours,
        chunkSize: input.chunkSize,
        workers: input.workers,
        model: input.model,
        mode: input.mode,
        prompt: input.prompt,
        maxOutputTokens: input.maxOutputTokens,
        ratioThreshold: input.ratioThreshold,
        earlyStopOnThinking: input.earlyStopOnThinking,
        earlyStopDelayMs: input.earlyStopDelayMs,
        cooldownHours: input.cooldownHours,
        autoDisable: input.autoDisable,
      };
      return updateAccountProbeConfig(editable);
    },
    onSuccess: async () => {
      toast.success(t("accountProbe.saved", "短测设置已保存"));
      // Re-seed the form from the server response: the backend clamps values,
      // and without this the panel would keep showing pre-clamp numbers.
      const next = await queryClient.fetchQuery({
        queryKey: ["account-probe-status"],
        queryFn: fetchAccountProbeStatus,
      });
      setDraft(next.config);
    },
    onError: (error: Error) => toast.error(error.message),
  });

  const runMutation = useMutation({
    mutationFn: (ids: number[]) => runAccountProbe(ids),
    onSuccess: () => {
      toast.success(t("accountProbe.started", "短测已启动"));
      void queryClient.invalidateQueries({ queryKey: ["account-probe-status"] });
    },
    onError: (error: Error) => toast.error(error.message),
  });

  const stopMutation = useMutation({
    mutationFn: stopAccountProbe,
    onSuccess: (stopped) => {
      toast.success(stopped ? t("accountProbe.stopped", "已请求停止") : t("accountProbe.notRunning", "当前没有运行中的任务"));
      void queryClient.invalidateQueries({ queryKey: ["account-probe-status"] });
    },
    onError: (error: Error) => toast.error(error.message),
  });

  const runs = query.data?.runs ?? [];
  const activeRun = runs.find((run) => run.running);
  const latestResults = useMemo(
    () => (activeRun?.results?.length ? activeRun.results : query.data?.recent ?? []),
    [activeRun, query.data],
  );
  // The counters come from the run summary while one is in flight, because
  // `results` only holds finished accounts and would make a half-done sweep look
  // like a tiny one. The recent list is a flat history, so count it locally.
  const total = useMemo(() => {
    if (activeRun) {
      return { healthy: activeRun.healthy, hard: activeRun.hard, risk: activeRun.risk, error: activeRun.errors };
    }
    const summary = { healthy: 0, hard: 0, risk: 0, error: 0 };
    for (const item of latestResults) {
      if (item.verdict in summary) {
        summary[item.verdict] += 1;
      }
    }
    return summary;
  }, [activeRun, latestResults]);

  if (query.isError) {
    return <ErrorState message={t("accountProbe.loadFailed", "短测状态加载失败")} onRetry={() => void query.refetch()} />;
  }

  const config = draft ?? query.data?.config;

  return (
    <div className="space-y-6">
      <div className="rounded-xl border bg-card p-5">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2 text-sm font-medium">
              <FlaskConical className="size-4" />
              {t("accountProbe.title", "账号短测（降智检测）")}
            </div>
            <p className="max-w-2xl text-xs leading-relaxed text-muted-foreground">
              {t(
                "accountProbe.hint",
                "向单个 Build 账号发一道短题，见到推理内容立即停止。整段回复没有任何推理即判定为降智，并按与请求链路相同的口径冷却账号。出口沿用账号自身绑定的代理，不会漂移到其他节点。",
              )}
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={() => void query.refetch()} disabled={query.isFetching}>
              <RefreshCw className={cn("size-4", query.isFetching && "animate-spin")} />
            </Button>
            {activeRun ? (
              <Button variant="outline" size="sm" onClick={() => stopMutation.mutate()} disabled={stopMutation.isPending}>
                <Square className="size-4" />
                {t("accountProbe.stop", "停止")}
              </Button>
            ) : (
              <Button
                size="sm"
                onClick={() => runMutation.mutate(effectiveSelection)}
                disabled={runMutation.isPending || effectiveSelection.length === 0}
                title={effectiveSelection.length ? undefined : t("accountProbe.selectFirst", "请先在下方勾选要测的账号")}
              >
                <Play className="size-4" />
                {t("accountProbe.runSelected", "测选中账号")}
                {effectiveSelection.length > 0 ? ` (${effectiveSelection.length})` : ""}
              </Button>
            )}
          </div>
        </div>

        {config ? (
          <div className="mt-5 grid gap-4 border-t pt-5 sm:grid-cols-2 lg:grid-cols-4">
            <label className="space-y-1.5">
              <span className="text-xs font-medium text-muted-foreground">{t("accountProbe.autoEnabled", "后台自动评测")}</span>
              <div className="flex h-9 items-center">
                <Switch
                  checked={config.enabled}
                  onCheckedChange={(checked) => setDraft({ ...config, enabled: checked })}
                />
              </div>
            </label>
            <label className="space-y-1.5">
              <span className="text-xs font-medium text-muted-foreground">{t("accountProbe.model", "短测模型")}</span>
              <Input
                list="account-probe-models"
                value={config.model}
                onChange={(event) => setDraft({ ...config, model: event.target.value })}
                placeholder="grok-4.6"
              />
              <datalist id="account-probe-models">
                {buildModels.map((item) => (
                  <option key={item.id} value={item.publicId} />
                ))}
              </datalist>
              {buildModels.length === 0 ? (
                <span className="text-xs text-amber-600 dark:text-amber-400">
                  {t("accountProbe.noBuildModels", "没有可用的 Build 模型，短测会直接失败")}
                </span>
              ) : config.model && !buildModels.some((item) => item.publicId === config.model) ? (
                <span className="text-xs text-amber-600 dark:text-amber-400">
                  {t("accountProbe.modelMissing", "当前值不在 Build 模型列表里")}
                </span>
              ) : null}
            </label>
            <label className="space-y-1.5">
              <span className="text-xs font-medium text-muted-foreground">{t("accountProbe.interval", "轮测间隔（小时）")}</span>
              <Input
                type="number"
                min={1}
                value={config.intervalHours}
                onChange={(event) => setDraft({ ...config, intervalHours: Number(event.target.value) })}
              />
            </label>
            <label className="space-y-1.5">
              <span className="text-xs font-medium text-muted-foreground">{t("accountProbe.chunk", "每轮账号数")}</span>
              <Input
                type="number"
                min={1}
                value={config.chunkSize}
                onChange={(event) => setDraft({ ...config, chunkSize: Number(event.target.value) })}
              />
            </label>
            <label className="space-y-1.5">
              <span className="text-xs font-medium text-muted-foreground">{t("accountProbe.workers", "并发")}</span>
              <Input
                type="number"
                min={1}
                max={16}
                value={config.workers}
                onChange={(event) => setDraft({ ...config, workers: Number(event.target.value) })}
              />
            </label>
            <label className="space-y-1.5">
              <span className="text-xs font-medium text-muted-foreground">{t("accountProbe.cooldown", "降智冷却（小时）")}</span>
              <Input
                type="number"
                min={1}
                value={config.cooldownHours}
                onChange={(event) => setDraft({ ...config, cooldownHours: Number(event.target.value) })}
              />
            </label>
            <label className="space-y-1.5">
              <span className="text-xs font-medium text-muted-foreground">{t("accountProbe.maxTokens", "回复上限 Token")}</span>
              <Input
                type="number"
                // Reasoning shares this budget, so a small cap truncates before any
                // thinking streams and makes healthy accounts look degraded.
                min={128}
                value={config.maxOutputTokens}
                onChange={(event) => setDraft({ ...config, maxOutputTokens: Number(event.target.value) })}
              />
            </label>
            <label className="space-y-1.5">
              <span className="text-xs font-medium text-muted-foreground">{t("accountProbe.ratioThreshold", "判据阈值 (字节/token)")}</span>
              <Input
                type="number"
                step={0.1}
                min={0.5}
                // Coupled to the prompt: 3.0 fits the clock puzzle, ~3.8 fits a short
                // arithmetic question. Recalibrate whenever the prompt changes.
                value={config.ratioThreshold}
                onChange={(event) => setDraft({ ...config, ratioThreshold: Number(event.target.value) })}
              />
            </label>
            <label className="space-y-1.5">
              <span className="text-xs font-medium text-muted-foreground">{t("accountProbe.autoDisable", "首次命中直接禁用")}</span>
              <div className="flex h-9 items-center">
                <Switch
                  checked={config.autoDisable}
                  onCheckedChange={(checked) => setDraft({ ...config, autoDisable: checked })}
                />
              </div>
            </label>
            <label className="space-y-1.5">
              <span className="text-xs font-medium text-muted-foreground">{t("accountProbe.earlyStop", "见到思考即停")}</span>
              <div className="flex h-9 items-center">
                <Switch
                  checked={config.earlyStopOnThinking}
                  onCheckedChange={(checked) => setDraft({ ...config, earlyStopOnThinking: checked })}
                />
              </div>
            </label>
            <p className="text-xs text-muted-foreground sm:col-span-2 lg:col-span-4">
              {t(
                "accountProbe.fullRequestNotice",
                "注意：Build 在流末尾才给出推理证据，早停实际不会触发，每次短测都会跑完整回复（约 1.3k–3.9k token）。控制成本请调整每轮账号数或轮测间隔。",
              )}
            </p>
            <div className="sm:col-span-2 lg:col-span-4">
              <Button
                size="sm"
                onClick={() => draft && saveMutation.mutate(draft)}
                disabled={saveMutation.isPending || !draft}
              >
                {t("accountProbe.save", "保存设置")}
              </Button>
            </div>
          </div>
        ) : null}
      </div>

      {accountIds?.length ? null : (
        <div className="rounded-xl border bg-card">
          <div className="flex flex-wrap items-center justify-between gap-3 border-b px-4 py-3">
            <div className="text-sm font-medium">
              {t("accountProbe.pickAccounts", "选择要短测的账号")}
              <span className="ml-2 text-xs font-normal text-muted-foreground">
                {t("accountProbe.pickHint", "仅列出启用中的 Build 账号")}
              </span>
            </div>
            <div className="flex items-center gap-2">
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setSelected(new Set(candidates.map((item) => Number(item.id))))}
                disabled={candidates.length === 0}
              >
                {t("accountProbe.selectAll", "全选")}
              </Button>
              <Button variant="ghost" size="sm" onClick={() => setSelected(new Set())} disabled={selected.size === 0}>
                {t("accountProbe.clearSelection", "清空")}
              </Button>
            </div>
          </div>
          {accountsQuery.isError ? (
            <ErrorState message={t("accountProbe.accountsFailed", "账号列表加载失败")} onRetry={() => void accountsQuery.refetch()} />
          ) : candidates.length === 0 ? (
            <EmptyState message={t("accountProbe.noAccounts", "没有可短测的 Build 账号")} />
          ) : (
            <div className="max-h-80 overflow-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-10" />
                    <TableHead>{t("accountProbe.colAccount", "账号")}</TableHead>
                    <TableHead>{t("accountProbe.colEgress", "出口")}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {candidates.map((account) => {
                    // The account list serializes ids as strings to stay safe for
                    // large values, while the probe API takes numbers. Account ids
                    // are database sequence values well below 2^53, so the
                    // conversion is exact; anything larger would need both sides
                    // switched to string.
                    const id = Number(account.id);
                    return (
                      <TableRow key={id} className="cursor-pointer" onClick={() => {
                        setSelected((previous) => {
                          const next = new Set(previous);
                          if (next.has(id)) next.delete(id); else next.add(id);
                          return next;
                        });
                      }}>
                        <TableCell onClick={(event) => event.stopPropagation()}>
                          <Checkbox checked={selected.has(id)} onCheckedChange={(checked) => {
                            setSelected((previous) => {
                              const next = new Set(previous);
                              if (checked === true) next.add(id); else next.delete(id);
                              return next;
                            });
                          }} />
                        </TableCell>
                        <TableCell>
                          <div className="font-medium">{account.name || `#${id}`}</div>
                          <div className="text-xs text-muted-foreground">{account.email ?? ""}</div>
                        </TableCell>
                        <TableCell className="text-xs text-muted-foreground">
                          {account.egressNodeId ? `#${account.egressNodeId}` : t("accountProbe.pool", "池选")}
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </div>
          )}
        </div>
      )}

      <div className="grid gap-3 sm:grid-cols-4">
        {(["healthy", "hard", "risk", "error"] as AccountProbeVerdict[]).map((verdict) => (
          <div key={verdict} className="rounded-xl border bg-card p-4">
            <div className="text-xs text-muted-foreground">{verdictLabels[verdict]}</div>
            <div className="mt-1 flex items-baseline gap-2">
              <span className="text-2xl font-semibold tabular-nums">{total[verdict]}</span>
              {verdict === "hard" ? <Ban className="size-4 text-red-500" /> : null}
              {verdict === "healthy" ? <Activity className="size-4 text-emerald-500" /> : null}
              {verdict === "error" ? <TimerReset className="size-4 text-slate-400" /> : null}
            </div>
          </div>
        ))}
      </div>

      <div className="rounded-xl border bg-card">
        <div className="flex items-center justify-between border-b px-4 py-3">
          <div className="text-sm font-medium">{t("accountProbe.results", "短测结果")}</div>
          {activeRun ? (
            <Badge variant="secondary">
              {t("accountProbe.progress", "进行中")} {activeRun.done}/{activeRun.total}
            </Badge>
          ) : null}
        </div>
        {latestResults.length === 0 ? (
          <EmptyState message={t("accountProbe.empty", "还没有短测记录")} />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t("accountProbe.colAccount", "账号")}</TableHead>
                <TableHead>{t("accountProbe.colVerdict", "判定")}</TableHead>
                <TableHead>{t("accountProbe.colThinking", "推理字节")}</TableHead>
                <TableHead>{t("accountProbe.colTokens", "输出 Token")}</TableHead>
                <TableHead>{t("accountProbe.colTps", "TPS")}</TableHead>
                <TableHead>{t("accountProbe.colEgress", "出口")}</TableHead>
                <TableHead>{t("accountProbe.colTime", "时间")}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {latestResults.map((item: AccountProbeResult) => (
                <TableRow key={`${item.accountId}-${item.probedAt}`}>
                  <TableCell>
                    <div className="font-medium">{item.accountName || `#${item.accountId}`}</div>
                    <div className="text-xs text-muted-foreground">{item.email}</div>
                  </TableCell>
                  <TableCell>
                    <span className={cn("rounded-md px-2 py-0.5 text-xs font-medium", verdictStyles[item.verdict])}>
                      {verdictLabels[item.verdict]}
                    </span>
                    {item.penalized ? <div className="mt-1 text-xs text-muted-foreground">{t("accountProbe.penalized", "已冷却")}</div> : null}
                  </TableCell>
                  <TableCell className="tabular-nums">
                    <div>{item.reasoningBytes}</div>
                    {/* The ratio is the whole verdict: healthy accounts carry
                        ~4.5-4.9 bytes of encrypted reasoning per claimed token,
                        degraded ones ~1.6-1.9. Showing it makes the separation
                        visible instead of asking anyone to trust a label. */}
                    <div className={cn("text-xs", item.reasoningRatio > 0 && item.reasoningRatio < 3 ? "text-amber-600" : "text-muted-foreground")}>
                      {item.reasoningDeltaBytes > 0
                        ? `${t("accountProbe.reasoningPlain", "明文")} ${item.reasoningDeltaBytes}`
                        : `${t("accountProbe.reasoningRatio", "比值")} ${item.reasoningRatio || "-"}`}
                    </div>
                  </TableCell>
                  <TableCell className="tabular-nums">{item.outputTokens}</TableCell>
                  <TableCell className="tabular-nums">{item.outputTps ? item.outputTps.toFixed(0) : "-"}</TableCell>
                  <TableCell className="text-xs text-muted-foreground">
                    {item.egressNodeName || (item.egressNodeId ? `#${item.egressNodeId}` : t("accountProbe.pool", "池选"))}
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">{formatCompactDateTime(item.probedAt, i18n.language)}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </div>
    </div>
  );
}
