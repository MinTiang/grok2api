# 短测与降智排查手册

这份文档记录的是实测出来的结论，不是设计意图。所有数字都来自真实运行数据。

## 一、降智的物理特征

在请求审计里，一个降智账号的表现是：

```
statusCode = 200
outputTokens = 0
reasoningTokens = 0
usageSource = "none"
durationMs = 30000 ~ 220000
```

**HTTP 200，但一个 token 都没有。** 模型跑了半分钟到几分钟，什么都没吐出来。

它不是「返回很快」——恰恰相反，它耗了很长时间才决定不给内容。用户感受到的「快」是指失败返回得快，不是响应快。

### 怎么确认

```sql
-- 或直接查接口
GET /api/admin/v1/request-audits?page=1&pageSize=200
```

按账号聚合，`outputTokens = 0` 且 `statusCode = 200` 的记录占比高的就是降智号。

实测数据（2436 条真实请求）：

| operation | 总数 | 零输出 | 失败率 |
|---|---|---|---|
| `chat` | 2267 | 222 | 10% |
| `responses` | 123 | 81 | 66% |
| `messages`（Claude Code） | 41 | 20 | 49% |

## 二、不要用这些信号判断

以下都在实测中被否掉了：

| 信号 | 实测结果 |
|---|---|
| 是否调用工具 | 降智号照样选对工具、参数正确、能用上返回结果（4 种测试设计，约 90% 通过率） |
| 首字延迟 | 降智 27192ms vs 健康 27412ms，差 0.8% |
| 输出 token 数 | 1934 vs 1893，差 2% |
| 答案正确率 | 三步应用题、CRT 陷阱题，两组都是 100% |
| `numServerSideToolsUsed` | 全部为 0（这是服务端工具计数，客户端工具不走这里） |

## 三、短测判据

短测用的是**加密推理载荷与声称推理量的比值**：

```
ratio = encryptedBytes / reasoningTokens
```

实测分布（38 条）：

| 群体 | ratio 区间 |
|---|---|
| 健康 | 4.42 – 4.97 |
| 降智 | 1.60 – 1.98 |

空隙 2.3 倍，无重叠。阈值取 3.0 居中。

**但这个比值会随 prompt 变化**：换成短算术题后两组都上移（健康 4.9–5.7 / 降智 2.1–2.7），阈值要改成 3.8。所以它是配置项 `ratioThreshold`，不是常量。

### 判定流程

1. 5 次采样，3 票定胜负
2. 平票继续采，数学上不可能再达标就提前退出
3. 样本分歧 → `probe_inconclusive`，**不惩罚**
4. 2xx 空回复 → `empty_reply` → 判降智（这是最关键的一条）
5. 非 2xx → `error`，不惩罚
6. 401/403/429 → `risk`，立即返回，不参与投票

## 四、四个必须知道的运维陷阱

### 1. `/app/config.yaml` 是只读副本

`docker/entrypoint.sh` 每次启动执行：

```sh
cp "${GROK2API_CONFIG_SOURCE}" /app/config.yaml
```

改容器内的 `/app/config.yaml` **重启即失效**。真正的配置文件是宿主机上 bind mount 进去的那个：

```bash
docker inspect grok2api --format '{{range .Mounts}}{{.Source}} -> {{.Destination}}{{"\n"}}{{end}}'
```

### 2. `autoDisable` 会独立启用质量守护

```go
Enabled: retry.Enabled || retry.AutoDisable
```

把 `requestRetry.enabled` 设成 false 但 `autoDisable` 还是 true，**检测依然生效**。要彻底关掉必须两个都关。

### 3. 池选偏好老账号

实测：损坏账号集中在 ID 较小（注册较早）的区间。池选会持续命中它们，每次请求重试 6 次全部失败，用户看到的就是全空。

短测的轮测游标从第 1 页开始，而老账号在**最后一页**。所以：

- 游标必须持久化（已实现，`account-probe-state.json`）
- 否则重启就回到第一页，永远扫不到出问题的那批

### 4. 探测强度过高会触发上游风控

`workers` 提到 8、跑几百个账号的扫描后，上游开始返回 `403 permission-denied`，且 `account_scoped: false`（全局，不是单账号问题）。

**`workers` 保持 2**。要加快覆盖速度，调 `chunkSize` 和 `interval`，不要加并发。

## 五、质量守护的推荐配置

请求路径的质量守护有一个容易造成误伤的默认组合：

```yaml
requestRetry:
  enabled: true
  holdTimeout: 30s          # 慢账号要 35 秒+ 才出内容
  onExhausted: fail_closed  # 超时直接 503，不给内容
  autoDisable: true         # 每次失败还禁用账号
  maxAttempts: 6            # 一次请求最多禁用 6 个
```

这个组合会把「慢」变成「503」，并且顺带大量禁用账号。建议：

```yaml
    onExhausted: fail_open
    autoDisable: false
```

**`holdTimeout` 不能调大。** 代码硬性限制在 200ms 到 30s 之间：

```go
if d := value.HoldTimeout.Value(); d != 0 && (d < 200*time.Millisecond || d > 30*time.Second) {
    return errors.New("qualityGuard.requestRetry.holdTimeout 必须在 200ms 到 30s 之间")
}
```

设成 90s 会让容器**启动即崩、无限重启**。应对「慢账号」只能靠 `fail_open`——超时后把已收到的内容发出去，而不是靠延长观察窗口。

`autoDisable: false` 之后，禁用工作交给短测探针——它用固定题目、多次采样，比按真实流量判断更准（实测现有检测器标记的账号里约有一半是误报）。

## 六、排查步骤

出现「请求返回空」时按顺序查：

1. **查审计**：`GET /request-audits?page=1&pageSize=200`，看 `outputTokens=0 && statusCode=200` 的占比
2. **按账号聚合**：找出零输出次数最多的账号 ID
3. **用短测探这些账号**：`POST /account-probe/run {"accountIds":[...]}`
4. **确认判据**：看返回的 `reasoningRatio`，健康应该在 4.4 以上，降智在 2.0 以下
5. **如果探针说健康但实际失败**：说明是请求路径问题，不是账号问题——对比探针路径（`accountProbe: true`）和普通路径的差异

## 七、已验证无效的方向

- 用 `tool_choice: "required"` 强制调用：上游只遵守约 50%，纯噪声
- 用流式请求测工具调用：Build 的流式响应里完全没有 `tool_calls`
- 用首字延迟早停：降智号也慢，无法提前判定
- 单次采样判定：降智是瞬时的，同一账号 ratio 会在 1.7 和 4.8 之间跳变
