import { apiRequest } from "@/shared/api/client";
import {
  createObjectDecoder,
  createValidatedDecoder,
  hasShape,
  isArrayOf,
  isBoolean,
  isNumber,
  isOptional,
  isOneOf,
  isString,
} from "@/shared/api/decoder";

export const accountProbePath = "/api/admin/v1/account-probe";

export type AccountProbeVerdict = "healthy" | "hard" | "risk" | "error";

export type AccountProbeConfig = {
  enabled: boolean;
  intervalHours: number;
  chunkSize: number;
  workers: number;
  model: string;
  /** "thinking" judges reasoning integrity, "tool" judges tool calling. */
  mode: string;
  prompt: string;
  maxOutputTokens: number;
  /**
   * Encrypted bytes required per claimed reasoning token. Coupled to the prompt:
   * 3.0 for the clock puzzle, about 3.8 for a short arithmetic question.
   */
  ratioThreshold: number;
  /** Read-only: the server funds probes from its own managed identity. */
  clientKeyId: number;
  earlyStopOnThinking: boolean;
  earlyStopDelayMs: number;
  cooldownHours: number;
  autoDisable: boolean;
};

/** Panel-editable subset; clientKeyId is server-managed and never sent back. */
export type AccountProbeEditableConfig = Omit<AccountProbeConfig, "clientKeyId">;

export type AccountProbeResult = {
  accountId: number;
  accountName: string;
  email: string;
  verdict: AccountProbeVerdict;
  reason: string;
  statusCode: number;
  hasThinking: boolean;
  reasoningBytes: number;
  /** Plaintext reasoning delta bytes; conclusive proof of thinking. */
  reasoningDeltaBytes: number;
  /** Encrypted-reasoning payload length; only counts above the scaled floor. */
  encryptedBytes: number;
  /** Encrypted length this reply had to reach, from its own reasoning tokens. */
  encryptionFloor: number;
  /**
   * Encrypted-reasoning bytes per claimed reasoning token. Healthy accounts sit
   * near 4.5-4.9 and degraded ones near 1.6-1.9, so this single number explains
   * the verdict.
   */
  reasoningRatio: number;
  outputTokens: number;
  reasoningTokens: number;
  visibleChars: number;
  firstTokenMs: number;
  durationMs: number;
  outputTps: number;
  egressNodeId: number;
  egressNodeName: string;
  earlyStop: boolean;
  model: string;
  error?: string;
  penalized: boolean;
  probedAt: string;
};

export type AccountProbeRun = {
  id: string;
  trigger: string;
  startedAt: string;
  finishedAt?: string;
  total: number;
  done: number;
  healthy: number;
  hard: number;
  risk: number;
  errors: number;
  penalized: number;
  running: boolean;
  lastError?: string;
  results: AccountProbeResult[];
};

export type AccountProbeStatus = {
  config: AccountProbeConfig;
  recent: AccountProbeResult[];
  runs: AccountProbeRun[];
};

const resultShape = hasShape({
  accountId: isNumber,
  accountName: isString,
  email: isString,
  verdict: isOneOf("healthy", "hard", "risk", "error"),
  reason: isString,
  statusCode: isNumber,
  hasThinking: isBoolean,
  reasoningBytes: isNumber,
  reasoningDeltaBytes: isNumber,
  encryptedBytes: isNumber,
  encryptionFloor: isNumber,
  reasoningRatio: isNumber,
  outputTokens: isNumber,
  reasoningTokens: isNumber,
  visibleChars: isNumber,
  firstTokenMs: isNumber,
  durationMs: isNumber,
  outputTps: isNumber,
  egressNodeId: isNumber,
  egressNodeName: isString,
  earlyStop: isBoolean,
  model: isString,
  error: isOptional(isString),
  penalized: isBoolean,
  probedAt: isString,
});

const runShape = hasShape({
  id: isString,
  trigger: isString,
  startedAt: isString,
  finishedAt: isOptional(isString),
  total: isNumber,
  done: isNumber,
  healthy: isNumber,
  hard: isNumber,
  risk: isNumber,
  errors: isNumber,
  penalized: isNumber,
  running: isBoolean,
  lastError: isOptional(isString),
  results: isArrayOf(resultShape),
});

const configShape = hasShape({
  enabled: isBoolean,
  intervalHours: isNumber,
  chunkSize: isNumber,
  workers: isNumber,
  model: isString,
  mode: isString,
  prompt: isString,
  maxOutputTokens: isNumber,
  ratioThreshold: isNumber,
  clientKeyId: isNumber,
  earlyStopOnThinking: isBoolean,
  earlyStopDelayMs: isNumber,
  cooldownHours: isNumber,
  autoDisable: isBoolean,
});

// Decoder shapes are predicates, not decoders: nested objects go through
// hasShape(...) and lists through isArrayOf(shape). Handing one decoder to
// createObjectDecoder does not type-check.
const runDecoder = createValidatedDecoder<AccountProbeRun>("accountProbeRun", runShape);

const statusDecoder = createObjectDecoder<AccountProbeStatus>("accountProbeStatus", {
  config: configShape,
  recent: isArrayOf(resultShape),
  runs: isArrayOf(runShape),
});

export async function fetchAccountProbeStatus(): Promise<AccountProbeStatus> {
  return apiRequest(accountProbePath, { method: "GET" }, statusDecoder);
}

export async function updateAccountProbeConfig(input: AccountProbeEditableConfig): Promise<void> {
  await apiRequest(`${accountProbePath}/config`, { method: "PUT", body: input }, createObjectDecoder<{ ok: boolean }>("accountProbeSave", { ok: isBoolean }));
}

export async function runAccountProbe(accountIds: number[]): Promise<AccountProbeRun> {
  return apiRequest(`${accountProbePath}/run`, { method: "POST", body: { accountIds } }, runDecoder);
}

export async function stopAccountProbe(): Promise<boolean> {
  const data = await apiRequest(`${accountProbePath}/stop`, { method: "POST" }, createObjectDecoder<{ stopped: boolean }>("accountProbeStop", { stopped: isBoolean }));
  return data.stopped;
}
