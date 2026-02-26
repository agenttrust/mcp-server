#!/usr/bin/env node

import { randomUUID } from 'crypto';
import { promises as fs } from 'fs';
import os from 'os';
import path from 'path';
import readline from 'readline/promises';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import fetch from 'node-fetch';
import nacl from 'tweetnacl';
import {
  Method,
  Role,
  TaskState,
  TaskStateLabel,
  TextPart,
  buildMessage,
  buildRpcEnvelope,
  normalizeState,
} from './a2a-format.js';
import { IDENTITY_URI, PlatformStateLabel, extensionsFromMeta } from './platform-metadata.js';

const DEFAULT_API_BASE_URL = 'https://us-central1-agenttrustai.cloudfunctions.net';
const DEFAULT_ENDPOINT = 'https://agenttrust-test.web.app';
const CONFIG_DIR = path.join(os.homedir(), '.agenttrust');
const CONFIG_PATH = path.join(CONFIG_DIR, 'config.json');
const KEY_DIR = path.join(CONFIG_DIR, 'keys');

interface RuntimeConfig {
  apiKey: string | null;
  endpoint: string;
  apiBaseUrl: string;
  slug: string | null;
  agentId: string | null;
}

interface JsonRpcResponse<T> {
  jsonrpc: '2.0';
  id: string | number | null;
  result?: T;
  error?: {
    code: number;
    message: string;
  };
}

interface ApiTaskItem {
  id: string;
  sender?: string | null;
  recipient?: string | null;
  turn?: string | null;
  from: {
    slug: string | null;
    name: string | null;
    orgName?: string | null;
    verified: boolean;
    anonymous: boolean;
  };
  status: {
    state: string;
    timestamp: string;
  };
  lastMessage: {
    parts: Array<{ kind: typeof TextPart.KIND; text: string }>;
  } | null;
  messageCount: number;
  createdAt: string;
}

interface ApiTaskContext {
  sender?: string | null;
  recipient?: string | null;
  from?: {
    slug?: string | null;
  };
  to?: {
    slug?: string | null;
  };
}

interface AgentProfile {
  agent_id?: string;
  slug?: string;
  name?: string;
  org?: string;
  org_name?: string;
}

interface ApiContactItem {
  contact?: {
    slug?: string | null;
    orgName?: string | null;
  };
  createdAt?: string;
  updatedAt?: string;
}

interface ApiContactsResponse {
  contacts?: ApiContactItem[];
}

let runtimeConfigCache: RuntimeConfig | null = null;
let runtimeConfigPending: Promise<RuntimeConfig> | null = null;
const signingKeyCache = new Map<string, Uint8Array>();

function makeError(message: string): Error {
  return new Error(message);
}

async function parseJson<T>(response: { text: () => Promise<string> }): Promise<T> {
  const text = await response.text();
  if (!text) return {} as T;
  return JSON.parse(text) as T;
}

function safeUrl(base: string, pathname: string): string {
  return new URL(pathname, base.endsWith('/') ? base : `${base}/`).toString();
}

function readString(value: unknown): string | null {
  return typeof value === 'string' && value.trim() ? value.trim() : null;
}

async function readConfigFile(): Promise<Record<string, unknown> | null> {
  try {
    const raw = await fs.readFile(CONFIG_PATH, 'utf8');
    return JSON.parse(raw) as Record<string, unknown>;
  } catch {
    return null;
  }
}

async function writeConfigFile(config: RuntimeConfig): Promise<void> {
  await fs.mkdir(CONFIG_DIR, { recursive: true });
  const serializable = {
    apiKey: config.apiKey,
    endpoint: config.endpoint,
    apiBaseUrl: config.apiBaseUrl,
    slug: config.slug,
    agentId: config.agentId,
  };
  await fs.writeFile(CONFIG_PATH, JSON.stringify(serializable, null, 2), { encoding: 'utf8', mode: 0o600 });
}

function resolveConfig(fileConfig: Record<string, unknown> | null): RuntimeConfig {
  const source = fileConfig || {};
  const apiKey = readString(source.apiKey) || readString(process.env.AGENTTRUST_API_KEY);
  const endpoint = readString(source.endpoint) || readString(process.env.AGENTTRUST_ENDPOINT) || DEFAULT_ENDPOINT;
  const apiBaseUrl = readString(source.apiBaseUrl)
    || readString(process.env.AGENTTRUST_API_BASE_URL)
    || readString(process.env.AGENTTRUST_API_URL)
    || DEFAULT_API_BASE_URL;
  const slug = readString(source.slug) || readString(process.env.AGENTTRUST_SLUG);
  const agentId = readString(source.agentId) || readString(process.env.AGENTTRUST_AGENT_ID);
  return { apiKey, endpoint, apiBaseUrl, slug, agentId };
}

async function fetchAgentBySlug(endpoint: string, apiKey: string, slug: string): Promise<AgentProfile | null> {
  try {
    return await apiRequest<AgentProfile>(
      safeUrl(endpoint, `/a/${encodeURIComponent(slug)}?format=json`),
      { method: 'GET', apiKey },
    );
  } catch {
    return null;
  }
}

async function fetchSingleAccessibleAgent(endpoint: string, apiKey: string): Promise<AgentProfile | null> {
  try {
    const payload = await apiRequest<{ agents?: AgentProfile[] }>(
      safeUrl(endpoint, '/api/agents?limit=2'),
      { method: 'GET', apiKey },
    );
    if (!Array.isArray(payload.agents) || payload.agents.length !== 1) return null;
    return payload.agents[0] || null;
  } catch {
    return null;
  }
}

async function loadRuntimeConfigInternal(): Promise<RuntimeConfig> {
  const fileConfig = await readConfigFile();
  const hasDiskConfig = fileConfig !== null;
  const resolved = resolveConfig(fileConfig);

  // Silent bootstrap: if no config exists but env API key is present, infer identity and save config.
  if (!hasDiskConfig && resolved.apiKey) {
    let slug = resolved.slug;
    let agentId = resolved.agentId;

    if (slug) {
      const profile = await fetchAgentBySlug(resolved.endpoint, resolved.apiKey, slug);
      slug = readString(profile?.slug) || slug;
      agentId = readString(profile?.agent_id) || agentId;
    } else {
      const profile = await fetchSingleAccessibleAgent(resolved.endpoint, resolved.apiKey);
      slug = readString(profile?.slug) || slug;
      agentId = readString(profile?.agent_id) || agentId;
    }

    // Persist only when we can resolve agent identity. This keeps stdio startup non-interactive.
    if (slug && agentId) {
      const bootstrapped: RuntimeConfig = {
        ...resolved,
        slug,
        agentId,
      };
      await writeConfigFile(bootstrapped);
      return bootstrapped;
    }
  }

  return resolved;
}

async function loadRuntimeConfig(opts?: { refresh?: boolean }): Promise<RuntimeConfig> {
  const refresh = opts?.refresh === true;
  if (!refresh && runtimeConfigCache) return runtimeConfigCache;
  if (!refresh && runtimeConfigPending) return runtimeConfigPending;

  runtimeConfigPending = loadRuntimeConfigInternal();
  try {
    const config = await runtimeConfigPending;
    runtimeConfigCache = config;
    return config;
  } finally {
    runtimeConfigPending = null;
  }
}

function requireConfigured(config: RuntimeConfig, toolName: string, opts?: { requireSlug?: boolean }): void {
  if (!config.apiKey) {
    throw makeError(`AgentTrust not configured for ${toolName}. Set AGENTTRUST_API_KEY or create ~/.agenttrust/config.json`);
  }
  if (opts?.requireSlug && !config.slug) {
    throw makeError(`AgentTrust slug is required for ${toolName}. Set slug in ~/.agenttrust/config.json or AGENTTRUST_SLUG`);
  }
}

async function apiRequest<T>(
  url: string,
  init: {
    method?: 'GET' | 'POST' | 'DELETE' | 'PATCH';
    apiKey?: string | null;
    body?: Record<string, unknown>;
    timeoutMs?: number;
  },
): Promise<T> {
  const headers: Record<string, string> = {};
  if (init.apiKey) headers['x-api-key'] = init.apiKey;
  if (init.body) headers['Content-Type'] = 'application/json';
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), init.timeoutMs ?? 20_000);

  let response;
  try {
    response = await fetch(url, {
      method: init.method || 'GET',
      headers,
      body: init.body ? JSON.stringify(init.body) : undefined,
      signal: controller.signal,
    });
  } catch (error) {
    if ((error as Error).name === 'AbortError') {
      throw makeError(`Request timed out: ${url}`);
    }
    throw error;
  } finally {
    clearTimeout(timeout);
  }

  if (!response.ok) {
    const payload = await parseJson<{ error?: string }>(response);
    throw makeError(payload.error || `HTTP ${response.status}`);
  }
  return parseJson<T>(response);
}

function keyPathForSlug(slug: string): string {
  return path.join(KEY_DIR, `${slug}.key`);
}

async function registerPublicKey(config: RuntimeConfig, publicKey: Uint8Array): Promise<void> {
  if (!config.apiKey) throw makeError('API key is required to register signing key');
  await apiRequest(
    safeUrl(config.endpoint, '/api/keys'),
    {
      method: 'POST',
      apiKey: config.apiKey,
      body: {
        public_key: `ed25519:${Buffer.from(publicKey).toString('base64')}`,
      },
    },
  );
}

async function revokePublicKey(config: RuntimeConfig): Promise<void> {
  if (!config.apiKey) throw makeError('API key is required to revoke signing key');
  await apiRequest(
    safeUrl(config.endpoint, '/api/keys'),
    {
      method: 'DELETE',
      apiKey: config.apiKey,
      body: {},
    },
  );
}

async function readSigningKeyFromDisk(slug: string): Promise<Uint8Array | null> {
  try {
    const raw = await fs.readFile(keyPathForSlug(slug), 'utf8');
    const secret = Buffer.from(raw.trim(), 'base64');
    if (secret.length !== 64) return null;
    return new Uint8Array(secret);
  } catch {
    return null;
  }
}

async function writeSigningKeyToDisk(slug: string, secretKey: Uint8Array): Promise<void> {
  await fs.mkdir(KEY_DIR, { recursive: true });
  await fs.writeFile(
    keyPathForSlug(slug),
    Buffer.from(secretKey).toString('base64'),
    { encoding: 'utf8', mode: 0o600 },
  );
}

async function createAndRegisterSigningKey(config: RuntimeConfig): Promise<Uint8Array> {
  if (!config.slug) throw makeError('Cannot generate key without agent slug');
  const pair = nacl.sign.keyPair();
  await writeSigningKeyToDisk(config.slug, pair.secretKey);
  try {
    await registerPublicKey(config, pair.publicKey);
    signingKeyCache.set(config.slug, pair.secretKey);
    return pair.secretKey;
  } catch (error) {
    try {
      await fs.unlink(keyPathForSlug(config.slug));
    } catch {
      // no-op
    }
    throw error;
  }
}

async function getOrCreateSigningKey(config: RuntimeConfig): Promise<Uint8Array | null> {
  if (!config.slug || !config.apiKey) return null;
  const cached = signingKeyCache.get(config.slug);
  if (cached) return cached;

  const diskKey = await readSigningKeyFromDisk(config.slug);
  if (diskKey) {
    signingKeyCache.set(config.slug, diskKey);
    return diskKey;
  }

  try {
    const secret = await createAndRegisterSigningKey(config);
    console.error(`Keypair generated and registered for ${config.slug}`);
    return secret;
  } catch (error) {
    console.error(`Warning: keypair generation/registration failed: ${(error as Error).message}`);
    return null;
  }
}

async function rotateSigningKey(config: RuntimeConfig): Promise<void> {
  if (!config.slug || !config.apiKey) throw makeError('slug and apiKey are required for key rotation');

  // Best effort revoke current key; continue even if key is already absent.
  try {
    await revokePublicKey(config);
  } catch {
    // no-op
  }

  const pair = nacl.sign.keyPair();
  await writeSigningKeyToDisk(config.slug, pair.secretKey);
  try {
    await registerPublicKey(config, pair.publicKey);
    signingKeyCache.set(config.slug, pair.secretKey);
  } catch (error) {
    try {
      await fs.unlink(keyPathForSlug(config.slug));
    } catch {
      // no-op
    }
    throw error;
  }
}

async function signMessage(
  config: RuntimeConfig,
  recipientSlug: string,
  messageText: string,
): Promise<{ signature: string; nonce: string; timestamp: string } | null> {
  if (!config.slug) return null;
  const secretKey = await getOrCreateSigningKey(config);
  if (!secretKey) return null;
  const nonce = randomUUID();
  const timestamp = new Date().toISOString();
  const payload = [config.slug, recipientSlug, messageText, nonce, timestamp].join('\n');
  const signatureBytes = nacl.sign.detached(Buffer.from(payload, 'utf8'), secretKey);
  return {
    signature: Buffer.from(signatureBytes).toString('base64'),
    nonce,
    timestamp,
  };
}

function buildSignedIdentityMetadata(
  config: RuntimeConfig,
  signed: { signature: string; nonce: string; timestamp: string } | null,
): Record<string, unknown> | undefined {
  if (!signed) return undefined;
  return {
    [IDENTITY_URI]: {
      slug: config.slug,
      agentId: config.agentId,
      signature: signed.signature,
      nonce: signed.nonce,
      timestamp: signed.timestamp,
    },
  };
}

function resolveCounterpartySlug(context: ApiTaskContext, selfSlug: string): string {
  const sender = typeof context.sender === 'string' && context.sender.trim() ? context.sender.trim().toLowerCase() : '';
  const recipient = typeof context.recipient === 'string' && context.recipient.trim() ? context.recipient.trim().toLowerCase() : '';
  if (sender && recipient) return sender === selfSlug ? recipient : sender;
  const fromSlug = typeof context.from?.slug === 'string' && context.from.slug.trim() ? context.from.slug.trim().toLowerCase() : '';
  const toSlug = typeof context.to?.slug === 'string' && context.to.slug.trim() ? context.to.slug.trim().toLowerCase() : '';
  if (fromSlug && toSlug) return fromSlug === selfSlug ? toSlug : fromSlug;
  return fromSlug || toSlug || 'unknown';
}

async function getTaskContext(config: RuntimeConfig, taskId: string): Promise<ApiTaskContext> {
  return apiRequest<ApiTaskContext>(
    safeUrl(config.endpoint, `/r/${encodeURIComponent(config.slug || '')}/inbox/${encodeURIComponent(taskId)}`),
    { method: 'GET', apiKey: config.apiKey },
  );
}

function toTextResult(payload: unknown) {
  return {
    content: [
      {
        type: 'text' as const,
        text: JSON.stringify(payload, null, 2),
      },
    ],
  };
}

function toDateOnly(value: unknown): string | null {
  const raw = readString(value);
  if (!raw) return null;
  const parsed = new Date(raw);
  if (Number.isNaN(parsed.getTime())) return null;
  return parsed.toISOString().slice(0, 10);
}

const A2A_STATE_VALUES = new Set<string>(Object.values(TaskState));

function normalizeStatusFilterArg(raw: string): string {
  const value = raw.trim();
  if (!value) return '';
  if (value === 'awaiting-response') return normalizeState(value);
  if (A2A_STATE_VALUES.has(value) || value.startsWith('TASK_STATE_')) return normalizeState(value);
  return value;
}

async function fetchKeyStatus(config: RuntimeConfig): Promise<Record<string, unknown>> {
  if (!config.slug || !config.apiKey) return {};
  try {
    return await apiRequest<Record<string, unknown>>(
      safeUrl(config.endpoint, `/a/${encodeURIComponent(config.slug)}/key`),
      { method: 'GET', apiKey: config.apiKey },
    );
  } catch {
    return {};
  }
}

function formatStatusValue(value: unknown): string {
  if (value === null || value === undefined) return '-';
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  return JSON.stringify(value);
}

async function runStatusCommand(): Promise<number> {
  const config = await loadRuntimeConfig();
  const keyPath = config.slug ? keyPathForSlug(config.slug) : null;
  let hasLocalKey = false;
  if (keyPath) {
    try {
      await fs.access(keyPath);
      hasLocalKey = true;
    } catch {
      hasLocalKey = false;
    }
  }

  const keyStatus = await fetchKeyStatus(config);
  console.log('AgentTrust MCP status');
  console.log('---------------------');
  console.log(`Config file: ${CONFIG_PATH}`);
  console.log(`API key: ${config.apiKey ? 'configured' : 'missing'}`);
  console.log(`Endpoint: ${config.endpoint}`);
  console.log(`API base URL: ${config.apiBaseUrl}`);
  console.log(`Slug: ${config.slug || '-'}`);
  console.log(`Agent ID: ${config.agentId || '-'}`);
  console.log(`Local signing key: ${hasLocalKey ? 'present' : 'missing'}`);
  if (Object.keys(keyStatus).length > 0) {
    console.log(`Remote key status: ${formatStatusValue(keyStatus.key_status)}`);
    console.log(`Remote key id: ${formatStatusValue(keyStatus.key_id)}`);
    console.log(`Remote key expires: ${formatStatusValue(keyStatus.expires_at || keyStatus.key_expires_at)}`);
  }
  return config.apiKey ? 0 : 1;
}

async function promptInput(promptText: string): Promise<string> {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });
  try {
    const value = await rl.question(promptText);
    return value.trim();
  } finally {
    rl.close();
  }
}

async function resolveAgentIdentityForSetup(
  endpoint: string,
  apiKey: string,
  preferredSlug: string | null,
): Promise<{ slug: string; agentId: string } | null> {
  if (preferredSlug) {
    const profile = await fetchAgentBySlug(endpoint, apiKey, preferredSlug);
    const slug = readString(profile?.slug) || preferredSlug;
    const agentId = readString(profile?.agent_id);
    if (slug && agentId) return { slug, agentId };
  }

  const single = await fetchSingleAccessibleAgent(endpoint, apiKey);
  const singleSlug = readString(single?.slug);
  const singleAgentId = readString(single?.agent_id);
  if (singleSlug && singleAgentId) return { slug: singleSlug, agentId: singleAgentId };
  return null;
}

async function runInitCommand(): Promise<number> {
  console.log('AgentTrust MCP Server Setup');
  console.log('---------------------------');

  const existingConfig = await readConfigFile();
  const initial = resolveConfig(existingConfig);

  let apiKey = initial.apiKey || await promptInput('API key (atk_...): ');
  if (!apiKey) {
    console.error('API key is required.');
    return 1;
  }

  const endpointInput = await promptInput(`Endpoint [${initial.endpoint}]: `);
  const endpoint = endpointInput || initial.endpoint;
  const apiBaseInput = await promptInput(`API base URL [${initial.apiBaseUrl}]: `);
  const apiBaseUrl = apiBaseInput || initial.apiBaseUrl;

  let slug = initial.slug || null;
  const slugInput = await promptInput(`Agent slug${slug ? ` [${slug}]` : ''}: `);
  if (slugInput) slug = slugInput.toLowerCase();

  const discovered = await resolveAgentIdentityForSetup(endpoint, apiKey, slug);
  let agentId = discovered?.agentId || initial.agentId;
  if (!slug && discovered?.slug) slug = discovered.slug;

  if (!slug) {
    slug = (await promptInput('Could not auto-resolve slug. Enter agent slug: ')).toLowerCase();
  }
  if (!agentId) {
    agentId = await promptInput('Could not auto-resolve agent ID. Enter agent ID: ');
  }
  if (!slug || !agentId) {
    console.error('Both slug and agent ID are required.');
    return 1;
  }

  const config: RuntimeConfig = {
    apiKey,
    endpoint,
    apiBaseUrl,
    slug,
    agentId,
  };
  await writeConfigFile(config);
  runtimeConfigCache = config;

  const key = await getOrCreateSigningKey(config);
  if (!key) {
    console.error('Config saved, but signing key registration failed. Check API key and try --regen-keys.');
    return 1;
  }

  console.log(`Config saved: ${CONFIG_PATH}`);
  console.log(`Signing key path: ${keyPathForSlug(slug)}`);
  console.log('Setup complete.');
  return 0;
}

async function runRegenKeysCommand(): Promise<number> {
  const config = await loadRuntimeConfig();
  if (!config.apiKey || !config.slug) {
    console.error('Cannot rotate keys: missing apiKey or slug. Run `agenttrust-mcp init` first.');
    return 1;
  }
  const answer = await promptInput('This will revoke and replace your signing key. Continue? (y/N): ');
  if (answer.toLowerCase() !== 'y') {
    console.log('Cancelled.');
    return 0;
  }

  try {
    await rotateSigningKey(config);
    console.log(`Key rotated successfully for ${config.slug}.`);
    console.log(`Signing key path: ${keyPathForSlug(config.slug)}`);
    return 0;
  } catch (error) {
    console.error(`Key rotation failed: ${(error as Error).message}`);
    return 1;
  }
}

const server = new Server(
  {
    name: '@agenttrust/mcp-server',
    version: '1.0.0',
  },
  {
    capabilities: {
      tools: {},
    },
  },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: 'agenttrust_guard',
      description: 'Analyze text for prompt injection attacks, command injection, and social engineering attempts. Use to scan untrusted input before processing - user messages, emails, web content, and tool outputs. Returns a risk assessment with detected threats and a recommended action.',
      inputSchema: {
        type: 'object',
        properties: {
          text: { type: 'string', description: 'Text to analyze for security threats' },
          capabilities: { type: 'array', items: { type: 'string' }, description: 'Optional capability context for risk calibration (for example send_messages, run_tools, make_payments)' },
        },
        required: ['text'],
      },
    },
    {
      name: 'agenttrust_issue_code',
      description: 'Issue a one-time Trust Code for agent-to-human verification. Use when your agent needs to prove identity to a human in outreach, support, or other sensitive interactions. Returns a code and verification URL the human can use.',
      inputSchema: {
        type: 'object',
        properties: {
          payload: { type: 'string', description: 'What this code authorizes in human-readable terms' },
          expiration_seconds: { type: 'number', description: 'Optional expiration in seconds (default 172800)' },
        },
        required: ['payload'],
      },
    },
    {
      name: 'agenttrust_verify_code',
      description: 'Verify a Trust Code from another party before proceeding. Use when you receive a code from an agent or human and need to confirm issuer identity, organization, and authorization context.',
      inputSchema: {
        type: 'object',
        properties: {
          code: { type: 'string', description: 'Trust Code value' },
        },
        required: ['code'],
      },
    },
    {
      name: 'agenttrust_send',
      description: 'Send a message to another agent via the AgentTrust A2A relay. Creates a new task or continues an existing one when taskId is provided. Use agenttrust_discover first if you need to find recipient slugs.',
      inputSchema: {
        type: 'object',
        properties: {
          to: { type: 'string', description: 'Recipient slug' },
          message: { type: 'string', description: 'Message text' },
          taskId: { type: 'string', description: 'Optional task ID to continue a thread' },
        },
        required: ['to', 'message'],
      },
    },
    {
      name: 'agenttrust_inbox',
      description: 'Check your A2A inbox for incoming tasks from other agents. Use this to triage pending work, inspect task status, and choose what to open with agenttrust_context.',
      inputSchema: {
        type: 'object',
        properties: {
          status: { type: 'string', description: 'Optional task status filter' },
          turn: { type: 'string', description: 'Optional turn filter (e.g. your slug)' },
          limit: { type: 'number', description: 'Optional max results (1-100)' },
        },
        required: [],
      },
    },
    {
      name: 'agenttrust_reply',
      description: 'Reply to an existing A2A task and optionally update its status. AgentTrust extends the A2A protocol with a negotiation lifecycle. Status values and when to use them:\n\n- "working" — you are actively working on this task\n- "input-required" — you need more information from the other agent before continuing\n- "propose_complete" — you believe the work is done; proposes closure (the other party must confirm with "completed")\n- "completed" — ONLY use to confirm after the other party sent "propose_complete"; do NOT set this directly to close your own task\n- "disputed" — you disagree with something (a deliverable, a term, a claim)\n- "failed" — you cannot fulfil the request\n- "canceled" — you are stopping this task\n- "rejected" — you are rejecting this task or proposal outright\n\nOmit status to continue the conversation without changing state.',
      inputSchema: {
        type: 'object',
        properties: {
          taskId: { type: 'string', description: 'Task ID to reply to' },
          message: { type: 'string', description: 'Reply text' },
          status: { type: 'string', enum: ['working', 'input-required', 'propose_complete', 'completed', 'disputed', 'failed', 'canceled', 'rejected'], description: 'Task status update. "working" = in progress. "input-required" = need info. "propose_complete" = proposing closure. "completed" = confirming closure (only after other party proposed). "disputed" = disagreement. "failed" = cannot do. "canceled" = stopping. "rejected" = rejecting outright. Omit to keep current status.' },
        },
        required: ['taskId', 'message'],
      },
    },
    {
      name: 'agenttrust_comment',
      description: 'Add a comment to a task without changing turn or task state. Use for notes, rationale, or coordination context; set internal=true for comments visible only to your side.',
      inputSchema: {
        type: 'object',
        properties: {
          taskId: { type: 'string', description: 'Task ID' },
          text: { type: 'string', description: 'Comment text' },
          internal: { type: 'boolean', description: 'If true, only visible to your side' },
        },
        required: ['taskId', 'text'],
      },
    },
    {
      name: 'agenttrust_escalate',
      description: 'Escalate an A2A task for human review through HITL. Use when you are uncertain, the request exceeds your authorization, or you need human approval before proceeding. The task is held until a human reviews and responds.',
      inputSchema: {
        type: 'object',
        properties: {
          taskId: { type: 'string', description: 'Task ID' },
          reason: { type: 'string', description: 'Escalation reason shown to human reviewer' },
        },
        required: ['taskId', 'reason'],
      },
    },
    {
      name: 'agenttrust_context',
      description: 'Get conversation history for a task in light or full mode. Use before replying when you need complete context, including prior messages, status transitions, and review actions.',
      inputSchema: {
        type: 'object',
        properties: {
          taskId: { type: 'string', description: 'Task ID' },
          mode: { type: 'string', description: 'light (default) or full' },
        },
        required: ['taskId'],
      },
    },
    {
      name: 'agenttrust_discover',
      description: 'Search the AgentTrust directory for agents by name, skill, or organization. Provide query to filter results, or leave it empty to list all publicly discoverable agents.',
      inputSchema: {
        type: 'object',
        properties: {
          query: { type: 'string', description: 'Optional search term; if empty, returns all public agents' },
        },
        required: [],
      },
    },
    {
      name: 'agenttrust_status',
      description: 'Check your current AgentTrust identity and runtime status, including endpoint identity, signing key status, and pending task count.',
      inputSchema: {
        type: 'object',
        properties: {},
        required: [],
      },
    },
    {
      name: 'agenttrust_cancel',
      description: 'Cancel an ongoing A2A task. Use when work should stop and both sides should see the task as canceled.',
      inputSchema: {
        type: 'object',
        properties: {
          taskId: { type: 'string', description: 'Task ID to cancel' },
        },
        required: ['taskId'],
      },
    },
    {
      name: 'agenttrust_allowlist',
      description: 'View your organization allowlist to see which agents and organizations are permitted to contact your agents. This tool is read-only; allowlist changes are managed by your org admin in the AgentTrust dashboard.',
      inputSchema: {
        type: 'object',
        properties: {},
        required: [],
      },
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    const config = await loadRuntimeConfig();

    if (name === 'agenttrust_guard') {
      requireConfigured(config, name);
      const text = typeof args?.text === 'string' ? args.text : '';
      if (!text.trim()) throw makeError('text is required');
      const capabilities = Array.isArray(args?.capabilities) ? args.capabilities : [];
      const result = await apiRequest<Record<string, unknown>>(
        safeUrl(config.apiBaseUrl, '/injectionGuard'),
        {
          method: 'POST',
          apiKey: config.apiKey,
          body: { text, capabilities },
        },
      );
      return toTextResult(result);
    }

    if (name === 'agenttrust_issue_code') {
      requireConfigured(config, name);
      const payload = typeof args?.payload === 'string' ? args.payload : '';
      if (!payload.trim()) throw makeError('payload is required');
      const expirationSeconds = typeof args?.expiration_seconds === 'number' ? args.expiration_seconds : 172800;
      const result = await apiRequest<Record<string, unknown>>(
        safeUrl(config.apiBaseUrl, '/issue'),
        {
          method: 'POST',
          apiKey: config.apiKey,
          body: {
            payload,
            expiration_seconds: expirationSeconds,
          },
        },
      );
      return toTextResult(result);
    }

    if (name === 'agenttrust_verify_code') {
      requireConfigured(config, name);
      const code = typeof args?.code === 'string' ? args.code : '';
      if (!code.trim()) throw makeError('code is required');
      const result = await apiRequest<Record<string, unknown>>(
        safeUrl(config.apiBaseUrl, '/verify'),
        {
          method: 'POST',
          apiKey: config.apiKey,
          body: { code },
        },
      );
      return toTextResult(result);
    }

    if (name === 'agenttrust_send') {
      requireConfigured(config, name, { requireSlug: true });
      const to = typeof args?.to === 'string' ? args.to.trim().toLowerCase() : '';
      const message = typeof args?.message === 'string' ? args.message.trim() : '';
      const taskId = typeof args?.taskId === 'string' ? args.taskId.trim() : '';
      if (!to || !message) throw makeError('to and message are required');
      const signed = await signMessage(config, to, message);
      const metadata = buildSignedIdentityMetadata(config, signed);
      const extensions = metadata ? extensionsFromMeta(metadata) : undefined;
      const rpc = buildRpcEnvelope(
        Method.SEND_MESSAGE,
        {
          message: buildMessage(Role.USER, message, {
            messageId: randomUUID(),
            ...(metadata ? { metadata } : {}),
            ...(extensions?.length ? { extensions } : {}),
          }),
          ...(taskId ? { taskId } : {}),
        },
        randomUUID(),
      );

      const raw = await apiRequest<JsonRpcResponse<{ id: string; status: { state: string } }>>(
        safeUrl(config.endpoint, `/r/${encodeURIComponent(to)}`),
        {
          method: 'POST',
          apiKey: config.apiKey,
          body: rpc as unknown as Record<string, unknown>,
        },
      );
      if (raw.error) throw makeError(raw.error.message);
      const state = raw.result?.status?.state ? normalizeState(raw.result.status.state) : '';
      return toTextResult({
        taskId: raw.result?.id,
        status: state || raw.result?.status?.state,
        statusLabel: state ? (TaskStateLabel[state] || PlatformStateLabel[state] || state) : undefined,
        to,
        verified: Boolean(signed),
      });
    }

    if (name === 'agenttrust_inbox') {
      requireConfigured(config, name, { requireSlug: true });
      const status = typeof args?.status === 'string' ? normalizeStatusFilterArg(args.status) : '';
      const turn = typeof args?.turn === 'string' ? args.turn.trim() : '';
      const limit = typeof args?.limit === 'number' ? Math.max(1, Math.min(100, Math.floor(args.limit))) : 20;
      const url = new URL(safeUrl(config.endpoint, `/r/${encodeURIComponent(config.slug || '')}/inbox`));
      url.searchParams.set('limit', String(limit));
      if (status) url.searchParams.set('status', status);
      if (turn) url.searchParams.set('turn', turn);
      const payload = await apiRequest<{ tasks: ApiTaskItem[]; total: number }>(url.toString(), {
        method: 'GET',
        apiKey: config.apiKey,
      });
      const tasks = (payload.tasks || []).map((task) => {
        const fromSlug = task.from.slug || 'unknown';
        const fromName = task.from.name || 'Unknown sender';
        const org = task.from.orgName ? `, ${task.from.orgName}` : '';
        const badge = task.from.verified ? 'Verified' : (task.from.anonymous ? 'Unknown sender' : 'Unverified');
        const normalizedState = normalizeState(task.status.state);
        return {
          taskId: task.id,
          from: `${fromSlug} (${fromName}${org}) ${badge}`,
          status: normalizedState,
          statusLabel: TaskStateLabel[normalizedState] || PlatformStateLabel[normalizedState] || task.status.state,
          turn: task.turn || null,
          preview: task.lastMessage?.parts?.[0]?.text || '',
          messages: task.messageCount,
          receivedAt: task.createdAt,
        };
      });
      return toTextResult({ tasks, total: payload.total ?? tasks.length });
    }

    if (name === 'agenttrust_reply') {
      requireConfigured(config, name, { requireSlug: true });
      const taskId = typeof args?.taskId === 'string' ? args.taskId.trim() : '';
      const message = typeof args?.message === 'string' ? args.message.trim() : '';
      const status = typeof args?.status === 'string' ? normalizeStatusFilterArg(args.status) : '';
      if (!taskId || !message) throw makeError('taskId and message are required');

      const context = await getTaskContext(config, taskId);
      const recipientSlug = resolveCounterpartySlug(context, config.slug || '');
      const signed = await signMessage(config, recipientSlug, message);
      const metadata = buildSignedIdentityMetadata(config, signed);
      const result = await apiRequest<Record<string, unknown>>(
        safeUrl(config.endpoint, `/r/${encodeURIComponent(config.slug || '')}/inbox/${encodeURIComponent(taskId)}/reply`),
        {
          method: 'POST',
          apiKey: config.apiKey,
          body: {
            message,
            ...(status ? { status } : {}),
            ...(metadata ? { metadata } : {}),
            ...(signed ? signed : {}),
          },
        },
      );
      return toTextResult({
        ...result,
        verified: Boolean(signed),
      });
    }

    if (name === 'agenttrust_comment') {
      requireConfigured(config, name, { requireSlug: true });
      const taskId = typeof args?.taskId === 'string' ? args.taskId.trim() : '';
      const text = typeof args?.text === 'string' ? args.text.trim() : '';
      const internal = args?.internal === true;
      if (!taskId || !text) throw makeError('taskId and text are required');

      const context = await getTaskContext(config, taskId);
      const recipientSlug = resolveCounterpartySlug(context, config.slug || '');
      const signed = await signMessage(config, recipientSlug, text);
      const metadata = buildSignedIdentityMetadata(config, signed);
      const result = await apiRequest<Record<string, unknown>>(
        safeUrl(config.endpoint, `/r/${encodeURIComponent(config.slug || '')}/inbox/${encodeURIComponent(taskId)}/reply`),
        {
          method: 'POST',
          apiKey: config.apiKey,
          body: {
            message: text,
            comment: true,
            ...(internal ? { internal: true } : {}),
            ...(metadata ? { metadata } : {}),
            ...(signed ? signed : {}),
          },
        },
      );
      return toTextResult({
        ...result,
        internal,
        verified: Boolean(signed),
      });
    }

    if (name === 'agenttrust_escalate') {
      requireConfigured(config, name, { requireSlug: true });
      const taskId = typeof args?.taskId === 'string' ? args.taskId.trim() : '';
      const reason = typeof args?.reason === 'string' ? args.reason.trim() : '';
      if (!taskId || !reason) throw makeError('taskId and reason are required');

      const context = await getTaskContext(config, taskId);
      const recipientSlug = resolveCounterpartySlug(context, config.slug || '');
      const signed = await signMessage(config, recipientSlug, reason);
      const metadata = buildSignedIdentityMetadata(config, signed);
      const result = await apiRequest<Record<string, unknown>>(
        safeUrl(config.endpoint, `/r/${encodeURIComponent(config.slug || '')}/inbox/${encodeURIComponent(taskId)}/reply`),
        {
          method: 'POST',
          apiKey: config.apiKey,
          body: {
            message: reason,
            comment: true,
            escalate: true,
            ...(metadata ? { metadata } : {}),
            ...(signed ? signed : {}),
          },
        },
      );
      return toTextResult({
        ...result,
        verified: Boolean(signed),
      });
    }

    if (name === 'agenttrust_context') {
      requireConfigured(config, name, { requireSlug: true });
      const taskId = typeof args?.taskId === 'string' ? args.taskId.trim() : '';
      const mode = typeof args?.mode === 'string' ? args.mode.trim().toLowerCase() : 'light';
      if (!taskId) throw makeError('taskId is required');
      const payload = await apiRequest<Record<string, unknown>>(
        safeUrl(config.endpoint, `/r/${encodeURIComponent(config.slug || '')}/inbox/${encodeURIComponent(taskId)}`),
        {
          method: 'GET',
          apiKey: config.apiKey,
        },
      );
      if (mode === 'full') return toTextResult(payload);

      const status = typeof (payload.status as Record<string, unknown> | undefined)?.state === 'string'
        ? String((payload.status as Record<string, unknown>).state)
        : 'unknown';
      const history = Array.isArray(payload.history) ? payload.history as Array<Record<string, unknown>> : [];
      const lines = [`Task: ${taskId} | Status: ${status}`, `Messages: ${history.length}`, ''];
      history.forEach((entry, idx) => {
        const role = typeof entry.role === 'string' ? entry.role : 'unknown';
        const parts = Array.isArray(entry.parts) ? entry.parts as Array<Record<string, unknown>> : [];
        const text = parts
          .map((part) => (typeof part.text === 'string' ? part.text : ''))
          .filter(Boolean)
          .join('\n');
        lines.push(`[${idx + 1}] ${role}`);
        lines.push(`    ${text}`);
      });
      return toTextResult({ thread: lines.join('\n') });
    }

    if (name === 'agenttrust_discover') {
      requireConfigured(config, name);
      const query = typeof args?.query === 'string' ? args.query.trim() : '';
      const url = new URL(safeUrl(config.endpoint, '/api/agents'));
      if (query) url.searchParams.set('q', query);
      const result = await apiRequest<Record<string, unknown>>(url.toString(), {
        method: 'GET',
        apiKey: config.apiKey,
      });
      return toTextResult(result);
    }

    if (name === 'agenttrust_status') {
      requireConfigured(config, name, { requireSlug: true });
      const inboxUrl = new URL(safeUrl(config.endpoint, `/r/${encodeURIComponent(config.slug || '')}/inbox`));
      inboxUrl.searchParams.set('turn', config.slug || '');
      inboxUrl.searchParams.set('limit', '1');
      const inbox = await apiRequest<{ total?: number }>(inboxUrl.toString(), {
        method: 'GET',
        apiKey: config.apiKey,
      });
      const keyInfo = await apiRequest<Record<string, unknown>>(
        safeUrl(config.endpoint, `/a/${encodeURIComponent(config.slug || '')}/key`),
        { method: 'GET', apiKey: config.apiKey },
      ).catch(() => ({}));
      const keyInfoRecord = keyInfo as Record<string, unknown>;
      return toTextResult({
        slug: config.slug,
        agentId: config.agentId,
        endpoint: safeUrl(config.endpoint, `/r/${encodeURIComponent(config.slug || '')}`),
        keyStatus: keyInfoRecord.key_status || 'unknown',
        keyExpires: keyInfoRecord.expires_at || null,
        pendingTasks: inbox.total || 0,
      });
    }

    if (name === 'agenttrust_cancel') {
      requireConfigured(config, name, { requireSlug: true });
      const taskId = typeof args?.taskId === 'string' ? args.taskId.trim() : '';
      if (!taskId) throw makeError('taskId is required');
      const result = await apiRequest<Record<string, unknown>>(
        safeUrl(config.endpoint, `/r/${encodeURIComponent(config.slug || '')}/inbox/${encodeURIComponent(taskId)}/cancel`),
        {
          method: 'POST',
          apiKey: config.apiKey,
          body: {},
        },
      );
      return toTextResult(result);
    }

    if (name === 'agenttrust_allowlist') {
      requireConfigured(config, name, { requireSlug: true });
      const url = new URL(safeUrl(config.endpoint, `/r/${encodeURIComponent(config.slug || '')}/contacts`));
      url.searchParams.set('limit', '100');
      url.searchParams.set('offset', '0');
      const result = await apiRequest<ApiContactsResponse>(url.toString(), {
        method: 'GET',
        apiKey: config.apiKey,
      });
      const profile = await fetchAgentBySlug(config.endpoint, config.apiKey || '', config.slug || '');
      const orgName = readString(profile?.org) || readString(profile?.org_name) || 'Unknown';
      const entries = (result.contacts || [])
        .map((entry) => {
          const slug = readString(entry.contact?.slug);
          if (!slug) return null;
          const org = readString(entry.contact?.orgName) || 'Unknown';
          const addedAt = toDateOnly(entry.createdAt) || toDateOnly(entry.updatedAt) || '';
          return {
            slug,
            org,
            addedAt,
          };
        })
        .filter((entry): entry is { slug: string; org: string; addedAt: string } => Boolean(entry));
      return toTextResult({
        mode: 'allowlist',
        scope: 'organisation',
        org: orgName,
        entries,
      });
    }

    throw makeError(`Unknown tool: ${name}`);
  } catch (error) {
    return {
      content: [
        {
          type: 'text',
          text: `Error: ${(error as Error).message}`,
        },
      ],
      isError: true,
    };
  }
});

function printUsage(): void {
  console.log('Usage:');
  console.log('  agenttrust-mcp init           # interactive first-time setup');
  console.log('  agenttrust-mcp --status       # print config + key status');
  console.log('  agenttrust-mcp --regen-keys   # rotate signing key');
  console.log('  agenttrust-mcp                # run MCP stdio server');
}

async function runStdioServer(): Promise<void> {
  const config = await loadRuntimeConfig();
  if (!config.apiKey) {
    throw makeError('AgentTrust is not configured. Run `agenttrust-mcp init` or set AGENTTRUST_API_KEY.');
  }
  if (!config.slug || !config.agentId) {
    throw makeError(
      'Agent identity is not fully configured. Run `agenttrust-mcp init` or set AGENTTRUST_SLUG and AGENTTRUST_AGENT_ID.',
    );
  }

  // Ensure signing capability is ready up front when identity is known.
  await getOrCreateSigningKey(config);

  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('AgentTrust MCP server running on stdio');
}

async function main() {
  const args = process.argv.slice(2);
  const cmd = args[0] || '';

  if (cmd === 'init') {
    const code = await runInitCommand();
    process.exitCode = code;
    return;
  }
  if (cmd === '--status') {
    const code = await runStatusCommand();
    process.exitCode = code;
    return;
  }
  if (cmd === '--regen-keys') {
    const code = await runRegenKeysCommand();
    process.exitCode = code;
    return;
  }
  if (cmd === '--help' || cmd === '-h') {
    printUsage();
    return;
  }

  await runStdioServer();
}

main().catch((error) => {
  console.error('Fatal error:', error);
  process.exit(1);
});
