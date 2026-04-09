export const IDENTITY_URI = 'https://agenttrust.ai/ext/identity/v1';
export const PLATFORM_URI = 'https://agenttrust.ai/ext/platform/v1';
export const TRUST_URI = 'https://agenttrust.ai/ext/trust/v1';
export const ALLOWED_INTENTS = [
  'chat',
  'code-review',
  'procurement',
  'onboarding',
  'support',
  'research',
  'negotiation',
  'approval',
  'other',
] as const;
export type TaskIntent = typeof ALLOWED_INTENTS[number];
const INTENT_SET = new Set<string>(ALLOWED_INTENTS);

export function extensionsFromMeta(metadata: Record<string, unknown>): string[] {
  return Object.keys(metadata).filter((key) => key.startsWith('https://'));
}

export function isValidIntent(value: unknown): value is TaskIntent {
  return typeof value === 'string' && INTENT_SET.has(value);
}

export function getTaskIntent(task: {
  intent?: unknown;
  metadata?: Record<string, unknown> | null;
}): TaskIntent {
  if (isValidIntent(task.intent)) return task.intent;
  const root = task.metadata && typeof task.metadata === 'object' ? task.metadata : null;
  const platformRaw = root ? (root[PLATFORM_URI] as unknown) : null;
  if (!platformRaw || typeof platformRaw !== 'object' || Array.isArray(platformRaw)) return 'other';
  const intentRaw = (platformRaw as Record<string, unknown>).intent;
  return isValidIntent(intentRaw) ? intentRaw : 'other';
}
