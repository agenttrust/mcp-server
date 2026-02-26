import { randomUUID } from 'crypto';

export const Role = {
  USER: 'user',
  AGENT: 'agent',
} as const;

export type RoleType = (typeof Role)[keyof typeof Role];

export const TaskState = {
  // Standard A2A states
  SUBMITTED: 'submitted',
  WORKING: 'working',
  INPUT_REQUIRED: 'input-required',
  COMPLETED: 'completed',
  FAILED: 'failed',
  CANCELED: 'canceled',
  // AgentTrust extended states (negotiation lifecycle)
  PROPOSE_COMPLETE: 'propose_complete',
  DISPUTED: 'disputed',
  REJECTED: 'rejected',
} as const;

export type TaskStateType = (typeof TaskState)[keyof typeof TaskState];

export const TaskStateLabel: Record<string, string> = {
  [TaskState.SUBMITTED]: 'Submitted',
  [TaskState.WORKING]: 'Working',
  [TaskState.INPUT_REQUIRED]: 'Awaiting Response',
  [TaskState.COMPLETED]: 'Completed',
  [TaskState.FAILED]: 'Failed',
  [TaskState.CANCELED]: 'Canceled',
  [TaskState.PROPOSE_COMPLETE]: 'Completion Proposed',
  [TaskState.DISPUTED]: 'Disputed',
  [TaskState.REJECTED]: 'Rejected',
};

export const Method = {
  SEND_MESSAGE: 'message/send',
  STREAM_MESSAGE: 'message/stream',
  GET_TASK: 'tasks/get',
  LIST_TASKS: 'tasks/list',
  CANCEL_TASK: 'tasks/cancel',
  SUBSCRIBE: 'tasks/resubscribe',
} as const;

export const TextPart = {
  KIND: 'text',
} as const;

export const FilePart = {
  KIND: 'file',
} as const;

export interface TextMessagePart {
  kind: typeof TextPart.KIND;
  text: string;
}

export interface FilePartPayload {
  name: string;
  mimeType: string;
  uri?: string;
  bytes?: string;
  size?: number;
}

export interface FileMessagePart {
  kind: typeof FilePart.KIND;
  file: FilePartPayload;
}

export type MessagePart = TextMessagePart | FileMessagePart;

export function textPart(text: string): TextMessagePart {
  return { kind: TextPart.KIND, text };
}

export function filePart(name: string, mimeType: string, uri: string): FileMessagePart {
  return {
    kind: FilePart.KIND,
    file: { name, mimeType, uri },
  };
}

export function isTextPart(part: unknown): part is TextMessagePart {
  if (typeof part !== 'object' || part === null || Array.isArray(part)) return false;
  const value = part as Record<string, unknown>;
  return value.kind === TextPart.KIND && typeof value.text === 'string' && value.text.length > 0;
}

export function isFilePart(part: unknown): part is FileMessagePart {
  if (typeof part !== 'object' || part === null || Array.isArray(part)) return false;
  const value = part as Record<string, unknown>;
  if (value.kind !== FilePart.KIND) return false;
  if (typeof value.file !== 'object' || value.file === null || Array.isArray(value.file)) return false;
  const file = value.file as Record<string, unknown>;
  return typeof file.name === 'string'
    && file.name.length > 0
    && typeof file.mimeType === 'string'
    && file.mimeType.length > 0
    && ((typeof file.uri === 'string' && file.uri.length > 0) || (typeof file.bytes === 'string' && file.bytes.length > 0));
}

export function partText(part: unknown): string {
  return isTextPart(part) ? part.text : '';
}

export function extractText(parts: unknown): string {
  if (!Array.isArray(parts)) return '';
  return parts.map((part) => partText(part)).filter(Boolean).join('\n');
}

export function extractFiles(parts: unknown): FileMessagePart[] {
  if (!Array.isArray(parts)) return [];
  return parts.filter((part): part is FileMessagePart => isFilePart(part));
}

export function buildMessage(
  role: RoleType,
  text: string,
  opts?: {
    messageId?: string;
    metadata?: Record<string, unknown>;
    extensions?: string[];
  },
): Record<string, unknown> {
  const msg: Record<string, unknown> = {
    role,
    parts: [textPart(text)],
  };
  if (opts?.messageId) msg.messageId = opts.messageId;
  if (opts?.metadata) msg.metadata = opts.metadata;
  if (opts?.extensions?.length) msg.extensions = opts.extensions;
  return msg;
}

export function buildRpcEnvelope(
  method: string,
  params: Record<string, unknown>,
  id?: string,
): Record<string, unknown> {
  return {
    jsonrpc: '2.0',
    id: id || randomUUID(),
    method,
    params,
  };
}

const STATE_MAP: Record<string, TaskStateType> = {
  // Standard A2A states
  submitted: TaskState.SUBMITTED,
  working: TaskState.WORKING,
  completed: TaskState.COMPLETED,
  failed: TaskState.FAILED,
  canceled: TaskState.CANCELED,
  'input-required': TaskState.INPUT_REQUIRED,
  'awaiting-response': TaskState.INPUT_REQUIRED,
  // A2A enum-style aliases
  TASK_STATE_SUBMITTED: TaskState.SUBMITTED,
  TASK_STATE_WORKING: TaskState.WORKING,
  TASK_STATE_COMPLETED: TaskState.COMPLETED,
  TASK_STATE_FAILED: TaskState.FAILED,
  TASK_STATE_CANCELED: TaskState.CANCELED,
  TASK_STATE_INPUT_REQUIRED: TaskState.INPUT_REQUIRED,
  // AgentTrust extended states
  propose_complete: TaskState.PROPOSE_COMPLETE,
  disputed: TaskState.DISPUTED,
  rejected: TaskState.REJECTED,
};

export function normalizeState(raw: string): TaskStateType {
  return STATE_MAP[raw] || TaskState.SUBMITTED;
}
