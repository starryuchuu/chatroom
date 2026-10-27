/** Public desktop/core contract. Keep Python and future Rust implementations compatible. */
export const PROTOCOL_VERSION = 1;
export type ChatKey = { kind: 'private' | 'group'; target: string };
export type Profile = { name: string; host: string; port: number; fingerprint: string | null };
export type Message = { id: string; author: string; content: string; timestamp: string;
  self: boolean; protection: 'e2ee' | 'legacy' | 'failed' };
export type Peer = { username: string; fingerprint: string; verified: boolean; changeFingerprint: string | null };
export type Group = { group_name: string; owner: string; members: string[] };
export type Conversation = { key: ChatKey; title: string; preview: string; unread: number; timestamp: string; online: boolean };
export type Pending = { id: string; key: ChatKey; text: string; status: string; receipts: boolean; createdAt: string };
export type State = {
  session: string; page: 'login' | 'chat'; username: string | null;
  busy: boolean; authStatus: string; status: string; connected: boolean; reconnecting: boolean;
  theme: 'light' | 'dark'; profiles: Profile[]; selectedProfile: string;
  notifications: { enabled: boolean; do_not_disturb: boolean };
  conversations: Conversation[]; currentChat: ChatKey | null; messages: Message[];
  groups: Record<string, Group>; onlineUsers: string[]; unread: number;
  loadingHistory: boolean; syncing: boolean; syncFailed: boolean;
  canLoadOlder: boolean; newerEvicted: boolean; canSend: boolean;
  encryption: { enabled: boolean; ready: boolean; status: string; fingerprint: string; peers: Peer[] };
  requests: { id: string; title: string; text: string }[]; pending: Pending[];
};
export type Prompt = { id: string; title: string; text: string; gid?: string;
  recipients?: { username: string; fingerprint: string; change: string }[]; removed?: string[] };
export type CoreEvent = { method: string; params: unknown };
export type InitResult = { protocolVersion: number; implementation: string; state: State };
export const METHODS = [
  'initialize', 'auth.login', 'auth.cancel', 'auth.migrate', 'auth.unlockLegacy', 'session.disconnect',
  'profile.select', 'profile.save', 'profile.delete', 'settings.theme', 'settings.notifications',
  'window.activity', 'conversation.select', 'conversation.clear', 'draft.set', 'message.send',
  'history.older', 'history.latest', 'sync.retry', 'friend.add', 'request.reply', 'prompt.reply',
  'group.create', 'group.info', 'group.invite', 'group.kick', 'group.transfer', 'group.rename',
  'group.leave', 'group.disband', 'keys.reviewGroup', 'keys.verify', 'keys.acceptChange',
  'keys.export', 'keys.import', 'password.change', 'send.recover', 'send.dismiss',
] as const;
export type Method = typeof METHODS[number];
export interface DesktopAPI {
  request(method: Method, params?: Record<string, unknown>): Promise<unknown>;
  subscribe(callback: (event: CoreEvent) => void): () => void;
  copy(text: string): Promise<void>;
  platform: string;
}
declare global { interface Window { chatroom: DesktopAPI } }
export function sameKey(a: ChatKey | null, b: ChatKey | null): boolean {
  return a?.kind === b?.kind && a?.target === b?.target;
}
export function keyId(key: ChatKey | null): string { return key ? JSON.stringify([key.kind, key.target]) : ''; }
