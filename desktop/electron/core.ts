import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { EventEmitter } from 'node:events';
import { resolve } from 'node:path';
import { PROTOCOL_VERSION, type InitResult } from '../src/protocol';

const MAX_LINE = 32 * 1024 * 1024;

/** Transport/lifecycle only; no dependency on Python semantics or application UI. */
export class CoreProcess extends EventEmitter {
  private child: ChildProcessWithoutNullStreams;
  private nextId = 0;
  private pending = new Map<number, { resolve: (value: unknown) => void; reject: (error: Error) => void;
    timer: ReturnType<typeof setTimeout> }>();
  private ended = false;
  private stopping = false;

  constructor(packaged: boolean, resources: string, repository: string) {
    super();
    const executable = packaged
      ? resolve(resources, 'core', process.platform === 'win32' ? 'chatroom-core.exe' : 'chatroom-core')
      : process.env.CHATROOM_PYTHON || (process.platform === 'win32' ? 'python' : 'python3');
    this.child = spawn(executable, packaged ? [] : ['-u', resolve(repository, 'core_client.py')], {
      cwd: packaged ? resources : repository, windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'],
      env: { ...process.env, PYTHONIOENCODING: 'utf-8', PYTHONUNBUFFERED: '1' },
    });
    // Drain stderr without copying passwords, plaintext or private file paths into app logs.
    this.child.stderr.on('data', () => {});
    let bytes = Buffer.alloc(0);
    this.child.stdout.on('data', (chunk: Buffer) => {
      bytes = Buffer.concat([bytes, chunk]);
      let end: number;
      while ((end = bytes.indexOf(10)) >= 0) {
        if (end > MAX_LINE) { this.fail('核心响应超过大小限制'); this.child.kill(); return; }
        const line = bytes.subarray(0, end).toString('utf8');
        bytes = bytes.subarray(end + 1);
        try { this.receive(JSON.parse(line)); }
        catch { this.fail('核心返回了无效响应'); this.child.kill(); return; }
      }
      if (bytes.length > MAX_LINE) { this.fail('核心响应超过大小限制'); this.child.kill(); }
    });
    this.child.stdin.on('error', () => this.fail('核心连接已关闭'));
    this.child.on('error', () => this.fail('无法启动核心。开发环境请设置 CHATROOM_PYTHON，指向安装了项目依赖的 Python。'));
    this.child.on('exit', () => this.fail(this.stopping ? '' : '核心进程已退出，请重新启动客户端。'));
  }

  private receive(packet: { jsonrpc?: string; id?: number; method?: string; params?: unknown;
    error?: { message: string }; result?: unknown }) {
    if (packet.jsonrpc !== '2.0') throw new Error('Invalid RPC version');
    if (typeof packet.id === 'number') {
      const pending = this.pending.get(packet.id);
      if (!pending) return;
      clearTimeout(pending.timer);
      this.pending.delete(packet.id);
      if (packet.error) pending.reject(new Error(packet.error.message));
      else pending.resolve(packet.result);
    } else if (typeof packet.method === 'string') {
      this.emit('event', { method: packet.method, params: packet.params });
    } else throw new Error('Invalid RPC packet');
  }

  request(method: string, params: Record<string, unknown> = {}): Promise<unknown> {
    if (this.ended) return Promise.reject(new Error('核心连接已关闭'));
    if (this.pending.size >= 128) return Promise.reject(new Error('操作过于频繁，请稍后重试'));
    const id = ++this.nextId;
    return new Promise((resolveResult, reject) => {
      const timer = setTimeout(() => { this.pending.delete(id); reject(new Error('操作等待超时，请检查当前状态后重试')); }, 150_000);
      this.pending.set(id, { resolve: resolveResult, reject, timer });
      const line = JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n';
      if (Buffer.byteLength(line) > MAX_LINE) {
        clearTimeout(timer); this.pending.delete(id); reject(new Error('操作内容超过大小限制')); return;
      }
      this.child.stdin.write(line);
    });
  }

  async initialize(): Promise<InitResult> {
    const result = await this.request('initialize', { protocolVersion: PROTOCOL_VERSION }) as InitResult;
    if (result.protocolVersion !== PROTOCOL_VERSION) throw new Error('桌面与核心协议版本不兼容');
    return result;
  }

  private fail(message: string) {
    if (this.ended) return;
    this.ended = true;
    for (const pending of this.pending.values()) { clearTimeout(pending.timer); pending.reject(new Error(message || '核心已关闭')); }
    this.pending.clear();
    if (message) this.emit('event', { method: 'core.failed', params: { message } });
  }

  async stop(): Promise<void> {
    if (this.stopping || this.ended) return;
    this.stopping = true;
    const exited = new Promise<void>(resolveResult => this.child.once('exit', () => resolveResult()));
    void this.request('shutdown').catch(() => {});
    const force = setTimeout(() => this.child.kill(), 4000);
    await exited;
    clearTimeout(force);
  }
}
