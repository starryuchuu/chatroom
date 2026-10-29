import { test, expect } from '@playwright/test';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { CoreProcess } from '../electron/core';
import { PROTOCOL_VERSION } from '../src/protocol';

test('real Python snapshots above 32 MiB reassemble and the core remains usable', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'chatroom-rpc-chunks-'));
  const script = `import sys
sys.path.insert(0, ${JSON.stringify(resolve('..'))})
from chatroom_client.models import ChatKey, Message
from chatroom_client.preferences import PreferencesStore
from chatroom_client.rpc import CoreRuntime
runtime = CoreRuntime(preferences=PreferencesStore(persistent=False), encryption=False)
app = runtime.app
app.state.username, app.state.friends = 'alice', ['bob']
key = app.state.current_chat = ChatKey('private', 'bob')
runtime.view.page = 'chat'
for number in range(1, 23):
    app.state.conversation(key).add(Message('bob', '\\x00' * (256 * 1024), message_id=number))
runtime.run()
`;
  await writeFile(join(directory, 'core_client.py'), script);
  const core = new CoreProcess(false, '', directory);
  const failures: unknown[] = [];
  core.on('event', event => { if (event.method === 'core.failed') failures.push(event); });
  try {
    const result = await core.initialize();
    expect(result.state.messages).toHaveLength(22);
    expect(result.state.messages.every(item => item.content === '\x00'.repeat(256 * 1024))).toBe(true);
    await core.request('conversation.clear', { session: result.state.session, draft: '' });
    const cleared = await core.initialize();
    expect(cleared.state.messages).toEqual([]);
    expect(cleared.state.currentChat).toBeNull();
    expect(failures).toEqual([]);
  } finally {
    await core.stop();
    await rm(directory, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  }
});

test('a maximum-size JSON response accepts a separately delivered Windows CRLF', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'chatroom-rpc-crlf-'));
  const script = `import json, sys, time
request = json.loads(sys.stdin.readline())
reply = {'jsonrpc': '2.0', 'id': request['id'], 'result': {
    'protocolVersion': ${PROTOCOL_VERSION}, 'implementation': 'crlf-fixture', 'state': {}, 'padding': ''}}
size = len(json.dumps(reply, separators=(',', ':')).encode('utf-8'))
reply['result']['padding'] = 'x' * (32 * 1024 * 1024 - size)
raw = json.dumps(reply, separators=(',', ':')).encode('utf-8')
assert len(raw) == 32 * 1024 * 1024
sys.stdout.buffer.write(raw + b'\\r')
sys.stdout.buffer.flush()
time.sleep(.05)
sys.stdout.buffer.write(b'\\n')
sys.stdout.buffer.flush()
for line in sys.stdin:
    if json.loads(line).get('method') == 'shutdown':
        break
`;
  await writeFile(join(directory, 'core_client.py'), script);
  const core = new CoreProcess(false, '', directory);
  try {
    const result = await core.initialize();
    expect(result.implementation).toBe('crlf-fixture');
  } finally {
    await core.stop();
    await rm(directory, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  }
});

for (const kind of ['oversized', 'out-of-order', 'interrupted'] as const) {
  test(`invalid ${kind} transfers are rejected within the transport budget`, async () => {
    const directory = await mkdtemp(join(tmpdir(), 'chatroom-rpc-invalid-'));
    const script = `import base64, json, sys
sys.stdin.readline()
chunk = {'jsonrpc': '2.0', 'method': 'transport.chunk', 'params': {
    'transfer': 'a' * 32, 'index': 0, 'total': 33, 'bytes': 33 * 1024 * 1024,
    'data': base64.b64encode(b'x' * (1024 * 1024)).decode('ascii')}}
kind = ${JSON.stringify(kind)}
if kind == 'oversized':
    chunk['params'].update(bytes=129 * 1024 * 1024, total=129, data='')
elif kind == 'out-of-order':
    chunk['params']['index'] = 1
print(json.dumps(chunk), flush=True)
if kind == 'interrupted':
    print(json.dumps({'jsonrpc': '2.0', 'id': 1, 'result': {}}), flush=True)
sys.stdin.read()
`;
    await writeFile(join(directory, 'core_client.py'), script);
    const core = new CoreProcess(false, '', directory);
    try {
      await expect(core.initialize()).rejects.toThrow('核心返回了无效响应');
    } finally {
      await core.stop();
      await rm(directory, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
    }
  });
}
