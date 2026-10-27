import { createServer } from 'vite';
import { spawn } from 'node:child_process';
import electron from 'electron';
import { buildMain } from './build.mjs';

await buildMain();
const server = await createServer();
await server.listen();
const child = spawn(electron, ['.'], { stdio: 'inherit',
  env: { ...process.env, CHATROOM_DEV_URL: 'http://127.0.0.1:5173' } });
child.on('exit', async code => { await server.close(); process.exit(code ?? 1); });
for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => child.kill(signal));
}
