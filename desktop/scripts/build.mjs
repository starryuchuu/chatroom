import { build as bundle } from 'esbuild';
import { build } from 'vite';
import { mkdir, readFile, writeFile } from 'node:fs/promises';

export async function buildMain() {
  await mkdir('dist', { recursive: true });
  const notices = await Promise.all(['react', 'react-dom', 'scheduler', 'lucide-react', 'react-virtuoso'].map(async name => {
    const metadata = JSON.parse(await readFile(`node_modules/${name}/package.json`, 'utf8'));
    return `${name} ${metadata.version}\n\n${await readFile(`node_modules/${name}/LICENSE`, 'utf8')}`;
  }));
  await writeFile('dist/THIRD_PARTY_NOTICES.txt', notices.join('\n\n--------------------\n\n'));
  await bundle({ entryPoints: ['electron/main.ts'], bundle: true, platform: 'node',
    format: 'cjs', outfile: 'dist/main.cjs', external: ['electron'], target: 'node24' });
  await bundle({ entryPoints: ['electron/preload.ts'], bundle: true, platform: 'node',
    format: 'cjs', outfile: 'dist/preload.cjs', external: ['electron'], target: 'node24' });
}

if (process.argv[1]?.endsWith('build.mjs')) {
  await buildMain();
  await build();
}
