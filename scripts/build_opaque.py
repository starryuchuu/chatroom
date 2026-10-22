"""Rebuild the shared, sandboxed OPAQUE core from the locked Rust source."""
from pathlib import Path
import hashlib
import os
import shutil
import subprocess


ROOT = Path(__file__).resolve().parents[1]


def main():
    env = dict(os.environ)
    # Keep workstation paths out of the distributed WebAssembly module.
    env['RUSTFLAGS'] = ' '.join([
        '-C', 'link-arg=--max-memory=268435456',
        '--remap-path-prefix=' + str(ROOT) + '=/chatroom',
        '--remap-path-prefix=' + str(Path(env.get('CARGO_HOME', Path.home() / '.cargo'))) + '=/cargo',
        '--remap-path-prefix=' + str(Path(env.get('RUSTUP_HOME', Path.home() / '.rustup'))) + '=/rust',
    ])
    subprocess.run(['cargo', 'build', '--locked', '--release', '--target',
                    'wasm32-unknown-unknown'], cwd=ROOT / 'opaque-core', env=env, check=True)
    source = ROOT / 'opaque-core/target/wasm32-unknown-unknown/release/chatroom_opaque_core.wasm'
    if not source.is_file():
        raise SystemExit('OPAQUE core output was not produced')
    destinations = [ROOT / 'chatroom_client/opaque_core.wasm',
                    ROOT / 'go-server/internal/opaqueauth/opaque_core.wasm']
    for destination in destinations:
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
    print('OPAQUE core SHA-256:', hashlib.sha256(source.read_bytes()).hexdigest())


if __name__ == '__main__':
    main()
