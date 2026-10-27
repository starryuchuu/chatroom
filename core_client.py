"""Headless desktop core. stdout is exclusively versioned JSON-RPC/JSONL."""
import logging
import sys


def main():
    # The RPC contract uses UTF-8 even when a host launches us in a legacy
    # Windows code page without Electron's PYTHONIOENCODING environment.
    for stream in (sys.stdin, sys.stdout, sys.stderr):
        if hasattr(stream, 'reconfigure'):
            stream.reconfigure(encoding='utf-8')
    logging.basicConfig(stream=sys.stderr, level=logging.WARNING,
                        format='%(levelname)s %(name)s: %(message)s')
    if sys.argv[1:] == ['--check-encryption-runtime']:
        from chatroom_client.runtime_check import check_encryption_runtime
        check_encryption_runtime()
        return 0
    if sys.argv[1:]:
        return 2
    from chatroom_client.rpc import CoreRuntime
    return CoreRuntime().run()


if __name__ == '__main__':
    raise SystemExit(main())
