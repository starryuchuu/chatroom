"""Headless desktop core. stdout is exclusively versioned JSON-RPC/JSONL."""
import logging
import sys


def main():
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
