"""Python desktop client entry point and first-launch server defaults.

The application is composed in chatroom_client. Wire helpers remain exported
here for existing protocol integrations and command-line scripts.
"""
import sys


def _check_encryption_runtime():
    try:
        from chatroom_client.runtime_check import check_encryption_runtime
        check_encryption_runtime()
    except Exception as error:
        # A PyInstaller --windowed executable has no stdout/stderr. Returning a
        # nonzero status still fails CI without triggering its exception GUI.
        stream = sys.stderr
        if stream is not None:
            try:
                stream.write(f'Encryption runtime self-check failed: {type(error).__name__}: {error}\n')
                stream.flush()
            except (OSError, ValueError):
                pass
        return 1
    stream = sys.stdout
    if stream is not None:
        try:
            stream.write('PASS encryption runtime: Argon2id vault, Ed25519, X25519, authenticated private messages\n')
            stream.flush()
        except (OSError, ValueError):
            pass
    return 0


# Handle the frozen-runtime probe before importing Tk or the application.
# Missing optional native providers must become a clean failing exit status.
if __name__ == '__main__' and '--check-encryption-runtime' in sys.argv[1:]:
    raise SystemExit(_check_encryption_runtime() if sys.argv[1:] == ['--check-encryption-runtime'] else 2)


import logging
import socket
import tkinter as tk
from tkinter import messagebox

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import transport
from chatroom_client import protocol
from chatroom_client.protocol import (
    MAX_RECV_MSG_LEN, authenticated_sockets, recvall, send_msg, recv_msg,
    encrypt_message, decrypt_message,
)
from chatroom_client.app import ChatApplication
from chatroom_client.connection import ClientSettings, ConnectionManager
from chatroom_client.preferences import PreferencesStore, ServerProfile
from chatroom_client.view import TkClientView

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 12345
# Remote connections require the server's verified SHA-256 public-key fingerprint.
EXPECTED_SERVER_KEY_FINGERPRINT = None

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def check_server_public_key(public_key_data):
    return protocol.check_server_public_key(
        public_key_data, host=SERVER_HOST,
        expected_fingerprint=EXPECTED_SERVER_KEY_FINGERPRINT)


class ChatClient(ChatApplication):
    def __init__(self, master, *, preferences=None, encryption=True):
        if preferences is None:
            default = ServerProfile('默认服务器', SERVER_HOST, SERVER_PORT, EXPECTED_SERVER_KEY_FINGERPRINT)
            preferences = PreferencesStore(default_profile=default)
        profile = preferences.selected_profile
        settings = ClientSettings(profile.host, profile.port, profile.fingerprint)
        view = TkClientView(master)
        connection = ConnectionManager(settings)
        try:
            super().__init__(view, connection, preferences, encryption=encryption)
        except Exception:
            connection.close()
            raise


def main(argv=None):
    arguments = sys.argv[1:] if argv is None else list(argv)
    if '--check-encryption-runtime' in arguments:
        return _check_encryption_runtime() if arguments == ['--check-encryption-runtime'] else 2
    if '--check-desktop-ui' in arguments:
        if len(arguments) not in (1, 2) or arguments[0] != '--check-desktop-ui':
            return 2
        from chatroom_client.desktop_check import check_desktop_ui
        try:
            check_desktop_ui(arguments[1] if len(arguments) == 2 else None)
        except Exception as error:
            if len(arguments) == 2:
                from pathlib import Path
                try:
                    destination = Path(arguments[1])
                    destination.mkdir(parents=True, exist_ok=True)
                    (destination / 'desktop-ui-error.txt').write_text(
                        f'{type(error).__name__}: {error}\n', encoding='utf-8')
                except OSError:
                    pass
            if sys.stderr is not None:
                sys.stderr.write(f'Desktop UI self-check failed: {type(error).__name__}: {error}\n')
            return 1
        return 0
    logging.info('Starting Chat Client')
    root = tk.Tk()
    ChatClient(root)
    root.mainloop()


if __name__ == '__main__':
    raise SystemExit(main())
