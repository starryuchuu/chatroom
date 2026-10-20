"""Python desktop client entry point and first-launch server defaults.

The application is composed in chatroom_client. Wire helpers remain exported
here for existing protocol integrations and command-line scripts.
"""
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


def main():
    logging.info('Starting Chat Client')
    root = tk.Tk()
    ChatClient(root)
    root.mainloop()


if __name__ == '__main__':
    main()
