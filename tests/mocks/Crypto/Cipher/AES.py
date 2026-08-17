# 测试用 mock：模拟 pycryptodome 的 AES-GCM / RSA / OAEP
import os
import hmac
import hashlib


class AESCipher:
    def __init__(self, key, mode, nonce=None):
        self.key = bytes(key)
        self._nonce = bytes(nonce) if nonce is not None else None

    @property
    def nonce(self):
        if self._nonce is None:
            self._nonce = os.urandom(16)
        return self._nonce

    def encrypt_and_digest(self, data):
        nonce = self.nonce
        tag = hmac.new(self.key, nonce + bytes(data), hashlib.sha256).digest()[:16]
        return bytes(data), tag

    def decrypt_and_verify(self, data, tag):
        expected = hmac.new(self.key, self.nonce + bytes(data), hashlib.sha256).digest()[:16]
        if not hmac.compare_digest(expected, bytes(tag)):
            raise ValueError("MAC check failed")
        return bytes(data)


def new(key, mode, nonce=None):
    return AESCipher(key, mode, nonce)


MODE_GCM = 1
