# 测试用 mock：PKCS1_OAEP（测试用途，非真实加密）
class PKCS1_OAEPCipher:
    def __init__(self, key):
        self.key = key

    def encrypt(self, data):
        return bytes(data) + b'::ENC::'

    def decrypt(self, data):
        d = bytes(data)
        return d[:-7] if d.endswith(b'::ENC::') else d


def new(key):
    return PKCS1_OAEPCipher(key)
