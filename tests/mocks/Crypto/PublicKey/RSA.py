# 测试用 mock：RSA（测试用途，非真实加密）
class RsaKey:
    def __init__(self, marker=b'PUB'):
        self._marker = marker

    @classmethod
    def generate(cls, bits):
        return cls(b'PRIV')

    @classmethod
    def import_key(cls, data):
        d = bytes(data)
        return cls(b'PRIV') if b'PRIV' in d else cls(b'PUB')

    def export_key(self, format='PEM'):
        return b'-----BEGIN MOCK %s KEY-----' % self._marker

    def publickey(self):
        return RsaKey(b'PUB')

    def encrypt(self, data):
        return bytes(data) + b'::ENC::'

    def decrypt(self, data):
        d = bytes(data)
        return d[:-7] if d.endswith(b'::ENC::') else d


def generate(bits):
    return RsaKey(b'PRIV')


def import_key(data):
    return RsaKey.import_key(data)
