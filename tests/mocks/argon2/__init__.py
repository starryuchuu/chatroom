# 测试用 mock：argon2.PasswordHasher（模拟 argon2-cffi 行为）
import hashlib
import hmac

from . import exceptions


class PasswordHasher:
    """mock：hash 返回 'mock$<sha256>'，verify 在哈希无效时抛 InvalidHashError。"""

    def __init__(self, *args, **kwargs):
        pass

    def hash(self, password, *args, **kwargs):
        return 'mock$' + hashlib.sha256(bytes(str(password), 'utf-8')).hexdigest()

    def verify(self, hash, password):
        h = str(hash)
        prefix = 'mock$'
        if not h.startswith(prefix):
            raise exceptions.InvalidHashError('invalid hash')
        expected = hashlib.sha256(bytes(str(password), 'utf-8')).hexdigest()
        if not hmac.compare_digest(h[len(prefix):], expected):
            raise exceptions.VerifyMismatchError('mismatch')
        return True
