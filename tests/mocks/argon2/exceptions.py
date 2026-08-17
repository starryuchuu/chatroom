# 测试用 mock：argon2.exceptions（与 argon2-cffi 异常层次一致）
class Argon2Error(Exception):
    pass


class VerificationError(Argon2Error):
    pass


class VerifyMismatchError(VerificationError):
    pass


class HashingError(Argon2Error):
    pass


class InvalidHashError(ValueError):
    pass


InvalidHash = InvalidHashError
