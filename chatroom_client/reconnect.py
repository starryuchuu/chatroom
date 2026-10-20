"""Reconnect timing and cancellation, without Tk or background timer threads."""


class ReconnectPolicy:
    """Issue owner-thread retry delays and invalidate stale scheduled callbacks.

    A delay is bounded at 30 seconds. By default retries continue until the user
    cancels; callers may choose a finite attempt limit when appropriate.
    """
    DELAYS = (1, 2, 4, 8, 15, 30)

    def __init__(self, max_attempts=None):
        if max_attempts is not None and (type(max_attempts) is not int or max_attempts < 1):
            raise ValueError('max_attempts must be a positive integer or None')
        self.max_attempts = max_attempts
        self.active = False
        self.attempt = 0
        self.token = 0

    @property
    def delay(self):
        if not self.active:
            return None
        return self.DELAYS[min(self.attempt - 1, len(self.DELAYS) - 1)]

    def start(self):
        self.token += 1
        self.active = True
        self.attempt = 1
        return self.delay

    def retry(self):
        if not self.active:
            return None
        if self.max_attempts is not None and self.attempt >= self.max_attempts:
            self.stop()
            return None
        self.attempt += 1
        return self.delay

    def stop(self):
        self.token += 1
        self.active = False
        self.attempt = 0

    def is_current(self, token):
        return self.active and token == self.token
