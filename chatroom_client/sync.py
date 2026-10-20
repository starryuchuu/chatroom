"""Bounded message catch-up with an account-scoped, durable completion cursor."""
import uuid


MAX_CURSOR = 9007199254740991


def _cursor(value):
    return type(value) is int and 0 <= value <= MAX_CURSOR


class SyncController:
    """Advance a checkpoint only after every page in one fixed snapshot arrives.

    Duplicate messages from a retried page are handled by Conversation. This
    controller never resubmits an outgoing chat message or stores its contents.
    All methods, including scheduled timeouts, run on the controller's owner
    thread; no worker captures UI callbacks.
    """

    def __init__(self, state, send, preferences, notify, refresh, schedule, *, before_commit=None):
        self.state, self.send, self.preferences = state, send, preferences
        self.notify, self.refresh, self.schedule = notify, refresh, schedule
        self.before_commit = before_commit
        self.endpoint = self.username = None
        self.capabilities = ()
        self.checkpoint = None
        self.active = self.failed = self.awaiting_initial = False
        self._initial_boundary = None
        self._boundary = self._after = self._request_id = None
        self._invalid_checkpoint = False
        self._begun = False

    def establish(self, endpoint, username, capabilities):
        """Prepare before starting the newly authenticated socket's receiver."""
        self.abort()
        self.endpoint, self.username = tuple(endpoint), username
        self.capabilities = tuple(capabilities)
        self._initial_boundary = None
        self._invalid_checkpoint = False
        self.checkpoint = None
        try:
            stored = self.preferences.account(self.endpoint, username) if self.preferences is not None else {}
        except (OSError, ValueError) as error:
            self.notify('消息同步', f'读取同步位置失败：{error}')
            stored = {}
        if 'sync_cursor' in stored:
            if _cursor(stored['sync_cursor']):
                self.checkpoint = stored['sync_cursor']
            else:
                self._invalid_checkpoint = True
        self.awaiting_initial = True

    def on_initial_history_end(self, message):
        """The unscoped login snapshot establishes the upper catch-up boundary."""
        if (not self.awaiting_initial or message.get('type') != 'history_end'
                or message.get('history_kind') or message.get('history_target')):
            return False
        self.awaiting_initial = False
        boundary = message.get('boundary')
        if not _cursor(boundary):
            self._fail('服务器返回的历史同步位置无效，请重新连接。')
            return True
        self._initial_boundary = boundary
        if self._invalid_checkpoint:
            self._fail('已保存的同步位置超出支持范围，请检查客户端配置。')
        elif self.checkpoint is None:
            # A first login intentionally starts with the recent history page.
            # Subsequent logins resume from this fully received boundary.
            self._commit(boundary)
        elif 'message_sync' not in self.capabilities:
            self._legacy_complete(boundary)
        else:
            self.retry()
        return True

    def _legacy_complete(self, boundary):
        self.active = self.failed = False
        self.state.history_syncing = False
        if self.checkpoint is not None and boundary > self.checkpoint:
            self.notify('消息同步', '服务器不支持完整增量同步，已加载最近的聊天记录；更早消息可在会话中加载。')
        # Keep the old checkpoint: upgrading the server later can fill any gap.
        self.refresh()

    def _send_page(self, after):
        self._after, self._boundary = after, self._initial_boundary
        request_id = uuid.uuid4().hex
        self._request_id = request_id
        self._begun = False
        self.active, self.failed = True, False
        self.state.history_syncing = True
        request = {'type': 'sync_request', 'after_id': after,
                   'boundary': self._boundary, 'request_id': request_id}
        try:
            self.send(request)
        except Exception as error:
            self._fail(f'补取消息失败：{error}；已保留同步位置，可重试。')
            return False
        self.schedule(20000, lambda: self._timeout(request_id))
        self.refresh()
        return True

    def _timeout(self, request_id):
        if self.active and self._request_id == request_id:
            self._fail('补取消息超时；已保留同步位置，请重试或重新连接。')

    def handle(self, message):
        if not isinstance(message, dict) or message.get('type') not in ('sync_begin', 'sync_end', 'sync_error'):
            return False
        if not self.active or message.get('request_id') != self._request_id:
            # Old page responses and canceled timeout callbacks cannot complete
            # a newer page or a replacement connection's checkpoint.
            return True
        if message['type'] == 'sync_error':
            error = message.get('error')
            self._fail(error if isinstance(error, str) and error else '补取消息失败，请重试。')
            return True
        if (not _cursor(message.get('after_id')) or message['after_id'] != self._after
                or not _cursor(message.get('boundary')) or message['boundary'] != self._boundary):
            self._fail('服务器返回的同步页与请求不匹配；已保留同步位置。')
            return True
        if message['type'] == 'sync_begin':
            self._begun = True
            self.state.history_syncing = True
            return True
        next_after, more = message.get('next_after_id'), message.get('has_more')
        if (not self._begun or not _cursor(next_after) or type(more) is not bool
                or (more and not self._after < next_after < self._boundary)
                or (not more and next_after != self._boundary)):
            self._fail('服务器返回的同步游标无效；已保留同步位置。')
            return True
        if more:
            self._send_page(next_after)
        else:
            self._commit(self._boundary)
        return True

    def _commit(self, boundary):
        try:
            # Persist the unread metadata before publishing a newer cursor. A
            # process exit between these writes can replay IDs, never lose a badge.
            if self.before_commit is not None and self.before_commit() is False:
                self._fail('未读状态尚未保存，已保留同步位置；请检查设置目录后重试。')
                return False
            if self.preferences is not None:
                self.preferences.update_account(self.endpoint, self.username, {'sync_cursor': boundary})
        except (OSError, ValueError) as error:
            self._fail(f'消息已收到，但同步位置保存失败：{error}；重试时会自动去重。')
            return False
        self.checkpoint = boundary
        self._request_id = self._after = self._boundary = None
        self._begun = False
        self.active = self.failed = False
        self.state.history_syncing = False
        self.refresh()
        return True

    def _fail(self, message):
        self._request_id = None
        self._begun = False
        self.active, self.failed, self.awaiting_initial = False, True, False
        self.state.history_syncing = False
        self.refresh()
        self.notify('消息同步', message)

    def retry(self):
        if self.active or self.awaiting_initial or self.endpoint is None or self.username is None:
            return False
        if self._initial_boundary is None or self._invalid_checkpoint:
            self._fail('同步位置不可用，请重新连接并检查客户端配置。')
            return False
        if self.checkpoint is None:
            return self._commit(self._initial_boundary)
        if 'message_sync' not in self.capabilities:
            self._legacy_complete(self._initial_boundary)
            return False
        if self.checkpoint > self._initial_boundary:
            self._fail('服务器历史记录已回退，请核对服务器和数据库；原同步位置已保留。')
            return False
        return self._send_page(self.checkpoint)

    def abort(self):
        self._request_id = self._after = self._boundary = None
        self._begun = False
        self.active = self.failed = self.awaiting_initial = False
        self.state.history_syncing = False
