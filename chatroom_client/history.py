"""Correlated history pages with bounded waits and legacy-server compatibility."""
from .models import ChatKey
from .request_context import RequestToken, SessionContext


class HistoryController:
    def __init__(self, state, send, notify, redraw, refresh, *, connection=None,
                 schedule=None, sync_active=lambda: False):
        self.state, self.send, self.notify = state, send, notify
        self.redraw, self.refresh = redraw, refresh
        self.connection, self.schedule, self.sync_active = connection, schedule, sync_active
        self._request = self._batch_context = self._batch_id = None
        self._latest_request = None
        self._discard_batch = False
        self.retry_requires_reconnect = False

    @property
    def correlated(self):
        return (self.connection is not None
                and 'history_request_id' in self.connection.capabilities)

    def _context(self, key=None):
        return SessionContext.capture(self.state, self.connection, key) if self.connection is not None else None

    def _current(self, token):
        return (token is not None and self._request is token
                and self.state.pending_history is not None
                and (token.context is None or token.context.key == self.state.pending_history)
                and (token.context is None or token.context.matches(self.state, self.connection)))

    def load_older(self):
        return self._load()

    def load_latest(self):
        return self._load(latest=True)

    def _load(self, *, latest=False):
        key = self.state.current_chat
        if key is None or self.state.pending_history is not None or self.retry_requires_reconnect:
            return
        context = self._context(key)
        if context is not None and not context.matches(self.state, self.connection):
            return
        conversation = self.state.conversation(key)
        if conversation.exhausted and not latest:
            return
        before = 9223372036854775807 if latest else conversation.before_id
        token = RequestToken(context)
        request = {'type': 'history_request', 'chat_type': key.kind,
                   'target': key.target, 'before_id': before}
        if self.correlated:
            request['request_id'] = token.request_id
        try:
            self.send(request)
        except Exception as error:
            self.notify('历史记录', str(error))
            return
        if latest:
            conversation.clear_cache(reload_latest=True)
        conversation.cursor = before
        self._request, self.state.pending_history = token, key
        self._latest_request = token if latest else None
        if self.schedule is not None:
            self.schedule(20000, lambda: self._timeout(token))
        self.refresh()
        return True

    def _timeout(self, token):
        if not self._current(token):
            return
        self._request = self.state.pending_history = None
        self._latest_request = None
        self.state.history_syncing = self.sync_active()
        self._discard_batch = True
        self.retry_requires_reconnect = not self.correlated
        text = ('历史加载超时，已保留加载位置，请重试。' if self.correlated else
                '历史加载超时，已保留加载位置；请重新连接后再加载。')
        self.notify('历史记录', text)
        self.refresh()

    def abort(self):
        self._request = self._batch_context = self._batch_id = None
        self._latest_request = None
        self._discard_batch = self.retry_requires_reconnect = False
        self.state.pending_history = None
        self.state.history_syncing = self.sync_active()

    @staticmethod
    def _scope(message):
        kind, target = message.get('history_kind'), message.get('history_target')
        return ChatKey(kind, target) if kind in ('private', 'group') and isinstance(target, str) and target else None

    def accepts_message(self, message, key=None):
        """Explicit live/sync frames may interleave with a canceled history page."""
        request_id = message.get('history_request_id')
        if request_id is not None:
            return (self._current(self._request) and self._request.matches(request_id)
                    and (key is None or self._request.context is None or self._request.context.key == key))
        if message.get('history') is False or message.get('sync') is True:
            return True
        return (not self._discard_batch and (self._batch_context is None
                or self._batch_context.matches(self.state, self.connection)))

    def handle(self, message):
        kind = message['type']
        if kind not in ('history_begin', 'history_end', 'history_error'):
            return False
        scope, request_id = self._scope(message), message.get('request_id')
        token = self._request
        identified = request_id is not None
        current = self._current(token) and token.matches(request_id)
        if identified and current and scope is not None and scope != self.state.pending_history:
            return True
        if kind == 'history_begin':
            self._batch_id = request_id
            self._batch_context = token.context if current else self._context(scope)
            if not identified and scope is None and self._current(token):
                self._batch_context = token.context
            self._discard_batch = (identified and not current) or self.retry_requires_reconnect
            if not self._discard_batch:
                self.state.history_syncing = True
            return True

        stale_context = (not current and self._batch_context is not None
                         and (scope is None or self._batch_context.key == scope)
                         and not self._batch_context.matches(self.state, self.connection))
        if (identified and not current) or stale_context or self.retry_requires_reconnect:
            if request_id == self._batch_id:
                self._batch_context = self._batch_id = None
                self._discard_batch = False
            if self.state.pending_history is None:
                self.state.history_syncing = self.sync_active()
            return True
        # Login/auto-join snapshots have no request ID, even on modern servers.
        # They cannot complete a modern manual page with the same ChatKey.
        matches_pending = scope is not None and scope == self.state.pending_history
        unscoped_error = kind == 'history_error' and scope is None
        if self.correlated and token is not None and not identified and (matches_pending or unscoped_error):
            return True
        latest = (self._current(token) and token is self._latest_request
                  and matches_pending and kind == 'history_end')
        if self.state.pending_history is None or matches_pending or unscoped_error:
            self.state.history_syncing = self.sync_active()
        if matches_pending or unscoped_error:
            self._request = self.state.pending_history = None
            self._latest_request = None
        if (kind == 'history_end' and scope is not None
                and (scope.kind != 'group' or scope.target in self.state.groups)):
            conversation = self.state.conversation(scope)
            cursor = message.get('before_id')
            if type(cursor) is int and cursor > 0:
                conversation.cursor = cursor
            if not message.get('has_more', False):
                conversation.exhausted = True
        if request_id == self._batch_id:
            self._batch_context = self._batch_id = None
            self._discard_batch = False
        if self.state.current_chat is not None:
            if latest and scope == self.state.current_chat:
                self.redraw(self.state.current_chat, False, preserve_scroll=False)
            else:
                self.redraw(self.state.current_chat, kind == 'history_end' and scope == self.state.current_chat)
        if kind == 'history_error':
            self.notify('历史记录', message.get('error', '历史加载失败'))
        self.refresh()
        return True
