"""Retry-safe history pagination, independent of Tk and the connection workers."""
from .models import ChatKey


class HistoryController:
    def __init__(self, state, send, notify, redraw, refresh):
        self.state, self.send, self.notify = state, send, notify
        self.redraw, self.refresh = redraw, refresh

    def load_older(self):
        key = self.state.current_chat
        if key is None or self.state.pending_history is not None:
            return
        conversation = self.state.conversation(key)
        if conversation.exhausted:
            return
        before = conversation.before_id
        try:
            self.send({'type': 'history_request', 'chat_type': key.kind,
                       'target': key.target, 'before_id': before})
        except Exception as error:
            self.notify('历史记录', str(error))
            return
        conversation.cursor = before
        self.state.pending_history = key
        self.refresh()

    def handle(self, message):
        kind = message['type']
        if kind == 'history_begin':
            self.state.history_syncing = True
            return True
        if kind not in ('history_end', 'history_error'):
            return False
        self.state.history_syncing = False
        scope = None
        if message.get('history_kind') in ('private', 'group') and message.get('history_target'):
            scope = ChatKey(message['history_kind'], message['history_target'])
        if kind == 'history_error' or self.state.pending_history is None or scope == self.state.pending_history:
            self.state.pending_history = None
        if kind == 'history_end' and scope is not None:
            conversation = self.state.conversation(scope)
            cursor = message.get('before_id')
            if type(cursor) is int and cursor > 0:
                conversation.cursor = cursor
            if not message.get('has_more', False):
                conversation.exhausted = True
        if self.state.current_chat is not None:
            self.redraw(self.state.current_chat, kind == 'history_end' and scope == self.state.current_chat)
        if kind == 'history_error':
            self.notify('历史记录', message.get('error', '历史加载失败'))
        self.refresh()
        return True
