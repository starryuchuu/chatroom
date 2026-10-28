"""Unread markers and account-scoped activity metadata, without Tk dependencies.

Message bodies and previews only live in Conversation. The preferences file
contains message IDs and read markers, so reopening the client can restore
unread counts without saving chat text in an unencrypted file.
"""
import logging

from .models import ChatKey


class ActivityController:
    def __init__(self, state, preferences=None, *, refresh=None, notify=None,
                 is_visible=None, schedule=None, on_error=None, notify_message=None):
        self.state = state
        self.preferences = preferences
        self.refresh = refresh or (lambda: None)
        self.notify = notify or (lambda title, text: None)
        self.notify_message = notify_message
        self.is_visible = is_visible or (lambda key: False)
        self.schedule = schedule
        self.on_error = on_error or (lambda text: None)
        self.endpoint = self.username = None
        self.initialized = False
        self._dirty = self._scheduled = self._reported_error = False

    @property
    def active(self):
        return self.endpoint is not None and self.username is not None

    def activate(self, endpoint, username):
        """Activate after resetting account state, before receiving login history."""
        self.flush()
        self.endpoint, self.username = tuple(endpoint), username
        self._dirty = self._scheduled = self._reported_error = False
        stored = self.preferences.account(self.endpoint, username) if self.preferences is not None else {}
        activity = stored.get('activity', {})
        if not isinstance(activity, dict):
            activity = {}
        self.initialized = activity.get('initialized') is True
        records = activity.get('conversations', [])
        if not isinstance(records, list):
            records = []
        for record in records:
            if not isinstance(record, dict):
                continue
            try:
                key = ChatKey(record.get('kind'), record.get('target'))
            except (TypeError, ValueError):
                continue
            conversation = self.state.conversation(key)
            read_id = record.get('read_id', 0)
            conversation.read_id = read_id if type(read_id) is int and read_id >= 0 else 0
            ids = record.get('unread_ids', [])
            if not isinstance(ids, list):
                ids = []
            conversation.unread_ids = {mid for mid in ids if type(mid) is int and mid > 0}
            conversation._anonymous_unread = 0
        self.refresh()

    def receive(self, key, item, *, historical=False, catchup=False):
        """Record a unique message already inserted into its Conversation."""
        if not self.active:
            return
        conversation = self.state.conversation(key)
        message_id = item.message_id
        numbered = type(message_id) is int and message_id > 0
        visible = self.is_visible(key) is True
        added_unread = False
        if visible:
            self.mark_read(key, refresh=False)
        elif not item.is_self:
            if historical and not catchup and not self.initialized:
                # A first-ever login establishes a baseline; old snapshot
                # messages do not become a hundred fresh unread notifications.
                if numbered:
                    conversation.read_id = max(conversation.read_id, message_id)
            elif numbered:
                if message_id > conversation.read_id and message_id not in conversation.unread_ids:
                    conversation.unread_ids.add(message_id)
                    added_unread = True
            elif not historical:
                conversation._anonymous_unread += 1
                added_unread = True
        self._changed()
        if added_unread and not historical and not catchup and self._notifications_allowed():
            if self.notify_message is not None:
                self.notify_message(key, item)
            else:
                self.notify('聊天室新消息', '你收到了一条新消息，请打开聊天室查看。')
        self.refresh()

    def mark_read(self, key, *, refresh=True):
        if not self.active or key is None:
            return
        conversation = self.state.conversation(key)
        ids = conversation.message_ids
        if conversation.latest_message is not None and type(conversation.latest_message.message_id) is int:
            ids.append(conversation.latest_message.message_id)
        # Restored unread IDs can refer to messages outside the last login
        # page. Opening the conversation acknowledges its entire unread badge.
        conversation.read_id = max([conversation.read_id, *ids, *conversation.unread_ids])
        conversation.unread_ids.clear()
        conversation._anonymous_unread = 0
        self._changed()
        if refresh:
            self.refresh()

    def focus_changed(self):
        key = self.state.current_chat
        if key is not None and self.is_visible(key) is True:
            self.mark_read(key)

    def history_complete(self):
        """Called only for the first, unscoped login snapshot's completion."""
        if self.active:
            self.initialized = True
            self._changed()

    def forget(self, key):
        # The caller removes its Conversation. Persist the remaining markers so
        # a removed group cannot reappear as a phantom unread count next login.
        if key in self.state.conversations:
            conversation = self.state.conversations[key]
            conversation.unread_ids.clear()
            conversation._anonymous_unread = 0
        self._changed()
        self.refresh()

    def reconcile_groups(self, gids):
        valid = set(gids)
        changed = False
        for key in list(self.state.conversations):
            if key.kind == 'group' and key.target not in valid:
                self.state.conversations.pop(key, None)
                changed = True
        if changed:
            self._changed()
            self.refresh()

    def reset(self):
        self.flush()
        self.endpoint = self.username = None
        self.initialized = False
        self._dirty = self._scheduled = self._reported_error = False

    def _notifications_allowed(self):
        if self.preferences is None:
            return True
        return (self.preferences.notifications_enabled is True and
                self.preferences.do_not_disturb is not True)

    def _changed(self):
        if not self.active:
            return
        self._dirty = True
        if self.schedule is None:
            self.flush()
        elif not self._scheduled:
            self._scheduled = True
            self.schedule(500, self.flush)

    def flush(self):
        self._scheduled = False
        if not self.active or not self._dirty or self.preferences is None:
            return True
        activity = {
            'initialized': self.initialized,
            'conversations': [
                {'kind': key.kind, 'target': key.target, 'read_id': conversation.read_id,
                 'unread_ids': sorted(conversation.unread_ids)}
                for key, conversation in self.state.conversations.items()
            ],
        }
        try:
            # A shallow top-level merge preserves the sync cursor written by
            # the reconnect controller between activity updates.
            self.preferences.update_account(self.endpoint, self.username, {'activity': activity})
        except (OSError, ValueError) as error:
            logging.warning('无法保存未读状态: %s', error)
            if not self._reported_error:
                self.on_error('未读状态保存失败；当前会话可继续使用，请检查配置目录权限。')
                self._reported_error = True
            return False
        else:
            self._dirty = self._reported_error = False
            return True
