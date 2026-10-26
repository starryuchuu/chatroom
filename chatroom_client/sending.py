"""Owner-thread send recovery. Outgoing bodies never leave volatile memory."""
from contextlib import nullcontext
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import uuid

from .models import ChatKey
from .protocol import encrypt_message
from .request_context import SessionContext


@dataclass(repr=False)
class PendingSend:
    context: SessionContext
    endpoint: tuple
    payload: dict
    text: str
    receipts: bool
    size: int
    record_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    status: str = 'sending'
    timer: object = field(default_factory=object)
    query: str | None = None

    @property
    def request_id(self):
        return self.payload['request_id']


class SendController:
    MAX_RECORDS = 20
    MAX_BYTES = 8 * 1024 * 1024

    def __init__(self, app):
        self.app = app
        self.records = []

    def _owns(self, record):
        state, connection = self.app.state, self.app.connection
        context = record.context
        endpoint = connection.endpoint or (self.app._session_endpoint if self.app.reconnecting else None)
        return (state.username == context.username and tuple(endpoint or ()) == record.endpoint
                and (context.group_generation is None or (
                    context.key.target in state.groups and state.group_generations.get(context.key.target, 0)
                    == context.group_generation)))

    def before_send(self, key, text):
        for record in self.records[:]:
            if not self._owns(record):
                self._forget(record)
            elif record.context.key == key and record.text == text and record.status != 'sending':
                self.recover(record)
                return False
        return True

    def send(self, payload, text):
        payload = deepcopy(payload)
        receipts = 'message_receipts' in self.app.connection.capabilities
        if receipts:
            payload['idempotency_key'] = payload['request_id']
        size = len(json.dumps(payload, ensure_ascii=True).encode()) + len(text.encode('utf-8'))
        if len(self.records) >= self.MAX_RECORDS or sum(item.size for item in self.records) + size > self.MAX_BYTES:
            self._notify('待确认消息较多，请先核对发送结果；输入已保留')
            return
        key = ChatKey('group', payload['gid']) if payload['type'] == 'group_chat' else ChatKey('private', payload['to'])
        context = SessionContext.capture(self.app.state, self.app.connection, key)
        if not context.matches(self.app.state, self.app.connection) or not self.app.try_send(payload):
            return
        record = PendingSend(context, tuple(self.app.connection.endpoint or ()), payload, text, receipts, size)
        self.records.append(record)
        self._wait(record)

    def _wait(self, record):
        record.status, record.query, record.timer = 'sending', None, object()
        self.app.state.pending_messages[record.request_id] = record.text
        self.app.view.refresh_controls()
        self._notify('发送中，等待服务器保存确认…')
        token, sock = record.timer, self.app.connection.sock
        request_id = record.request_id
        self.app.view.schedule(15000, lambda: self.expire(sock, request_id, token))

    def expire(self, sock, request_id, token=None):
        record = next((item for item in self.records if item.request_id == request_id), None)
        if record is not None and not self._owns(record):
            self._forget(record)
            self.app.view.refresh_controls()
            return
        if (record is None or self.app.connection.sock is not sock
                or (token is not None and record.timer is not token) or record.status != 'sending'):
            return
        self.app.state.pending_messages.pop(request_id, None)
        record.status = 'uncertain'
        self._notify('保存结果待确认，输入已保留；可以继续编辑或发送其他内容')
        if record.receipts:
            self.query(record)
        self.app.view.refresh_controls()

    def finish(self, message):
        record = next((item for item in self.records if item.request_id == message.get('request_id')), None)
        if record is None:
            return False
        if not self._owns(record):
            self._forget(record)
            self.app.view.refresh_controls()
            return True
        kind = message.get('type')
        if kind not in (None, record.payload['type'] + '_result', 'send_failed'):
            return True
        if kind == 'send_failed':
            self.app.state.pending_messages.pop(record.request_id, None)
            record.status = 'uncertain'
            self._notify('发送中断，保存结果待确认；输入已保留')
        else:
            self._complete(record, message.get('success') is True, message.get('error'))
        self.app.view.refresh_controls()
        return True

    def _complete(self, record, success, error=None):
        self._forget(record)
        if success:
            self.app.clear_sent_draft(record.context.key, record.text)
            self._notify('服务器已保存')
        else:
            self._notify(error or '发送失败，输入已保留')

    def current(self):
        return next((item for item in self.records if item.context.key == self.app.state.current_chat
                     and self._owns(item) and item.status != 'sending'), None)

    def owned_records(self):
        return [record for record in self.records if self._owns(record)]

    def dismiss(self, record_id):
        record = next((item for item in self.owned_records() if item.record_id == record_id), None)
        if record is None or record.status == 'sending':
            return False
        self._forget(record)
        self._notify('已移除本机待确认记录；这不会撤回消息或确认服务器保存结果')
        self.app.view.refresh_controls()
        return True

    def recover(self, record=None):
        record = record or self.current()
        if (record is None or not any(item is record for item in self.records)
                or not self._owns(record) or not self.app.connection.running or record.status == 'sending'):
            return
        if not record.receipts or 'message_receipts' not in self.app.connection.capabilities:
            self._notify('此服务器无法核对发送结果，请查看历史记录后再决定是否重发')
            return
        if record.status == 'retry':
            if self.app.state.pending_messages:
                self._notify('请等待当前消息的保存确认')
                return
            payload = dict(record.payload, request_id=uuid.uuid4().hex)
            if 'content' in payload:
                payload['content'] = encrypt_message(record.text, self.app.connection.session_key)
            try:
                encryption = self.app.encryption
                guard = encryption.retry_guard(payload) if encryption is not None else nullcontext()
                with guard:
                    sent = self.app.try_send(payload)
            except (ValueError, TypeError, KeyError, OSError) as error:
                self._notify(str(error))
                return
            if sent:
                record.payload = payload
                record.context = SessionContext.capture(self.app.state, self.app.connection, record.context.key)
                self._wait(record)
        elif record.query is None:
            self.query(record)

    def query(self, record):
        query = uuid.uuid4().hex
        key = record.context.key
        if not self.app.try_send({'type': 'message_status_request', 'request_id': query,
                                 'idempotency_key': record.payload['idempotency_key'],
                                 'chat_type': key.kind, 'target': key.target}):
            return
        record.query, record.status = query, 'checking'
        sock = self.app.connection.sock

        def expired():
            pending = next((item for item in self.records if item.query == query), None)
            if pending is not None and self.app.connection.sock is sock:
                pending.query, pending.status = None, 'uncertain'
                self._notify('暂时无法核对保存结果，可稍后再次核对；输入已保留')
                self.app.view.refresh_controls()
        self.app.view.schedule(10000, expired)

    def handle(self, message):
        if not isinstance(message, dict) or message.get('type') != 'message_status_result':
            return False
        record = next((item for item in self.records if item.query == message.get('request_id')
                       and item.query is not None), None)
        if record is None or not self._owns(record):
            return True
        key = record.context.key
        if (message.get('idempotency_key') != record.payload.get('idempotency_key')
                or message.get('chat_type') != key.kind or message.get('target') != key.target):
            return True
        record.query = None
        if (message.get('success') is True and message.get('status') == 'saved'
                and type(message.get('message_id')) is int and message['message_id'] > 0):
            payload = dict(record.payload, **{'from': self.app.state.username},
                           message_id=message['message_id'], timestamp=message.get('timestamp', ''), history=False)
            if 'content' in payload:
                payload['content'] = encrypt_message(record.text, self.app.connection.session_key)
            self._complete(record, True)
            self.app.events.chat_message(payload, recovered=True)
        elif message.get('success') is True and message.get('status') == 'not_found':
            record.status = 'retry'
            self._notify('服务器尚无保存回执，可在“待确认消息”中选择重试；重复请求会自动去重')
        else:
            record.status = 'uncertain'
            self._notify('暂时无法核对保存结果，输入已保留')
        self.app.view.refresh_controls()
        return True

    def pause(self):
        for record in self.records:
            record.query, record.status, record.timer = None, 'uncertain', object()

    def resume(self):
        for record in self.records[:]:
            if not self._owns(record):
                self._forget(record)
            elif record.receipts and 'message_receipts' in self.app.connection.capabilities:
                self.query(record)

    def _forget(self, record):
        self.app.state.pending_messages.pop(record.request_id, None)
        if record in self.records:
            self.records.remove(record)

    def reset(self):
        self.records.clear()

    def invalidate(self, key):
        for record in self.records[:]:
            if record.context.key == key:
                self._forget(record)

    def _notify(self, text):
        self.app.view.notify('消息', text)
