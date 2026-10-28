"""UI-independent desktop API, shared by the Python and future Rust cores.

Only this adapter knows the current controller's view interface. Network workers
never mutate this view. All dispatch, scheduled callbacks and state projections
run on one owner thread. No Tk imports, sockets listening locally, or UI secrets
in snapshots/logs. See docs/DESKTOP_PROTOCOL.md for the wire contract.
"""
from dataclasses import asdict
from datetime import datetime
import heapq
import itertools
import json
from pathlib import Path
import queue
import sys
import threading
import time
from types import SimpleNamespace
import uuid

from .app import ChatApplication
from .connection import ClientSettings, ConnectionManager
from .e2ee_crypto import bundle_fingerprint
from .key_vault import VaultExistsError
from .models import ChatKey
from .notification_preview import message_preview
from .preferences import PreferencesStore, ServerProfile


PROTOCOL_VERSION = 1
MAX_LINE_BYTES = 32 * 1024 * 1024


def key_data(key):
    return asdict(key) if key is not None else None


def read_text(params, name, *, maximum=256, empty=False):
    value = params.get(name)
    if not isinstance(value, str) or len(value) > maximum or (not empty and not value):
        raise ValueError('字段格式无效：' + name)
    return value


def message_data(message):
    # IDs are strings on the wire: SQLite's 64-bit IDs exceed JS safe integers.
    return {'id': str(message.message_id) if message.message_id is not None else 'local:' + str(id(message)),
            'author': message.author or '', 'content': message.content,
            'timestamp': message.timestamp, 'self': message.is_self,
            'protection': message.encryption}


class CoreView:
    def __init__(self, runtime):
        self.runtime = runtime
        self.controller = None
        self._destroyed = False
        self._scheduled = set()
        self._input = ''
        self.username = self.password = ''
        self.port = '12345'
        self.busy = False
        self.page = 'login'
        self.status = ''
        self.auth_status = ''
        self.session = uuid.uuid4().hex
        self.focused = False
        self.at_bottom = True
        self.online = []
        self.requests = {}
        self.groups_ui = SimpleNamespace(windows={}, show=self.open_group, close=self.close_group)
        # Compatibility with the existing controller's import-keys fallback.
        self.username_entry = SimpleNamespace(get=lambda: self.username)

    @property
    def state(self):
        return self.controller.state

    def bind_controller(self, controller):
        self.controller = controller
        self.port = str(controller.connection.settings.port)

    def schedule(self, milliseconds, callback):
        if self._destroyed:
            return None
        token = next(self.runtime.sequence)
        self._scheduled.add(token)
        heapq.heappush(self.runtime.timers, (time.monotonic() + milliseconds / 1000, token, callback))
        return token

    def destroy(self):
        self._destroyed = True
        self._scheduled.clear()
        self.runtime.stopped = True

    def changed(self, *args, **kwargs):
        self.runtime.dirty = True

    refresh_controls = refresh_activity = refresh_encryption = changed
    update_friends_listbox = changed

    def build_login(self):
        self.page = 'login'
        self.session = uuid.uuid4().hex
        self.password = self._input = ''
        self.busy = False
        self.requests.clear()
        self.groups_ui.windows.clear()
        self.status = self.auth_status = ''
        self.online = []
        self.runtime.emit('session.reset', {'session': self.session})
        self.changed()

    def build_chat(self):
        self.page = 'chat'
        self.session = uuid.uuid4().hex
        self.password = ''
        self.replace_input(self.controller.take_draft())
        self.changed()

    def set_auth_busy(self, busy, text=''):
        self.busy, self.auth_status = busy, text
        self.changed()

    def registration_complete(self, username):
        self.username, self.password = username, ''
        self.runtime.emit('auth.registered', {'username': username})
        self.changed()

    def credentials(self):
        if not self.username.strip() or not self.password:
            raise ValueError('用户名和密码不能为空')
        port = self.read_port()
        return self.username.strip(), self.password, port

    def read_port(self):
        try:
            port = int(self.port)
            if not 1 <= port <= 65535:
                raise ValueError
            return port
        except ValueError:
            raise ValueError('端口必须是 1–65535 之间的整数') from None

    def apply_profile(self, profile):
        self.port = str(profile.port)
        self.changed()

    def input_text(self):
        return self._input

    @property
    def can_send(self):
        app = self.controller
        encryption = app.encryption
        return bool(app.state.current_chat and app.connection.running and not app.state.pending_messages
                    and (encryption is None or (encryption.ready and not encryption.sending)))

    def replace_input(self, text):
        previous, self._input = self._input, text
        self.runtime.emit('draft.changed', {'session': self.session,
                          'key': key_data(self.state.current_chat), 'text': text, 'previous': previous})

    def clear_input_if_unchanged(self, text):
        if self._input == text:
            self.replace_input('')

    def encryption_passphrase(self):
        return ''

    def notify(self, title, text):
        if self.page == 'login':
            self.auth_status = text
        self.runtime.emit('notice', {'title': title, 'text': text})
        self.changed()

    show_error = notify

    def bell(self):
        self.runtime.emit('bell', {})

    def set_connection_status(self, text, reconnecting=False):
        self.status = text
        self.changed()

    def is_chat_visible(self, key):
        return self.focused and self.page == 'chat' and self.state.current_chat == key and self.at_bottom

    def keep_history(self, key):
        return self.state.current_chat == key and not self.at_bottom

    def render_conversation(self, key, scroll_top=False, *, preserve_scroll=True, **kwargs):
        self.changed()
        if not preserve_scroll:
            self.runtime.emit('conversation.latest', {'key': key_data(key)})

    def append_message(self, key, message):
        self.changed()
        if message.is_self and self.state.pending_history is None and not self.controller.sync.active:
            self.runtime.emit('conversation.latest', {'key': key_data(key)})

    def cache_changed(self, key, evicted):
        self.changed()

    def note_uncached_message(self, key, message):
        self.runtime.emit('conversation.uncached', {'key': key_data(key)})
        self.changed()

    def remove_conversation(self, key):
        self.changed()

    def clear_selection(self):
        self.changed()

    def refresh_groups(self):
        for gid in list(self.groups_ui.windows):
            if gid not in self.state.groups:
                self.close_group(gid)
        self.changed()

    def open_group(self, gid):
        if gid in self.state.groups:
            # React owns its details panel. Do not retain a Python "window":
            # the server handler must emit another open event after it closes.
            self.runtime.emit('group.opened', {'gid': gid})
            self.changed()

    def close_group(self, gid):
        self.groups_ui.windows.pop(gid, None)
        self.changed()

    def update_online_users(self, users):
        self.online = list(users)
        self.changed()

    def ask_request(self, key, title, text, callback):
        # Never answer a queued request using a later account's connection.
        if any(record['key'] == key for record in self.requests.values()):
            return
        self.requests[uuid.uuid4().hex] = {'key': key, 'title': title, 'text': text,
                                         'callback': callback, 'socket': self.controller.connection.sock,
                                         'session': self.session}
        self.changed()

    def confirm_encryption_roster(self, gid, identities, previous):
        old = previous or {}
        recipients = []
        for name, bundle in sorted(identities.items()):
            fingerprint = bundle if isinstance(bundle, str) else bundle_fingerprint(bundle)
            recipients.append({'username': name, 'fingerprint': fingerprint,
                               'change': '新增' if name not in old else ('密钥改变' if old[name] != fingerprint else '')})
        return self.runtime.confirm('确认群聊加密接收人',
                                    '请通过可信渠道核对所有成员与指纹。每位接收人都可以解密此消息。',
                                    recipients=recipients, removed=sorted(set(old) - set(identities)), gid=gid)

    def snapshot(self):
        app, state = self.controller, self.state
        key = state.current_chat
        conversation = state.conversation(key) if key else None
        encryption = app.encryption
        conversations = []
        keys = [ChatKey('private', name) for name in state.friends]
        keys += [ChatKey('group', gid) for gid in state.groups]
        for item in keys:
            chat = state.conversations.get(item)
            latest = chat.latest_message if chat else None
            conversations.append({'key': key_data(item),
                'title': state.groups.get(item.target, {}).get('group_name', item.target) if item.kind == 'group' else item.target,
                'preview': chat.preview if chat else '', 'unread': chat.unread_count if chat else 0,
                'timestamp': latest.timestamp if latest else '', 'online': item.target in self.online if item.kind == 'private' else False})
        profiles = [asdict(profile) for profile in app.preferences.profiles]
        return {'session': self.session, 'page': self.page, 'username': state.username,
                'busy': self.busy, 'authStatus': self.auth_status, 'status': self.status,
                'connected': app.connection.running, 'reconnecting': app.reconnecting,
                'theme': app.preferences.theme, 'profiles': profiles,
                'selectedProfile': app.preferences.selected_profile.name,
                'notifications': app.preferences.notifications,
                'conversations': conversations, 'currentChat': key_data(key),
                'messages': [message_data(message) for message in conversation.messages] if conversation else [],
                'groups': state.groups, 'onlineUsers': self.online,
                'unread': state.total_unread, 'loadingHistory': state.pending_history is not None,
                'syncing': app.sync.active or app.sync.awaiting_initial,
                'syncFailed': app.sync.failed,
                'canLoadOlder': bool(conversation and not conversation.exhausted and app.connection.running
                    and state.pending_history is None and not app.sync.active and not app.sync.awaiting_initial
                    and not app.history.retry_requires_reconnect),
                'newerEvicted': bool(conversation and conversation.newer_evicted),
                'canSend': self.can_send,
                'encryption': {'enabled': encryption is not None, 'ready': bool(encryption and encryption.ready),
                    'status': encryption.status if encryption else '',
                    'fingerprint': encryption.fingerprint if encryption else '',
                    'peers': [dict(peer, changeFingerprint=bundle_fingerprint(change) if (change := encryption.peer_change(peer['username'])) else None)
                              for peer in encryption.peers()] if encryption else []},
                'requests': [{'id': token, 'title': item['title'], 'text': item['text']}
                             for token, item in self.requests.items()],
                'pending': [{'id': item.record_id, 'key': key_data(item.context.key), 'text': item.text,
                             'status': item.status, 'receipts': item.receipts,
                             'createdAt': item.created_at.isoformat()}
                            for item in app.sends.owned_records()]}


class CoreRuntime:
    def __init__(self, *, preferences=None, connection=None, encryption=True, output=None):
        self.output = output or sys.stdout
        self.output_lock = threading.Lock()
        self.incoming = queue.Queue(maxsize=128)
        self.timers = []
        self.sequence = itertools.count()
        self.stopped = False
        self.dirty = True
        self.prompt = None
        self.prompt_answer = None
        self.view = CoreView(self)
        preferences = preferences if preferences is not None else PreferencesStore()
        profile = preferences.selected_profile
        connection = connection or ConnectionManager(ClientSettings(profile.host, profile.port, profile.fingerprint))
        try:
            self.app = ChatApplication(self.view, connection, preferences, encryption=encryption)
        except BaseException:
            connection.close()
            raise
        self.last_notification = None
        self.app.activity.notify_message = self.desktop_message_notification

    def write(self, packet):
        raw = json.dumps(packet, ensure_ascii=False, separators=(',', ':'))
        with self.output_lock:
            self.output.write(raw + '\n')
            self.output.flush()

    def emit(self, method, params):
        self.write({'jsonrpc': '2.0', 'method': method, 'params': params})

    def desktop_message_notification(self, key, message):
        # Capture chat, session and policy on the owner thread, before IPC.
        now, session = time.monotonic(), self.view.session
        if self.last_notification is not None and self.last_notification[0] == session and now - self.last_notification[1] < 1:
            return
        self.last_notification = session, now
        preview = self.app.preferences.notifications['preview']
        title, body = message_preview(key, message, self.app.state.groups, preview)
        self.view.changed()
        self.flush()
        self.emit('desktop.notification', {'title': title, 'body': body,
                  'session': session, 'key': key_data(key), 'preview': preview})

    def flush(self):
        if self.dirty and not self.stopped:
            self.dirty = False
            self.emit('state.changed', self.view.snapshot())

    def _reader(self, source):
        while True:
            line = source.readline(MAX_LINE_BYTES + 2)
            if not line:
                self.incoming.put(None)
                return
            if len(line) > MAX_LINE_BYTES:
                while line and not line.endswith(b'\n'):
                    line = source.readline(MAX_LINE_BYTES + 2)
                self.incoming.put({'invalid': True})
                continue
            try:
                packet = json.loads(line)
            except (ValueError, UnicodeError, RecursionError):
                packet = {'invalid': True}
            self.incoming.put(packet)

    def dispatch(self, packet):
        if packet is None:
            self.app.close()
            return
        request_id = packet.get('id') if isinstance(packet, dict) else None
        if not isinstance(packet, dict) or packet.get('jsonrpc') != '2.0' or type(request_id) not in (int, str):
            self.write({'jsonrpc': '2.0', 'id': None, 'error': {'code': -32600, 'message': '无效的 RPC 请求'}})
            return
        try:
            method, params = packet.get('method'), packet.get('params', {})
            if not isinstance(method, str) or not isinstance(params, dict):
                raise ValueError('无效的方法或参数')
            if self.prompt and method not in ('prompt.reply', 'session.disconnect', 'shutdown'):
                raise ValueError('请先完成或取消当前确认')
            result = self.invoke(method, params)
            self.write({'jsonrpc': '2.0', 'id': request_id, 'result': result})
        except (ValueError, OSError) as error:
            self.write({'jsonrpc': '2.0', 'id': request_id, 'error': {'code': -32000, 'message': str(error)}})
        except Exception:
            # Request payloads can contain passwords, paths and plaintext.
            self.write({'jsonrpc': '2.0', 'id': request_id, 'error': {'code': -32603, 'message': '核心操作失败，请重新连接后重试'}})
        self.flush()

    def require_session(self, params):
        if params.get('session') != self.view.session or self.app.closing:
            raise ValueError('会话已改变，请重新操作')

    def require_connected(self):
        if not self.app.connection.running or self.app.reconnecting:
            raise ValueError('请先连接服务器')

    def selected_key(self, params):
        raw = params.get('key')
        if not isinstance(raw, dict):
            raise ValueError('请选择会话')
        key = ChatKey(raw.get('kind'), raw.get('target'))
        if key != self.app.state.current_chat:
            raise ValueError('当前会话已改变')
        return key

    def profile_guard(self):
        if self.app.connection.running or self.app.connection.auth_busy or self.app.reconnecting:
            raise ValueError('请先断开连接或取消认证，再编辑服务器配置')

    def confirm(self, title, text, **details):
        if self.prompt is not None or self.app.closing:
            return False
        token, session = uuid.uuid4().hex, self.view.session
        self.prompt, self.prompt_answer = token, None
        self.emit('prompt', {'id': token, 'title': title, 'text': text, **details})
        self.flush()
        deadline = time.monotonic() + 120
        try:
            # Preserve synchronous controller trust guards without re-entering
            # network events. Only reply, disconnect and shutdown can run here.
            while self.prompt_answer is None and time.monotonic() < deadline:
                if self.app.closing or self.view.session != session:
                    return False
                try:
                    packet = self.incoming.get(timeout=.05)
                except queue.Empty:
                    continue
                self.dispatch(packet)
            return self.prompt_answer is True and session == self.view.session and not self.app.closing
        finally:
            self.prompt = self.prompt_answer = None
            self.emit('prompt.closed', {'id': token})

    def invoke(self, method, params):
        app, view = self.app, self.view
        if method == 'initialize':
            if type(params.get('protocolVersion')) is not int or params['protocolVersion'] != PROTOCOL_VERSION:
                raise ValueError('不支持的桌面协议版本')
            return {'protocolVersion': PROTOCOL_VERSION, 'implementation': 'python', 'state': view.snapshot()}
        if method == 'shutdown':
            app.close()
            return True
        self.require_session(params)
        if method == 'prompt.reply':
            if self.prompt != params.get('id') or type(params.get('accepted')) is not bool:
                raise ValueError('确认已过期')
            self.prompt_answer = params['accepted']
        elif method == 'auth.login':
            self.profile_guard()
            view.username = read_text(params, 'username').strip()
            view.password = read_text(params, 'password', maximum=1024)
            view.port = str(params.get('port', app.connection.settings.port))
            register = params.get('register', False)
            if type(register) is not bool:
                raise ValueError('注册参数无效')
            try:
                app.login(register=register)
            finally:
                view.password = ''
        elif method == 'auth.migrate':
            self.profile_guard()
            username = read_text(params, 'username').strip()
            password = read_text(params, 'password', maximum=128)
            old = read_text(params, 'oldPassword', maximum=1024)
            local = read_text(params, 'legacyPassphrase', maximum=1024, empty=True)
            if not 8 <= len(password) <= 128 or password == old:
                raise ValueError('新密码须为 8–128 个字符，且不同于旧密码')
            app.start_auth(username, password, migration_password=old, legacy_passphrase=local or None)
        elif method == 'auth.unlockLegacy':
            self.profile_guard()
            if app.encryption is None:
                raise ValueError('未启用加密')
            app.encryption.prepare_legacy_unlock(read_text(params, 'username').strip(),
                (app.connection.settings.host, app.connection.settings.port),
                read_text(params, 'passphrase', maximum=1024))
        elif method == 'auth.cancel':
            app.cancel_auth()
        elif method == 'session.disconnect':
            app.disconnect()
        elif method == 'profile.select':
            self.profile_guard()
            app.apply_profile(app.preferences.select_profile(read_text(params, 'name', maximum=64)))
        elif method == 'profile.save':
            self.profile_guard()
            profile = ServerProfile(read_text(params, 'name', maximum=64), read_text(params, 'host', maximum=253),
                                    params.get('port'), params.get('fingerprint'))
            replacement = params.get('replaceName')
            if replacement is not None and not isinstance(replacement, str):
                raise ValueError('配置名称无效')
            app.preferences.save_profile(profile, replace_name=replacement)
            app.apply_profile(profile)
        elif method == 'profile.delete':
            self.profile_guard()
            app.apply_profile(app.preferences.delete_profile(read_text(params, 'name', maximum=64)))
        elif method == 'settings.theme':
            app.preferences.set_theme(read_text(params, 'theme', maximum=5))
        elif method == 'settings.notifications':
            for field in ('enabled', 'doNotDisturb'):
                if type(params.get(field)) is not bool:
                    raise ValueError('提醒设置无效')
            preview = params.get('preview', app.preferences.notifications['preview'])
            if not isinstance(preview, str) or preview not in ('generic', 'sender', 'message'):
                raise ValueError('通知内容设置无效')
            app.preferences.set_notifications(enabled=params['enabled'], do_not_disturb=params['doNotDisturb'], preview=preview)
            app.notifier.discard_pending()
            # Revoke old native notifications before acknowledging a policy
            # change, rather than leaving a response/state-update race.
            view.changed()
            self.flush()
        elif method == 'window.activity':
            view.focused = params.get('focused') is True
            view.at_bottom = params.get('atBottom') is True
            app.activity.focus_changed()
        elif method == 'conversation.select':
            raw = params.get('key')
            if not isinstance(raw, dict):
                raise ValueError('会话无效')
            key = ChatKey(raw.get('kind'), raw.get('target'))
            if (key.kind == 'private' and key.target not in app.state.friends
                    or key.kind == 'group' and key.target not in app.state.groups):
                raise ValueError('会话已不存在')
            # Save the exact UI draft before switching, without a debounce race.
            view._input = read_text(params, 'draft', maximum=2 * 1024 * 1024, empty=True)
            view.at_bottom = True
            app.select_chat(key)
        elif method == 'conversation.clear':
            view._input = read_text(params, 'draft', maximum=2 * 1024 * 1024, empty=True)
            app.clear_chat_selection()
        elif method == 'draft.set':
            if params.get('key') != key_data(app.state.current_chat):
                raise ValueError('当前会话已改变')
            view._input = read_text(params, 'text', maximum=2 * 1024 * 1024, empty=True)
            return True
        elif method == 'message.send':
            self.require_connected()
            self.selected_key(params)
            if not view.can_send:
                raise ValueError('请等待连接或加密身份准备完成')
            view._input = read_text(params, 'text', maximum=2 * 1024 * 1024)
            app.send_message()
        elif method in ('history.older', 'history.latest'):
            self.require_connected()
            self.selected_key(params)
            (app.load_older_history if method.endswith('older') else app.load_latest_history)()
        elif method == 'sync.retry':
            self.require_connected()
            app.retry_sync()
        elif method == 'friend.add':
            self.require_connected()
            app.add_friend(read_text(params, 'username').strip())
        elif method == 'request.reply':
            item = view.requests.pop(read_text(params, 'id'), None)
            if item is None or type(params.get('accepted')) is not bool:
                raise ValueError('申请已过期')
            if item['session'] != view.session or item['socket'] is not app.connection.sock:
                raise ValueError('连接已改变，请等待重新获取申请')
            self.require_connected()
            item['callback'](params['accepted'])
        elif method.startswith('group.'):
            self.group_action(method, params)
        elif method.startswith('keys.'):
            self.key_action(method, params)
        elif method == 'password.change':
            current = read_text(params, 'currentPassword', maximum=1024)
            new = read_text(params, 'newPassword', maximum=128)
            if not 8 <= len(new) <= 128:
                raise ValueError('新密码须为 8–128 个字符')
            app.change_account_password(current, new)
        elif method in ('send.recover', 'send.dismiss'):
            record = next((item for item in app.sends.owned_records() if item.record_id == params.get('id')), None)
            if record is None:
                raise ValueError('记录已不存在')
            if method == 'send.recover':
                app.sends.recover(record)
            else:
                app.sends.dismiss(record.record_id)
        else:
            raise ValueError('未知的桌面方法')
        view.changed()
        return True

    def group_action(self, method, params):
        self.require_connected()
        app = self.app
        if method == 'group.create':
            members = params.get('members')
            if (not isinstance(members, list) or not 1 <= len(members) <= 255
                    or any(not isinstance(name, str) or name not in app.state.friends for name in members)
                    or len(set(members)) != len(members)):
                raise ValueError('请选择有效的好友作为群成员')
            app.try_send({'type': 'group_create', 'from': app.state.username,
                          'group_name': read_text(params, 'name', maximum=128).strip(), 'members': members})
            return
        gid = read_text(params, 'gid')
        info = app.state.groups.get(gid)
        if info is None:
            raise ValueError('群聊已不存在')
        if method == 'group.info':
            app.request_group_info(gid, open_window=True)
            return
        actions = {'group.invite': ('group_invite', 'to', 'username'),
                   'group.kick': ('group_kick', 'kick', 'username'),
                   'group.transfer': ('group_transfer', 'new_owner', 'username'),
                   'group.rename': ('group_rename', 'new_name', 'name'),
                   'group.leave': ('group_leave', None, None),
                   'group.disband': ('group_disband', None, None)}
        if method not in actions:
            raise ValueError('未知的群操作')
        if method in ('group.kick', 'group.transfer', 'group.rename', 'group.disband') and info.get('owner') != app.state.username:
            raise ValueError('此操作需要群主权限')
        kind, field, parameter = actions[method]
        packet = {'type': kind, 'gid': gid, 'from': app.state.username}
        if field:
            packet[field] = read_text(params, parameter).strip()
        app.try_send(packet)

    def key_action(self, method, params):
        app = self.app
        if app.encryption is None:
            raise ValueError('未启用加密')
        if method == 'keys.reviewGroup':
            self.selected_key(params)
            app.review_encryption_group()
        elif method == 'keys.verify':
            app.verify_encryption_peer(read_text(params, 'username'), read_text(params, 'fingerprint', maximum=64))
        elif method == 'keys.acceptChange':
            name = read_text(params, 'username')
            bundle = app.encryption.peer_change(name)
            if bundle is None or bundle_fingerprint(bundle) != params.get('fingerprint'):
                raise ValueError('联系人密钥已改变，请重新核对')
            app.accept_encryption_peer(name, bundle)
        elif method == 'keys.export':
            password = read_text(params, 'password', maximum=1024)
            if not app.connection.is_login_password(password):
                raise ValueError('统一密码不正确，未导出备份')
            app.export_encryption_keys(read_text(params, 'path', maximum=4096), password)
            self.view.notify('密钥备份', '离线备份已加密导出，恢复时需要导出时的密码。改密后请重新导出备份。')
        elif method == 'keys.import':
            self.profile_guard()
            path = read_text(params, 'path', maximum=4096)
            password = read_text(params, 'password', maximum=1024)
            username = read_text(params, 'username').strip()
            with Path(path).open('rb') as source:
                raw = source.read(8 * 1024 * 1024 + 1)
            if len(raw) > 8 * 1024 * 1024:
                raise ValueError('密钥备份超过大小限制')
            header = json.loads(raw)
            origin = header.get('scope', {}) if isinstance(header, dict) else {}
            if not isinstance(origin, dict):
                raise ValueError('备份账号格式无效')
            endpoint = (app.connection.settings.host, app.connection.settings.port)
            rebind = origin.get('endpoint') != [endpoint[0].lower(), endpoint[1]]
            if rebind and not self.confirm('确认密钥备份迁移',
                    f'备份所属服务器：{origin.get("endpoint")}\n当前服务器：{list(endpoint)}\n'
                    '请核实当前服务器指纹。是否将同一账号的密钥恢复到当前服务器？'):
                return
            try:
                app.import_encryption_keys(path, password, username, endpoint, allow_rebind=rebind)
            except VaultExistsError:
                if not self.confirm('替换本机密钥', '备份已验证。本机已有密钥，替换将覆盖私钥、联系人信任、群确认与重放记录。较旧备份可能恢复旧的信任状态。确定替换？'):
                    return
                app.import_encryption_keys(path, password, username, endpoint, allow_rebind=rebind, replace=True)
            self.view.notify('恢复密钥', '备份已恢复，请使用统一密码登录；旧账号请先迁移。')
        else:
            raise ValueError('未知的密钥操作')

    def run_due(self):
        started = time.monotonic()
        while self.timers and self.timers[0][0] <= time.monotonic() and time.monotonic() - started < .02:
            _, token, callback = heapq.heappop(self.timers)
            if token in self.view._scheduled:
                self.view._scheduled.remove(token)
                callback()

    def run(self, source=None):
        source = source or sys.stdin.buffer
        threading.Thread(target=self._reader, args=(source,), name='desktop-stdin', daemon=True).start()
        try:
            self.flush()
            while not self.stopped:
                try:
                    packet = self.incoming.get(timeout=.01)
                except queue.Empty:
                    pass
                else:
                    self.dispatch(packet)
                self.run_due()
                self.flush()
        except (BrokenPipeError, KeyboardInterrupt):
            pass
        finally:
            if not self.app.closing:
                self.app.close()
            self.app.connection.close()
        return 0
