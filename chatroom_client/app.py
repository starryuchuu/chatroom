"""Application actions and event pump, composed from UI, model and connection."""
import logging
import queue
import time
import uuid

from .connection import AuthResult, PasswordChangeResult, ServerEvent
from .activity import ActivityController
from .events import ServerEvents
from .history import HistoryController
from .models import ClientState
from .notifications import DesktopNotifier
from .preferences import PreferencesStore
from .protocol import encrypt_message
from .reconnect import ReconnectPolicy
from .sync import SyncController


class ChatApplication:
    def __init__(self, view, connection, preferences=None, *, encryption=None):
        self.view, self.connection = view, connection
        self.preferences = preferences if preferences is not None else PreferencesStore(persistent=False)
        self.state = ClientState()
        if encryption is True:
            from .encryption import EncryptionController
            self.encryption = EncryptionController(self)
        else:
            self.encryption = encryption or None
        self.closing = False
        self.auth_window = None
        self.reconnecting = False
        self.reconnect_policy = ReconnectPolicy()
        self._uncertain_send = False
        self._session_endpoint = None
        self.notifier = DesktopNotifier()
        self.activity = ActivityController(
            self.state, self.preferences,
            refresh=lambda: self.view.refresh_activity(),
            notify=self.notifier.notify,
            is_visible=lambda key: self.view.is_chat_visible(key) is True,
            schedule=lambda delay, callback: self.view.schedule(delay, callback),
            on_error=lambda text: self.view.notify('设置保存失败', text))
        self.sync = SyncController(
            self.state, self.queue_send, self.preferences,
            lambda title, text: self.view.notify(title, text),
            self.refresh_sync, lambda delay, callback: self.view.schedule(delay, callback),
            before_commit=self.activity.flush)
        self.history = HistoryController(
            self.state, self.queue_send,
            lambda title, text: self.view.notify(title, text),
            lambda key, top: self.view.render_conversation(key, top),
            lambda: self.view.refresh_controls())
        self.events = ServerEvents(self)
        self.view.bind_controller(self)
        self.view.build_login()
        self.view.schedule(50, self.drain_incoming)
        if self.preferences.warning:
            self.view.notify('客户端设置', self.preferences.warning)

    def apply_profile(self, profile):
        if self.connection.running or self.connection.auth_busy or self.reconnecting:
            raise ValueError('请先断开连接或取消重连，再切换服务器')
        self.connection.settings.host = profile.host
        self.connection.settings.port = profile.port
        self.connection.settings.expected_fingerprint = profile.fingerprint
        self.connection.forget_credentials()
        self.view.apply_profile(profile)

    def login(self):
        if self.connection.auth_busy or self.closing or self.connection.running or self.reconnecting:
            return
        credentials = self.view.credentials()
        if credentials is not None:
            username, password, port = credentials
            self.connection.settings.port = port
            self.connect_server(username, password)

    def connect_server(self, username, password):
        self.start_auth(username, password)

    def start_auth(self, username, password, register=False, window=None,
                   migration_password=None, legacy_passphrase=None):
        options = {'register': register}
        if self.encryption is not None:
            try:
                endpoint = (self.connection.settings.host, self.connection.settings.port)
                options['prepare'] = self.encryption.prepare_login(username, password, endpoint)
                if legacy_passphrase is not None:
                    options['prepare'].passphrase = legacy_passphrase
                if migration_password is not None:
                    options['migration_password'] = migration_password
            except (ValueError, OSError) as error:
                self.view.notify('本机密钥', str(error))
                return
        if self.connection.authenticate(username, password, **options):
            self.auth_window = window
            self.view.set_auth_busy(True, '正在迁移旧账号…' if migration_password is not None else
                                    ('正在注册…' if register else '正在连接…'))

    def cancel_auth(self):
        if self.reconnecting:
            self.disconnect()
            return
        self.connection.cancel_auth()
        self.auth_window = None
        self.view.set_auth_busy(False, '连接已取消')

    def finish_auth(self, result):
        if not self.connection.accept_auth(result):
            if self.encryption is not None:
                self.encryption.discard_result(result)
            return
        resuming = self.reconnecting
        if not resuming:
            self.view.set_auth_busy(False)
        window, self.auth_window = self.auth_window, None
        if result.error is not None:
            if self.encryption is not None:
                self.encryption.discard_result(result)
            if resuming:
                if result.retryable and self.connection.can_reconnect:
                    self.schedule_reconnect(self.reconnect_policy.retry())
                else:
                    self.disconnect()
                    self.view.notify('自动重连已停止', result.error + '；请重新登录')
            else:
                self.view.notify('注册失败' if result.register else '登录失败', result.error)
        elif result.register:
            self.view.notify('注册成功', '注册成功，请登录')
            if window is not None and window.winfo_exists():
                window.destroy()
        else:
            self.reconnecting = False
            self.reconnect_policy.stop()
            self._session_endpoint = result.endpoint
            if not resuming:
                self.state.reset_session(result.username)
                self.activity.activate(result.endpoint, result.username)
            self.sync.establish(result.endpoint, result.username, result.capabilities)
            if not resuming:
                self.view.build_chat()
            if self.encryption is not None:
                self.encryption.establish(result)
            self.view.set_connection_status('已连接 · 正在补取消息')
            self.view.refresh_controls()
            self.connection.receive()

    def lost_connection(self):
        if not self.connection.running:
            return
        if not self.connection.can_reconnect:
            self.disconnect()
            self.view.notify('连接断开', '与服务器的连接已断开；输入将在重新登录后恢复')
            return
        self._uncertain_send = bool(self.state.pending_messages) or self._uncertain_send
        self.state.pending_messages.clear()
        self.state.pending_history = None
        self.sync.abort()
        if self.encryption is not None:
            self.encryption.pause()
        self.activity.flush()
        self.connection.disconnect(preserve_credentials=True)
        self.reconnecting = True
        self.schedule_reconnect(self.reconnect_policy.start())

    def schedule_reconnect(self, delay):
        if delay is None or self.closing or not self.reconnecting:
            return
        token = self.reconnect_policy.token
        self.view.set_connection_status(f'连接已断开 · {delay} 秒后自动重试（第 {self.reconnect_policy.attempt} 次）', reconnecting=True)
        self.view.refresh_controls()
        self.view.schedule(int(delay * 1000), lambda: self.attempt_reconnect(token))

    def attempt_reconnect(self, token):
        if self.closing or not self.reconnecting or not self.reconnect_policy.is_current(token):
            return
        self.view.set_connection_status(f'正在重新连接（第 {self.reconnect_policy.attempt} 次）…', reconnecting=True)
        if not self.connection.authenticate_saved():
            if not self.connection.can_reconnect:
                self.disconnect()
                self.view.notify('自动重连已停止', '请重新登录')
            elif not self.connection.auth_busy:
                self.schedule_reconnect(self.reconnect_policy.retry())

    def refresh_sync(self):
        if self.closing or not self.connection.running:
            return
        if self.sync.active or self.sync.awaiting_initial:
            self.view.set_connection_status('已连接 · 正在补取消息')
        elif self.sync.failed:
            self.view.set_connection_status('已连接 · 消息补取未完成')
        else:
            self.view.set_connection_status('已连接')
            if self._uncertain_send:
                self.view.notify('消息结果待确认', '断线前未确认的输入已保留，请查看历史后决定是否重发')
                self._uncertain_send = False
        key = self.state.current_chat
        if key is not None and not self.state.history_syncing:
            self.view.render_conversation(key)
        self.view.refresh_controls()

    def retry_sync(self):
        if self.connection.running:
            self.sync.retry()

    def queue_send(self, data):
        self.connection.send(data)

    def try_send(self, data):
        try:
            self.queue_send(data)
            return True
        except Exception as error:
            self.view.notify('发送失败', str(error))
            return False

    def send_message(self):
        text = self.view.input_text()
        if not text.strip() or self.state.pending_messages:
            return
        if not self.connection.session_key:
            self.view.notify('发送失败', '会话密钥未建立')
            return
        key = self.state.current_chat
        if key is None:
            self.view.notify('提示', '请选择好友或群组进行聊天')
            return
        if self.encryption is not None:
            self.encryption.send_message(text, key)
            return
        request_id = uuid.uuid4().hex
        data = {'type': key.kind + '_chat', 'request_id': request_id,
                'content': encrypt_message(text, self.connection.session_key),
                'gid' if key.kind == 'group' else 'to': key.target}
        self.send_chat_payload(data, text)

    def send_chat_payload(self, data, text):
        if not self.try_send(data):
            return
        request_id = data['request_id']
        self.state.pending_messages[request_id] = text
        self.view.refresh_controls()
        self.view.notify('消息', '发送中，等待服务器保存确认…')
        sock = self.connection.sock
        self.view.schedule(15000, lambda: self.expire_pending(sock, request_id))

    def expire_pending(self, sock, request_id):
        if self.connection.sock is sock and request_id in self.state.pending_messages:
            self.view.notify('消息', '尚未收到确认，输入已保留；可断开后查看历史确认结果')

    def finish_pending(self, message):
        text = self.state.pending_messages.pop(message.get('request_id'), None)
        if text is None:
            return
        if message.get('success'):
            self.view.clear_input_if_unchanged(text)
            self.view.notify('消息', '服务器已保存')
        else:
            self.view.notify('发送失败', message.get('error', '请重试，输入已保留'))
        self.view.refresh_controls()

    def add_friend(self, friend):
        if not friend:
            self.view.show_error('错误', '请输入好友用户名！')
        elif friend == self.state.username:
            self.view.show_error('错误', '不能添加自己为好友！')
        elif friend in self.state.friends:
            self.view.show_error('错误', f'{friend} 已经是你的好友')
        else:
            self.try_send({'type': 'friend_request', 'from': self.state.username, 'to': friend})

    def request_group_info(self, gid, open_window=False):
        if open_window:
            self.state.group_info_requests.add(gid)
        if not self.try_send({'type': 'group_info', 'from': self.state.username, 'gid': gid}):
            self.state.group_info_requests.discard(gid)

    def select_chat(self, key):
        self.state.current_chat = key
        self.view.render_conversation(key)
        self.activity.focus_changed()

    def clear_chat_selection(self):
        self.state.current_chat = None
        self.view.clear_selection()

    def load_older_history(self):
        if self.connection.running and not self.sync.active and not self.sync.awaiting_initial:
            self.history.load_older()

    def handle_server_message(self, message):
        if self.encryption is not None and self.encryption.handle(message):
            return
        if self.sync.handle(message):
            return
        self.events.handle(message)
        if isinstance(message, dict) and message.get('type') == 'history_end' and not message.get('history_kind'):
            self.activity.history_complete()
            self.sync.on_initial_history_end(message)

    def drain_incoming(self):
        if self.closing:
            return
        started = time.monotonic()
        try:
            for _ in range(100):
                try:
                    event = self.connection.events.get_nowait()
                except queue.Empty:
                    break
                try:
                    if isinstance(event, AuthResult):
                        self.finish_auth(event)
                    elif isinstance(event, PasswordChangeResult):
                        if event.generation == self.connection.generation and event.sock is self.connection.sock:
                            self.view.notify('修改账号密码', event.error or event.warning or
                                             '统一密码已更新。原离线备份仍使用导出时的密码，请重新导出备份。')
                    elif isinstance(event, ServerEvent) and self.connection.running and self.connection.sock is event.sock:
                        if event.message is None:
                            self.lost_connection()
                        else:
                            self.handle_server_message(event.message)
                except Exception:
                    logging.exception('忽略格式异常的服务器消息')
                # Encrypted trust persistence can take longer than transport
                # decryption. Yield to Tk between messages during catch-up.
                if time.monotonic() - started >= 0.02:
                    break
        finally:
            if not self.closing:
                if self.notifier.poll():
                    self.view.bell()
                self.view.schedule(50, self.drain_incoming)

    def draft_key(self):
        endpoint = self.connection.endpoint or self._session_endpoint or (self.connection.settings.host, self.connection.settings.port)
        return (*endpoint, self.state.username)

    def take_draft(self):
        return self.state.drafts.pop(self.draft_key(), '')

    def disconnect(self):
        had_session = self.connection.running or self.reconnecting or self.state.username is not None
        if had_session:
            draft = self.view.input_text()
            if draft:
                self.state.drafts[self.draft_key()] = draft
            else:
                self.state.drafts.pop(self.draft_key(), None)
        self.reconnecting = False
        self.reconnect_policy.stop()
        self.sync.abort()
        if self.encryption is not None:
            self.encryption.reset()
        self.activity.flush()
        self.activity.reset()
        self.notifier.discard_pending()
        self.connection.cancel_auth()
        self.connection.disconnect()
        self.state.reset_session()
        self._session_endpoint = None
        self._uncertain_send = False
        if not self.closing:
            self.view.build_login()

    def export_encryption_keys(self, path, passphrase=None):
        if self.encryption is None:
            raise ValueError('此客户端实例未启用端到端加密')
        return self.encryption.export_keys(path, passphrase)

    def change_account_password(self, current_password, new_password):
        if self.encryption is None or self.encryption.vault is None:
            raise ValueError('请先登录并解锁加密身份')
        if not self.connection.change_password(current_password, new_password, self.encryption.vault):
            raise ValueError('密码更新正在进行，或当前连接不支持统一密码；请稍后重试')
        self.view.notify('修改账号密码', '正在验证并更新统一密码，请等待结果。')

    def change_encryption_passphrase(self, value):
        if self.encryption is None:
            raise ValueError('此客户端实例未启用端到端加密')
        return self.encryption.change_passphrase(value)

    def import_encryption_keys(self, path, passphrase, username=None, endpoint=None, *, replace=False, allow_rebind=False):
        if self.encryption is None:
            raise ValueError('此客户端实例未启用端到端加密')
        if username is None:
            username = self.view.username_entry.get().strip()
        if not username:
            raise ValueError('请先填写密钥备份所属的用户名')
        if endpoint is None:
            port = self.view.read_port()
            if port is None:
                raise ValueError('请输入有效的服务器端口')
            endpoint = (self.connection.settings.host, port)
        return self.encryption.import_keys(path, passphrase, username, endpoint,
                                           replace=replace, allow_rebind=allow_rebind)

    def verify_encryption_peer(self, username):
        if self.encryption is None:
            raise ValueError('此客户端实例未启用端到端加密')
        return self.encryption.verify_peer(username)

    def accept_encryption_peer(self, username, bundle):
        if self.encryption is None:
            raise ValueError('此客户端实例未启用端到端加密')
        return self.encryption.accept_peer(username, bundle)

    def review_encryption_group(self):
        if self.encryption is None:
            raise ValueError('此客户端实例未启用端到端加密')
        return self.encryption.review_group(self.state.current_chat)

    def close(self):
        if self.closing:
            return
        self.closing = True
        self.disconnect()
        self.auth_window = None
        self.notifier.close()
        self.connection.close()
        self.finish_close()

    def finish_close(self):
        if self.connection.workers_alive():
            self.view.schedule(25, self.finish_close)
            return
        self.connection.clear_events()
        self.view.destroy()
