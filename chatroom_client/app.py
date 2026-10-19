"""Application actions and event pump, composed from UI, model and connection."""
import logging
import queue
import uuid

from .connection import AuthResult, ServerEvent
from .events import ServerEvents
from .history import HistoryController
from .models import ClientState
from .protocol import encrypt_message


class ChatApplication:
    def __init__(self, view, connection):
        self.view, self.connection = view, connection
        self.state = ClientState()
        self.closing = False
        self.auth_window = None
        self.history = HistoryController(
            self.state, self.queue_send,
            lambda title, text: self.view.notify(title, text),
            lambda key, top: self.view.render_conversation(key, top),
            lambda: self.view.refresh_controls())
        self.events = ServerEvents(self)
        self.view.bind_controller(self)
        self.view.build_login()
        self.view.schedule(50, self.drain_incoming)

    def login(self):
        if self.connection.auth_busy or self.closing:
            return
        credentials = self.view.credentials()
        if credentials is not None:
            username, password, port = credentials
            self.connection.settings.port = port
            self.connect_server(username, password)

    def connect_server(self, username, password):
        self.start_auth(username, password)

    def start_auth(self, username, password, register=False, window=None):
        if self.connection.authenticate(username, password, register=register):
            self.auth_window = window
            self.view.set_auth_busy(True, '正在注册…' if register else '正在连接…')

    def cancel_auth(self):
        self.connection.cancel_auth()
        self.auth_window = None
        self.view.set_auth_busy(False, '连接已取消')

    def finish_auth(self, result):
        if not self.connection.accept_auth(result):
            return
        self.view.set_auth_busy(False)
        window, self.auth_window = self.auth_window, None
        if result.error is not None:
            self.view.notify('注册失败' if result.register else '登录失败', result.error)
        elif result.register:
            self.view.notify('注册成功', '注册成功，请登录')
            if window is not None and window.winfo_exists():
                window.destroy()
        else:
            self.state.reset_session(result.username)
            self.view.build_chat()
            self.connection.receive()

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
        request_id = uuid.uuid4().hex
        data = {'type': key.kind + '_chat', 'request_id': request_id,
                'content': encrypt_message(text, self.connection.session_key),
                'gid' if key.kind == 'group' else 'to': key.target}
        if not self.try_send(data):
            return
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

    def clear_chat_selection(self):
        self.state.current_chat = None
        self.view.clear_selection()

    def load_older_history(self):
        self.history.load_older()

    def handle_server_message(self, message):
        self.events.handle(message)

    def drain_incoming(self):
        if self.closing:
            return
        try:
            for _ in range(100):
                try:
                    event = self.connection.events.get_nowait()
                except queue.Empty:
                    break
                try:
                    if isinstance(event, AuthResult):
                        self.finish_auth(event)
                    elif isinstance(event, ServerEvent) and self.connection.running and self.connection.sock is event.sock:
                        if event.message is None:
                            self.disconnect()
                            self.view.notify('连接断开', '与服务器的连接已断开；输入将在重新登录后恢复')
                        else:
                            self.handle_server_message(event.message)
                except Exception:
                    logging.exception('忽略格式异常的服务器消息')
        finally:
            if not self.closing:
                self.view.schedule(50, self.drain_incoming)

    def draft_key(self):
        endpoint = self.connection.endpoint or (self.connection.settings.host, self.connection.settings.port)
        return (*endpoint, self.state.username)

    def take_draft(self):
        return self.state.drafts.pop(self.draft_key(), '')

    def disconnect(self):
        if not self.connection.running:
            return
        draft = self.view.input_text()
        if draft:
            self.state.drafts[self.draft_key()] = draft
        else:
            self.state.drafts.pop(self.draft_key(), None)
        self.connection.disconnect()
        self.state.reset_session()
        self.view.build_login()

    def close(self):
        if self.closing:
            return
        self.closing = True
        if self.connection.running:
            self.disconnect()
        self.auth_window = None
        self.connection.close()
        self.finish_close()

    def finish_close(self):
        if self.connection.workers_alive():
            self.view.schedule(25, self.finish_close)
            return
        self.connection.clear_events()
        self.view.destroy()
