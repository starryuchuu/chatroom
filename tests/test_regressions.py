"""Regression tests using real RSA/AES/Argon2 and isolated SQLite state."""
from contextlib import closing
import base64
import gc
import importlib.util
import io
import os
from pathlib import Path
import queue
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

client = load('chat_client', ROOT / 'client.py')

from chatroom_client.app import ChatApplication
from chatroom_client.connection import ClientSettings, ConnectionManager, ServerEvent
from chatroom_client.models import ChatKey, Message
from chatroom_client.preferences import PreferencesStore
from chatroom_client.view import TkClientView


def headless_client(testcase):
    view = Mock()
    view.input_text.return_value = ''
    connection = ConnectionManager(ClientSettings())
    app = ChatApplication(view, connection)
    connection.sock = Mock()
    connection.running = True
    connection.send = Mock()
    view.reset_mock()
    testcase.addCleanup(app.close)
    return app


class ClientTests(unittest.TestCase):
    def app(self):
        return headless_client(self)

    def test_server_error_survives_disconnect(self):
        app = self.app()
        order = []
        app.disconnect = lambda: order.append('disconnect')
        app.view.notify = lambda title, text: order.append(text)
        app.handle_server_message({'type': 'error', 'message': 'expired'})
        self.assertEqual(order, ['disconnect', 'expired'])

    def test_group_snapshot_chunks_are_applied_only_when_complete(self):
        import json
        app = self.app()
        app.state.groups = {'old': {}}
        app.view.refresh_groups = Mock()
        data = json.dumps({'type': 'user_groups_list', 'groups': [{'gid': 'g', 'group_name': '名字'}]})
        app.handle_server_message({'type': 'user_groups_chunk', 'data': data[:20], 'first': True})
        self.assertIn('old', app.state.groups)
        app.handle_server_message({'type': 'user_groups_chunk', 'data': data[20:], 'last': True})
        self.assertEqual(set(app.state.groups), {'g'})

    def test_old_connection_events_do_not_disconnect_new_login(self):
        app = self.app()
        app.handle_server_message = Mock()
        app.disconnect = Mock()
        app.connection.events.put(ServerEvent(object(), None))
        app.connection.events.put(ServerEvent(object(), {'type': 'friends_list', 'friends': ['old']}))
        app.connection.events.put(ServerEvent(app.connection.sock, {'type': 'friends_list', 'friends': ['new']}))
        app.drain_incoming()
        app.disconnect.assert_not_called()
        app.handle_server_message.assert_called_once_with({'type': 'friends_list', 'friends': ['new']})

    def test_receiver_does_not_call_tk_or_mutate_state(self):
        app = self.app()
        sock = app.connection.sock
        app.handle_server_message = Mock()
        with patch.object(client.protocol, 'recv_msg', side_effect=[{'type': 'online_users'}, None]):
            worker = threading.Thread(target=app.connection._receive_loop, args=(sock,))
            worker.start(); worker.join(2)
        self.assertFalse(worker.is_alive())
        app.view.master.assert_not_called()
        self.assertEqual(app.view.master.mock_calls, [])
        app.handle_server_message.assert_not_called()
        self.assertEqual(app.connection.events.get_nowait(), ServerEvent(sock, {'type': 'online_users'}))
        self.assertEqual(app.connection.events.get_nowait(), ServerEvent(sock, None))

    def test_disconnect_shutdown_and_clear_session_history(self):
        app = self.app()
        sock = app.connection.sock
        app.connection.session_key = b'secret'
        app.state.username = 'alice'
        key = ChatKey('group', 'old')
        app.state.conversation(key).add(Message('alice', 'old account history', message_id=1))
        app.view.build_login = Mock()
        app.disconnect()
        sock.shutdown.assert_called_once_with(socket.SHUT_RDWR)
        sock.close.assert_called_once()
        self.assertIsNone(app.connection.session_key)
        self.assertIsNone(app.state.username)
        self.assertNotIn(key, app.state.conversations)

    def test_friend_success_waits_for_server_ack(self):
        app = self.app()
        with patch.object(app.view, 'notify') as info:
            app.handle_server_message({'type': 'friend_request_result', 'success': True, 'message': 'stored'})
        info.assert_called_once_with('好友申请', 'stored')

    def test_unrelated_group_removal_keeps_current_chat(self):
        for kind in ('group_kick_notification', 'group_disband_notification'):
            app = self.app()
            app.state.groups = {'old': {'group_name': 'Old'}}
            app.state.current_chat = ChatKey('group', 'other')
            app.view.refresh_groups = Mock()
            app.clear_chat_selection = Mock()
            with patch.object(client.messagebox, 'showinfo'):
                app.handle_server_message({'type': kind, 'gid': 'old', 'group_name': 'Old'})
            self.assertNotIn('old', app.state.groups)
            app.clear_chat_selection.assert_not_called()

    def test_bad_message_does_not_prevent_next_event(self):
        app = self.app()
        app.view.update_online_users = Mock()
        app.connection.events.put(ServerEvent(app.connection.sock, {'type': 'user_groups_list', 'groups': None}))
        app.connection.events.put(ServerEvent(app.connection.sock, {'type': 'online_users', 'users': ['alice']}))
        app.drain_incoming()
        app.view.update_online_users.assert_called_once_with(['alice'])

    def test_clear_selection_preserves_cached_chat_frames(self):
        app = self.app()
        app.state.current_chat = ChatKey('group', 'removed')
        removed_frame, other_frame = Mock(), Mock()
        app.view.chat_frames = {ChatKey('group', 'removed'): removed_frame, ChatKey('group', 'other'): other_frame}
        app.view.current_chat_frame = removed_frame
        app.view.clear_selection = TkClientView.clear_selection.__get__(app.view)
        app.view.chat_container = Mock()
        app.view.chat_container.winfo_children.return_value = [removed_frame, other_frame]
        app.clear_chat_selection()
        removed_frame.pack_forget.assert_called_once()
        removed_frame.destroy.assert_not_called()
        other_frame.destroy.assert_not_called()
        self.assertIsNone(app.view.current_chat_frame)
        self.assertIsNone(app.state.current_chat)

    def test_history_live_overlap_is_deduplicated_and_sorted(self):
        app = self.app()
        app.state.username = 'alice'
        app.connection.session_key = os.urandom(16)
        app.state.friends = ['bob']
        key = ChatKey('private', 'bob')
        app.state.current_chat = key
        app.view.render_conversation = Mock()
        app.view.display_message_with_time = Mock()
        app.handle_server_message({'type': 'history_begin'})
        for message_id in (8, 3, 8, 5):
            app.handle_server_message({'type': 'private_chat', 'from': 'bob', 'to': 'alice',
                                       'message_id': message_id,
                                       'content': client.encrypt_message(str(message_id), app.connection.session_key)})
        self.assertEqual([message.content for message in app.state.conversation(key).messages], ['3', '5', '8'])
        app.view.append_message.assert_not_called()
        app.handle_server_message({'type': 'history_end'})
        app.view.render_conversation.assert_called_once_with(key, False)

    def test_serialized_size_check_never_writes_oversize(self):
        sock = Mock()
        with self.assertRaises(ValueError):
            client.send_msg(sock, {'content': '中' * client.MAX_RECV_MSG_LEN})
        sock.sendall.assert_not_called()

    def test_idle_receive_timeout_preserves_partial_packet(self):
        sock = Mock()
        client.authenticated_sockets.add(sock)
        try:
            sock.recv.side_effect = [b'ab', socket.timeout(), b'cd']
            self.assertEqual(client.recvall(sock, 4), b'abcd')
        finally:
            client.authenticated_sockets.discard(sock)

    def test_ack_requests_conditional_clear_and_failure_supports_retry(self):
        app = self.app()
        app.state.pending_messages = {'request': 'original'}
        app.view.msg_entry = Mock()
        app.view.notify = Mock()
        app.finish_pending({'request_id': 'request', 'success': True})
        app.view.clear_input_if_unchanged.assert_called_once_with('original')
        self.assertEqual(app.state.pending_messages, {})
        app.view.clear_input_if_unchanged.reset_mock()
        app.state.pending_messages = {'retry': 'edited'}
        app.finish_pending({'request_id': 'retry', 'success': False, 'error': 'database locked'})
        self.assertEqual(app.state.pending_messages, {})
        app.view.clear_input_if_unchanged.assert_not_called()

    def test_rejected_invite_sends_response(self):
        app = self.app()
        app.connection.send = Mock()
        app.view.ask_request = Mock(side_effect=lambda key, title, text, callback: callback(False))
        app.handle_server_message({'type': 'group_invite', 'from': 'bob', 'gid': 'gid'})
        app.connection.send.assert_called_once_with({'type': 'group_invite_response', 'gid': 'gid', 'accepted': False})

    def test_failed_history_page_resumes_live_message_display(self):
        app=self.app()
        app.state.current_chat = ChatKey('private', 'bob')
        app.state.history_syncing=True;app.state.pending_history=app.state.current_chat
        app.view.render_conversation=Mock();app.view.refresh_controls=Mock();app.view.notify=Mock()
        app.handle_server_message({'type':'history_error','error':'retry'})
        self.assertFalse(app.state.history_syncing)
        self.assertIsNone(app.state.pending_history)
        app.view.render_conversation.assert_called_once_with(ChatKey('private', 'bob'), False)

    def test_rejoin_restores_history_after_group_cache_removal(self):
        app=self.app()
        app.state.username='alice';app.connection.session_key=os.urandom(16)
        app.state.current_chat=None
        app.state.groups={'g':{'owner':'bob','group_name':'Team','members':['alice','bob']}}
        app.view.refresh_groups=Mock();app.view.notify=Mock()
        msg={'type':'group_chat','gid':'g','from':'bob','message_id':101,
             'content':client.encrypt_message('old message',app.connection.session_key)}
        app.handle_server_message(msg)
        app.handle_server_message({'type':'group_leave_result','gid':'g','success':True})
        app.handle_server_message({'type':'group_join_result','gid':'g','success':True,'group_name':'Team','owner':'bob','members':['alice','bob']})
        app.handle_server_message(msg)
        conversation = app.state.conversation(ChatKey('group', 'g'))
        self.assertEqual(len(conversation.messages),1)
        self.assertEqual(conversation.messages[0].content,'old message')
        self.assertEqual(conversation.message_ids,[101])

class TkClientTests(unittest.TestCase):
    """Exercise real Tk widgets without showing windows or contacting a server."""
    def setUp(self):
        self.root = client.tk.Tk()
        self.root.withdraw()
        self.app = client.ChatClient(self.root, preferences=PreferencesStore(persistent=False), encryption=False)

    def tearDown(self):
        if self.app.connection.auth_busy:
            self.app.cancel_auth()
        if self.app.connection.running:
            self.app.disconnect()
        self.app.close()
        # Tests may replace methods with callbacks that capture the client.
        # Reclaim these cycles on Tcl's owner thread before server tests start.
        self.app = self.root = None
        gc.collect()

    def chat(self):
        self.app.connection.running = True
        self.app.state.username = 'alice'
        self.app.connection.sock = Mock()
        self.app.connection.session_key = os.urandom(16)
        self.app.view.build_chat()
        self.app.connection.send = Mock()
        self.app.state.groups = {'g': {'group_name': 'Before', 'owner': 'alice', 'members': ['alice', 'bob']}}
        self.app.state.current_chat = ChatKey('group', 'g')
        self.app.view.refresh_groups()
        self.app.view.render_conversation(ChatKey('group', 'g'))

    def test_selection_title_send_state_and_live_group_window(self):
        self.chat()
        app = self.app
        app.view.groups_ui.show('g')
        window = app.view.groups_ui.windows['g']
        def texts(widget):
            result = []
            for child in widget.winfo_children():
                if isinstance(child, (client.tk.Label, client.tk.Button)):
                    result.append(child.cget('text'))
                if isinstance(child, client.tk.Listbox):
                    result.extend(child.get(0, client.tk.END))
                result.extend(texts(child))
            return result
        self.assertIn('踢出成员', texts(window))
        app.handle_server_message({'type': 'group_update', 'gid': 'g', 'group_name': 'After',
                                   'owner': 'bob', 'members': ['alice', 'bob', 'carol']})
        self.assertIs(app.view.groups_ui.windows['g'], window)
        self.assertIn('carol', texts(window))
        self.assertIn('群主: bob', texts(window))
        self.assertNotIn('踢出成员', texts(window))
        self.assertEqual(app.view.group_listbox.curselection(), (0,))
        self.assertIn('After', app.view.chat_title.cget('text'))
        app.handle_server_message({'type': 'group_kick_notification', 'gid': 'g', 'group_name': 'After'})
        self.assertFalse(window.winfo_exists())
        self.assertIsNone(app.state.current_chat)
        self.assertEqual(app.view.send_button.cget('state'), 'disabled')

    def test_input_remains_until_ack_and_oversize_stays_editable(self):
        self.chat()
        app = self.app
        app.view.msg_entry.insert('1.0', 'hello')
        app.send_message()
        app.send_message()
        app.connection.send.assert_called_once()
        self.assertEqual(app.view.msg_entry.get('1.0', 'end-1c'), 'hello')
        request_id = next(iter(app.state.pending_messages))
        app.handle_server_message({'type': 'group_chat_result', 'success': True, 'request_id': request_id})
        self.assertEqual(app.view.msg_entry.get('1.0', 'end-1c'), '')
        app.connection.send = ConnectionManager.send.__get__(app.connection)
        text = '中' * (client.MAX_RECV_MSG_LEN // 2)
        app.view.msg_entry.insert('1.0', text)
        app.send_message()
        self.assertEqual(app.view.msg_entry.get('1.0', 'end-1c'), text)
        self.assertEqual(app.state.pending_messages, {})
        self.assertIn('1 MiB', app.view.status_label.cget('text'))

    def test_requests_do_not_pause_event_queue_and_wheel_is_local(self):
        self.chat()
        app = self.app
        app.connection.events.put(ServerEvent(app.connection.sock, {'type': 'group_invite', 'from': 'bob', 'gid': 'other'}))
        app.connection.events.put(ServerEvent(app.connection.sock, {'type': 'online_users', 'users': ['carol']}))
        app.drain_incoming()
        self.assertEqual(app.view.online_listbox.get(0, client.tk.END), ('carol',))
        self.assertIsNone(self.root.grab_current())
        self.assertTrue(app.view.request_windows[('group', 'other')].winfo_exists())
        self.assertFalse(self.root.bind_all('<MouseWheel>'))
        app.view.msg_entry.insert('1.0', 'draft')
        app.disconnect()
        self.assertEqual(app.state.drafts[(client.SERVER_HOST, app.connection.settings.port, 'alice')], 'draft')
        self.assertFalse(self.root.bind_all('<MouseWheel>'))

    def scrollable_chat(self):
        self.chat()
        app = self.app
        key = ChatKey('group', 'g')
        for index in range(80):
            app.state.conversation(key).add(Message('bob', f'message {index}', 'now', index))
        app.view.render_conversation(key)
        self.root.deiconify()
        self.root.update()
        frame = app.view.chat_frames[key]
        bubble = frame.winfo_children()[0]
        return [app.view.chat_canvas, app.view.chat_container, frame, bubble, *bubble.winfo_children()]

    def test_x11_wheel_scrolls_every_chat_surface_without_global_bindings(self):
        if self.root.tk.call('tk', 'windowingsystem') != 'x11':
            self.skipTest('X11 mouse buttons are specific to the X11 Tk backend')
        widgets = self.scrollable_chat()
        app = self.app
        for widget in widgets:
            for event, direction in (('<Button-4>', -1), ('<Button-5>', 1)):
                with self.subTest(widget=widget.winfo_class(), event=event):
                    app.view.chat_canvas.yview_moveto(0.5)
                    before = app.view.chat_canvas.yview()[0]
                    widget.event_generate(event, x=5, y=5)
                    self.root.update()
                    after = app.view.chat_canvas.yview()[0]
                    self.assertGreater((after - before) * direction, 0)
        for event in ('<MouseWheel>', '<Button-4>', '<Button-5>'):
            self.assertFalse(self.root.bind_all(event))
            self.assertFalse(app.view.msg_entry.bind(event))

    def test_mousewheel_keeps_both_directions_on_every_chat_surface(self):
        widgets = self.scrollable_chat()
        app = self.app
        for widget in widgets:
            for delta, direction in ((120, -1), (-120, 1)):
                with self.subTest(widget=widget.winfo_class(), delta=delta):
                    app.view.chat_canvas.yview_moveto(0.5)
                    before = app.view.chat_canvas.yview()[0]
                    widget.event_generate('<MouseWheel>', delta=delta, x=5, y=5)
                    self.root.update()
                    self.assertGreater((app.view.chat_canvas.yview()[0] - before) * direction, 0)

    def test_login_runs_off_thread_and_can_be_cancelled(self):
        app = self.app
        entered, release = threading.Event(), threading.Event()
        sock = Mock()
        def slow_connect(address):
            entered.set()
            release.wait(2)
            raise OSError('cancelled')
        sock.connect.side_effect = slow_connect
        with patch.object(client.socket, 'socket', return_value=sock):
            started = time.monotonic()
            app.connect_server('alice', 'password')
            self.assertLess(time.monotonic() - started, .5)
            self.assertTrue(entered.wait(1))
            self.assertEqual(app.view.login_button.cget('state'), 'disabled')
            app.cancel_auth()
            self.assertEqual(app.view.login_button.cget('state'), 'normal')
            sock.shutdown.assert_called_once()
            release.set()

    def test_close_stops_workers_before_destroying_tk_and_clears_callbacks(self):
        app = self.app
        entered, release = threading.Event(), threading.Event()
        sock = Mock()
        def connect(address):
            entered.set()
            release.wait(2)
            raise OSError('cancelled')
        sock.connect.side_effect = connect
        sock.shutdown.side_effect = lambda how: release.set()
        with patch.object(client.socket, 'socket', return_value=sock):
            app.connect_server('alice', 'password')
            self.assertTrue(entered.wait(1))
            with patch.object(app.view.master, 'destroy', wraps=app.view.master.destroy) as destroy:
                app.close()
                self.assertTrue(all(not worker.is_alive() for worker in app.connection.workers))
                self.assertTrue(app.connection.events.empty())
                app.close()
                destroy.assert_called_once()

    def test_close_keeps_tk_alive_until_slow_worker_finishes(self):
        app = self.app
        entered, release = threading.Event(), threading.Event()
        def slow_worker():
            entered.set()
            release.wait(2)
        app.connection.start_worker(slow_worker)
        self.assertTrue(entered.wait(1))
        try:
            with patch.object(app.view.master, 'destroy', wraps=app.view.master.destroy) as destroy:
                started = time.monotonic()
                app.close()
                self.assertLess(time.monotonic() - started, 0.5)
                destroy.assert_not_called()
                self.assertTrue(app.view.master.winfo_exists())
                workers = list(app.connection.workers)
                app.connect_server('alice', 'password')
                self.assertEqual(app.connection.workers, workers)
                self.assertFalse(app.connection.auth_busy)
                release.set()
                deadline = time.monotonic() + 2
                while not destroy.called and time.monotonic() < deadline:
                    self.root.update()
                    time.sleep(0.01)
                destroy.assert_called_once()
                self.assertTrue(all(not worker.is_alive() for worker in app.connection.workers))
        finally:
            release.set()

    def test_history_button_requests_earlier_page_and_disables_at_end(self):
        self.chat()
        app=self.app
        conversation = app.state.conversation(ChatKey('group', 'g'))
        conversation.add(Message('alice', 'newest', 'now', 101, True))
        app.view.load_history_button.invoke()
        app.connection.send.assert_called_once_with({'type':'history_request','chat_type':'group','target':'g','before_id':101})
        self.assertEqual(app.view.load_history_button.cget('state'),'disabled')
        app.handle_server_message({'type':'history_begin'})
        for message_id in (99,100):
            app.handle_server_message({'type':'group_chat','gid':'g','from':'bob','message_id':message_id,
                                       'content':client.encrypt_message(str(message_id),app.connection.session_key)})
        app.handle_server_message({'type':'history_end','history_kind':'group','history_target':'g','has_more':False})
        self.assertEqual(conversation.message_ids,[99,100,101])
        self.assertEqual(len(conversation.messages),3)
        self.assertIsNone(app.state.pending_history)
        self.assertEqual(app.view.load_history_button.cget('state'),'disabled')

    def test_ack_keeps_input_edited_while_send_is_pending(self):
        self.chat()
        app = self.app
        app.view.msg_entry.insert('1.0', 'original')
        app.send_message()
        request_id = next(iter(app.state.pending_messages))
        app.view.msg_entry.delete('1.0', client.tk.END)
        app.view.msg_entry.insert('1.0', 'edited')
        app.handle_server_message({'type': 'group_chat_result', 'success': True, 'request_id': request_id})
        self.assertEqual(app.view.input_text(), 'edited')
        self.assertFalse(app.state.pending_messages)

    def test_disconnect_cancels_pending_scroll_before_destroying_chat_widgets(self):
        self.chat()
        app = self.app
        errors = []
        self.root.report_callback_exception = lambda kind, error, trace: errors.append(error)
        app.handle_server_message({'type': 'group_chat', 'gid': 'g', 'from': 'bob', 'message_id': 1,
                                   'content': client.encrypt_message('pending scroll', app.connection.session_key)})
        app.disconnect()
        self.root.update()
        self.assertEqual(errors, [])
        self.assertTrue(app.view.username_entry.winfo_exists())

    def test_private_and_group_with_same_target_keep_separate_frames_and_history(self):
        self.chat()
        app = self.app
        app.state.friends = ['g']
        private, group = ChatKey('private', 'g'), ChatKey('group', 'g')
        app.state.conversation(private).add(Message('g', 'private text', message_id=1))
        app.state.conversation(group).add(Message('bob', 'group text', message_id=2))
        for key, wanted, other in ((private, 'private text', 'group text'), (group, 'group text', 'private text')):
            app.select_chat(key)
            labels = [child.cget('text') for bubble in app.view.current_chat_frame.winfo_children()
                      for child in bubble.winfo_children() if isinstance(child, client.tk.Label)]
            self.assertTrue(any(wanted in label for label in labels))
            self.assertFalse(any(other in label for label in labels))
        self.assertIsNot(app.view.chat_frames[private], app.view.chat_frames[group])

class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.old_cwd = os.getcwd()
        cls.tmp = tempfile.TemporaryDirectory()
        os.chdir(cls.tmp.name)
        cls.server = load('chat_server', ROOT / 'server.py')

    @classmethod
    def tearDownClass(cls):
        os.chdir(cls.old_cwd)
        cls.tmp.cleanup()

    def setUp(self):
        self.peers = []
        self.threads = []
        s = self.server
        s.clients.clear()
        for mapping in (s.usernames, s.session_keys, s.session_timestamps, s.user_friends,
                        s.rate_limit_tracker, s.pending_friend_requests, s.group_pending_joins,
                        s.groups_data, s.send_locks):
            mapping.clear()
        Path('chat.db').unlink(missing_ok=True)
        s.init_db()
        for user in ('alice', 'bob', 'carol'):
            self.assertTrue(s.register_user(user, ' password ')[0])

    def tearDown(self):
        for peer, key in self.peers:
            try: peer.shutdown(socket.SHUT_RDWR)
            except OSError: pass
            peer.close()
        for thread in self.threads:
            thread.join(3)
            self.assertFalse(thread.is_alive(), 'server handler did not terminate')

    def connect(self, user, password=' password ', register=False):
        peer, remote = socket.socketpair()
        peer.settimeout(3)
        thread = threading.Thread(target=self.server.handle_client, args=(remote, ('127.0.0.1', 1)), daemon=True)
        thread.start()
        self.threads.append(thread)
        public = client.recv_msg(peer)
        key = os.urandom(16)
        rsa = client.RSA.import_key(public['key'])
        encrypted = client.PKCS1_OAEP.new(rsa).encrypt(key)
        client.send_msg(peer, {'type': 'session_key', 'protocol': client.transport.VERSION, 'key': base64.b64encode(encrypted).decode()})
        client.transport.configure(peer, key)
        import json
        client.send_msg(peer, {'type': 'encrypted_register' if register else 'encrypted_login',
                               'data': client.encrypt_message(json.dumps({'from': user, 'password': password}), key)})
        result = client.recv_msg(peer)
        self.peers.append((peer, key))
        return peer, key, result

    def read_type(self, peer, kind):
        for _ in range(50):
            msg = client.recv_msg(peer)
            self.assertIsNotNone(msg)
            if msg['type'] == kind: return msg
        self.fail('missing message: ' + kind)

    def test_large_legacy_group_snapshot_roundtrips_bounded_packets(self):
        import json
        s = self.server
        name = '名字' * 100000
        gid = s.create_group_db('alice', name, ['alice'])
        packets = []
        with patch.object(s, 'enqueue_packet', side_effect=lambda sock, data, ready=None: packets.append(data)):
            s.send_user_groups(object(), 'alice')
        messages = [json.loads(packet[4:]) for packet in packets]
        self.assertGreater(len(messages), 1)
        self.assertTrue(all(len(packet) - 4 <= s.MAX_MESSAGE_LEN for packet in packets))
        snapshot = json.loads(''.join(msg['data'] for msg in messages))
        self.assertEqual(snapshot['groups'][0]['group_name'], name)
        self.assertEqual(snapshot['groups'][0]['gid'], gid)

    def test_successful_auth_preserves_ip_failures(self):
        s = self.server
        s.record_auth_failure('127.0.0.1')
        _, _, result = self.connect('alice')
        self.assertTrue(result['success'])
        _, _, result = self.connect('newuser', register=True)
        self.assertTrue(result['success'])
        self.assertEqual(len(s.rate_limit_tracker['127.0.0.1']), 1)

    def test_drip_feed_cannot_extend_receive_deadline(self):
        s = self.server
        sock = Mock()
        sock.recv.return_value = b'x'
        with patch.object(s.time, 'monotonic', side_effect=[10, 10.1, 10.3]):
            self.assertIsNone(s.recvall(sock, 4, deadline=10.2))
        self.assertEqual(sock.recv.call_count, 2)

    def test_join_immediately_replays_only_joined_group_history(self):
        s = self.server
        gid = s.create_group_db('alice', 'Team', ['alice'])
        s.save_message('group', 'alice', None, gid, 'before join', '2026-10-08 10:00:00')
        bob, key, _ = self.connect('bob')
        self.read_type(bob, 'online_users')
        s.group_pending_joins[gid] = {'bob': ('alice', time.time())}
        client.send_msg(bob, {'type': 'group_join', 'gid': gid})
        self.assertTrue(self.read_type(bob, 'group_join_result')['success'])
        history = self.read_type(bob, 'group_chat')
        self.assertEqual(history['gid'], gid)
        self.assertEqual(client.decrypt_message(history['content'], key), 'before join')
        self.read_type(bob, 'history_end')

    def test_group_chat_is_queued_before_concurrent_kick(self):
        s = self.server
        gid = s.create_group_db('alice', 'Team', ['alice', 'bob'])
        alice, _, _ = self.connect('alice')
        bob, key, _ = self.connect('bob')
        self.read_type(alice, 'online_users'); self.read_type(bob, 'online_users')
        entered, finish = threading.Event(), threading.Event()
        original = s.save_message
        def paused_save(*args, **kwargs):
            entered.set()
            if not finish.wait(3):
                raise TimeoutError('test did not release save')
            return original(*args, **kwargs)
        with patch.object(s, 'save_message', side_effect=paused_save):
            client.send_msg(bob, {'type': 'group_chat', 'gid': gid,
                                    'content': client.encrypt_message('in flight', key)})
            self.assertTrue(entered.wait(3))
            client.send_msg(alice, {'type': 'group_kick', 'gid': gid, 'kick': 'bob'})
            finish.set()
            self.assertEqual(client.recv_msg(bob)['type'], 'group_chat_result')
            self.assertEqual(client.recv_msg(bob)['type'], 'group_chat')
            self.assertEqual(client.recv_msg(bob)['type'], 'group_kick_notification')
        self.assertNotIn('bob', s.get_group_db(gid)['members'])

    def test_group_chat_is_queued_before_concurrent_disband(self):
        s = self.server
        gid = s.create_group_db('alice', 'Team', ['alice', 'bob'])
        alice, _, _ = self.connect('alice')
        bob, key, _ = self.connect('bob')
        self.read_type(alice, 'online_users'); self.read_type(bob, 'online_users')
        entered, finish = threading.Event(), threading.Event()
        original = s.save_message
        def paused_save(*args, **kwargs):
            entered.set()
            if not finish.wait(3):
                raise TimeoutError('test did not release save')
            return original(*args, **kwargs)
        with patch.object(s, 'save_message', side_effect=paused_save):
            client.send_msg(bob, {'type': 'group_chat', 'gid': gid,
                                    'content': client.encrypt_message('in flight', key)})
            self.assertTrue(entered.wait(3))
            client.send_msg(alice, {'type': 'group_disband', 'gid': gid})
            finish.set()
            self.assertEqual(client.recv_msg(bob)['type'], 'group_chat_result')
            self.assertEqual(client.recv_msg(bob)['type'], 'group_chat')
            self.assertEqual(client.recv_msg(bob)['type'], 'group_disband_notification')
        self.assertIsNone(s.get_group_db(gid))

    def test_snapshot_staging_blocks_member_changes_until_queued(self):
        import json
        s = self.server
        s.create_group_db('alice', 'Team', ['alice'])
        entered, finish, acquired = threading.Event(), threading.Event(), threading.Event()
        packets = []
        original = s.send_msg
        def paused_send(sock, msg):
            if msg['type'] == 'user_groups_list':
                entered.set()
                if not finish.wait(3):
                    raise TimeoutError('test did not release snapshot')
            return original(sock, msg)
        def change():
            s.group_ops_lock.acquire()
            try:
                acquired.set()
                s.send_msg(target, {'type': 'group_disband_notification', 'gid': 'g'})
            finally:
                s.group_ops_lock.release()
        target = object()
        with patch.object(s, 'send_msg', side_effect=paused_send), patch.object(s, 'enqueue_packet', side_effect=lambda sock, packet, ready=None: packets.append(packet)):
            sync = threading.Thread(target=s.send_user_groups, args=(target, 'alice'))
            sync.start()
            self.assertTrue(entered.wait(3))
            mutation = threading.Thread(target=change)
            mutation.start()
            try:
                self.assertFalse(acquired.wait(.1))
            finally:
                finish.set()
                sync.join(3); mutation.join(3)
        self.assertFalse(sync.is_alive()); self.assertFalse(mutation.is_alive())
        self.assertEqual([json.loads(packet[4:])['type'] for packet in packets],
                         ['user_groups_list', 'group_disband_notification'])

    def test_long_rename_rejected_before_database_change(self):
        s = self.server
        gid = s.create_group_db('alice', 'Before', ['alice'])
        alice, _, _ = self.connect('alice')
        self.read_type(alice, 'online_users')
        client.send_msg(alice, {'type': 'group_rename', 'gid': gid, 'new_name': 'x' * 129})
        self.assertFalse(self.read_type(alice, 'group_rename_result')['success'])
        self.assertEqual(s.get_group_db(gid)['group_name'], 'Before')

    def test_rate_limit_cleanup_uses_scalar_timestamps(self):
        s = self.server
        for i in range(1001): s.rate_limit_tracker[str(i)] = [time.time() - 120]
        s.rate_limit_tracker['active'] = [time.time()] * s.RATE_LIMIT_MAX_ATTEMPTS
        self.assertTrue(s.is_rate_limited('active'))
        self.assertEqual(set(s.rate_limit_tracker), {'active'})

    def test_key_generation_with_ascii_console(self):
        previous_cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as key_dir:
            try:
                os.chdir(key_dir)
                with io.TextIOWrapper(io.BytesIO(), encoding='ascii') as console:
                    with patch('sys.stdout', console):
                        private_key, public_pem = self.server.ensure_rsa_keys()
                self.assertTrue(private_key.has_private())
                self.assertEqual(client.RSA.import_key(public_pem).n, private_key.n)
            finally:
                os.chdir(previous_cwd)

    def test_rate_limited_connections_do_not_leak_send_locks(self):
        s = self.server
        s.rate_limit_tracker['127.0.0.1'] = [time.time()] * s.RATE_LIMIT_MAX_ATTEMPTS
        peer, remote = socket.socketpair()
        try:
            s.handle_client(remote, ('127.0.0.1', 1))
            self.assertEqual(client.recv_msg(peer)['type'], 'error')
            self.assertNotIn(remote, s.send_locks)
        finally:
            peer.close()

    def test_rate_limited_connections_are_removed_from_clients(self):
        s = self.server
        s.rate_limit_tracker['127.0.0.1'] = [time.time()] * s.RATE_LIMIT_MAX_ATTEMPTS
        peer, remote = socket.socketpair()
        s.clients.append(remote)  # main() tracks accepted sockets before dispatch.
        try:
            s.handle_client(remote, ('127.0.0.1', 1))
            self.assertEqual(client.recv_msg(peer)['type'], 'error')
            self.assertNotIn(remote, s.clients)
            self.assertNotIn(remote, s.send_locks)
        finally:
            peer.close()

    def test_accept_offline_friend_does_not_leak_cache(self):
        s = self.server
        bob, _, _ = self.connect('bob')
        self.read_type(bob, 'online_users')
        s.pending_friend_requests[('alice', 'bob')] = time.time()
        client.send_msg(bob, {'type': 'friend_response', 'to': 'alice', 'accepted': True})
        self.read_type(bob, 'friend_update')
        self.assertNotIn('alice', s.user_friends)
        self.assertIn('bob', s.load_friends('alice'))

    def test_encrypted_registration_login_and_wrong_password(self):
        _, _, result = self.connect('dave', register=True)
        self.assertTrue(result['success'])
        _, _, result = self.connect('dave')
        self.assertTrue(result['success'])
        _, _, result = self.connect('bob', password='wrongpass')
        self.assertFalse(result['success'])

    def test_duplicate_login_and_first_response_order(self):
        results = []
        barrier = threading.Barrier(3)
        def attempt():
            barrier.wait()
            results.append(self.connect('alice')[2])
        threads = [threading.Thread(target=attempt) for _ in range(2)]
        for thread in threads: thread.start()
        barrier.wait()
        for thread in threads: thread.join(5)
        self.assertEqual(len(results), 2)
        self.assertTrue(all(msg['type'] == 'login_result' for msg in results))
        self.assertEqual(sorted(msg['success'] for msg in results), [False, True])

    def test_friend_private_group_lifecycle_and_history(self):
        alice, ak, _ = self.connect('alice')
        bob, bk, _ = self.connect('bob')
        self.read_type(alice, 'online_users'); self.read_type(bob, 'online_users')
        client.send_msg(alice, {'type': 'friend_request', 'to': 'bob'})
        self.assertTrue(self.read_type(alice, 'friend_request_result')['success'])
        self.read_type(bob, 'friend_request')
        client.send_msg(bob, {'type': 'friend_response', 'to': 'alice', 'accepted': True})
        self.read_type(alice, 'friend_update'); self.read_type(bob, 'friend_update')
        client.send_msg(alice, {'type': 'private_chat', 'to': 'bob', 'content': client.encrypt_message('你好 Bob', ak)})
        self.assertEqual(client.decrypt_message(self.read_type(bob, 'private_chat')['content'], bk), '你好 Bob')
        self.assertEqual(client.decrypt_message(self.read_type(alice, 'private_chat')['content'], ak), '你好 Bob')
        client.send_msg(alice, {'type': 'group_create', 'group_name': 'Team', 'members': ['bob']})
        group = self.read_type(alice, 'group_create_result')
        gid = group['gid']
        self.read_type(bob, 'group_create_result')
        client.send_msg(bob, {'type': 'group_chat', 'gid': gid, 'content': client.encrypt_message('群消息', bk)})
        self.assertEqual(client.decrypt_message(self.read_type(alice, 'group_chat')['content'], ak), '群消息')
        self.read_type(bob, 'group_chat')
        # Relogin must replay persisted private and group messages with a fresh key.
        bob.shutdown(socket.SHUT_RDWR); bob.close()
        deadline = time.monotonic() + 3
        while self.server.get_sock_by_username('bob') and time.monotonic() < deadline:
            time.sleep(.01)
        bob, bk, result = self.connect('bob')
        self.assertTrue(result['success'])
        self.read_type(bob, 'history_begin')
        history = [client.recv_msg(bob), client.recv_msg(bob)]
        self.assertEqual([msg['message_id'] for msg in history], sorted(msg['message_id'] for msg in history))
        self.assertEqual({msg['type']:client.decrypt_message(msg['content'],bk) for msg in history}, {'private_chat':'你好 Bob','group_chat':'群消息'})
        client.send_msg(alice, {'type': 'group_rename', 'gid': gid, 'new_name': 'Renamed'})
        self.assertTrue(self.read_type(alice, 'group_rename_result')['success'])
        client.send_msg(alice, {'type': 'group_transfer', 'gid': gid, 'new_owner': 'bob'})
        self.assertTrue(self.read_type(alice, 'group_transfer_result')['success'])
        client.send_msg(alice, {'type': 'group_leave', 'gid': gid})
        self.assertTrue(self.read_type(alice, 'group_leave_result')['success'])
        client.send_msg(bob, {'type': 'group_disband', 'gid': gid})
        self.assertTrue(self.read_type(bob, 'group_disband_result')['success'])
        self.assertIsNone(self.server.get_group_db(gid))

    def test_database_failure_retains_friend_request_and_cache(self):
        s = self.server
        bob, _, _ = self.connect('bob')
        self.read_type(bob, 'online_users')
        s.pending_friend_requests[('alice', 'bob')] = time.time()
        with patch.object(s, 'save_friend_relationship', side_effect=s.sqlite3.OperationalError('disk full')):
            client.send_msg(bob, {'type': 'friend_response', 'to': 'alice', 'accepted': True})
            result = self.read_type(bob, 'friend_response_result')
            self.assertFalse(result['success'])
        self.assertIn(('alice', 'bob'), s.pending_friend_requests)
        self.assertNotIn('alice', s.user_friends['bob'])
        self.assertEqual(s.load_friends('bob'), set())
        client.send_msg(bob, {'type': 'friend_response', 'to': 'alice', 'accepted': True})
        self.read_type(bob, 'friend_update')
        self.assertNotIn(('alice', 'bob'), s.pending_friend_requests)
        self.assertEqual(s.load_friends('bob'), {'alice'})

    def test_database_failure_does_not_forward_chat(self):
        s = self.server
        s.save_friend_relationship('alice', 'bob')
        gid = s.create_group_db('alice', 'Team', ['alice', 'bob'])
        alice, key, _ = self.connect('alice')
        bob, _, _ = self.connect('bob')
        self.read_type(alice, 'online_users')
        self.read_type(bob, 'online_users')
        # Drain alice's broadcast caused by bob's login.
        self.read_type(alice, 'online_users')
        with patch.object(s, 'save_message', side_effect=s.sqlite3.OperationalError('database locked')):
            for kind in ('private_chat', 'group_chat'):
                data = {'type': kind, 'request_id': kind, 'content': client.encrypt_message('must not forward', key)}
                data['to' if kind == 'private_chat' else 'gid'] = 'bob' if kind == 'private_chat' else gid
                client.send_msg(alice, data)
                result = self.read_type(alice, kind + '_result')
                self.assertFalse(result['success'])
                self.assertEqual(result['request_id'], kind)
        bob.settimeout(.15)
        with self.assertRaises(socket.timeout):
            client.recv_msg(bob)
        conn = s.sqlite3.connect('chat.db')
        try:
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM messages').fetchone()[0], 0)
        finally:
            conn.close()

    def test_savers_rollback_and_raise_on_commit_failure(self):
        s = self.server
        for save, args in ((s.save_friend_relationship, ('alice', 'bob')),
                           (s.save_message, ('private', 'alice', 'bob', None, 'text', 'now'))):
            connection = Mock()
            connection.commit.side_effect = s.sqlite3.OperationalError('disk full')
            with patch.object(s.sqlite3, 'connect', return_value=connection):
                with self.assertRaises(s.sqlite3.OperationalError):
                    save(*args)
            connection.rollback.assert_called_once()
            connection.close.assert_called_once()

    def test_declined_and_expired_group_invites_are_not_replayed(self):
        s = self.server
        gid = s.create_group_db('alice', 'Team', ['alice'])
        s.group_pending_joins[gid] = {'bob': ('alice', time.time())}
        bob, _, _ = self.connect('bob')
        self.read_type(bob, 'group_invite')
        self.read_type(bob, 'online_users')
        client.send_msg(bob, {'type': 'group_invite_response', 'gid': gid, 'accepted': False})
        self.assertTrue(self.read_type(bob, 'group_invite_response_result')['success'])
        self.assertNotIn('bob', s.group_pending_joins[gid])
        s.group_pending_joins[gid]['bob'] = ('alice', time.time() - s.PENDING_REQUEST_TIMEOUT_SECONDS - 1)
        client.send_msg(bob, {'type': 'group_join', 'gid': gid})
        self.assertFalse(self.read_type(bob, 'group_join_result')['success'])
        self.assertNotIn('bob', s.get_group_db(gid)['members'])
        self.assertNotIn('bob', s.group_pending_joins[gid])

    def test_group_batch_snapshot_order_and_network_outside_lock(self):
        s = self.server
        sock = Mock()
        packets = []
        def sent(packet):
            self.assertTrue(s.group_ops_lock.lock.acquire(blocking=False))
            s.group_ops_lock.lock.release()
            packets.append(packet)
        sock.sendall.side_effect = sent
        s.group_ops_lock.acquire()
        data = {'type': 'group_update', 'members': ['alice']}
        s.send_msg(sock, data)
        data['members'].append('bob')
        s.send_msg(sock, data)
        sock.sendall.assert_not_called()
        s.group_ops_lock.release()
        deadline = time.monotonic() + 2
        while len(packets) < 2 and time.monotonic() < deadline:
            time.sleep(.01)
        self.assertEqual(len(packets), 2)
        import json
        self.assertEqual(json.loads(packets[0][4:])['members'], ['alice'])
        self.assertEqual(json.loads(packets[1][4:])['members'], ['alice', 'bob'])
        s.remove_send_lock(sock)

    def test_slow_member_does_not_block_other_group_operations(self):
        s = self.server
        slow_gid = s.create_group_db('alice', 'Slow', ['alice', 'bob'])
        fast_gid = s.create_group_db('carol', 'Fast', ['carol'])
        alice, _, _ = self.connect('alice')
        bob, _, _ = self.connect('bob')
        carol, _, _ = self.connect('carol')
        self.read_type(carol, 'online_users')
        remote = s.get_sock_by_username('bob')
        remote.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024)
        bob.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024)
        # Raw transport stress: exceed OS buffering while this peer stops reading.
        packet = b'\x00' * 4 + b'x' * s.MAX_MESSAGE_LEN
        for _ in range(128):
            s.enqueue_packet(remote, packet)
        time.sleep(.2)
        self.assertGreater(s.send_queues[remote].qsize(), 0, 'test must fill OS buffering')
        client.send_msg(alice, {'type': 'group_rename', 'gid': slow_gid, 'new_name': 'Slow member'})
        self.assertTrue(self.read_type(alice, 'group_rename_result')['success'])
        started = time.monotonic()
        client.send_msg(carol, {'type': 'group_rename', 'gid': fast_gid, 'new_name': 'Still responsive'})
        self.assertTrue(self.read_type(carol, 'group_rename_result')['success'])
        self.assertLess(time.monotonic() - started, 2)
        self.assertEqual(remote.gettimeout(), s.SEND_TIMEOUT_SECONDS)

    def test_send_timeout_shuts_connection_and_cleans_writer(self):
        s = self.server
        sock = Mock()
        sock.sendall.side_effect = socket.timeout('client stopped reading')
        outbox = queue.Queue()
        outbox.put((b'packet', None))
        s.send_queues[sock] = outbox
        s.send_worker(sock, outbox)
        sock.shutdown.assert_called_once_with(socket.SHUT_RDWR)
        self.assertNotIn(sock, s.send_queues)
        self.assertNotIn(sock, s.send_locks)

    def test_history_uses_one_id_boundary_across_group_and_private_queries(self):
        s = self.server
        gid = s.create_group_db('alice', 'Team', ['alice', 'bob'])
        s.save_friend_relationship('alice', 'bob')
        first = s.save_message('group', 'bob', None, gid, 'group before', 'now')
        second = s.save_message('private', 'bob', 'alice', None, 'private before', 'now')
        sock = Mock()
        s.session_keys[sock] = os.urandom(16)
        s.user_friends['alice'] = {'bob'}
        events = []
        def send(sock, payload):
            events.append(payload)
            if payload['type'] == 'group_chat':
                s.save_message('private', 'bob', 'alice', None, 'after boundary', 'now')
        with patch.object(s, 'send_msg', side_effect=send):
            s.send_history(sock, 'alice')
        self.assertEqual([event['message_id'] for event in events if 'message_id' in event], [first, second])
        self.assertEqual(events[-1], {'type': 'history_end', 'boundary': second})

    def test_management_result_has_old_name_and_no_duplicate_notification(self):
        s = self.server
        gid = s.create_group_db('alice', 'Before', ['alice', 'bob'])
        alice, _, _ = self.connect('alice')
        self.read_type(alice, 'online_users')
        client.send_msg(alice, {'type': 'group_rename', 'gid': gid, 'new_name': 'After'})
        result = client.recv_msg(alice)
        self.assertEqual(result['type'], 'group_rename_result')
        self.assertEqual((result['old_name'], result['new_name']), ('Before', 'After'))
        client.send_msg(alice, {'type': 'group_transfer', 'gid': gid, 'new_owner': 'bob'})
        self.assertEqual(client.recv_msg(alice)['type'], 'group_transfer_result')

    def test_transfer_cannot_race_new_owner_leave(self):
        s = self.server
        s.save_friend_relationship('alice', 'bob')
        gid = s.create_group_db('alice', 'Team', ['alice', 'bob'])
        alice, _, _ = self.connect('alice')
        bob, _, _ = self.connect('bob')
        self.read_type(alice, 'online_users'); self.read_type(bob, 'online_users')
        entered, finish = threading.Event(), threading.Event()
        original = s.transfer_group_ownership_db
        def paused_transfer(gid, owner):
            entered.set()
            self.assertTrue(finish.wait(3))
            return original(gid, owner)
        with patch.object(s, 'transfer_group_ownership_db', side_effect=paused_transfer):
            client.send_msg(alice, {'type': 'group_transfer', 'gid': gid, 'new_owner': 'bob'})
            self.assertTrue(entered.wait(3))
            client.send_msg(bob, {'type': 'group_leave', 'gid': gid})
            try:
                bob.settimeout(.15)
                with self.assertRaises(socket.timeout): client.recv_msg(bob)
            finally:
                bob.settimeout(3)
                finish.set()
            self.assertTrue(self.read_type(alice, 'group_transfer_result')['success'])
            self.assertFalse(self.read_type(bob, 'group_leave_result')['success'])
        group = s.get_group_db(gid)
        self.assertEqual(group['owner'], 'bob')
        self.assertIn('bob', group['members'])

    def test_tampered_recipient_is_rejected_before_persistence(self):
        import json,struct
        s=self.server
        s.save_friend_relationship('alice','bob');s.save_friend_relationship('alice','carol')
        peer,key,result=self.connect('alice');self.assertTrue(result['success'])
        self.read_type(peer,'online_users')
        class Capture:
            def sendall(self,data):self.packet=data
        capture=Capture();client.transport.configure(capture,key)
        client.transport.state_for(capture).send_seq=client.transport.state_for(peer).send_seq
        client.send_msg(capture,{'type':'private_chat','to':'bob','content':client.encrypt_message('secret',key)})
        packet=capture.packet
        data=packet[4:].replace(b'"to": "bob"',b'"to": "carol"')
        peer.sendall(struct.pack('!I',len(data))+data)
        self.threads[-1].join(2)
        self.assertFalse(self.threads[-1].is_alive())
        with closing(s.sqlite3.connect('chat.db')) as db, db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM messages').fetchone()[0],0)

    def test_plain_control_frame_cannot_disband_group(self):
        import json,struct
        s=self.server;gid=s.create_group_db('alice','Team',['alice'])
        peer,key,_=self.connect('alice');self.read_type(peer,'online_users')
        data=json.dumps({'type':'group_disband','gid':gid}).encode()
        peer.sendall(struct.pack('!I',len(data))+data)
        self.threads[-1].join(2)
        self.assertFalse(self.threads[-1].is_alive())
        self.assertIsNotNone(s.get_group_db(gid))

    def test_pending_requests_restore_and_decline_durably(self):
        s=self.server;peer,key,_=self.connect('alice');self.read_type(peer,'online_users')
        client.send_msg(peer,{'type':'friend_request','to':'bob'})
        self.assertTrue(self.read_type(peer,'friend_request_result')['success'])
        s.pending_friend_requests.clear();s.restore_pending_requests()
        self.assertIn(('alice','bob'),s.pending_friend_requests)
        bob,bk,_=self.connect('bob');self.assertEqual(self.read_type(bob,'friend_request')['from'],'alice')
        client.send_msg(bob,{'type':'friend_response','to':'alice','accepted':False})
        self.read_type(peer,'friend_response')
        s.restore_pending_requests()
        self.assertNotIn(('alice','bob'),s.pending_friend_requests)

    def test_pending_invite_restore_and_consumption(self):
        s=self.server;gid=s.create_group_db('alice','Team',['alice'])
        s.save_friend_relationship('alice','bob')
        peer,key,_=self.connect('alice');self.read_type(peer,'online_users')
        client.send_msg(peer,{'type':'group_invite','to':'bob','gid':gid})
        self.assertTrue(self.read_type(peer,'group_invite_result')['success'])
        s.group_pending_joins.clear();s.restore_pending_requests()
        self.assertEqual(s.group_pending_joins[gid]['bob'][0],'alice')
        bob,bk,_=self.connect('bob');self.read_type(bob,'group_invite')
        client.send_msg(bob,{'type':'group_join','gid':gid})
        self.assertTrue(self.read_type(bob,'group_join_result')['success'])
        self.read_type(bob,'history_end')
        s.restore_pending_requests()
        self.assertNotIn('bob',s.group_pending_joins.get(gid,{}))

    def test_history_pagination_bounded_complete_and_authorized(self):
        s=self.server;s.save_friend_relationship('alice','bob')
        for i in range(205):
            s.save_message('private','bob','alice',None,str(i),'now')
        s.save_message('private','carol','alice',None,'hidden','now')
        peer,key,_=self.connect('alice');self.read_type(peer,'history_begin')
        seen=[]
        for size in (100,100,5):
            page=[]
            while True:
                msg=client.recv_msg(peer)
                if msg['type']=='history_end':end=msg;break
                if msg['type']=='private_chat':page.append(msg['message_id']);seen.append(msg['message_id'])
            self.assertEqual(len(page),size)
            self.assertEqual(page,sorted(page))
            self.assertEqual(end.get('has_more',False),size==100)
            if size!=5:
                client.send_msg(peer,{'type':'history_request','chat_type':'private','target':'bob','before_id':min(page)})
                self.read_type(peer,'history_begin')
        self.assertEqual(sorted(seen),list(range(1,206)))
        client.send_msg(peer,{'type':'history_request','chat_type':'private','target':'carol','before_id':206})
        self.assertIn('无权',self.read_type(peer,'history_error')['error'])

    def test_scoped_history_failure_allows_retry_on_same_connection(self):
        s = self.server
        s.save_friend_relationship('alice', 'bob')
        s.save_message('private', 'bob', 'alice', None, 'saved', 'now')
        peer, _, result = self.connect('alice')
        self.assertTrue(result['success'])
        self.read_type(peer, 'history_end')
        request = {'type': 'history_request', 'chat_type': 'private', 'target': 'bob', 'before_id': 2}
        with patch.object(s.history_store, 'page', side_effect=RuntimeError('database busy')):
            client.send_msg(peer, request)
            self.read_type(peer, 'history_begin')
            response = client.recv_msg(peer)
        self.assertEqual(response['type'], 'history_error')
        client.send_msg(peer, request)
        self.read_type(peer, 'history_begin')
        self.assertEqual(self.read_type(peer, 'private_chat')['message_id'], 1)
        self.read_type(peer, 'history_end')

    def test_partial_history_failure_retries_full_page_on_same_connection(self):
        s = self.server
        s.save_friend_relationship('alice', 'bob')
        for text in ('first', 'second'):
            s.save_message('private', 'bob', 'alice', None, text, 'now')
        peer, key, _ = self.connect('alice')
        self.read_type(peer, 'history_end')
        request = {'type': 'history_request', 'chat_type': 'private', 'target': 'bob', 'before_id': 3}
        first = s.encrypt_message('first', key)
        with patch.object(s, 'encrypt_message', side_effect=[first, RuntimeError('partial page')]):
            client.send_msg(peer, request)
            self.read_type(peer, 'history_begin')
            self.assertEqual(self.read_type(peer, 'private_chat')['message_id'], 1)
            self.assertEqual(client.recv_msg(peer)['type'], 'history_error')
        client.send_msg(peer, request)
        self.read_type(peer, 'history_begin')
        self.assertEqual(self.read_type(peer, 'private_chat')['message_id'], 1)
        self.assertEqual(self.read_type(peer, 'private_chat')['message_id'], 2)
        self.read_type(peer, 'history_end')


if __name__ == '__main__':
    unittest.main()
