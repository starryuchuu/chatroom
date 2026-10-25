"""Real Tk regression coverage for conversation and sidebar reading positions."""
import gc
from time import monotonic
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

import client
from chatroom_client.models import ChatKey, Message
from chatroom_client.preferences import PreferencesStore
from chatroom_client.protocol import encrypt_message


class ClientScrollingTests(unittest.TestCase):
    def setUp(self):
        self.root = client.tk.Tk()
        self.root.withdraw()
        preferences = PreferencesStore(persistent=False)
        preferences.set_notifications(enabled=False)
        self.app = client.ChatClient(self.root, preferences=preferences, encryption=False)
        self.app.connection.running = True
        self.app.connection.sock = Mock()
        self.app.connection.session_key = b's' * 16
        self.app.connection.endpoint = ('127.0.0.1', 12345)
        self.app.state.username = 'synthetic-account'
        self.app.view.build_chat()
        self.app.activity.activate(self.app.connection.endpoint, self.app.state.username)
        self.view = self.app.view
        self.root.geometry('900x700')
        self.root.deiconify()
        self.wait_for_geometry(self.view.chat_canvas, self.view.friends_listbox,
                               self.view.group_listbox)

    def tearDown(self):
        self.app.close()
        self.view = self.app = self.root = None
        gc.collect()

    def wait_for_geometry(self, *widgets, size=(900, 700)):
        deadline = monotonic() + 2
        previous = None
        geometry = ()
        while monotonic() < deadline:
            self.root.update()
            geometry = tuple((widget.winfo_ismapped(), widget.winfo_width(), widget.winfo_height(),
                              widget.winfo_rootx(), widget.winfo_rooty())
                             for widget in (self.root, *widgets))
            if (geometry[0][1:3] == size
                    and all(mapped and width > 1 and height > 1
                            for mapped, width, height, _left, _top in geometry)
                    and geometry == previous):
                return
            previous = geometry
        self.fail(f'Tk widgets did not finish mapping within 2 seconds: {geometry}')

    def show_history(self, *, failed=False):
        key = ChatKey('private', 'synthetic-peer')
        self.app.state.friends[:] = [key.target]
        conversation = self.app.state.conversation(key)
        for number in range(101, 181):
            conversation.add(Message(key.target, f'Synthetic history message {number}',
                                     message_id=number, encryption='failed' if failed else 'legacy'))
        self.view.refresh_activity()
        self.app.select_chat(key)
        self.root.update()
        return key

    def deliver(self, message_id, *, is_self=False, peer='synthetic-peer'):
        username = self.app.state.username
        self.app.events.chat_message({
            'type': 'private_chat',
            'from': username if is_self else peer,
            'to': peer if is_self else username,
            'content': encrypt_message(f'Synthetic incoming message {message_id}',
                                       self.app.connection.session_key),
            'message_id': message_id,
            'history': False,
        })

    def visible_message(self):
        """Identify an actual displayed row rather than inspecting scroll internals."""
        canvas_top = self.view.chat_canvas.winfo_rooty()
        canvas_bottom = canvas_top + self.view.chat_canvas.winfo_height()
        for row in self.view.current_chat_frame.winfo_children():
            if canvas_top <= row.winfo_rooty() < canvas_bottom:
                labels = [child for child in row.winfo_children()
                          if isinstance(child, client.tk.Label)]
                if labels:
                    return labels[-1].cget('text'), row.winfo_rooty() - canvas_top
        self.fail('No message row is visible in the chat viewport')

    def assert_message_position(self, content, position):
        for row in self.view.current_chat_frame.winfo_children():
            labels = [child for child in row.winfo_children()
                      if isinstance(child, client.tk.Label)]
            if labels and labels[-1].cget('text') == content:
                actual = row.winfo_rooty() - self.view.chat_canvas.winfo_rooty()
                # The canvas intentionally quantizes vertical movement to 20px.
                self.assertLessEqual(abs(actual - position), 20)
                return
        self.fail('The previously visible synthetic message was lost')

    def read_earlier_messages(self):
        self.view.chat_canvas.yview_moveto(.35)
        self.root.update()
        self.assertLess(self.view.chat_canvas.yview()[1], .9)
        return self.visible_message()

    def test_incoming_activity_preserves_long_sidebar_scroll_and_keyboard_positions(self):
        self.app.state.friends[:] = [f'synthetic-peer-{number:03d}' for number in range(100)]
        self.app.state.groups = {
            f'synthetic-group-{number:03d}': {'group_name': f'Synthetic group {number:03d}'}
            for number in range(100)
        }
        self.app.state.current_chat = ChatKey('private', self.app.state.friends[30])
        self.view.refresh_activity()
        self.root.update()
        snapshots = []
        for widget, selected, active, anchor in (
                (self.view.friends_listbox, (30,), 31, 29),
                (self.view.group_listbox, (), 41, 39)):
            widget.selection_clear(0, client.tk.END)
            for index in selected:
                widget.selection_set(index)
            widget.activate(active)
            widget.selection_anchor(anchor)
            widget.yview_moveto(.4)
            snapshots.append((widget, widget.curselection(), widget.index(client.tk.ACTIVE),
                              widget.index(client.tk.ANCHOR), widget.yview()[0]))
        self.deliver(201, peer=self.app.state.friends[80])
        self.root.update()
        for widget, selected, active, anchor, top in snapshots:
            self.assertEqual(widget.curselection(), selected)
            self.assertEqual(widget.index(client.tk.ACTIVE), active)
            self.assertEqual(widget.index(client.tk.ANCHOR), anchor)
            self.assertAlmostEqual(widget.yview()[0], top, places=6)

    def test_sidebar_snapshot_insertion_preserves_the_same_selected_peer(self):
        self.app.state.friends[:] = [f'synthetic-peer-{number:03d}' for number in range(100)]
        selected_peer = self.app.state.friends[30]
        self.app.state.current_chat = ChatKey('private', selected_peer)
        self.view.refresh_activity()
        self.root.update()
        widget = self.view.friends_listbox
        widget.activate(31)
        widget.selection_anchor(29)
        widget.yview_moveto(.4)
        first_peer = self.view._friend_keys[widget.nearest(0)]
        self.app.events.friend_snapshot({'friends': ['synthetic-new-peer', *self.app.state.friends]})
        self.root.update()
        self.assertEqual(self.view._friend_keys[widget.curselection()[0]], selected_peer)
        self.assertEqual(self.view._friend_keys[widget.index(client.tk.ACTIVE)], 'synthetic-peer-031')
        self.assertEqual(self.view._friend_keys[widget.index(client.tk.ANCHOR)], 'synthetic-peer-029')
        self.assertEqual(self.view._friend_keys[widget.nearest(0)], first_peer)

    def test_batched_incoming_messages_preserve_the_visible_history_anchor(self):
        self.show_history()
        content, position = self.read_earlier_messages()
        for message_id in (201, 202, 203):
            self.deliver(message_id)
        self.root.update()
        self.assert_message_position(content, position)
        self.assertLess(self.view.chat_canvas.yview()[1], .9)
        self.assertTrue(self.view.new_messages_button.winfo_ismapped())
        self.assertIn('3', self.view.new_messages_button.cget('text'))

    def test_new_message_navigation_survives_both_themes_and_returns_to_bottom(self):
        self.show_history()
        content, position = self.read_earlier_messages()
        self.deliver(201)
        self.root.update()
        button = self.view.new_messages_button
        for mode in ('dark', 'light'):
            self.view.set_theme(mode)
            self.root.update()
            self.assertTrue(button.winfo_ismapped())
            self.assertNotEqual(button.cget('fg'), button.cget('bg'))
            self.assertIn(button.cget('bg'), self.view.colors.values())
            self.assert_message_position(content, position)
        button.invoke()
        self.root.update()
        self.assertGreaterEqual(self.view.chat_canvas.yview()[1], .999)
        self.assertFalse(button.winfo_ismapped())

    def test_scrolling_to_bottom_clears_new_message_navigation(self):
        self.show_history()
        self.read_earlier_messages()
        self.deliver(201)
        self.root.update()
        self.assertTrue(self.view.new_messages_button.winfo_ismapped())
        self.view.chat_canvas.yview_moveto(1)
        self.root.update()
        self.assertFalse(self.view.new_messages_button.winfo_ismapped())

    def test_batched_incoming_messages_follow_when_already_at_bottom(self):
        self.show_history()
        self.view.scroll_to_bottom()
        self.root.update()
        self.assertGreaterEqual(self.view.chat_canvas.yview()[1], .999)
        for message_id in (201, 202, 203):
            self.deliver(message_id)
        self.root.update()
        self.assertGreaterEqual(self.view.chat_canvas.yview()[1], .999)
        self.assertFalse(self.view.new_messages_button.winfo_ismapped())

    def test_self_message_follows_even_while_reading_earlier_history(self):
        self.show_history()
        self.read_earlier_messages()
        self.deliver(201, is_self=True)
        self.root.update()
        self.assertGreaterEqual(self.view.chat_canvas.yview()[1], .999)
        self.assertFalse(self.view.new_messages_button.winfo_ismapped())

    def test_reconnect_sync_redraw_keeps_the_visible_message_after_older_insertions(self):
        key = self.show_history()
        content, position = self.read_earlier_messages()
        for message_id in range(1, 21):
            is_self = message_id == 10
            self.app.state.conversation(key).add(Message(
                self.app.state.username if is_self else key.target,
                f'Synthetic recovered older message {message_id}', message_id=message_id, is_self=is_self))
        self.app.refresh_sync()
        self.root.update()
        self.assert_message_position(content, position)
        self.assertLess(self.view.chat_canvas.yview()[1], .9)

    def test_verified_replacement_preserves_anchor_without_a_new_message_badge(self):
        key = self.show_history(failed=True)
        self.read_earlier_messages()
        viewport = self.view.capture_chat_scroll()
        previous = viewport['message']
        recovered = Message(key.target, 'Synthetic recovered verified message',
                            message_id=previous.message_id, encryption='e2ee')
        self.assertIsNotNone(self.app.state.conversation(key).add(recovered))
        self.view.render_conversation(key)
        self.root.update()
        self.assert_message_position(recovered.content, viewport['offset'])
        self.assertEqual(len(self.view.current_chat_frame.winfo_children()), 80)
        self.assertFalse(self.view.new_messages_button.winfo_ismapped())

    def test_small_standard_and_x11_wheel_events_scroll_in_both_directions(self):
        self.show_history()
        for sequence, options, direction in (
                ('<MouseWheel>', {'delta': -1}, 1),
                ('<MouseWheel>', {'delta': 1}, -1),
                ('<MouseWheel>', {'delta': -120}, 1),
                ('<MouseWheel>', {'delta': 120}, -1),
                ('<Button-5>', {}, 1),
                ('<Button-4>', {}, -1)):
            with self.subTest(sequence=sequence, options=options):
                self.view.chat_canvas.yview_moveto(.4)
                self.root.update()
                before = self.view.chat_canvas.yview()[0]
                self.view.chat_canvas.event_generate(sequence, **options)
                self.root.update()
                after = self.view.chat_canvas.yview()[0]
                self.assertGreater((after - before) * direction, 0)

    def test_resize_during_chat_teardown_does_not_touch_destroyed_header(self):
        canvas = self.view.chat_canvas
        callback_errors = Mock()
        self.root.report_callback_exception = callback_errors
        live_canvas_at_destroy = []

        def delayed_resize(_event):
            live_canvas_at_destroy.append(canvas.winfo_exists())
            self.view.resize_chat(SimpleNamespace(widget=canvas, width=913))

        # Header widgets disappear before the canvas during a page rebuild.
        # Replay the native resize notification inside that teardown window.
        self.view.chat_title.bind('<Destroy>', delayed_resize)
        self.view.build_login()
        self.root.update()
        self.assertEqual(live_canvas_at_destroy, [1])
        callback_errors.assert_not_called()
        self.assertTrue(self.view.username_entry.winfo_ismapped())

    def test_queued_old_canvas_resize_cannot_reconfigure_replacement_chat(self):
        old_canvas = self.view.chat_canvas
        stale_event = SimpleNamespace(widget=old_canvas, width=913)
        callback_errors = Mock()
        self.root.report_callback_exception = callback_errors
        self.view.build_chat()
        self.wait_for_geometry(self.view.chat_canvas)
        current_canvas = self.view.chat_canvas
        original_window_width = current_canvas.itemcget(self.view.chat_window, 'width')
        original_wrap = self.view.chat_title.cget('wraplength')
        self.root.after_idle(lambda: self.view.resize_chat(stale_event))
        self.root.update()
        self.assertIsNot(current_canvas, old_canvas)
        self.assertFalse(old_canvas.winfo_exists())
        callback_errors.assert_not_called()
        self.assertEqual(current_canvas.itemcget(self.view.chat_window, 'width'), original_window_width)
        self.assertEqual(self.view.chat_title.cget('wraplength'), original_wrap)
        original_canvas_width = current_canvas.winfo_width()
        self.root.geometry('1000x700')
        self.wait_for_geometry(current_canvas, size=(1000, 700))
        self.assertGreater(current_canvas.winfo_width(), original_canvas_width)
        self.assertEqual(float(current_canvas.itemcget(self.view.chat_window, 'width')),
                         current_canvas.winfo_width())

    def test_resize_after_application_close_does_not_access_dead_tk_widgets(self):
        event = SimpleNamespace(widget=self.view.chat_canvas, width=913)
        self.app.close()
        self.view.resize_chat(event)


if __name__ == '__main__':
    unittest.main()
