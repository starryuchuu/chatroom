"""Live desktop theme changes preserve user state and persist safely."""
import gc
from pathlib import Path
import tempfile
import tkinter as tk
from tkinter import ttk
import unittest
from unittest.mock import Mock, patch

import client
from chatroom_client.models import ChatKey, Message
from chatroom_client.preferences import PreferencesError, PreferencesStore
from chatroom_client.settings_view import SettingsWindow
from chatroom_client.theme import DesktopTheme


class ClientThemeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='chatroom-theme-test-')
        self.config_path = Path(self.temp.name) / 'client.json'
        self.root = tk.Tk()
        self.root.withdraw()
        self.app = None

    def tearDown(self):
        if self.app is not None:
            self.app.close()
        elif self.root is not None:
            self.root.destroy()
        self.app = self.root = None
        gc.collect()
        self.temp.cleanup()

    def open_client(self, preferences=None):
        preferences = preferences or PreferencesStore(self.config_path)
        self.app = client.ChatClient(self.root, preferences=preferences, encryption=False)
        return self.app.view

    @staticmethod
    def color(value):
        return str(value).lower()

    def assert_color(self, actual, expected):
        self.assertEqual(self.color(actual), self.color(expected))

    def descendants(self, widget):
        for child in widget.winfo_children():
            yield child
            yield from self.descendants(child)

    def make_chat(self):
        view = self.open_client()
        self.app.connection.running = True
        self.app.connection.sock = Mock()
        self.app.state.username = 'theme-alice'
        self.app.state.friends.append('theme-bob')
        key = ChatKey('private', 'theme-bob')
        message = Message('theme-bob', 'Synthetic message retained while changing theme',
                          message_id=1, encryption='legacy')
        self.app.state.conversation(key).add(message)
        self.app.state.current_chat = key
        view.build_chat()
        view.update_friends_listbox()
        view.render_conversation(key)
        view.friends_listbox.selection_set(0)
        return view, key, message

    def test_saved_dark_theme_applies_on_start_and_toggle_persists(self):
        preferences = PreferencesStore(self.config_path)
        preferences.set_theme('dark')
        view = self.open_client(PreferencesStore(self.config_path))
        self.assertEqual(view.theme.mode, 'dark')
        self.assert_color(self.root.cget('bg'), view.colors['bg'])
        button = view.theme_button
        button.invoke()
        self.assertIs(view.theme_button, button)
        self.assertEqual(view.theme.mode, 'light')
        self.assertEqual(self.app.preferences.theme, 'light')
        self.assertEqual(PreferencesStore(self.config_path).theme, 'light')
        button.invoke()
        self.assertEqual(PreferencesStore(self.config_path).theme, 'dark')

    def test_login_toggle_preserves_entries_selection_and_widget_instances(self):
        view = self.open_client()
        username, password, port = view.username_entry, view.password_entry, view.port_entry
        username.insert(0, 'theme-alice')
        username.selection_range(1, 5)
        username.icursor(4)
        password.insert(0, 'synthetic-password-not-saved')
        port.delete(0, tk.END)
        port.insert(0, '23456')
        widgets = tuple(self.descendants(self.root))
        generation = self.app.connection.generation
        view.theme_button.invoke()
        self.assertEqual(view.theme.mode, 'dark')
        self.assertEqual(tuple(self.descendants(self.root)), widgets)
        self.assertIs(view.username_entry, username)
        self.assertIs(view.password_entry, password)
        self.assertIs(view.port_entry, port)
        self.assertEqual(username.get(), 'theme-alice')
        self.assertEqual((username.index(tk.SEL_FIRST), username.index(tk.SEL_LAST)), (1, 5))
        self.assertEqual(username.index(tk.INSERT), 4)
        self.assertEqual(password.get(), 'synthetic-password-not-saved')
        self.assertEqual(port.get(), '23456')
        self.assertFalse(self.app.connection.running)
        self.assertEqual(self.app.connection.generation, generation)
        self.assertNotIn('synthetic-password-not-saved', self.config_path.read_text())

    def test_chat_toggle_preserves_draft_selection_messages_and_connection(self):
        view, key, message = self.make_chat()
        view.msg_entry.insert('1.0', 'Synthetic unsent draft\nwith another line')
        self.app.state.pending_messages['synthetic-request'] = 'Synthetic pending message'
        view.refresh_controls()
        draft_widget, chat_frame = view.msg_entry, view.current_chat_frame
        conversation = self.app.state.conversation(key)
        messages = tuple(conversation.messages)
        widgets = tuple(self.descendants(self.root))
        sock, generation = self.app.connection.sock, self.app.connection.generation
        button = view.theme_button
        for mode in ('dark', 'light'):
            button.invoke()
            self.assertEqual(view.theme.mode, mode)
            self.assertIs(view.msg_entry, draft_widget)
            self.assertIs(view.current_chat_frame, chat_frame)
            self.assertEqual(tuple(self.descendants(self.root)), widgets)
            self.assertEqual(view.input_text(), 'Synthetic unsent draft\nwith another line')
            self.assertEqual(view.friends_listbox.curselection(), (0,))
            self.assertEqual(self.app.state.current_chat, key)
            self.assertIs(self.app.state.conversation(key), conversation)
            self.assertEqual(tuple(conversation.messages), messages)
            self.assertIs(conversation.messages[0], message)
            self.assertEqual(self.app.state.pending_messages,
                             {'synthetic-request': 'Synthetic pending message'})
            self.assertIs(self.app.connection.sock, sock)
            self.assertTrue(self.app.connection.running)
            self.assertEqual(self.app.connection.generation, generation)
            self.assertEqual(str(view.send_button.cget('state')), tk.DISABLED)
        sock.shutdown.assert_not_called()
        sock.close.assert_not_called()

    def assert_settings_palette(self, window, colors):
        self.assert_color(window.cget('bg'), colors['bg'])
        labels = [widget for widget in self.descendants(window) if isinstance(widget, ttk.Label)]
        self.assertTrue(labels)
        style = ttk.Style(self.root)
        for label in labels:
            name = str(label.cget('style')) or label.winfo_class()
            self.assert_color(style.lookup(name, 'background', label.state()), colors['bg'])
            foreground = 'muted' if name == 'Muted.TLabel' else 'text'
            self.assert_color(style.lookup(name, 'foreground', label.state()), colors[foreground])
        self.assert_color(window.profile_list.cget('bg'), colors['surface'])
        self.assert_color(window.profile_list.cget('fg'), colors['text'])
        self.assert_color(window.profile_list.cget('selectbackground'), colors['selected'])
        self.assert_color(window.profile_list.cget('selectforeground'), colors['text'])

    def test_open_and_new_settings_dialogs_use_current_palette(self):
        view = self.open_client()
        opened = SettingsWindow(self.root, self.app)
        existing_widgets = tuple(self.descendants(opened))
        profiles = opened.profile_list.get(0, tk.END)
        selection = opened.profile_list.curselection()
        view.set_theme('dark')
        self.assert_settings_palette(opened, view.colors)
        self.assertEqual(tuple(self.descendants(opened)), existing_widgets)
        self.assertEqual(opened.profile_list.get(0, tk.END), profiles)
        self.assertEqual(opened.profile_list.curselection(), selection)
        new = SettingsWindow(self.root, self.app)
        self.assert_settings_palette(new, view.colors)
        view.set_theme('light')
        self.assert_settings_palette(opened, view.colors)
        self.assert_settings_palette(new, view.colors)

    def test_disabled_primary_button_uses_new_palette_after_becoming_enabled(self):
        theme = DesktopTheme(self.root, mode='light')
        button = theme.button(self.root, 'Synthetic primary action', variant='primary', state=tk.DISABLED)
        for mode in ('dark', 'light', 'dark'):
            theme.set_mode(mode)
            self.assertEqual(str(button.cget('state')), tk.DISABLED)
            self.assert_color(button.cget('bg'), theme.colors['selected'])
            self.assert_color(button.cget('disabledforeground'), theme.colors['muted'])
            button.configure(state=tk.NORMAL)
            self.assert_color(button.cget('bg'), theme.colors['accent'])
            self.assert_color(button.cget('fg'), theme.colors['surface'])
            button.configure(state=tk.DISABLED)
            self.assert_color(button.cget('bg'), theme.colors['selected'])

    def test_canvas_items_text_tags_and_listbox_items_are_recolored_in_place(self):
        theme = DesktopTheme(self.root, mode='light')
        light = dict(theme.colors)
        canvas = tk.Canvas(self.root, bg=light['bg'])
        mark = canvas.create_polygon(0, 0, 20, 0, 20, 20, fill=light['accent'], outline=light['warning'])
        dot = canvas.create_oval(4, 4, 8, 8, fill=light['surface'], outline='')
        text = tk.Text(self.root, bg=light['field'], fg=light['text'])
        text.insert('1.0', 'Synthetic tagged text')
        text.tag_configure('notice', foreground=light['warning'], background=light['selected'])
        text.tag_add('notice', '1.0', '1.9')
        text.configure(state=tk.DISABLED)
        ranges = tuple(map(str, text.tag_ranges('notice')))
        listing = theme.listbox(self.root)
        listing.insert(tk.END, 'Synthetic highlighted item')
        listing.itemconfigure(0, background=light['selected'], foreground=light['warning'])
        listing.selection_set(0)
        items = canvas.find_all()
        coordinates = canvas.coords(mark)
        theme.set_mode('dark')
        dark = theme.colors
        self.assertEqual(canvas.find_all(), items)
        self.assertEqual(canvas.coords(mark), coordinates)
        self.assert_color(canvas.itemcget(mark, 'fill'), dark['accent'])
        self.assert_color(canvas.itemcget(mark, 'outline'), dark['warning'])
        self.assert_color(canvas.itemcget(dot, 'fill'), dark['surface'])
        self.assertEqual(canvas.itemcget(dot, 'outline'), '')
        self.assert_color(text.cget('bg'), dark['field'])
        self.assert_color(text.tag_cget('notice', 'foreground'), dark['warning'])
        self.assert_color(text.tag_cget('notice', 'background'), dark['selected'])
        self.assertEqual(tuple(map(str, text.tag_ranges('notice'))), ranges)
        self.assertEqual(text.get('1.0', 'end-1c'), 'Synthetic tagged text')
        self.assertEqual(str(text.cget('state')), tk.DISABLED)
        self.assert_color(listing.itemcget(0, 'background'), dark['selected'])
        self.assert_color(listing.itemcget(0, 'foreground'), dark['warning'])
        self.assertEqual(listing.curselection(), (0,))
        self.assertEqual(listing.get(0), 'Synthetic highlighted item')

    def test_populated_and_empty_menus_recolor_without_losing_entries(self):
        theme = DesktopTheme(self.root, mode='light')
        light = dict(theme.colors)
        empty = tk.Menu(self.root, tearoff=False, bg=light['surface'], fg=light['text'])
        menu = tk.Menu(self.root, tearoff=False, bg=light['surface'], fg=light['text'])
        callback = Mock()
        menu.add_command(label='Synthetic menu item', command=callback,
                         background=light['field'], foreground=light['warning'],
                         activebackground=light['selected'], activeforeground=light['text'])
        menu.add_separator()
        submenu = tk.Menu(menu, tearoff=False, bg=light['surface'], fg=light['text'])
        submenu.add_command(label='Synthetic nested item', background=light['selected'],
                            foreground=light['success'])
        menu.add_cascade(label='Synthetic submenu', menu=submenu)
        for mode in ('dark', 'light'):
            theme.set_mode(mode)
            colors = theme.colors
            self.assertIsNone(empty.index('end'))
            self.assert_color(empty.cget('bg'), colors['surface'])
            self.assert_color(empty.cget('fg'), colors['text'])
            self.assertEqual(menu.index('end'), 2)
            self.assertEqual(menu.entrycget(0, 'label'), 'Synthetic menu item')
            self.assertEqual(menu.type(1), 'separator')
            self.assertEqual(menu.entrycget(2, 'menu'), str(submenu))
            self.assert_color(menu.entrycget(0, 'background'), colors['field'])
            self.assert_color(menu.entrycget(0, 'foreground'), colors['warning'])
            self.assert_color(menu.entrycget(0, 'activebackground'), colors['selected'])
            self.assert_color(menu.entrycget(0, 'activeforeground'), colors['text'])
            self.assert_color(submenu.entrycget(0, 'background'), colors['selected'])
            self.assert_color(submenu.entrycget(0, 'foreground'), colors['success'])
        callback.assert_not_called()

    def test_treeview_tags_recolor_without_changing_selection_or_hierarchy(self):
        theme = DesktopTheme(self.root, mode='light')
        tree = ttk.Treeview(self.root, columns=('message',), show='headings')
        tree.heading('message', text='Synthetic column')
        tree.tag_configure('notice', background=theme.colors['selected'], foreground=theme.colors['warning'])
        tree.tag_configure('ok', foreground=theme.colors['success'])
        tree.insert('', tk.END, iid='parent', values=('Synthetic parent',), tags=('notice',), open=True)
        tree.insert('parent', tk.END, iid='child', values=('Synthetic child',), tags=('ok',))
        tree.selection_set('child')
        tree.focus('child')
        for mode in ('dark', 'light'):
            theme.set_mode(mode)
            colors = theme.colors
            self.assert_color(tree.tag_configure('notice', 'background'), colors['selected'])
            self.assert_color(tree.tag_configure('notice', 'foreground'), colors['warning'])
            self.assert_color(tree.tag_configure('ok', 'foreground'), colors['success'])
            self.assertEqual(tree.get_children(''), ('parent',))
            self.assertEqual(tree.get_children('parent'), ('child',))
            self.assertEqual(tree.selection(), ('child',))
            self.assertEqual(tree.focus(), 'child')
            self.assertEqual(tuple(tree.item('child', 'values')), ('Synthetic child',))
            self.assertTrue(tree.item('parent', 'open'))
            style = ttk.Style(self.root)
            self.assert_color(style.lookup('Treeview', 'background'), colors['surface'])
            self.assert_color(style.lookup('Treeview', 'foreground', ('selected',)), colors['text'])

    def test_existing_and_new_combobox_popdowns_follow_theme(self):
        theme = DesktopTheme(self.root, mode='light')
        combo = ttk.Combobox(self.root, values=('Synthetic first', 'Synthetic second'), state='readonly')
        combo.current(1)
        popdown = str(self.root.tk.call('ttk::combobox::PopdownWindow', combo))
        listbox = popdown + '.f.l'
        if not int(self.root.tk.call('winfo', 'exists', listbox)):
            if str(self.root.tk.call('tk', 'windowingsystem')) == 'aqua':
                self.skipTest('Aqua provides a native combobox popup')
            self.fail('The combobox popup listbox was not created')
        for mode in ('dark', 'light'):
            theme.set_mode(mode)
            colors = theme.colors
            self.assertEqual(str(self.root.tk.call('ttk::combobox::PopdownWindow', combo)), popdown)
            for option, role in (('-background', 'surface'), ('-foreground', 'text'),
                                 ('-selectbackground', 'selected'), ('-selectforeground', 'text')):
                self.assert_color(self.root.tk.call(listbox, 'cget', option), colors[role])
            self.assertEqual(combo.get(), 'Synthetic second')
            self.assertEqual(str(combo.cget('state')), 'readonly')
            newly_created = ttk.Combobox(self.root, values=('Synthetic new option',), state='readonly')
            new_popdown = str(self.root.tk.call('ttk::combobox::PopdownWindow', newly_created))
            new_listbox = new_popdown + '.f.l'
            self.assertTrue(int(self.root.tk.call('winfo', 'exists', new_listbox)))
            self.assert_color(self.root.tk.call(new_listbox, 'cget', '-background'), colors['surface'])
            self.assert_color(self.root.tk.call(new_listbox, 'cget', '-foreground'), colors['text'])
            newly_created.destroy()

    def test_future_classic_input_dialog_controls_inherit_and_follow_palette(self):
        theme = DesktopTheme(self.root, mode='light')

        def make_dialog():
            dialog = tk.Toplevel(self.root)
            frame = tk.Frame(dialog)
            frame.pack()
            label = tk.Label(frame, text='Synthetic input prompt')
            # Keep the two independent dialogs from competing for X11 PRIMARY.
            entry = tk.Entry(frame, exportselection=False)
            button = tk.Button(frame, text='Synthetic action')
            for widget in (label, entry, button):
                widget.pack()
            entry.insert(0, 'Synthetic retained input')
            entry.selection_range(1, 5)
            entry.icursor(6)
            return dialog, frame, label, entry, button

        def assert_palette(widgets):
            dialog, frame, label, entry, button = widgets
            for widget in (dialog, frame, label):
                self.assert_color(widget.cget('bg'), theme.colors['bg'])
            self.assert_color(label.cget('fg'), theme.colors['text'])
            self.assert_color(entry.cget('bg'), theme.colors['surface'])
            self.assert_color(entry.cget('fg'), theme.colors['text'])
            self.assert_color(entry.cget('insertbackground'), theme.colors['text'])
            self.assert_color(entry.cget('selectbackground'), theme.colors['selected'])
            self.assert_color(button.cget('bg'), theme.colors['field'])
            self.assert_color(button.cget('fg'), theme.colors['text'])
            self.assert_color(button.cget('activebackground'), theme.colors['selected'])
            self.assertEqual(entry.get(), 'Synthetic retained input')
            self.assertEqual((entry.index(tk.SEL_FIRST), entry.index(tk.SEL_LAST)), (1, 5))
            self.assertEqual(entry.index(tk.INSERT), 6)

        original = make_dialog()
        assert_palette(original)
        original_children = tuple(self.descendants(original[0]))
        theme.set_mode('dark')
        assert_palette(original)
        self.assertEqual(tuple(self.descendants(original[0])), original_children)
        new = make_dialog()
        assert_palette(new)
        theme.set_mode('light')
        assert_palette(original)
        assert_palette(new)

    def test_selected_checkbutton_indicator_has_contrast_in_both_themes(self):
        theme = DesktopTheme(self.root, mode='light')
        selected = tk.BooleanVar(self.root, True)
        callback = Mock()
        check = ttk.Checkbutton(self.root, text='Synthetic selection', variable=selected, command=callback)
        self.assertTrue(check.instate(('selected',)))
        initial_state = check.state()
        for mode in ('light', 'dark', 'light'):
            theme.set_mode(mode)
            style = ttk.Style(self.root)
            self.assert_color(style.lookup('TCheckbutton', 'indicatorbackground', check.state()),
                              theme.colors['accent'])
            self.assert_color(style.lookup('TCheckbutton', 'indicatorforeground', check.state()),
                              theme.colors['surface'])
            self.assert_color(style.lookup('TCheckbutton', 'indicatorbackground', ('selected', 'active')),
                              theme.colors['accent'])
            self.assert_color(style.lookup('TCheckbutton', 'indicatorforeground', ('selected', 'active')),
                              theme.colors['surface'])
            self.assertTrue(selected.get())
            self.assertEqual(check.state(), initial_state)
        callback.assert_not_called()

    def test_existing_brand_canvas_changes_colors_without_recreating_logo(self):
        view = self.open_client()
        logos = [widget for widget in self.descendants(self.root)
                 if isinstance(widget, tk.Canvas) and any(widget.type(item) == 'polygon'
                                                          for item in widget.find_all())]
        self.assertTrue(logos)
        logo = logos[0]
        items = logo.find_all()
        polygon = next(item for item in items if logo.type(item) == 'polygon')
        dots = [item for item in items if logo.type(item) == 'oval']
        view.set_theme('dark')
        self.assertEqual(logo.find_all(), items)
        self.assert_color(logo.itemcget(polygon, 'fill'), view.colors['accent'])
        for item in dots:
            self.assert_color(logo.itemcget(item, 'fill'), view.colors['surface'])

    def test_failed_preference_save_preserves_current_theme_and_notifies(self):
        view = self.open_client()
        before = dict(view.colors)
        widgets = tuple(self.descendants(self.root))
        view.notify = Mock()
        with patch.object(self.app.preferences, 'set_theme', side_effect=PreferencesError('synthetic disk failure')):
            view.set_theme('dark')
        self.assertEqual(view.theme.mode, 'light')
        self.assertEqual(view.colors, before)
        self.assertEqual(self.app.preferences.theme, 'light')
        self.assertEqual(tuple(self.descendants(self.root)), widgets)
        view.notify.assert_called_once()


if __name__ == '__main__':
    unittest.main()
