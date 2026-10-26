"""Synthetic desktop checks for source and frozen clients; no account or network."""
import ctypes
import gc
import json
import os
from pathlib import Path
import socket
import shutil
import subprocess
import sys
import tkinter as tk
from tkinter import font as tkfont
from types import SimpleNamespace


def _windows_input(entry, value):
    from ctypes import wintypes
    send = ctypes.windll.user32.SendMessageW
    send.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
    send.restype = ctypes.c_ssize_t
    raw = value.encode('utf-16-le')
    for index in range(0, len(raw), 2):
        send(entry.winfo_id(), 0x0102, int.from_bytes(raw[index:index + 2], 'little'), 1)


def _windows_cjk_font(root, family):
    from ctypes import wintypes
    user, gdi = ctypes.windll.user32, ctypes.windll.gdi32
    user.GetDC.argtypes, user.GetDC.restype = [wintypes.HWND], wintypes.HDC
    user.ReleaseDC.argtypes = [wintypes.HWND, wintypes.HDC]
    gdi.CreateFontW.argtypes = [ctypes.c_int] * 5 + [ctypes.c_uint] * 8 + [ctypes.c_wchar_p]
    gdi.CreateFontW.restype = wintypes.HANDLE
    gdi.SelectObject.argtypes, gdi.SelectObject.restype = [wintypes.HDC, wintypes.HANDLE], wintypes.HANDLE
    gdi.DeleteObject.argtypes = [wintypes.HANDLE]
    gdi.GetGlyphIndicesW.argtypes = [wintypes.HDC, wintypes.LPCWSTR, ctypes.c_int,
                                    ctypes.POINTER(wintypes.WORD), wintypes.DWORD]
    gdi.GetGlyphIndicesW.restype = wintypes.DWORD
    dc = user.GetDC(root.winfo_id())
    font = gdi.CreateFontW(-20, 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 0, 0, family)
    if not dc or not font:
        raise AssertionError('Could not inspect native Windows font')
    previous = gdi.SelectObject(dc, font)
    try:
        glyphs = (wintypes.WORD * 2)()
        count = gdi.GetGlyphIndicesW(dc, '中文', 2, glyphs, 1)
        if count == 0xFFFFFFFF or any(value == 0xFFFF for value in glyphs):
            raise AssertionError('Selected Windows font lacks Chinese glyphs')
    finally:
        gdi.SelectObject(dc, previous)
        gdi.DeleteObject(font)
        user.ReleaseDC(root.winfo_id(), dc)


def _capture_windows(root, path):
    script = r'''
Add-Type -AssemblyName System.Drawing
$bitmap = New-Object System.Drawing.Bitmap([int]$env:CHATROOM_CAPTURE_W, [int]$env:CHATROOM_CAPTURE_H)
try {
  $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
  try {
    $origin = New-Object System.Drawing.Point([int]$env:CHATROOM_CAPTURE_X, [int]$env:CHATROOM_CAPTURE_Y)
    $graphics.CopyFromScreen($origin, [System.Drawing.Point]::Empty, $bitmap.Size)
    $bitmap.Save($env:CHATROOM_CAPTURE_PATH, [System.Drawing.Imaging.ImageFormat]::Png)
  } finally { $graphics.Dispose() }
} finally { $bitmap.Dispose() }
'''
    env = dict(os.environ, CHATROOM_CAPTURE_PATH=str(path.resolve()),
               CHATROOM_CAPTURE_X=str(root.winfo_rootx()), CHATROOM_CAPTURE_Y=str(root.winfo_rooty()),
               CHATROOM_CAPTURE_W=str(root.winfo_width()), CHATROOM_CAPTURE_H=str(root.winfo_height()))
    subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', script],
                   env=env, check=True, capture_output=True, timeout=20)


def _visible(widget, name):
    if not widget.winfo_ismapped():
        raise AssertionError(f'{name} is hidden')
    left, top = widget.winfo_rootx(), widget.winfo_rooty()
    right, bottom = left + widget.winfo_width(), top + widget.winfo_height()
    parent = widget.master
    while parent is not None:
        x, y = parent.winfo_rootx(), parent.winfo_rooty()
        if left < x or top < y or right > x + parent.winfo_width() or bottom > y + parent.winfo_height():
            raise AssertionError(f'{name} is clipped by {parent.winfo_class()}')
        parent = parent.master


def check_desktop_ui(output_directory=None, *, scales=(1, 1.25, 1.5, 1.75, 2)):
    from .app import ChatApplication
    from .connection import ClientSettings, ConnectionManager
    from .models import ChatKey, Message
    from .preferences import PreferencesStore
    from .view import TkClientView

    directory = Path(output_directory) if output_directory is not None else None
    if directory is not None:
        directory.mkdir(parents=True, exist_ok=True)
    report = {'platform': sys.platform, 'cases': [], 'cjk_font_verified': False, 'cjk_font_available': False,
              'input_check': 'native WM_CHAR Unicode commit' if sys.platform == 'win32' else 'Tk Unicode insertion',
              'ime_composition': 'requires manual testing with an installed IME'}
    for scale in scales:
        root = tk.Tk()
        root.withdraw()
        original_scaling = float(root.tk.call('tk', 'scaling'))
        root.tk.call('tk', 'scaling', 4 / 3 * scale)
        errors = []
        root.report_callback_exception = lambda kind, value, traceback: errors.append(kind.__name__ + ': ' + str(value))
        preferences = PreferencesStore(persistent=False)
        preferences.set_notifications(enabled=False)
        app = ChatApplication(TkClientView(root), ConnectionManager(ClientSettings()), preferences)
        try:
            view = app.view
            app.connection.sock, app.connection.running = socket.socket(), True
            app.connection.endpoint = ('127.0.0.1', 12345)
            app.connection.send = lambda packet: None
            app.connection.capabilities = ('message_receipts',)
            app.state.username = '示例账号'
            app.encryption = SimpleNamespace(ready=False, sending=False, status='端到端加密：等待身份核对', reset=lambda: None)
            key = ChatKey('private', '中文示例联系人')
            app.state.friends = [key.target]
            app.state.conversation(key).add(Message(key.target, '这是可选择复制的中文消息。\nUnicode 输入与复制：中文🙂',
                                                    '2026-10-26T09:00:00Z', 1, encryption='e2ee'))
            view.build_chat()
            app.select_chat(key)
            app.sends.send({'type': 'private_chat', 'to': key.target, 'request_id': 'a' * 32,
                            'content': 'Synthetic pending envelope'}, '这是一条示例待确认消息')
            app.sends.pause()
            app.state.pending_messages.clear()
            view.refresh_controls()
            root.geometry('900x700')
            root.deiconify()
            for _ in range(8):
                root.update()
            family = tkfont.Font(root=root, font=view.fonts['body']).actual('family')
            report['cjk_font_available'] = any(name in tkfont.families(root) for name in
                ('Noto Sans CJK SC', 'Microsoft YaHei UI', 'Microsoft YaHei', 'PingFang SC', 'WenQuanYi Micro Hei'))
            if sys.platform == 'win32':
                _windows_cjk_font(root, family)
                report['cjk_font_verified'] = True
            view.msg_entry.focus_force()
            root.update()
            sample = '中文输入提交🙂'
            if sys.platform == 'win32':
                _windows_input(view.msg_entry, sample)
            else:
                view.msg_entry.insert('1.0', sample)
            root.update()
            if view.input_text() != sample:
                raise AssertionError('Unicode input commit did not preserve text')
            row = view.current_chat_frame.pack_slaves()[0]
            view.message_actions.activate(row)
            root.update()
            view.message_actions.copy_message()
            if root.clipboard_get() != row._chat_message.content:
                raise AssertionError('Unicode clipboard round-trip failed')
            view.message_actions.close_selection()
            for mode in ('light', 'dark'):
                view.set_theme(mode)
                view.search.open()
                view.search.query.set('中文')
                view.search.refresh(jump=True)
                view.send_recovery.toggle()
                for _ in range(5):
                    root.update()
                panel = view.send_recovery
                panel.dismiss()
                for _ in range(3):
                    root.update()
                panel.resize()
                for name, widget in [('send', view.send_button), ('draft', view.msg_entry),
                    ('pending', view.recover_send_button), ('pending list', panel.tree),
                    ('retry', panel.recover_button), ('remove confirmation', panel.dismiss_button),
                    ('search', view.search_button), ('search entry', view.search.entry),
                    ('search next', view.search.buttons[1]), ('encryption', view.encryption_button),
                    ('disconnect', view.disconnect_button)]:
                    _visible(widget, name)
                if view.chat_canvas.winfo_height() < 80:
                    raise AssertionError(f'Chat height {view.chat_canvas.winfo_height()} at scale {scale}, theme {mode}')
                if not panel.tree.bbox(app.sends.records[0].record_id):
                    raise AssertionError('Pending row cannot be read')
                name = f'chat-{round(scale * 100)}-{mode}.png'
                if directory is not None and sys.platform == 'win32':
                    _capture_windows(root, directory / name)
                elif directory is not None and shutil.which('import'):
                    subprocess.run(['import', '-window', str(root.winfo_id()), str(directory / name)],
                                   check=True, capture_output=True, timeout=20)
                report['cases'].append({'scale': scale, 'theme': mode, 'font': family,
                    'chat_height': view.chat_canvas.winfo_height(), 'toolbar_wrapped': view._toolbar_wrapped,
                    'screenshot': name if directory is not None and (directory / name).exists() else None})
                if directory is not None:
                    (directory / 'desktop-ui.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
                panel.hide()
                view.search.close()
            if errors:
                raise AssertionError('; '.join(errors))
        finally:
            root.tk.call('tk', 'scaling', original_scaling)
            app.close()
            # Tcl interpreters and Variables must be reclaimed on their owner
            # thread, before a later network worker can trigger cyclic GC.
            root = app = view = row = panel = widget = None
            gc.collect()
    if directory is not None:
        (directory / 'desktop-ui.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    return report
