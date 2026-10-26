"""Test menu commands without entering Win32's human-driven TrackPopupMenu loop."""
from contextlib import contextmanager
import sys
import tkinter as tk
from unittest.mock import patch


@contextmanager
def nonblocking_menu_posts():
    # Unix posts are asynchronous. Win32 uses a native modal menu loop, so
    # replace only posting: real Tk menu entries, bindings and commands remain.
    if sys.platform == 'win32':
        with patch.object(tk.Menu, 'tk_popup', autospec=True) as posting:
            yield posting
    else:
        yield None
