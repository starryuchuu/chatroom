"""Shared, dependency-free desktop styling for the Tk client."""
import sys
import tkinter as tk
from tkinter import font as tkfont, ttk


PALETTES = {
    'light': {
        'bg': '#FBFBFC', 'surface': '#FFFFFF', 'sidebar': '#F2F3F5',
        'text': '#22252B', 'muted': '#656B75', 'subtle': '#737A85',
        'line': '#E3E5E9', 'accent': '#343A43', 'accent_hover': '#4B535E',
        'selected': '#E0E4EA', 'self': '#E9EDF2', 'field': '#F6F7F9',
        'success': '#357058', 'warning': '#946126', 'danger': '#9B3C40',
    },
    'dark': {
        'bg': '#171A20', 'surface': '#20242C', 'sidebar': '#1B1F26',
        'text': '#E7EAF0', 'muted': '#ADB5C2', 'subtle': '#9AA4B3',
        'line': '#353D49', 'accent': '#CDD8E8', 'accent_hover': '#E1E8F2',
        'selected': '#364458', 'self': '#2D3A4D', 'field': '#272D37',
        'success': '#8BC6A7', 'warning': '#E4BC7F', 'danger': '#F0A0A6',
    },
}

_COLOR_OPTIONS = (
    'background', 'foreground', 'activebackground', 'activeforeground',
    'disabledbackground', 'disabledforeground', 'highlightbackground',
    'highlightcolor', 'insertbackground', 'selectbackground',
    'selectforeground', 'selectcolor', 'readonlybackground', 'troughcolor',
    'inactiveselectbackground',
)


class AutoScrollbar(ttk.Scrollbar):
    """Show a scrollbar only when its view has content outside the viewport."""

    def set(self, first, last):
        manager = self.winfo_manager()
        if float(first) <= 0 and float(last) >= 1:
            if manager == 'pack':
                self._pack_options = self.pack_info()
                self.pack_forget()
            elif manager == 'grid':
                self.grid_remove()
                self._grid_hidden = True
        elif not manager:
            if getattr(self, '_grid_hidden', False):
                self.grid()
            elif getattr(self, '_pack_options', None):
                self.pack(**self._pack_options)
        super().set(first, last)


class _ThemedButton(tk.Button):
    """Classic Tk button with a legible, neutral disabled appearance."""

    def __init__(self, parent, *, disabled_background, disabled_foreground, **kwargs):
        self._normal_background = kwargs.get('bg', kwargs.get('background'))
        self._disabled_background = disabled_background
        self._disabled_foreground = disabled_foreground
        super().__init__(parent, **kwargs)
        self._update_disabled_appearance()

    def _update_disabled_appearance(self):
        disabled = str(self.cget('state')) == tk.DISABLED
        super().configure(bg=self._disabled_background if disabled else self._normal_background,
                          disabledforeground=self._disabled_foreground)

    def configure(self, cnf=None, **kwargs):
        if cnf is not None and not isinstance(cnf, dict):
            return super().configure(cnf, **kwargs)
        options = dict(cnf or {})
        options.update(kwargs)
        if not options:
            return super().configure()
        if 'bg' in options or 'background' in options:
            self._normal_background = options.get('bg', options.get('background'))
        result = super().configure(options)
        self._update_disabled_appearance()
        return result

    config = configure


class DesktopTheme:
    """A theme belongs to one Tcl interpreter, including its child windows."""

    def __init__(self, root, mode='light'):
        if mode not in PALETTES:
            raise ValueError('未知的界面主题')
        self.root = root
        self.mode = mode
        self.colors = dict(PALETTES[mode])
        families = set(tkfont.families(root))
        candidates = {
            'darwin': ('PingFang SC', 'SF Pro Text', 'Helvetica Neue'),
            'win32': ('Microsoft YaHei UI', 'Microsoft YaHei', 'Segoe UI'),
        }.get(sys.platform, ('Noto Sans CJK SC', 'WenQuanYi Micro Hei', 'DejaVu Sans'))
        family = next((name for name in candidates if name in families),
                      tkfont.nametofont('TkDefaultFont', root=root).actual('family'))
        self.fonts = {
            'body': (family, 11), 'small': (family, 9), 'list': (family, 10),
            'title': (family, 17, 'bold'), 'heading': (family, 11, 'bold'),
            'hero': (family, 30, 'bold'),
        }
        root._chatroom_theme = self
        self._install_ttk()

    def set_mode(self, mode):
        """Recolor existing widgets in place, retaining focus, content and state."""
        if mode not in PALETTES:
            raise ValueError('未知的界面主题')
        if mode == self.mode:
            return
        replacements = {color.lower(): PALETTES[mode][role]
                        for role, color in self.colors.items()}
        # Views and dialogs hold this dictionary, so keep its identity stable.
        self.colors.update(PALETTES[mode])
        self.mode = mode
        self._install_ttk()
        self._recolor(self.root, replacements)

    @staticmethod
    def _replacement(value, replacements):
        return replacements.get(str(value).lower())

    def _recolor(self, widget, replacements):
        options = {}
        available = widget.configure()
        for option in _COLOR_OPTIONS:
            if option in available:
                color = self._replacement(widget.cget(option), replacements)
                if color is not None:
                    options[option] = color
        if isinstance(widget, _ThemedButton):
            # A disabled primary button displays its disabled background. Its
            # remembered normal background must follow the palette as well.
            options['background'] = (self._replacement(widget._normal_background, replacements)
                                     or widget._normal_background)
            widget._disabled_background = self.colors['selected']
            widget._disabled_foreground = self.colors['muted']
        if options:
            widget.configure(**options)
        if isinstance(widget, tk.Canvas):
            for item in widget.find_all():
                changes = {}
                item_options = widget.itemconfigure(item)
                for option in ('fill', 'outline', 'activefill', 'activeoutline',
                               'disabledfill', 'disabledoutline'):
                    if option in item_options:
                        color = self._replacement(widget.itemcget(item, option), replacements)
                        if color is not None:
                            changes[option] = color
                if changes:
                    widget.itemconfigure(item, **changes)
        elif isinstance(widget, tk.Text):
            for tag in widget.tag_names():
                changes = {option: color for option in ('background', 'foreground')
                           if (color := self._replacement(widget.tag_cget(tag, option), replacements))}
                if changes:
                    widget.tag_configure(tag, **changes)
        elif isinstance(widget, tk.Listbox):
            for item in range(widget.size()):
                changes = {option: color for option in ('background', 'foreground',
                           'selectbackground', 'selectforeground')
                           if (color := self._replacement(widget.itemcget(item, option), replacements))}
                if changes:
                    widget.itemconfigure(item, **changes)
        elif isinstance(widget, tk.Menu):
            end = widget.index('end')
            for item in range(end + 1 if end is not None else 0):
                if widget.type(item) in ('separator', 'tearoff', 'none', None):
                    continue
                changes = {option: color for option in ('background', 'foreground',
                           'activebackground', 'activeforeground')
                           if (color := self._replacement(widget.entrycget(item, option), replacements))}
                if changes:
                    widget.entryconfigure(item, **changes)
        elif isinstance(widget, ttk.Treeview):
            for tag in self.root.tk.splitlist(self.root.tk.call(widget, 'tag', 'names')):
                changes = {option: color for option in ('background', 'foreground')
                           if (color := self._replacement(widget.tag_configure(tag, option), replacements))}
                if changes:
                    widget.tag_configure(tag, **changes)
        elif isinstance(widget, ttk.Combobox):
            # Tk owns these popup widgets; they have no Python widget wrapper.
            popdown = str(self.root.tk.call('ttk::combobox::PopdownWindow', widget))
            listbox = popdown + '.f.l'
            # Aqua uses a native menu instead of the listbox used on X11/Win32.
            if self.root.tk.call('winfo', 'exists', listbox):
                self.root.tk.call(listbox, 'configure',
                                  '-background', self.colors['surface'],
                                  '-foreground', self.colors['text'],
                                  '-selectbackground', self.colors['selected'],
                                  '-selectforeground', self.colors['text'])
        # Python-owned children include hidden panels, menus and Toplevels.
        # Avoid winfo_children(), which also returns unwrapped Tk popup widgets.
        for child in list(widget.children.values()):
            self._recolor(child, replacements)

    def _install_ttk(self):
        c, f = self.colors, self.fonts
        # Tk's built-in input dialogs use classic widgets. Give new widgets
        # palette defaults too; explicitly styled application controls win.
        defaults = {
            '*background': c['bg'], '*foreground': c['text'],
            '*activeBackground': c['selected'], '*activeForeground': c['text'],
            '*disabledForeground': c['subtle'], '*highlightBackground': c['line'],
            '*highlightColor': c['accent'], '*insertBackground': c['text'],
            '*selectBackground': c['selected'], '*selectForeground': c['text'],
            '*selectColor': c['field'], '*Entry.background': c['surface'],
            '*Entry.disabledBackground': c['field'], '*Text.background': c['field'],
            '*Listbox.background': c['surface'], '*Menu.background': c['surface'],
            '*Button.background': c['field'],
        }
        for option, color in defaults.items():
            self.root.option_add(option, color, 60)
        style = ttk.Style(self.root)
        # Clam exposes field and focus colors consistently on all Tk platforms.
        style.theme_use('clam')
        style.configure('.', background=c['bg'], foreground=c['text'], font=f['body'],
                        bordercolor=c['line'], lightcolor=c['line'], darkcolor=c['line'])
        style.configure('TFrame', background=c['bg'])
        style.configure('TLabel', background=c['bg'], foreground=c['text'])
        style.configure('Muted.TLabel', foreground=c['muted'], font=f['small'])
        style.configure('Heading.TLabel', font=f['heading'])
        style.configure('TButton', background=c['field'], foreground=c['text'],
                        borderwidth=1, padding=(12, 7), focusthickness=1,
                        focuscolor=c['accent'])
        style.map('TButton', background=[('disabled', c['field']), ('active', c['selected'])],
                  foreground=[('disabled', c['subtle'])],
                  bordercolor=[('focus', c['accent'])])
        style.configure('Primary.TButton', background=c['accent'], foreground=c['surface'])
        style.map('Primary.TButton', background=[('disabled', c['selected']), ('active', c['accent_hover'])],
                  foreground=[('disabled', c['muted']), ('!disabled', c['surface'])])
        for name in ('TEntry', 'TCombobox'):
            style.configure(name, fieldbackground=c['surface'], foreground=c['text'],
                            padding=7, borderwidth=1, insertcolor=c['text'],
                            arrowcolor=c['muted'])
            style.map(name, fieldbackground=[('disabled', c['field']), ('readonly', c['surface'])],
                      foreground=[('disabled', c['subtle']), ('readonly', c['text'])],
                      bordercolor=[('focus', c['accent'])],
                      background=[('readonly', c['surface'])])
        style.configure('TCheckbutton', background=c['bg'], padding=(0, 3),
                        focuscolor=c['accent'], indicatorbackground=c['field'],
                        indicatorforeground=c['text'])
        style.map('TCheckbutton', background=[('active', c['bg'])],
                  indicatorbackground=[('selected', c['accent']), ('active', c['selected'])],
                  indicatorforeground=[('selected', c['surface'])])
        style.configure('Treeview', background=c['surface'], fieldbackground=c['surface'],
                        foreground=c['text'], rowheight=34, borderwidth=0)
        style.map('Treeview', background=[('selected', c['selected'])],
                  foreground=[('selected', c['text'])])
        style.configure('Treeview.Heading', background=c['sidebar'], foreground=c['muted'],
                        padding=(8, 8), font=f['small'], relief='flat')
        style.map('Treeview.Heading', background=[('active', c['selected'])])
        style.configure('TSeparator', background=c['line'])
        for orientation in ('Vertical', 'Horizontal'):
            name = orientation + '.TScrollbar'
            style.configure(name, background=c['subtle'], arrowcolor=c['text'],
                            troughcolor=c['bg'], bordercolor=c['bg'],
                            lightcolor=c['bg'], darkcolor=c['bg'], borderwidth=0, arrowsize=12)
            style.map(name, background=[('pressed', c['accent']), ('active', c['muted'])])
        # Also applies to newly created combobox dropdowns.
        for option, color in (('background', c['surface']), ('foreground', c['text']),
                              ('selectBackground', c['selected']), ('selectForeground', c['text'])):
            self.root.option_add('*TCombobox*Listbox.' + option, color)
        self.style = style

    def _button_options(self, parent, variant):
        c = self.colors
        if variant == 'primary':
            background, foreground, hover = c['accent'], c['surface'], c['accent_hover']
        elif variant == 'quiet':
            try:
                background = parent.cget('background')
            except tk.TclError:
                background = c['bg']
            foreground, hover = c['muted'], c['selected']
        else:
            background, foreground, hover = c['field'], c['text'], c['selected']
        return dict(font=self.fonts['body'], bg=background, fg=foreground,
                    activebackground=hover, activeforeground=foreground,
                    disabledforeground=c['subtle'], relief=tk.FLAT, bd=0,
                    padx=14, pady=7, cursor='hand2', takefocus=True,
                    highlightthickness=1, highlightbackground=background if variant == 'quiet' else c['line'],
                    highlightcolor=c['accent'])

    def button(self, parent, text, command=None, variant='secondary', **kwargs):
        options = self._button_options(parent, variant)
        options.update(kwargs)
        if variant == 'primary':
            return _ThemedButton(parent, text=text, command=command,
                                 disabled_background=self.colors['selected'],
                                 disabled_foreground=self.colors['muted'], **options)
        return tk.Button(parent, text=text, command=command, **options)

    def _entry_options(self):
        c = self.colors
        return dict(font=self.fonts['body'], bg=c['surface'], fg=c['text'],
                    insertbackground=c['text'], relief=tk.FLAT, bd=0,
                    highlightthickness=1, highlightbackground=c['line'],
                    highlightcolor=c['accent'], selectbackground=c['selected'],
                    selectforeground=c['text'], disabledbackground=c['field'],
                    disabledforeground=c['subtle'])

    def entry(self, parent, **kwargs):
        options = self._entry_options()
        options.update(kwargs)
        return tk.Entry(parent, **options)

    def _listbox_options(self):
        c = self.colors
        return dict(font=self.fonts['body'], bg=c['surface'], fg=c['text'],
                    relief=tk.FLAT, bd=0, highlightthickness=1,
                    highlightbackground=c['line'], highlightcolor=c['accent'],
                    selectbackground=c['selected'], selectforeground=c['text'],
                    selectborderwidth=0, activestyle='none', exportselection=False)

    def listbox(self, parent, **kwargs):
        options = self._listbox_options()
        options.update(kwargs)
        return tk.Listbox(parent, **options)

    def style_window(self, window):
        """Style existing classic widgets without changing their behavior."""
        c, f = self.colors, self.fonts
        if 'background' in window.keys():
            window.configure(background=c['bg'])
        for child in window.winfo_children():
            if isinstance(child, tk.Toplevel):
                continue
            if isinstance(child, tk.Frame):
                child.configure(bg=c['bg'], bd=0)
            elif isinstance(child, tk.Label):
                foreground = child.cget('foreground')
                child.configure(bg=c['bg'], font=f['body'],
                                fg=foreground if foreground in (c['warning'], c['danger'], c['success']) else c['text'])
            elif isinstance(child, tk.Button):
                child.configure(**self._button_options(child.master, 'secondary'))
            elif isinstance(child, tk.Entry):
                child.configure(**self._entry_options())
            elif isinstance(child, tk.Listbox):
                child.configure(**self._listbox_options())
            elif isinstance(child, tk.Text):
                child.configure(bg=c['field'], fg=c['text'],
                                relief=tk.FLAT, bd=0, padx=12, pady=8,
                                highlightthickness=1, highlightbackground=c['line'],
                                highlightcolor=c['accent'], insertbackground=c['text'])
            elif isinstance(child, tk.Checkbutton):
                child.configure(font=f['body'], bg=c['bg'], fg=c['text'],
                                activebackground=c['bg'], activeforeground=c['text'],
                                selectcolor=c['surface'], highlightthickness=1,
                                highlightbackground=c['bg'], highlightcolor=c['accent'])
            if child.winfo_children():
                self.style_window(child)


def get_theme(master):
    root = master._root()
    theme = getattr(root, '_chatroom_theme', None)
    return theme if theme is not None else DesktopTheme(root)
