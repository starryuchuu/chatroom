"""Best-effort native desktop notifications, isolated from Tk's owner thread."""
import base64
import json
import logging
import queue
import shutil
import subprocess
import sys
import threading
import time


_WINDOWS_SCRIPT = r'''
[Console]::InputEncoding = New-Object System.Text.UTF8Encoding
$payload = [Console]::In.ReadToEnd() | ConvertFrom-Json
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
$icon = New-Object System.Windows.Forms.NotifyIcon
try {
    $icon.Icon = [System.Drawing.SystemIcons]::Information
    $icon.Visible = $true
    $icon.ShowBalloonTip(3000, [string]$payload.title, [string]$payload.body,
        [System.Windows.Forms.ToolTipIcon]::Info)
    Start-Sleep -Milliseconds 3200
} finally { $icon.Dispose() }
'''
_MAC_SCRIPT = '''on run argv
display notification (item 2 of argv) with title (item 1 of argv)
end run'''


def native_notify(title, body):
    """Run a supported desktop notifier with bounded lifetime and literal data."""
    common = {'stdout': subprocess.DEVNULL, 'stderr': subprocess.DEVNULL, 'check': True}
    try:
        if sys.platform == 'win32':
            executable = shutil.which('powershell.exe')
            if not executable:
                return False
            encoded = base64.b64encode(_WINDOWS_SCRIPT.encode('utf-16le')).decode('ascii')
            subprocess.run(
                [executable, '-NoProfile', '-NonInteractive', '-WindowStyle', 'Hidden',
                 '-EncodedCommand', encoded],
                input=json.dumps({'title': title, 'body': body}, ensure_ascii=False).encode('utf-8'),
                timeout=6, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0), **common)
        elif sys.platform == 'darwin':
            subprocess.run(['/usr/bin/osascript', '-e', _MAC_SCRIPT, title, body],
                           timeout=3, **common)
        else:
            executable = shutil.which('notify-send')
            if not executable:
                return False
            subprocess.run([executable, '--app-name=Chatroom', '--expire-time=5000', '--', title, body],
                           timeout=3, **common)
    except (OSError, subprocess.SubprocessError):
        return False
    return True


class DesktopNotifier:
    """A bounded worker reports fallback bells through poll(), never a Tk callback."""
    def __init__(self, deliver=None, *, minimum_interval=1.0):
        self.deliver = deliver or native_notify
        self.minimum_interval = minimum_interval
        self.requests = queue.Queue(maxsize=8)
        self.results = queue.Queue()
        self.closed = False
        self._generation = 0
        self._last_notice = float('-inf')
        self._worker = threading.Thread(target=self._run, name='chatroom-notifications', daemon=True)
        self._worker.start()

    def notify(self, title, body):
        if self.closed:
            return
        now = time.monotonic()
        if now - self._last_notice < self.minimum_interval:
            return
        self._last_notice = now
        try:
            self.requests.put_nowait((self._generation, title, body))
        except queue.Full:
            pass

    def _run(self):
        while True:
            item = self.requests.get()
            if item is None:
                return
            generation, title, body = item
            if self.closed or generation != self._generation:
                continue
            try:
                delivered = self.deliver(title, body)
            except Exception:
                logging.exception('桌面提醒不可用')
                delivered = False
            if not delivered and not self.closed and generation == self._generation:
                self.results.put(True)

    def discard_pending(self):
        """Drop queued notices and late fallback bells on logout or mute."""
        self._generation += 1
        self._last_notice = float('-inf')
        while True:
            try:
                item = self.requests.get_nowait()
                if item is None:
                    self.requests.put_nowait(None)
                    break
            except queue.Empty:
                break
        self.poll()

    def poll(self):
        """Return pending fallback count; callers may ring once on the UI thread."""
        count = 0
        while True:
            try:
                self.results.get_nowait()
                count += 1
            except queue.Empty:
                return count

    def close(self):
        if self.closed:
            return
        self.closed = True
        self.discard_pending()
        self.requests.put_nowait(None)
        self._worker.join(timeout=.1)
