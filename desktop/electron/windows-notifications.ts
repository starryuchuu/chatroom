import { app, shell } from 'electron';
import { mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';

// Must match electron-builder's appId. Portable ZIPs do not run an installer
// that would otherwise create this per-user Start Menu registration.
export const APP_ID = 'io.github.starryuchuu.chatroom';

export function registerWindowsNotifications(): boolean {
  if (process.platform !== 'win32' || !app.isPackaged) return true;
  try {
    const programs = join(app.getPath('appData'), 'Microsoft', 'Windows', 'Start Menu', 'Programs');
    const shortcut = join(programs, 'Chatroom Desktop.lnk');
    mkdirSync(programs, { recursive: true });
    try {
      const existing = shell.readShortcutLink(shortcut);
      if (existing.target === process.execPath && existing.appUserModelId === APP_ID) return true;
    } catch { /* First launch, or a shortcut that needs to be replaced. */ }
    return shell.writeShortcutLink(shortcut, 'create', {
      target: process.execPath, cwd: dirname(process.execPath),
      icon: process.execPath, iconIndex: 0,
      description: 'Chatroom Desktop', appUserModelId: APP_ID,
    });
  } catch {
    return false;
  }
}
