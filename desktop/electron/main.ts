import { app, BrowserWindow, clipboard, dialog, ipcMain, Menu, Notification, session } from 'electron';
import { resolve, sep } from 'node:path';
import { mkdirSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { CoreProcess } from './core';
import { METHODS, sameKey, type CoreEvent, type DesktopNotification, type InitResult, type Method, type State } from '../src/protocol';
import { APP_ID, registerWindowsNotifications } from './windows-notifications';

let window: BrowserWindow | null = null;
let core: CoreProcess | null = null;
let latest: State | null = null;
let initialization: Promise<InitResult>;
let failure: string | null = null;
let quitting = false;
const activeNotifications = new Map<Notification, DesktopNotification>();
let notificationFailureReported = false;
const repository = resolve(__dirname, '../..');
const rendererFile = resolve(__dirname, 'renderer/index.html');
const devURL = !app.isPackaged && process.env.CHATROOM_DEV_URL === 'http://127.0.0.1:5173'
  ? process.env.CHATROOM_DEV_URL : null;
const documentURL = devURL || pathToFileURL(rendererFile).href;
const allowedDocumentURL = new URL(documentURL).href;

if (process.platform === 'win32') app.setAppUserModelId(APP_ID);

if (process.env.CHATROOM_CONFIG_DIR) {
  const userData = resolve(process.env.CHATROOM_CONFIG_DIR, 'desktop');
  mkdirSync(userData, { recursive: true });
  app.setPath('userData', userData);
}

function validSender(event: Electron.IpcMainInvokeEvent): boolean {
  return !!window && event.sender === window.webContents && event.senderFrame === window.webContents.mainFrame
    && event.senderFrame.url.split('#')[0] === allowedDocumentURL;
}

function notificationAllowed(notice: DesktopNotification): boolean {
  return !!latest && latest.page === 'chat' && latest.session === notice.session
    && latest.notifications.enabled && !latest.notifications.do_not_disturb
    && latest.notifications.preview === notice.preview
    && !!notice.key && latest.conversations.some(item => sameKey(item.key, notice.key));
}

function closeNotifications() {
  for (const native of activeNotifications.keys()) native.close();
  activeNotifications.clear();
}

function notificationFailed() {
  if (notificationFailureReported) return;
  notificationFailureReported = true;
  send({ method: 'notice', params: { title: '桌面通知', text: '系统未能显示桌面通知，请检查系统通知设置。' } });
}

function send(event: CoreEvent) {
  if (event.method === 'session.reset') { latest = null; closeNotifications(); }
  if (event.method === 'state.changed') {
    latest = event.params as State;
    for (const [native, notice] of activeNotifications) {
      if (!notificationAllowed(notice)) { native.close(); activeNotifications.delete(native); }
    }
  }
  if (event.method === 'core.failed') failure = (event.params as { message: string }).message;
  if (event.method === 'desktop.notification') {
    const notice = event.params as DesktopNotification;
    if (!notice || typeof notice.title !== 'string' || typeof notice.body !== 'string'
        || notice.title.length > 160 || notice.body.length > 400
        || Array.from(notice.title).length > 80 || Array.from(notice.body).length > 200
        || !notificationAllowed(notice)) return;
    if (!Notification.isSupported()) { notificationFailed(); return; }
    try {
      const native = new Notification({ title: notice.title, body: notice.body });
      native.on('click', () => {
        if (!activeNotifications.has(native) || !notificationAllowed(notice) || !window || window.isDestroyed()) return;
        if (window.isMinimized()) window.restore();
        window.show(); window.focus();
        send({ method: 'notification.open', params: { session: notice.session, key: notice.key } });
        native.close(); activeNotifications.delete(native);
      });
      native.on('close', () => activeNotifications.delete(native));
      native.on('failed', () => { activeNotifications.delete(native); notificationFailed(); });
      if (activeNotifications.size >= 20) {
        const oldest = activeNotifications.keys().next().value;
        if (oldest) { oldest.close(); activeNotifications.delete(oldest); }
      }
      activeNotifications.set(native, notice);
      native.show();
    } catch { notificationFailed(); }
    return;
  }
  if (window && !window.isDestroyed()) window.webContents.send('core:event', event);
}

function createWindow() {
  window = new BrowserWindow({ width: 1180, height: 820, minWidth: 760, minHeight: 580,
    title: 'Chatroom', backgroundColor: '#faf9f6', show: false,
    titleBarStyle: process.platform === 'darwin' ? 'hiddenInset' : 'default',
    webPreferences: { preload: resolve(__dirname, 'preload.cjs'), nodeIntegration: false,
      contextIsolation: true, sandbox: true, webSecurity: true, devTools: !app.isPackaged },
  });
  window.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  window.webContents.on('will-navigate', (event, url) => { if (url !== documentURL) event.preventDefault(); });
  window.webContents.on('will-attach-webview', event => event.preventDefault());
  window.webContents.on('render-process-gone', () => { void core?.stop(); });
  window.on('closed', () => { window = null; });
  window.once('ready-to-show', () => window?.show());
  void (devURL ? window.loadURL(devURL) : window.loadFile(rendererFile));
}

if (!app.requestSingleInstanceLock()) app.quit();
else {
  app.on('second-instance', () => { window?.show(); window?.focus(); });
  app.whenReady().then(() => {
    const notificationRegistered = registerWindowsNotifications();
    session.defaultSession.setPermissionRequestHandler((_contents, _permission, callback) => callback(false));
    session.defaultSession.setPermissionCheckHandler(() => false);
    // The renderer only loads local application assets. It has no network API.
    session.defaultSession.webRequest.onBeforeRequest((details, callback) => {
      let localAsset = false;
      if (details.url.startsWith('file://')) {
        try { localAsset = fileURLToPath(details.url).startsWith(resolve(__dirname, 'renderer') + sep); }
        catch { /* Reject malformed file URLs. */ }
      }
      const local = localAsset || (devURL &&
        ['http://127.0.0.1:5173/', 'ws://127.0.0.1:5173/'].some(prefix => details.url.startsWith(prefix)));
      callback({ cancel: !local });
    });
    Menu.setApplicationMenu(Menu.buildFromTemplate([
      ...(process.platform === 'darwin' ? [{ label: 'Chatroom', submenu: [{ role: 'about' as const },
        { type: 'separator' as const }, { role: 'quit' as const }] }] : []),
      { label: '编辑', submenu: [{ role: 'undo' }, { role: 'redo' }, { type: 'separator' },
        { role: 'cut' }, { role: 'copy' }, { role: 'paste' }, { role: 'selectAll' }] },
      { label: '显示', submenu: [{ role: 'resetZoom' }, { role: 'zoomIn' }, { role: 'zoomOut' },
        { role: 'togglefullscreen' }, ...(!app.isPackaged ? [{ role: 'toggleDevTools' as const }] : [])] },
    ]));
    core = new CoreProcess(app.isPackaged, process.resourcesPath, repository);
    core.on('event', send);
    initialization = core.initialize();
    void initialization.catch(error => send({ method: 'core.failed', params: { message: String(error.message) } }));
    ipcMain.handle('core:request', async (event, method: Method, raw: unknown) => {
      if (!validSender(event) || !METHODS.includes(method) || !raw || typeof raw !== 'object' || Array.isArray(raw)) {
        throw new Error('无效的桌面操作');
      }
      if (failure) throw new Error(failure);
      if (method === 'initialize') {
        const initialized = await initialization;
        return { ...initialized, state: latest || initialized.state };
      }
      const params = { ...raw as Record<string, unknown> };
      if (method === 'keys.export' || method === 'keys.import') {
        if (!window) throw new Error('窗口已关闭');
        // Never accept arbitrary filesystem paths from the renderer.
        delete params.path;
        if (method === 'keys.export') {
          const selected = await dialog.showSaveDialog(window, { title: '导出加密密钥备份',
            defaultPath: 'chatroom-e2ee-keys.json', filters: [{ name: '密钥备份', extensions: ['json'] }] });
          if (selected.canceled) return false;
          params.path = selected.filePath;
        } else {
          const selected = await dialog.showOpenDialog(window, { title: '选择加密密钥备份',
            properties: ['openFile'], filters: [{ name: '密钥备份', extensions: ['json'] }] });
          if (selected.canceled) return false;
          params.path = selected.filePaths[0];
        }
      }
      return core!.request(method, params);
    });
    ipcMain.handle('clipboard:write', (event, text: unknown) => {
      if (!validSender(event) || typeof text !== 'string' || text.length > 2 * 1024 * 1024) throw new Error('无法复制');
      clipboard.writeText(text);
    });
    createWindow();
    if (!notificationRegistered) window!.webContents.once('did-finish-load', () => {
      send({ method: 'notice', params: { title: 'Windows 通知',
        text: '无法创建开始菜单快捷方式，桌面通知可能不可用。请检查当前用户的开始菜单目录权限，然后重启客户端。' } });
    });
  });
  app.on('window-all-closed', () => app.quit());
  app.on('before-quit', event => {
    if (quitting) return;
    event.preventDefault();
    quitting = true;
    closeNotifications();
    void (core?.stop() || Promise.resolve()).finally(() => app.quit());
  });
}
