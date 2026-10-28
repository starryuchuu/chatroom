import { test, expect, _electron as electron, type ElectronApplication, type Page } from '@playwright/test';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { once } from 'node:events';
import type { State } from '../src/protocol';

let app: ElectronApplication;
let page: Page;
let directory: string;
const errors: string[] = [];

test.beforeEach(async () => {
  directory = await mkdtemp(resolve(tmpdir(), 'chatroom-electron-'));
  errors.length = 0;
  app = await electron.launch({ executablePath: process.env.CHATROOM_DESKTOP_EXECUTABLE,
    args: [...(process.env.CHATROOM_DESKTOP_EXECUTABLE ? [] : [resolve('.')]), ...(process.env.CHATROOM_TEST_NO_SANDBOX === '1' ? ['--no-sandbox'] : [])],
    env: { ...process.env, CHATROOM_CONFIG_DIR: directory, XDG_CACHE_HOME: directory, ELECTRON_DISABLE_SECURITY_WARNINGS: 'true' } });
  page = await app.firstWindow();
  page.on('pageerror', error => errors.push(error.message));
  await expect(page.getByRole('heading', { name: '让对话，继续发生' })).toBeVisible();
});
test.afterEach(async () => { await app?.close(); await rm(directory, { recursive: true, force: true }); });

test('real core startup, server settings, registration layout and themes', async () => {
  await expect(page.locator('body')).not.toContainText('无法连接客户端核心');
  const isolation = await page.evaluate(() => ({ require: typeof (window as unknown as { require?: unknown }).require,
    process: typeof (window as unknown as { process?: unknown }).process }));
  expect(isolation).toEqual({ require: 'undefined', process: 'undefined' });
  await page.getByRole('button', { name: '创建新账号' }).click();
  await expect(page.getByRole('heading', { name: '从这里，开始对话' })).toBeVisible();
  await page.getByRole('button', { name: '已有账号？返回登录' }).click();
  await page.getByRole('button', { name: '设置', exact: true }).click();
  await page.getByRole('button', { name: '深色', exact: true }).click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  await page.getByRole('combobox', { name: '通知内容', exact: true }).selectOption('message');
  await expect.poll(async () => (await page.evaluate(() => window.chatroom.request('initialize')) as { state: State }).state.notifications.preview).toBe('message');
  if (process.platform === 'win32' && process.env.CHATROOM_DESKTOP_EXECUTABLE) {
    const registration = await app.evaluate(({ app, shell }) => {
      const shortcut = app.getPath('appData') + '/Microsoft/Windows/Start Menu/Programs/Chatroom Desktop.lnk';
      const details = shell.readShortcutLink(shortcut);
      return { target: details.target, executable: process.execPath, appUserModelId: details.appUserModelId };
    });
    expect(registration.target).toBe(registration.executable);
    expect(registration.appUserModelId).toBe('io.github.starryuchuu.chatroom');
  }
  await page.getByRole('button', { name: '服务器', exact: true }).click();
  await page.getByRole('button', { name: '新建配置' }).click();
  await page.getByLabel('配置名称', { exact: true }).fill('测试服务器');
  await page.getByRole('button', { name: '保存并选用' }).click();
  await expect(page.getByRole('button', { name: /测试服务器/ })).toBeVisible();
  await page.getByRole('button', { name: '关闭', exact: true }).click();
  await expect(page.getByRole('combobox', { name: '服务器' })).toHaveValue('测试服务器');
  await page.screenshot({ path: 'test-results/login-dark.png' });
  expect(errors).toEqual([]);
});

// Seed only synthetic rendering data through the real main->preload channel.
// Authentication and E2EE wire behavior are tested using two real core processes.
async function showChat(count = 6) {
  const initialized = await page.evaluate(() => window.chatroom.request('initialize')) as { state: State };
  const state: State = { ...initialized.state, page: 'chat', username: '星野', connected: true,
    status: '已连接', canSend: true, currentChat: { kind: 'private', target: '木木' },
    encryption: { enabled: true, ready: true, status: '端到端加密已就绪', fingerprint: 'a'.repeat(64), peers: [] },
    conversations: [
      { key: { kind: 'private', target: '木木' }, title: '木木', preview: '好呀，晚一点见。', unread: 0, timestamp: '', online: true },
      { key: { kind: 'group', target: 'weekend' }, title: '周末出逃计划', preview: '有空的时候，一起出去走走', unread: 3, timestamp: '', online: false },
      { key: { kind: 'private', target: '小夏' }, title: '小夏', preview: '分享一些日常的小事', unread: 0, timestamp: '', online: false },
    ],
    messages: Array.from({ length: count }, (_, index) => ({ id: String(index + 1),
      author: index % 2 ? '星野' : '木木', self: index % 2 === 1, protection: 'e2ee',
      timestamp: `2026-10-27T07:${String(index % 60).padStart(2, '0')}:00Z`,
      content: count > 10 ? `消息 ${index + 1} · 中文🙂 ${index === 10 ? '查找目标' : '普通消息'}` : [
        '今天路过一家很安静的咖啡店，突然想起你之前说的那个地方。',
        '是窗边有一棵树的那家吗？我一直想找个下午过去坐坐。',
        '对，就是那里。阳光落在桌子上，感觉时间都慢下来了。\n这周末有空的话，要不要一起去？',
        '好呀。带上书，点一杯咖啡，什么都不用赶。',
        '那就这样说定了，周六下午见。', '好呀，晚一点见。',
      ][index % 6] })),
  };
  await app.evaluate(({ BrowserWindow, ipcMain }, snapshot) => {
    const window = BrowserWindow.getAllWindows()[0];
    ipcMain.removeHandler('core:request');
    ipcMain.handle('core:request', (_event, method: string, params: Record<string, unknown>) => {
      if (method === 'initialize') return { protocolVersion: 1, implementation: 'render-fixture', state: snapshot };
      if (method === 'settings.theme') {
        snapshot.theme = params.theme as 'light' | 'dark';
        window.webContents.send('core:event', { method: 'state.changed', params: snapshot });
      }
      return true;
    });
    window.webContents.send('core:event', { method: 'state.changed', params: snapshot });
  }, state);
  await expect(page.getByRole('heading', { name: '木木', exact: true })).toBeVisible();
  return state;
}

test('chat rendering, Unicode draft, search, sidebar and scale', async () => {
  await showChat();
  await expect(page.getByText('好呀，晚一点见。', { exact: true })).toBeVisible();
  await page.getByLabel('消息输入', { exact: true }).fill('中文输入🙂\n第二行');
  await expect(page.getByLabel('消息输入', { exact: true })).toHaveValue('中文输入🙂\n第二行');
  await page.getByRole('button', { name: '搜索消息', exact: true }).click();
  await page.getByRole('textbox', { name: '搜索已加载消息' }).fill('周六');
  await expect(page.locator('mark')).toHaveText('周六');
  await page.getByRole('button', { name: '关闭搜索' }).click();
  await page.getByRole('button', { name: '收起侧栏' }).click();
  await expect(page.getByRole('button', { name: '展开侧栏' })).toBeVisible();
  await page.getByRole('button', { name: '展开侧栏' }).click();
  await expect(async () => {
    await page.locator('[data-message-id="6"] .message-body').scrollIntoViewIfNeeded();
    await expect(page.locator('[data-message-id="6"] .message-body')).toBeVisible();
  }).toPass({ timeout: 5000 });
  await page.screenshot({ path: 'test-results/chat-light.png' });
  await page.getByRole('button', { name: '切换深色模式' }).click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  // The real core snapshot has no fake session; restore the synthetic chat.
  await showChat();
  for (const factor of [1, 1.5, 2]) {
    await app.evaluate(({ BrowserWindow }, factor) => BrowserWindow.getAllWindows()[0].webContents.setZoomFactor(factor), factor);
    await expect(page.getByLabel('消息输入', { exact: true })).toBeVisible();
    await expect(page.getByRole('button', { name: '发送消息', exact: true })).toBeVisible();
  }
  await app.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows()[0].webContents.setZoomFactor(1));
  // Zoom changes resize the virtual list and may replace a row mid-scroll.
  // Wait for the final row to be mounted and visible before capturing it.
  await expect(async () => {
    await page.locator('[data-message-id="6"] .message-body').scrollIntoViewIfNeeded();
    await expect(page.locator('[data-message-id="6"] .message-body')).toBeVisible();
  }).toPass({ timeout: 5000 });
  await page.screenshot({ path: 'test-results/chat-dark.png' });
  expect(errors).toEqual([]);
});

test('virtualized history stays bounded and search navigates far outside viewport', async () => {
  await showChat(2000);
  await expect(page.getByText('消息 2000 · 中文🙂 普通消息', { exact: true })).toBeVisible();
  expect(await page.locator('.message-row').count()).toBeLessThan(100);
  await page.getByRole('button', { name: '搜索消息', exact: true }).click();
  await page.getByRole('textbox', { name: '搜索已加载消息' }).fill('查找目标');
  await expect(page.locator('mark')).toHaveText('查找目标');
  await expect(page.getByText('消息 11 · 中文🙂 查找目标', { exact: false })).toBeVisible();
  expect(await page.locator('.message-row').count()).toBeLessThan(100);
  expect(errors).toEqual([]);
});

test('inline send states expose reconciliation, safe retry and failure details', async () => {
  const snapshot = await showChat(0);
  snapshot.messages = [{ id: '101', author: '星野', self: true, protection: 'e2ee',
    timestamp: '2026-10-28T06:30:00Z', content: '这条消息已保存。', sendStatus: 'saved' }];
  snapshot.outgoing = [
    { id: 'outgoing:uncertain', author: '星野', self: true, protection: 'local', sendId: 'uncertain', canRecover: true,
      timestamp: '2026-10-28T06:31:00Z', content: '这条消息需要核对原结果。', sendStatus: 'uncertain' },
    { id: 'outgoing:failure', author: '星野', self: true, protection: 'local',
      timestamp: '2026-10-28T06:32:00Z', content: '这条消息发送失败，原文保留。', sendStatus: 'failed', sendError: '好友关系已失效，请检查后重新发送。' },
  ];
  await app.evaluate(({ BrowserWindow, ipcMain }, snapshot) => {
    type Fixture = { snapshot: State; recoveries: string[] };
    const fixture: Fixture = { snapshot, recoveries: [] };
    (globalThis as unknown as { sendFixture: Fixture }).sendFixture = fixture;
    const win = BrowserWindow.getAllWindows()[0];
    ipcMain.removeHandler('core:request');
    ipcMain.handle('core:request', (_event, method: string, params: Record<string, unknown>) => {
      if (method === 'initialize') return { protocolVersion: 1, implementation: 'send-state-fixture', state: fixture.snapshot };
      if (method === 'settings.theme') fixture.snapshot.theme = params.theme as 'light' | 'dark';
      if (method === 'send.recover') {
        fixture.recoveries.push(String(params.id));
        const item = fixture.snapshot.outgoing.find(item => item.sendId === params.id)!;
        item.sendStatus = item.sendStatus === 'retry' ? 'sending' : 'checking';
      }
      win.webContents.send('core:event', { method: 'state.changed', params: fixture.snapshot });
      return true;
    });
    win.webContents.send('core:event', { method: 'state.changed', params: snapshot });
  }, snapshot);
  const uncertain = page.locator('[data-message-id="outgoing:uncertain"]');
  const failure = page.locator('[data-message-id="outgoing:failure"]');
  await expect(uncertain).toContainText('保存结果待确认');
  await expect(failure).toContainText('好友关系已失效');
  await expect(page.getByLabel('发送状态：服务器已保存')).toHaveAttribute('title', /不代表对方已收到或已读/);
  await expect(page.locator('.message-protection')).toHaveCount(0);
  // Virtuoso briefly paints measurement rows at opacity zero. Wait for the
  // visible list rather than capturing a frame during initial measurement.
  const waitForPaint = async () => {
    await expect(failure).toBeVisible();
    await expect(failure).toBeInViewport();
    await expect.poll(() => failure.evaluate(node => {
      for (let parent: Element | null = node; parent; parent = parent.parentElement) {
        if (Number(getComputedStyle(parent).opacity) === 0) return false;
      }
      return true;
    })).toBe(true);
  };
  await waitForPaint();
  await page.screenshot({ path: 'test-results/send-status-light.png', animations: 'disabled' });
  await page.getByRole('button', { name: '切换深色模式' }).click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  await waitForPaint();
  await page.screenshot({ path: 'test-results/send-status-dark.png', animations: 'disabled' });
  await page.getByLabel('消息输入', { exact: true }).fill('不应被核对或重试覆盖的草稿');
  await uncertain.getByRole('button', { name: '核对原结果', exact: true }).click();
  await expect(uncertain).toContainText('正在核对');
  await expect(uncertain.getByRole('button', { name: '重试发送' })).toHaveCount(0);
  await app.evaluate(({ BrowserWindow }) => {
    const f = (globalThis as unknown as { sendFixture: { snapshot: State; recoveries: string[] } }).sendFixture;
    f.snapshot.outgoing[0].sendStatus = 'retry';
    f.snapshot.connected = false;
    BrowserWindow.getAllWindows()[0].webContents.send('core:event', { method: 'state.changed', params: f.snapshot });
  });
  await expect(uncertain.getByRole('button', { name: '重试发送' })).toBeDisabled();
  await app.evaluate(({ BrowserWindow }) => {
    const f = (globalThis as unknown as { sendFixture: { snapshot: State } }).sendFixture;
    f.snapshot.connected = true;
    BrowserWindow.getAllWindows()[0].webContents.send('core:event', { method: 'state.changed', params: f.snapshot });
  });
  await uncertain.getByRole('button', { name: '重试发送' }).click();
  await expect(uncertain).toContainText('发送中');
  await expect(page.getByLabel('消息输入', { exact: true })).toHaveValue('不应被核对或重试覆盖的草稿');
  expect(await app.evaluate(() => (globalThis as unknown as { sendFixture: { recoveries: string[] } }).sendFixture.recoveries))
    .toEqual(['uncertain', 'uncertain']);
  expect(errors).toEqual([]);
});

test('two desktop windows register, add friends and exchange real encrypted messages', async () => {
  const fixture = spawn(process.env.CHATROOM_PYTHON || (process.platform === 'win32' ? 'python' : 'python3'),
    ['-u', resolve('tests/server_fixture.py')], { stdio: ['pipe', 'pipe', 'pipe'], env: process.env });
  fixture.stderr.on('data', () => {});
  const lines = createInterface({ input: fixture.stdout });
  const started = await Promise.race([
    once(lines, 'line'),
    once(fixture, 'exit').then(() => { throw new Error('Desktop server fixture exited before ready'); }),
  ]);
  const { port } = JSON.parse(started[0] as string) as { port: number };
  const bobDirectory = await mkdtemp(resolve(tmpdir(), 'chatroom-electron-bob-'));
  let bobApp: ElectronApplication | null = null;
  try {
    bobApp = await electron.launch({ executablePath: process.env.CHATROOM_DESKTOP_EXECUTABLE,
      args: process.env.CHATROOM_DESKTOP_EXECUTABLE ? [] : [resolve('.')],
      env: { ...process.env, CHATROOM_CONFIG_DIR: bobDirectory, XDG_CACHE_HOME: bobDirectory } });
    const bob = await bobApp.firstWindow();
    // Exercise the real core -> main -> native notification path without
    // posting test message content to the host's actual notification center.
    await bobApp.evaluate(({ Notification }) => {
      const notices: import('electron').Notification[] = [];
      (globalThis as unknown as { notificationSpies: import('electron').Notification[] }).notificationSpies = notices;
      Notification.isSupported = () => true;
      Notification.prototype.show = function () { notices.push(this); };
      Notification.prototype.close = function () { this.emit('close'); };
    });
    await expect(bob.getByRole('heading', { name: '让对话，继续发生' })).toBeVisible();
    const password = 'synthetic-desktop-unified-password';
    for (const [targetPage, username] of [[page, 'alice'], [bob, 'bob']] as const) {
      await targetPage.evaluate(async port => {
        const initial = await window.chatroom.request('initialize') as { state: State };
        await window.chatroom.request('profile.save', { session: initial.state.session, name: 'Real test',
          host: '127.0.0.1', port, fingerprint: null });
      }, port);
      await targetPage.getByRole('button', { name: '创建新账号' }).click();
      await targetPage.getByLabel('用户名', { exact: true }).fill(username);
      await targetPage.getByLabel('密码', { exact: true }).fill(password);
      await targetPage.getByRole('button', { name: '创建账号', exact: true }).click();
      await expect(targetPage.getByRole('heading', { name: '让对话，继续发生' })).toBeVisible();
      await targetPage.getByLabel('密码', { exact: true }).fill(password);
      await targetPage.getByRole('button', { name: '登录', exact: true }).click();
      await expect(targetPage.getByRole('heading', { name: '今天，想和谁聊聊？' })).toBeVisible();
    }
    await page.getByRole('button', { name: /添加好友/ }).click();
    await page.getByRole('dialog').getByLabel('用户名').fill('bob');
    await page.getByRole('button', { name: '发送申请' }).click();
    await expect(bob.locator('.sidebar-action').filter({ hasText: '申请与邀请' })).toContainText('1');
    await bob.locator('.sidebar-action').filter({ hasText: '申请与邀请' }).click();
    await bob.getByRole('button', { name: '接受', exact: true }).click();
    await bob.getByRole('button', { name: '关闭', exact: true }).click();
    await page.locator('.conversation').filter({ hasText: 'bob' }).click();
    await bob.locator('.conversation').filter({ hasText: 'alice' }).click();
    await expect(page.getByRole('button', { name: '发送消息', exact: true })).toBeDisabled();
    await page.getByRole('button', { name: /^在线用户/ }).click();
    const online = page.getByRole('dialog', { name: '在线用户', exact: true });
    await expect(online.getByRole('status')).toContainText('2 人在线');
    await expect(online.getByRole('listitem')).toHaveCount(2);
    await page.getByRole('textbox', { name: '搜索在线用户', exact: true }).fill('bob');
    await expect(online.getByRole('listitem')).toHaveCount(1);
    await expect(online.getByRole('listitem')).toContainText('bob');
    await page.getByRole('textbox', { name: '搜索在线用户', exact: true }).fill('missing-user');
    await expect(online.getByText('没有匹配的用户')).toBeVisible();
    await page.getByRole('textbox', { name: '搜索在线用户', exact: true }).fill('');
    await expect(online.getByText('你', { exact: true })).toBeVisible();
    await page.screenshot({ path: 'test-results/online-users.png' });
    await page.getByRole('button', { name: '关闭', exact: true }).click();
    await bob.evaluate(async () => {
      const { state } = await window.chatroom.request('initialize') as { state: State };
      await window.chatroom.request('settings.notifications', { session: state.session, enabled: true, doNotDisturb: false, preview: 'message' });
      await window.chatroom.request('window.activity', { session: state.session, focused: false, atBottom: true });
    });
    await page.getByLabel('消息输入', { exact: true }).fill('真实界面发送 · 中文🙂');
    await expect(page.getByRole('button', { name: '发送消息', exact: true })).toBeEnabled();
    await page.getByLabel('消息输入', { exact: true }).press('Enter');
    await expect(bob.locator('.message-body')).toContainText('真实界面发送 · 中文🙂');
    await expect.poll(() => bobApp!.evaluate(() => (globalThis as unknown as {
      notificationSpies: import('electron').Notification[];
    }).notificationSpies.map(item => ({ title: item.title, body: item.body })))).toContainEqual({ title: 'alice', body: '真实界面发送 · 中文🙂' });
    await expect(page.getByLabel('消息输入', { exact: true })).toHaveValue('');
    await expect(page.locator('.message-body').filter({ hasText: '真实界面发送 · 中文🙂' })).toHaveCount(1);
    await expect(page.locator('.message-row.own').filter({ hasText: '真实界面发送 · 中文🙂' }).locator('.message-send-status')).toHaveText('服务器已保存');
    // Wait past the one-second notification rate limit, then exercise Unicode
    // truncation through the real core and main process (UTF-16 != characters).
    await new Promise(resolve => setTimeout(resolve, 1050));
    await page.getByLabel('消息输入', { exact: true }).fill('🙂'.repeat(160));
    await page.getByLabel('消息输入', { exact: true }).press('Enter');
    await expect.poll(() => bobApp!.evaluate(() => (globalThis as unknown as {
      notificationSpies: import('electron').Notification[];
    }).notificationSpies.map(item => item.body))).toContain('🙂'.repeat(139) + '…');
    await bob.getByLabel('消息输入', { exact: true }).fill('收到，已经端到端加密。');
    await bob.getByLabel('消息输入', { exact: true }).press('Enter');
    await expect(page.locator('.message-body').last()).toHaveText('收到，已经端到端加密。');
    expect(await page.locator('.message-protection').count()).toBe(0);
    await page.screenshot({ path: 'test-results/real-encrypted-chat.png' });
    await page.getByRole('button', { name: '新的对话', exact: true }).click();
    await page.getByRole('button', { name: /创建群聊/ }).click();
    await page.getByRole('dialog').getByLabel('群聊名称', { exact: true }).fill('Desktop group');
    await page.getByRole('dialog').getByRole('checkbox').check();
    await page.getByRole('dialog').getByRole('button', { name: '创建群聊', exact: true }).click();
    for (const target of [page, bob]) {
      await target.locator('.conversation').filter({ hasText: 'Desktop group' }).click();
    }
    await page.getByLabel('消息输入', { exact: true }).fill('群聊也经过显式接收人核验');
    await page.getByLabel('消息输入', { exact: true }).press('Enter');
    for (const target of [page, bob]) {
      await expect(target.getByRole('heading', { name: '确认群聊加密接收人' })).toBeVisible();
      await expect(target.getByRole('button', { name: '确认', exact: true })).toBeDisabled();
      await target.getByLabel('我已核对以上所有接收人与指纹').check();
      await target.getByRole('button', { name: '确认', exact: true }).click();
    }
    await expect(bob.locator('.message-body').last()).toHaveText('群聊也经过显式接收人核验');
    await page.getByRole('button', { name: '群聊详情', exact: true }).click();
    await page.getByRole('dialog').getByLabel('群聊名称', { exact: true }).fill('Renamed group');
    await page.getByRole('button', { name: '保存名称', exact: true }).click();
    await page.getByRole('button', { name: '关闭', exact: true }).click();
    await expect(page.getByRole('heading', { name: 'Renamed group', exact: true })).toBeVisible();
    await expect(bob.getByRole('heading', { name: 'Renamed group', exact: true })).toBeVisible();
    await bob.getByLabel('消息输入', { exact: true }).fill('群聊里尚未发送的草稿');
    const clickPrivateNotification = (body = '真实界面发送 · 中文🙂') => bobApp!.evaluate((_electron, body) => {
      const notice = (globalThis as unknown as { notificationSpies: import('electron').Notification[] })
        .notificationSpies.find(item => item.body === body);
      if (!notice) throw new Error('Missing native notification');
      notice.emit('click');
    }, body);
    await clickPrivateNotification();
    await expect(bob.getByRole('heading', { name: 'alice', exact: true })).toBeVisible();
    await bob.locator('.conversation').filter({ hasText: 'Renamed group' }).click();
    await expect(bob.getByLabel('消息输入', { exact: true })).toHaveValue('群聊里尚未发送的草稿');
    await bob.evaluate(async () => {
      const { state } = await window.chatroom.request('initialize') as { state: State };
      await window.chatroom.request('settings.notifications', { session: state.session, enabled: true, doNotDisturb: true, preview: 'generic' });
    });
    await clickPrivateNotification('🙂'.repeat(139) + '…');
    await expect(bob.getByRole('heading', { name: 'Renamed group', exact: true })).toBeVisible();
    await page.getByRole('button', { name: '群聊详情', exact: true }).click();
    await expect(page.getByRole('dialog', { name: '群聊详情' })).toBeVisible();
    await page.getByRole('button', { name: '关闭', exact: true }).click();
    await page.getByRole('button', { name: /^在线用户/ }).click();
    await expect(page.getByRole('dialog', { name: '在线用户' }).getByRole('status')).toContainText('2 人在线');
    await bobApp.close();
    bobApp = null;
    await expect(page.getByRole('dialog', { name: '在线用户' }).getByRole('status')).toContainText('1 人在线');
    await expect(page.getByRole('dialog', { name: '在线用户' }).getByRole('listitem')).toHaveCount(1);
    await page.getByRole('button', { name: '关闭', exact: true }).click();
    expect(errors).toEqual([]);
  } finally {
    await bobApp?.close();
    await rm(bobDirectory, { recursive: true, force: true });
    fixture.stdin.end();
    await once(fixture, 'exit');
    lines.close();
  }
});
