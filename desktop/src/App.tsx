import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { AlertCircle, ArrowDown, ArrowUp, Check, ChevronDown, ChevronLeft, ChevronRight,
  CircleHelp, Copy, Hash, Inbox, Info, LoaderCircle, LockKeyhole, Menu, MessageSquare, Moon, MoreHorizontal,
  PanelLeftClose, Plus, Search, Settings, ShieldCheck, Sun, Users, X } from 'lucide-react';
import { Virtuoso, type VirtuosoHandle } from 'react-virtuoso';
import { PROTOCOL_VERSION, keyId, sameKey, type ChatKey, type CoreEvent, type InitResult,
  type Message, type Method, type Prompt, type State } from './protocol';
import { AsyncButton, Avatar, Button, Field, IconButton, Modal, clock, fingerprint } from './ui';
import { SettingsPanel, KeysPanel, GroupPanel, PendingPanel, RecoveryPanel, OnlineUsersPanel } from './panels';

export type Call = (method: Method, params?: Record<string, unknown>) => Promise<unknown>;
type Panel = 'settings' | 'keys' | 'friend' | 'createGroup' | 'group' | 'pending' | 'requests' | 'recovery' | 'online' | null;
type Toast = { id: number; title: string; text: string };
type SendActions = { connected: boolean; canSend: boolean; recover: (id: string) => Promise<unknown> };

export function App() {
  const [state, setState] = useState<State | null>(null);
  const current = useRef<State | null>(null);
  const [failure, setFailure] = useState('');
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [prompt, setPrompt] = useState<Prompt | null>(null);
  const [promptChecked, setPromptChecked] = useState(false);
  const [panel, setPanel] = useState<Panel>(null);
  const [groupId, setGroupId] = useState('');
  const [draft, setDraft] = useState('');
  const drafts = useRef(new Map<string, string>());
  const [registered, setRegistered] = useState(0);
  const [latestSignal, setLatestSignal] = useState(0);
  const toastSequence = useRef(0);
  const timers = useRef(new Set<ReturnType<typeof setTimeout>>());
  const notify = useCallback((title: string, text: string) => {
    const id = ++toastSequence.current;
    setToasts(previous => [...previous.slice(-3), { id, title, text }]);
    const timer = setTimeout(() => { timers.current.delete(timer); setToasts(items => items.filter(item => item.id !== id)); }, 6500);
    timers.current.add(timer);
  }, []);
  const applyState = useCallback((next: State) => {
    const before = current.current;
    if (before && before.session !== next.session) {
      setPanel(null); setPrompt(null);
      if (next.page === 'login') drafts.current.clear();
    }
    if (before?.session !== next.session || !sameKey(before?.currentChat ?? null, next.currentChat)) {
      setDraft(drafts.current.get(next.session + keyId(next.currentChat)) || '');
    }
    current.current = next;
    setState(next);
  }, []);
  useEffect(() => {
    const unsubscribe = window.chatroom.subscribe((event: CoreEvent) => {
      if (event.method === 'state.changed') applyState(event.params as State);
      else if (event.method === 'notification.open') {
        const data = event.params as { session: string; key: ChatKey };
        const state = current.current;
        if (state?.page !== 'chat' || state.session !== data.session
            || !state.conversations.some(item => sameKey(item.key, data.key))) return;
        const draft = drafts.current.get(state.session + keyId(state.currentChat)) || '';
        void window.chatroom.request('conversation.select', { session: state.session, key: data.key, draft })
          .then(() => setPanel(null))
          .catch(() => notify('打开会话', '此会话暂时无法打开，请从侧栏重新选择。'));
      }
      else if (event.method === 'notice') {
        const data = event.params as { title: string; text: string }; notify(data.title, data.text);
      } else if (event.method === 'prompt') {
        setPrompt(event.params as Prompt); setPromptChecked(false);
      } else if (event.method === 'prompt.closed') setPrompt(null);
      else if (event.method === 'draft.changed') {
        const data = event.params as { session: string; key: ChatKey | null; text: string; previous: string };
        const id = data.session + keyId(data.key);
        const active = current.current?.session === data.session && sameKey(current.current.currentChat, data.key);
        // A confirmation clears only the text that was actually sent, never a
        // newer edit that is still travelling through IPC.
        if (!active || (drafts.current.get(id) || '') === data.previous) {
          drafts.current.set(id, data.text);
          if (active) setDraft(data.text);
        }
      } else if (event.method === 'auth.registered') setRegistered(value => value + 1);
      else if (event.method === 'group.opened') {
        setGroupId((event.params as { gid: string }).gid); setPanel('group');
      } else if (event.method === 'conversation.latest') {
        setLatestSignal(value => value + 1);
      } else if (event.method === 'core.failed') setFailure((event.params as { message: string }).message);
    });
    void window.chatroom.request('initialize', { protocolVersion: PROTOCOL_VERSION }).then(result => {
      if (!current.current) applyState((result as InitResult).state);
    }).catch(error => setFailure(error.message));
    return () => { unsubscribe(); for (const timer of timers.current) clearTimeout(timer); };
  }, [applyState, notify]);
  useEffect(() => {
    document.documentElement.dataset.theme = state?.theme || 'light';
    document.title = state?.unread ? `(${state.unread}) Chatroom` : 'Chatroom';
  }, [state?.theme, state?.unread]);
  const call: Call = useCallback(async (method, params = {}) => {
    try { return await window.chatroom.request(method, { session: current.current?.session, ...params }); }
    catch (error) { notify('操作未完成', error instanceof Error ? error.message : String(error)); throw error; }
  }, [notify]);
  const act = useCallback((method: Method, params?: Record<string, unknown>) => { void call(method, params).catch(() => {}); }, [call]);
  const editDraft = useCallback((text: string) => {
    const state = current.current;
    if (!state) return;
    drafts.current.set(state.session + keyId(state.currentChat), text);
    setDraft(text);
    act('draft.set', { key: state.currentChat, text });
  }, [act]);

  if (failure) return <div className="startup"><AlertCircle size={28} /><h1>无法连接客户端核心</h1>
    <p>{failure}</p><p className="muted">关闭客户端后重新启动。你的服务器配置和加密密钥会保留。</p></div>;
  if (!state) return <div className="startup"><div className="brand-symbol">C</div><p>正在启动 Chatroom…</p></div>;
  const selected = state.conversations.find(item => sameKey(item.key, state.currentChat));
  const open = (next: Panel) => setPanel(next);
  return <>
    {state.page === 'login'
      ? <Login state={state} call={call} registered={registered} settings={() => open('settings')} recovery={() => open('recovery')} />
      : <Chat state={state} call={call} draft={draft} editDraft={editDraft} open={open}
        latestSignal={latestSignal} select={key => { act('conversation.select', { key, draft }); }}
        clear={() => act('conversation.clear', { draft })} />}
    {panel === 'settings' && <SettingsPanel state={state} call={call} close={() => open(null)} />}
    {panel === 'keys' && <KeysPanel state={state} call={call} close={() => open(null)} />}
    {panel === 'friend' && <AddFriend call={call} close={() => open(null)} />}
    {panel === 'createGroup' && <CreateGroup state={state} call={call} close={() => open(null)} />}
    {panel === 'group' && <GroupPanel state={state} gid={groupId} call={call} close={() => open(null)} />}
    {panel === 'pending' && <PendingPanel state={state} call={call} close={() => open(null)} />}
    {panel === 'recovery' && <RecoveryPanel call={call} close={() => open(null)} />}
    {panel === 'online' && <OnlineUsersPanel state={state} close={() => open(null)} />}
    {panel === 'requests' && <Modal title="申请与邀请" onClose={() => open(null)}>
      {!state.requests.length && <div className="empty-small"><Inbox size={30} /><p>暂时没有新的申请</p></div>}
      {state.requests.map(request => <section key={request.id} className="request-card"><h3>{request.title}</h3><p>{request.text}</p>
        <div className="actions"><AsyncButton action={() => call('request.reply', { id: request.id, accepted: false })}>拒绝</AsyncButton>
          <AsyncButton variant="primary" action={() => call('request.reply', { id: request.id, accepted: true })}>接受</AsyncButton></div></section>)}
    </Modal>}
    {prompt && <Modal title={prompt.title} onClose={() => act('prompt.reply', { id: prompt.id, accepted: false })} wide={!!prompt.recipients}>
      <p className="prewrap">{prompt.text}</p>
      {prompt.recipients && <div className="recipient-list">{prompt.recipients.map(person => <div key={person.username}>
        <strong>{person.username}</strong><span className="warning">{person.change}</span><code>{fingerprint(person.fingerprint)}</code></div>)}</div>}
      {!!prompt.removed?.length && <p className="warning">已移除：{prompt.removed.join('、')}</p>}
      <label className="check"><input type="checkbox" checked={promptChecked} onChange={event => setPromptChecked(event.target.checked)} />
        {prompt.recipients ? '我已核对以上所有接收人与指纹' : '我理解此操作并确认继续'}</label>
      <div className="actions"><Button onClick={() => act('prompt.reply', { id: prompt.id, accepted: false })}>取消</Button>
        <AsyncButton variant="primary" disabled={!promptChecked} action={() => call('prompt.reply', { id: prompt.id, accepted: true })}>确认</AsyncButton></div>
    </Modal>}
    <div className="toasts" aria-live="polite">{toasts.map(toast => <div className="toast" key={toast.id}>
      <div><strong>{toast.title}</strong><p>{toast.text}</p></div><IconButton label="关闭提示" onClick={() => setToasts(items => items.filter(item => item.id !== toast.id))}><X size={15} /></IconButton>
    </div>)}</div>
  </>;
}

function Login({ state, call, registered, settings, recovery }: { state: State; call: Call; registered: number; settings: () => void; recovery: () => void }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [registering, setRegistering] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const profile = state.profiles.find(item => item.name === state.selectedProfile)!;
  useEffect(() => { setRegistering(false); setPassword(''); }, [registered]);
  const busy = state.busy || submitting;
  const login = async () => {
    setSubmitting(true);
    try { await call('auth.login', { username, password, register: registering }); }
    finally { setSubmitting(false); }
  };
  return <div className="login-page">
    <header className="login-header"><div className="brand"><span className="brand-symbol">C</span>chatroom</div>
      <IconButton label="设置" onClick={settings}><Settings size={19} /></IconButton></header>
    <main className="login-stage"><div className="login-card">
      <div className="login-mark"><MessageSquare size={30} strokeWidth={1.4} /></div>
      <p className="eyebrow">YOUR SPACE TO CONNECT</p>
      <h1>{registering ? '从这里，开始对话' : '让对话，继续发生'}</h1>
      <p className="login-description">{registering ? '创建一个账号，与在意的人保持联系。' : '登录 Chatroom，回到你的好友与群聊。'}</p>
      <form onSubmit={event => { event.preventDefault(); void login().catch(() => {}); }}>
        <Field label="用户名" autoFocus autoComplete="username" value={username} disabled={busy} maxLength={256}
          placeholder="你的用户名" onChange={event => setUsername(event.target.value)} required />
        <Field label="密码" type="password" autoComplete={registering ? 'new-password' : 'current-password'} value={password}
          disabled={busy} maxLength={128} minLength={registering ? 8 : undefined} placeholder={registering ? '设置统一密码，至少 8 个字符' : '输入统一密码'}
          onChange={event => setPassword(event.target.value)} required />
        <div className="server-picker"><span className="status-dot" /><select aria-label="服务器" value={state.selectedProfile} disabled={busy}
          onChange={event => { void call('profile.select', { name: event.target.value }).catch(() => {}); }}>
          {state.profiles.map(profile => <option key={profile.name}>{profile.name}</option>)}</select>
          <span className="server-endpoint">{profile.host}:{profile.port}</span><ChevronDown size={13} /></div>
        <Button variant="primary" type="submit" disabled={busy || !username.trim() || !password} className="login-submit">
          {busy ? (state.authStatus || '正在连接…') : registering ? '创建账号' : '登录'}<ChevronRight size={17} /></Button>
        {busy && <Button type="button" onClick={() => { void call('auth.cancel').catch(() => {}); }}>取消连接</Button>}
      </form>
      <p className="auth-status" role="status">{state.authStatus}</p>
      <div className="login-links"><Button disabled={busy} onClick={() => setRegistering(value => !value)}>
        {registering ? '已有账号？返回登录' : '创建新账号'}</Button><Button disabled={busy} onClick={recovery}>恢复与迁移</Button></div>
      <div className="login-security"><LockKeyhole size={13} /><span>统一密码登录 · 端到端加密</span></div>
    </div></main>
    <footer className="login-footer"><span>一处安静的聊天空间</span><span>Chatroom Desktop</span></footer>
  </div>;
}

function Chat({ state, call, draft, editDraft, select, clear, open, latestSignal }: {
  state: State; call: Call; draft: string; editDraft: (text: string) => void; select: (key: ChatKey) => void;
  clear: () => void; open: (panel: Panel) => void; latestSignal: number;
}) {
  const [filter, setFilter] = useState('');
  const [tab, setTab] = useState<'all' | 'private' | 'group'>('all');
  const [collapsed, setCollapsed] = useState(false);
  const [searchOpen, setSearchOpen] = useState(false);
  const [query, setQuery] = useState('');
  const [more, setMore] = useState(false);
  const [atBottom, setAtBottom] = useState(true);
  const [sendBusy, setSendBusy] = useState(false);
  const [restorePosition, setRestorePosition] = useState<string | null>(null);
  const readingId = useRef<string | null>(null);
  const searchOrigin = useRef<string | null>(null);
  const input = useRef<HTMLTextAreaElement>(null);
  const selected = state.conversations.find(item => sameKey(item.key, state.currentChat));
  const act = (method: Method, params?: Record<string, unknown>) => { void call(method, params).catch(() => {}); };
  const timelineMessages = useMemo(() => state.newerEvicted ? state.messages : [...state.messages, ...(state.outgoing || [])],
    [state.messages, state.outgoing, state.newerEvicted]);
  useEffect(() => { setSearchOpen(false); setQuery(''); setMore(false); setAtBottom(true); readingId.current = null; }, [keyId(state.currentChat)]);
  useEffect(() => {
    const report = () => { void call('window.activity', { focused: document.hasFocus() && !document.hidden, atBottom }).catch(() => {}); };
    report();
    window.addEventListener('focus', report); window.addEventListener('blur', report); document.addEventListener('visibilitychange', report);
    return () => { window.removeEventListener('focus', report); window.removeEventListener('blur', report); document.removeEventListener('visibilitychange', report); };
  }, [call, atBottom, state.session]);
  const openSearch = useCallback(() => {
    if (!state.currentChat) return;
    if (!searchOpen) searchOrigin.current = readingId.current;
    setSearchOpen(true);
  }, [state.currentChat, searchOpen]);
  const closeSearch = () => { setSearchOpen(false); setQuery(''); setRestorePosition(searchOrigin.current); };
  useEffect(() => {
    const key = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key === 'f') { event.preventDefault(); openSearch(); }
    };
    window.addEventListener('keydown', key); return () => window.removeEventListener('keydown', key);
  }, [openSearch]);
  useEffect(() => {
    if (input.current) { input.current.style.height = 'auto'; input.current.style.height = Math.min(input.current.scrollHeight, 180) + 'px'; }
  }, [draft]);
  const send = async () => {
    if (!state.canSend || !draft.trim() || sendBusy) return;
    setSendBusy(true);
    try { await call('message.send', { key: state.currentChat, text: draft }); }
    finally { setSendBusy(false); input.current?.focus(); }
  };
  const conversations = state.conversations.filter(item => (tab === 'all' || item.key.kind === tab)
    && (item.title + ' ' + item.key.target).toLocaleLowerCase().includes(filter.toLocaleLowerCase()));
  return <div className={`workspace ${collapsed ? 'sidebar-collapsed' : ''} ${window.chatroom.platform === 'darwin' ? 'mac' : ''}`}>
    <aside className="sidebar">
      <div className="sidebar-header"><div className="brand"><span className="brand-symbol">C</span>chatroom</div>
        <IconButton label="收起侧栏" onClick={() => setCollapsed(true)}><PanelLeftClose size={18} /></IconButton></div>
      <button className="new-conversation" onClick={clear}><Plus size={18} /><span>新的对话</span></button>
      <div className="sidebar-search"><Search size={15} /><input aria-label="搜索会话" placeholder="搜索会话" value={filter} onChange={event => setFilter(event.target.value)} /></div>
      <div className="sidebar-tabs" role="tablist" aria-label="会话类型">{(['all', 'private', 'group'] as const).map((value, index) =>
        <button role="tab" aria-selected={value === tab} key={value} onClick={() => setTab(value)}>{['全部', '好友', '群聊'][index]}</button>)}</div>
      <div className="conversation-list">
        <div className="section-caption">你的对话<span>{conversations.length}</span></div>
        {!conversations.length && <div className="sidebar-empty">{filter ? '没有匹配的会话' : '对话会出现在这里'}</div>}
        {conversations.map(item => <button className={`conversation ${sameKey(state.currentChat, item.key) ? 'selected' : ''}`}
          key={keyId(item.key)} onClick={() => select(item.key)} aria-current={sameKey(state.currentChat, item.key) ? 'true' : undefined}>
          <span className="conversation-icon">{item.key.kind === 'group' ? <Hash size={18} /> : <MessageSquare size={17} />}</span>
          <span className="conversation-copy"><span className="conversation-title">{item.title}</span>
            <span className="conversation-preview">{item.preview || (item.key.kind === 'group' ? '群聊' : '开始聊天')}</span></span>
          {!!item.unread && <span className="badge">{item.unread > 99 ? '99+' : item.unread}</span>}
        </button>)}
      </div>
      <div className="sidebar-bottom">
        <button className="sidebar-action" onClick={() => open('online')}><Users size={17} />在线用户
          <span className="online-count">{state.connected ? state.onlineUsers.length : '—'}</span></button>
        <button className="sidebar-action" onClick={() => open('requests')}><Inbox size={17} />申请与邀请
          {!!state.requests.length && <span className="badge">{state.requests.length}</span>}</button>
        <button className="sidebar-action" onClick={() => open('keys')}><ShieldCheck size={17} />加密与密钥</button>
        <div className="account"><Avatar name={state.username || ''} small /><div><strong>{state.username}</strong>
          <span><i className={`status-dot ${state.reconnecting ? 'offline' : ''}`} />{state.reconnecting ? '正在重连' : state.connected ? '已连接' : '已断开'}</span></div>
          <IconButton label="设置" onClick={() => open('settings')}><Settings size={17} /></IconButton></div>
      </div>
    </aside>
    <main className="main-pane">
      <header className="chat-header"><div className="chat-heading">{collapsed && <IconButton label="展开侧栏" onClick={() => setCollapsed(false)}><Menu size={19} /></IconButton>}
        <h1>{selected?.title || '你的对话'}</h1>{selected && <span className="header-tag">{state.currentChat?.kind === 'group' ? '群聊' : '私聊'}</span>}</div>
        <div className="header-actions">{selected && <><IconButton label="搜索消息" onClick={openSearch}><Search size={18} /></IconButton>
          {state.currentChat?.kind === 'group' && <IconButton label="群聊详情" onClick={() => act('group.info', { gid: state.currentChat!.target })}><Users size={18} /></IconButton>}
          <div className="menu-anchor"><IconButton label="更多操作" onClick={() => setMore(value => !value)} aria-expanded={more}><MoreHorizontal size={20} /></IconButton>
            {more && <><button className="menu-backdrop" aria-label="关闭菜单" onClick={() => setMore(false)} /><div className="dropdown-menu">
              <Button disabled={!state.canLoadOlder} onClick={() => { act('history.older', { key: state.currentChat }); setMore(false); }}>加载更早消息</Button>
              <Button onClick={() => { act('history.latest', { key: state.currentChat }); setMore(false); }}>返回最新消息</Button>
              <Button onClick={() => { open('pending'); setMore(false); }}>待确认消息 ({state.pending.length})</Button>
              <Button onClick={() => { open('keys'); setMore(false); }}>加密与密钥</Button>
            </div></>}
          </div></>}
          <IconButton label={state.theme === 'light' ? '切换深色模式' : '切换浅色模式'} onClick={() => act('settings.theme', { theme: state.theme === 'light' ? 'dark' : 'light' })}>
            {state.theme === 'light' ? <Moon size={17} /> : <Sun size={17} />}</IconButton>
        </div>
      </header>
      {(state.reconnecting || state.syncing || state.syncFailed) && <div className={`connection-banner ${state.syncFailed ? 'warning' : ''}`} role="status">
        <span className="status-dot" />{state.status}{state.syncFailed && <Button onClick={() => act('sync.retry')}>重试补取</Button>}
        {state.reconnecting && <Button onClick={() => act('session.disconnect')}>取消重连</Button>}</div>}
      {selected ? <>
        <MessageTimeline key={state.session + keyId(state.currentChat)}
          messages={timelineMessages} query={query}
          sendActions={{ connected: state.connected, canSend: state.canSend, recover: id => call('send.recover', { id }) }}
          searchOpen={searchOpen} setQuery={setQuery} closeSearch={closeSearch} atBottom={atBottom} setAtBottom={setAtBottom}
          canLoadOlder={state.canLoadOlder} loading={state.loadingHistory} loadOlder={() => act('history.older', { key: state.currentChat })}
          latestSignal={latestSignal} restorePosition={restorePosition} onRead={id => { readingId.current = id; }}
          hasNewer={state.newerEvicted} loadLatest={() => act('history.latest', { key: state.currentChat })} />
        <div className="composer-area">
          {!!state.pending.length && <button className="pending-hint" onClick={() => open('pending')}><CircleHelp size={14} />
            {state.pending.length} 条消息等待确认 <ChevronRight size={14} /></button>}
          <div className="composer"><textarea ref={input} aria-label="消息输入" placeholder={`发送消息给 ${selected.title}…`}
            value={draft} maxLength={2 * 1024 * 1024} rows={2} onChange={event => editDraft(event.target.value)}
            onKeyDown={event => {
              if (event.key === 'Enter' && !event.shiftKey && !event.ctrlKey && !event.metaKey
                  && !event.nativeEvent.isComposing && event.nativeEvent.keyCode !== 229) {
                event.preventDefault(); void send().catch(() => {});
              }
            }} />
            <div className="composer-toolbar"><span><LockKeyhole size={13} />{state.encryption.ready ? '端到端加密' : state.encryption.status || '连接准备中'}</span>
              <IconButton label="发送消息" disabled={!state.canSend || !draft.trim() || sendBusy} onClick={() => { void send().catch(() => {}); }} className="send-button"><ArrowUp size={19} /></IconButton></div>
          </div>
          <div className="composer-footer"><span>Enter 发送 · Shift + Enter 换行</span><span>Chatroom</span></div>
        </div>
      </> : <div className="welcome"><span className="welcome-mark"><MessageSquare size={35} strokeWidth={1.3} /></span>
        <p className="eyebrow">STAY CLOSE, STAY CONNECTED</p><h2>今天，想和谁聊聊？</h2><p>选择左侧的对话，或从一条新的消息开始。</p>
        <div className="welcome-actions"><button onClick={() => open('friend')}><Plus size={20} /><strong>添加好友</strong><span>让熟悉的人来到这里</span></button>
          <button onClick={() => open('createGroup')}><Users size={20} /><strong>创建群聊</strong><span>给大家一个聊天的地方</span></button></div>
        <div className="welcome-note"><ShieldCheck size={14} />消息在你的设备上加密</div>
      </div>}
    </main>
  </div>;
}

function MessageTimeline({ messages, query, searchOpen, setQuery, closeSearch, atBottom, setAtBottom,
  canLoadOlder, loading, loadOlder, latestSignal, restorePosition, onRead, hasNewer, loadLatest, sendActions }: {
  sendActions: SendActions;
  messages: Message[]; query: string; searchOpen: boolean; setQuery: (value: string) => void; closeSearch: () => void;
  atBottom: boolean; setAtBottom: (value: boolean) => void; canLoadOlder: boolean; loading: boolean;
  loadOlder: () => void; latestSignal: number; restorePosition: string | null; onRead: (id: string) => void;
  hasNewer: boolean; loadLatest: () => void;
}) {
  const list = useRef<VirtuosoHandle>(null);
  const queryInput = useRef<HTMLInputElement>(null);
  const [hit, setHit] = useState(0);
  const [unseen, setUnseen] = useState(0);
  const range = useRef({ messages, first: 1_000_000 });
  const previous = range.current.messages;
  if (previous !== messages && previous.length && messages.length) {
    const prepend = messages.findIndex(message => message.id === previous[0].id);
    const trim = previous.findIndex(message => message.id === messages[0].id);
    if (prepend > 0) range.current.first -= prepend;
    else if (trim > 0) range.current.first += trim;
  }
  range.current.messages = messages;
  const first = range.current.first;
  const hits = query ? messages.flatMap((message, index) => message.protection !== 'failed' && message.protection !== 'local'
    && message.content.toLocaleLowerCase().includes(query.toLocaleLowerCase()) ? [index] : []) : [];
  const focused = hits[hit % Math.max(1, hits.length)];
  const jump = (index: number) => { list.current?.scrollToIndex({ index, align: 'start' }); };
  useEffect(() => { if (searchOpen) queryInput.current?.focus(); }, [searchOpen]);
  useEffect(() => { setHit(0); if (hits.length) jump(hits[0]); }, [query]);
  useEffect(() => { if (atBottom) setUnseen(0); }, [atBottom]);
  const last = useRef(messages.at(-1)?.id);
  useEffect(() => {
    const next = messages.at(-1)?.id;
    if (next !== last.current && last.current && !atBottom) setUnseen(value => value + 1);
    last.current = next;
  }, [messages, atBottom]);
  const bottom = () => {
    if (hasNewer) loadLatest();
    else if (messages.length) list.current?.scrollToIndex({ index: messages.length - 1, align: 'end' });
    setUnseen(0);
  };
  useEffect(() => { if (!hasNewer) bottom(); }, [latestSignal]);
  useEffect(() => {
    if (restorePosition) { const index = messages.findIndex(message => message.id === restorePosition); if (index >= 0) jump(index); }
  }, [restorePosition]);
  return <div className="timeline-wrap">
    {searchOpen && <div className="message-search"><Search size={17} /><input ref={queryInput} aria-label="搜索已加载消息" maxLength={256}
      placeholder="搜索本会话已加载消息" value={query} onChange={event => setQuery(event.target.value)}
      onKeyDown={event => { if (event.key === 'Escape') closeSearch(); if (event.key === 'Enter' && hits.length) {
        const next = (hit + (event.shiftKey ? -1 : 1) + hits.length) % hits.length; setHit(next); jump(hits[next]);
      } }} /><span>{query ? hits.length ? `${hit % hits.length + 1} / ${hits.length}` : '无结果' : '仅已加载消息'}</span>
      <IconButton label="上一个结果" disabled={!hits.length} onClick={() => { const next = (hit - 1 + hits.length) % hits.length; setHit(next); jump(hits[next]); }}><ChevronLeft size={17} /></IconButton>
      <IconButton label="下一个结果" disabled={!hits.length} onClick={() => { const next = (hit + 1) % hits.length; setHit(next); jump(hits[next]); }}><ChevronRight size={17} /></IconButton>
      <IconButton label="关闭搜索" onClick={closeSearch}><X size={17} /></IconButton></div>}
    <div className="timeline">
      {messages.length ? <Virtuoso ref={list} data={messages} firstItemIndex={first}
        initialTopMostItemIndex={messages.length - 1} computeItemKey={(_index, message) => message.id}
        followOutput={isAtBottom => isAtBottom ? 'auto' : false} atBottomThreshold={60}
        atBottomStateChange={setAtBottom} rangeChanged={range => { const message = messages[range.startIndex - first]; if (message) onRead(message.id); }}
        components={{ Header: () => <div className="history-control"><Button disabled={!canLoadOlder || loading} onClick={loadOlder}>
          {loading ? '正在加载历史…' : canLoadOlder ? '加载更早消息' : '已加载的消息'}</Button></div> }}
        itemContent={(index, message) => <MessageRow message={message} previous={messages[index - first - 1]}
          highlighted={searchOpen && focused === index - first} query={query} sendActions={sendActions} />} />
        : <div className="empty-conversation"><MessageSquare size={26} strokeWidth={1.3} /><p>还没有消息，打个招呼吧。</p>
          <Button disabled={!canLoadOlder || loading} onClick={loadOlder}>{loading ? '正在加载…' : '加载历史消息'}</Button></div>}
    </div>
    {(!atBottom || hasNewer) && <button className="jump-latest" onClick={bottom}><ArrowDown size={15} />{hasNewer ? '返回最新消息' : unseen ? `${unseen} 次消息更新` : '回到最新'}</button>}
  </div>;
}

function MessageRow({ message, previous, highlighted, query, sendActions }: {
  message: Message; previous?: Message; highlighted: boolean; query: string; sendActions: SendActions;
}) {
  const [details, setDetails] = useState(false);
  const [copied, setCopied] = useState(false);
  const date = new Date(message.timestamp);
  const dateLabel = !Number.isNaN(date.getTime()) ? date.toLocaleDateString([], { month: 'long', day: 'numeric' }) : '';
  const newDate = dateLabel && (!previous || new Date(previous.timestamp).toDateString() !== date.toDateString());
  const parts: (string | { match: string })[] = [];
  if (highlighted && query && message.protection !== 'failed') {
    let offset = 0;
    const lower = message.content.toLocaleLowerCase(), needle = query.toLocaleLowerCase();
    let start: number;
    while ((start = lower.indexOf(needle, offset)) !== -1 && parts.length < 2000) {
      parts.push(message.content.slice(offset, start), { match: message.content.slice(start, start + query.length) });
      offset = start + query.length;
    }
    parts.push(message.content.slice(offset));
  } else parts.push(message.content);
  return <>
    {newDate && <div className="date-divider"><span>{dateLabel}</span></div>}
    <article className={`message-row ${message.self ? 'own' : ''} ${highlighted ? 'highlighted' : ''} ${message.sendStatus === 'failed' ? 'send-failed' : ''}`} data-message-id={message.id}>
      <Avatar name={message.author} small />
      <div className="message-content"><div className="message-heading"><strong>{message.self ? '你' : message.author}</strong></div>
        <div className="message-body" dir="auto">{parts.map((part, index) => typeof part === 'string' ? part : <mark key={index}>{part.match}</mark>)}</div>
        <div className="message-footer"><button className="message-time" onClick={() => setDetails(value => !value)} aria-label="消息详情" aria-expanded={details}>{clock(message.timestamp)}</button>
          {message.self && <SendIndicator message={message} actions={sendActions} />}
          {(message.protection === 'legacy' || message.protection === 'failed') && <span className={`message-protection ${message.protection === 'failed' ? 'danger-text' : ''}`}>{message.protection === 'failed' ? '验证失败' : '旧消息'}</span>}</div>
        {message.sendStatus === 'failed' && <p className="message-send-error">{message.sendError || '发送失败，请检查输入后重新发送。'}</p>}
        {details && <div className="message-details">{clock(message.timestamp, true)}<br />{message.protection === 'local' ? '本机发送时间' : '原始时间'}：{message.timestamp || '未提供'}<br />
          {message.protection === 'local' ? message.serverId ? `服务器消息编号：${message.serverId}` : '服务器消息编号尚未确认' : `消息编号：${message.id}`}<br />
          {message.protection === 'local' ? '本机发送记录 · 收到并验证原消息后显示加密验证结果' : message.protection === 'e2ee' ? '端到端加密 · 已通过身份与完整性验证' : message.protection === 'failed' ? '此消息未通过安全验证' : '旧消息 · 非端到端加密'}
          {message.self && <><br />保存确认只表示服务器已保存，不表示对方已收到或已读。</>}</div>}
      </div>
      <div className="message-tools"><IconButton label="复制消息" onClick={() => { void window.chatroom.copy(message.content).then(() => {
        setCopied(true); setTimeout(() => setCopied(false), 1500);
      }); }}>{copied ? <Check size={15} /> : <Copy size={15} />}</IconButton>
        <IconButton label="展开消息信息" onClick={() => setDetails(value => !value)}><Info size={15} /></IconButton></div>
    </article>
  </>;
}

function SendIndicator({ message, actions }: { message: Message; actions: SendActions }) {
  const status = message.sendStatus || (message.protection !== 'local' && /^[1-9]\d*$/.test(message.id) ? 'saved' : undefined);
  if (!status) return null;
  const labels = { sending: '发送中', saved: '服务器已保存', uncertain: '保存结果待确认', checking: '正在核对', retry: '暂无保存回执', failed: '发送失败' };
  const recovering = status === 'uncertain' || status === 'retry';
  return <>
    <span className={`message-send-status ${status}`} aria-label={`发送状态：${labels[status]}`}
      aria-live={message.protection === 'local' ? 'polite' : undefined}
      title={status === 'saved' ? '服务器已保存，不代表对方已收到或已读。' : status === 'uncertain' ? '尚不能确定服务器是否保存，请先核对原结果。' : labels[status]}>
      {status === 'saved' ? <Check size={12} /> : status === 'sending' || status === 'checking' ? <LoaderCircle size={12} className="send-spinner" />
        : status === 'failed' ? <AlertCircle size={12} /> : <CircleHelp size={12} />}{labels[status]}
    </span>
    {recovering && message.sendId && message.canRecover && <AsyncButton className="message-recover"
      disabled={!actions.connected || status === 'retry' && !actions.canSend}
      action={() => actions.recover(message.sendId!)}>{status === 'retry' ? '重试发送' : '核对原结果'}</AsyncButton>}
    {recovering && !message.canRecover && <span className="message-send-help">请查看历史记录后决定是否重发</span>}
  </>;
}

function AddFriend({ call, close }: { call: Call; close: () => void }) {
  const [username, setUsername] = useState('');
  return <Modal title="添加好友" onClose={close}><p className="muted">输入对方的用户名，发送好友申请。</p>
    <Field label="用户名" value={username} autoFocus onChange={event => setUsername(event.target.value)} maxLength={256} />
    <div className="actions"><AsyncButton variant="primary" disabled={!username.trim()} action={async () => { await call('friend.add', { username }); close(); }}>发送申请</AsyncButton></div></Modal>;
}
function CreateGroup({ state, call, close }: { state: State; call: Call; close: () => void }) {
  const [name, setName] = useState('');
  const [members, setMembers] = useState<string[]>([]);
  return <Modal title="创建群聊" onClose={close}><Field label="群聊名称" value={name} autoFocus maxLength={128} onChange={event => setName(event.target.value)} />
    <p className="muted">选择好友，一起开始对话。</p><div className="member-picker">{state.conversations.filter(item => item.key.kind === 'private').map(item =>
      <label className="check" key={item.key.target}><input type="checkbox" checked={members.includes(item.key.target)} onChange={event => setMembers(values =>
        event.target.checked ? [...values, item.key.target] : values.filter(name => name !== item.key.target))} /><Avatar name={item.title} small />{item.title}</label>)}</div>
    {!state.conversations.some(item => item.key.kind === 'private') && <p className="muted">先添加好友，再邀请他们创建群聊。</p>}
    <div className="actions"><AsyncButton variant="primary" disabled={!name.trim() || !members.length} action={async () => {
      await call('group.create', { name, members }); close();
    }}>创建群聊</AsyncButton></div></Modal>;
}
