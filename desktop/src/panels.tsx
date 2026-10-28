import { useState } from 'react';
import { Check, ChevronLeft, Copy, Download, LogOut, Moon, Plus, Search, ShieldCheck, Sun, Upload, UserRound, X } from 'lucide-react';
import type { Call } from './App';
import type { Method, Profile, State } from './protocol';
import { AsyncButton, Avatar, Button, Field, IconButton, Modal, clock, fingerprint } from './ui';

export function OnlineUsersPanel({ state, close }: { state: State; close: () => void }) {
  const [query, setQuery] = useState('');
  const users = state.onlineUsers.filter(username => username.toLocaleLowerCase().includes(query.trim().toLocaleLowerCase()));
  return <Modal title="在线用户" onClose={close}>
    <p className="muted" role="status">{state.connected
      ? `当前服务器共有 ${state.onlineUsers.length} 人在线（含自己）`
      : '连接已断开，以下为断线前的列表，重新连接后更新。'}</p>
    <div className="sidebar-search online-search"><Search size={15} /><input aria-label="搜索在线用户" placeholder="搜索用户名"
      value={query} onChange={event => setQuery(event.target.value)} autoFocus maxLength={256} /></div>
    <ul className="online-users" aria-label="在线用户列表">{users.map(username => <li key={username}>
      <Avatar name={username} small /><span className="online-username">{username}</span>
      {username === state.username && <span className="header-tag">你</span>}
      <span className="online-presence">{state.connected && <i className="status-dot" />}{state.connected ? '在线' : '待更新'}</span>
    </li>)}</ul>
    {!users.length && <div className="empty-small"><UserRound size={26} /><p>{query.trim() ? '没有匹配的用户' : '暂时没有在线用户'}</p></div>}
  </Modal>;
}

export function SettingsPanel({ state, call, close }: { state: State; call: Call; close: () => void }) {
  const [tab, setTab] = useState('general');
  const [editing, setEditing] = useState<string | null>(state.selectedProfile);
  const selected = state.profiles.find(item => item.name === state.selectedProfile)!;
  const [profile, setProfile] = useState<Profile>(selected);
  const [deleting, setDeleting] = useState(false);
  const locked = state.connected || state.busy || state.reconnecting;
  const edit = (profile: Profile) => { setProfile(profile); setEditing(profile.name); setDeleting(false); };
  return <Modal title="设置" onClose={close} wide><div className="settings-layout">
    <nav className="settings-nav" aria-label="设置分类">{[['general', '通用'], ['servers', '服务器'], ['account', '账号']].map(([key, title]) =>
      <button key={key} onClick={() => setTab(key)} aria-current={tab === key ? 'page' : undefined}>{title}</button>)}</nav>
    <div className="settings-content">{tab === 'general' && <>
      <h3>外观</h3><p className="muted">选择适合你的聊天空间。</p>
      <div className="theme-options">{(['light', 'dark'] as const).map(theme => <button key={theme} aria-pressed={state.theme === theme}
        onClick={() => { void call('settings.theme', { theme }).catch(() => {}); }}>
        <span className={`theme-preview ${theme}`}><i /><i /><i /></span><span>{theme === 'light' ? <Sun size={15} /> : <Moon size={15} />}
          {theme === 'light' ? '浅色' : '深色'}{state.theme === theme && <Check size={15} />}</span></button>)}</div>
      <h3>通知</h3><label className="setting-check"><span><strong>桌面通知</strong><small>收到新消息时提醒你，可选择通知显示的详细程度。</small></span>
        <input type="checkbox" checked={state.notifications.enabled} onChange={event => {
          void call('settings.notifications', { enabled: event.target.checked, doNotDisturb: state.notifications.do_not_disturb }).catch(() => {});
        }} /></label>
      <label className="field"><span>通知内容</span><select aria-label="通知内容" value={state.notifications.preview}
        onChange={event => { void call('settings.notifications', { enabled: state.notifications.enabled,
          doNotDisturb: state.notifications.do_not_disturb, preview: event.target.value }).catch(() => {}); }}>
        <option value="generic">仅提示有新消息</option><option value="sender">发送者与会话名称</option>
        <option value="message">发送者、会话与消息预览</option></select></label>
      <p className="caption">消息预览最多显示 140 个字符；系统可能将通知保留在通知中心或显示在锁屏。</p>
      <label className="setting-check"><span><strong>勿扰模式</strong><small>保留未读标记，暂停桌面提醒。</small></span>
        <input type="checkbox" checked={state.notifications.do_not_disturb} onChange={event => {
          void call('settings.notifications', { enabled: state.notifications.enabled, doNotDisturb: event.target.checked }).catch(() => {});
        }} /></label>
    </>}
    {tab === 'servers' && <><h3>服务器配置</h3><p className="muted">{locked ? '断开连接后可切换和编辑服务器配置。' : '配置保存在本机，不包含密码或消息正文。'}</p>
      <div className="profile-list">{state.profiles.map(item => <button key={item.name} disabled={locked} className={editing === item.name ? 'active' : ''}
        onClick={() => edit(item)}><span>{item.name}</span><small>{item.host}:{item.port}</small>{state.selectedProfile === item.name && <Check size={14} />}</button>)}
        <Button disabled={locked} onClick={() => { setEditing(null); setProfile({ name: '', host: '127.0.0.1', port: 12345, fingerprint: null }); }}><Plus size={15} />新建配置</Button></div>
      <fieldset disabled={locked} className="profile-form"><Field label="配置名称" maxLength={64} value={profile.name} onChange={event => setProfile({ ...profile, name: event.target.value })} />
        <div className="field-pair"><Field label="服务器地址" value={profile.host} maxLength={253} onChange={event => setProfile({ ...profile, host: event.target.value })} />
          <Field label="端口" type="number" min={1} max={65535} value={profile.port} onChange={event => setProfile({ ...profile, port: Number(event.target.value) })} /></div>
        <Field label="服务器公钥指纹 · SHA-256" value={profile.fingerprint || ''} placeholder="远程服务器必须填写经过核实的指纹"
          onChange={event => setProfile({ ...profile, fingerprint: event.target.value || null })} />
        <p className="caption">通过可信渠道向服务器管理员核对指纹。</p>
        <div className="actions">{editing && <Button variant="danger" disabled={state.profiles.length <= 1} onClick={() => setDeleting(true)}>删除配置</Button>}
          <AsyncButton variant="primary" action={() => call('profile.save', { ...profile, replaceName: editing }).then(() => { setEditing(profile.name.trim()); })}>保存并选用</AsyncButton></div>
        {deleting && <div className="confirm-box"><p>确定删除「{editing}」配置？</p><div className="actions"><Button onClick={() => setDeleting(false)}>取消</Button>
          <AsyncButton variant="danger" action={async () => { await call('profile.delete', { name: editing }); setDeleting(false); }}>确认删除</AsyncButton></div></div>}
      </fieldset></>}
    {tab === 'account' && <><h3>当前账号</h3><div className="account-summary"><Avatar name={state.username || 'C'} /><div><strong>{state.username || '尚未登录'}</strong><p>{state.status || selected.name}</p></div></div>
      <p className="muted">账号密码与消息正文不会写入客户端设置。退出后将清除当前会话缓存，未发送草稿仅在本次进程中保留。</p>
      {(state.connected || state.reconnecting) && <AsyncButton variant="danger" action={async () => { await call('session.disconnect'); close(); }}><LogOut size={16} />退出登录</AsyncButton>}
      <div className="about"><strong>Chatroom Desktop</strong><p>一个安静、私密的聊天空间。</p><span className="caption">GPL-3.0 · starryuchuu/chatroom</span></div></>}
    </div></div></Modal>;
}

type KeyTask = 'export' | 'password' | 'verify' | 'change' | null;
export function KeysPanel({ state, call, close }: { state: State; call: Call; close: () => void }) {
  const [task, setTask] = useState<KeyTask>(null);
  const [person, setPerson] = useState<{ username: string; fingerprint: string } | null>(null);
  const [password, setPassword] = useState('');
  const [next, setNext] = useState('');
  const [again, setAgain] = useState('');
  const [checked, setChecked] = useState(false);
  const back = () => { setTask(null); setPassword(''); setNext(''); setAgain(''); setChecked(false); };
  return <Modal title="加密与密钥" onClose={close} wide>
    {task ? <><Button onClick={back}><ChevronLeft size={16} />返回</Button>
      {(task === 'verify' || task === 'change') && person && <><h3>{task === 'verify' ? '核对联系人身份' : '确认联系人新密钥'}</h3>
        <p>{person.username}</p><code className="fingerprint">{fingerprint(person.fingerprint)}</code>
        <p className="muted">请通过其他可信渠道，与联系人本人逐项核对以上指纹。</p>
        {task === 'change' && <p className="warning">确认将替换固定的联系人密钥。旧密钥仅能验证本机此前已经记录的原始消息。</p>}
        <label className="check"><input type="checkbox" checked={checked} onChange={event => setChecked(event.target.checked)} />我已与联系人核对以上指纹</label>
        <div className="actions"><AsyncButton variant="primary" disabled={!checked} action={async () => {
          await call(task === 'verify' ? 'keys.verify' : 'keys.acceptChange', person); back();
        }}>确认{task === 'verify' ? '核对' : '新密钥'}</AsyncButton></div></>}
      {task === 'export' && <><h3>导出离线密钥备份</h3><p className="muted">备份使用当前统一密码加密。改密后请重新导出，并妥善保管备份。</p>
        <Field label="当前统一密码" type="password" value={password} onChange={event => setPassword(event.target.value)} autoComplete="current-password" />
        <div className="actions"><AsyncButton variant="primary" disabled={!password} action={async () => { if (await call('keys.export', { password })) back(); }}><Download size={16} />选择保存位置</AsyncButton></div></>}
      {task === 'password' && <><h3>修改统一密码</h3><Field label="当前密码" type="password" value={password} onChange={event => setPassword(event.target.value)} autoComplete="current-password" />
        <Field label="新密码 · 8–128 个字符" type="password" value={next} maxLength={128} onChange={event => setNext(event.target.value)} autoComplete="new-password" />
        <Field label="再次输入新密码" type="password" value={again} maxLength={128} onChange={event => setAgain(event.target.value)} autoComplete="new-password" />
        {again && next !== again && <p className="warning">两次密码输入不一致</p>}
        <div className="actions"><AsyncButton variant="primary" disabled={!password || next.length < 8 || next !== again} action={async () => {
          await call('password.change', { currentPassword: password, newPassword: next }); back();
        }}>更新密码</AsyncButton></div></>}
    </> : <><div className="encryption-status"><ShieldCheck size={22} /><div><strong>{state.encryption.ready ? '端到端加密已就绪' : '加密身份尚未就绪'}</strong>
      <p>{state.encryption.status}</p></div></div><h3>我的身份指纹</h3>
      <div className="fingerprint-row"><code className="fingerprint">{fingerprint(state.encryption.fingerprint) || '登录后显示你的身份指纹'}</code>
        <IconButton label="复制我的指纹" disabled={!state.encryption.fingerprint} onClick={() => { void window.chatroom.copy(state.encryption.fingerprint); }}><Copy size={16} /></IconButton></div>
      <p className="caption">请与联系人通过其他可信渠道核对。密码与全部恢复材料都丢失后，无法恢复历史消息。</p>
      <div className="inline-actions"><Button disabled={!state.encryption.fingerprint} onClick={() => setTask('export')}><Download size={16} />导出密钥备份</Button>
        <Button disabled={!state.connected || !state.encryption.ready} onClick={() => setTask('password')}>修改统一密码</Button></div>
      <h3>联系人身份</h3>{!state.encryption.peers.length && <p className="muted">与联系人交换消息后，身份指纹会出现在这里。</p>}
      <div className="peer-list">{state.encryption.peers.map(peer => <section className="peer" key={peer.username}><div className="peer-header"><Avatar name={peer.username} small /><strong>{peer.username}</strong>
        <span className={peer.verified ? 'success' : 'muted'}>{peer.verified ? '已核对' : '首次信任 · 未核对'}</span></div><code>{fingerprint(peer.fingerprint)}</code>
        <div className="actions"><Button onClick={() => { setPerson({ username: peer.username, fingerprint: peer.fingerprint }); setTask('verify'); }}>核对身份</Button>
          {peer.changeFingerprint && <Button variant="danger" onClick={() => {
            setPerson({ username: peer.username, fingerprint: peer.changeFingerprint! }); setTask('change');
          }}>核验新密钥</Button>}</div></section>)}</div>
      {state.currentChat?.kind === 'group' && <AsyncButton disabled={!state.connected} action={() => call('keys.reviewGroup', { key: state.currentChat })}>核对当前群聊接收人</AsyncButton>}
    </>}
  </Modal>;
}

export function GroupPanel({ state, gid, call, close }: { state: State; gid: string; call: Call; close: () => void }) {
  const group = state.groups[gid];
  const [invite, setInvite] = useState('');
  const [rename, setRename] = useState(group?.group_name || '');
  const [selected, setSelected] = useState('');
  const [confirm, setConfirm] = useState<{ method: Method; label: string; params: Record<string, unknown> } | null>(null);
  if (!group) return <Modal title="群聊详情" onClose={close}><p>此群聊已不存在，或你已离开。</p></Modal>;
  const owner = group.owner === state.username;
  return <Modal title="群聊详情" onClose={close} wide><div className="group-summary"><Avatar name={group.group_name} group /><div><h3>{group.group_name}</h3>
    <p className="muted">{group.members?.length || 0} 位成员 · 群主 {group.owner}</p><small>群 ID：{gid}</small></div></div>
    <div className="member-picker">{(group.members || []).map(name => <label className="check" key={name}><input type="radio" name="selected-member"
      checked={selected === name} onChange={() => setSelected(name)} /><Avatar name={name} small />{name}{name === group.owner && <span className="header-tag">群主</span>}</label>)}</div>
    <div className="inline-form"><Field label="邀请好友" placeholder="输入好友用户名" value={invite} onChange={event => setInvite(event.target.value)} />
      <AsyncButton disabled={!invite.trim() || !state.connected} action={async () => { await call('group.invite', { gid, username: invite }); setInvite(''); }}>发送邀请</AsyncButton></div>
    {owner && <><div className="inline-form"><Field label="群聊名称" value={rename} onChange={event => setRename(event.target.value)} maxLength={128} />
      <AsyncButton disabled={!rename.trim() || !state.connected} action={() => call('group.rename', { gid, name: rename })}>保存名称</AsyncButton></div>
      <div className="inline-actions"><Button disabled={!selected || selected === state.username || !state.connected} onClick={() => setConfirm({
        method: 'group.kick', label: `将 ${selected} 移出群聊`, params: { gid, username: selected },
      })}>移出选中成员</Button><Button disabled={!selected || selected === state.username || !state.connected} onClick={() => setConfirm({
        method: 'group.transfer', label: `将群主转让给 ${selected}`, params: { gid, username: selected },
      })}>转让群主</Button></div></>}
    <div className="actions"><AsyncButton disabled={!state.connected} action={() => call('group.info', { gid })}>刷新成员</AsyncButton>
      <Button variant="danger" disabled={!state.connected} onClick={() => setConfirm({ method: 'group.leave', label: '退出此群聊', params: { gid } })}>退出群聊</Button>
      {owner && <Button variant="danger" disabled={!state.connected} onClick={() => setConfirm({ method: 'group.disband', label: '解散此群聊，此操作不可撤销', params: { gid } })}>解散群聊</Button>}</div>
    {confirm && <div className="confirm-box"><p>确定{confirm.label}？</p><div className="actions"><Button onClick={() => setConfirm(null)}>取消</Button>
      <AsyncButton variant="danger" action={async () => { await call(confirm.method, confirm.params); setConfirm(null); }}>确认操作</AsyncButton></div></div>}
  </Modal>;
}

const statusLabels: Record<string, string> = { sending: '等待保存确认', uncertain: '保存结果未知', checking: '正在核对', retry: '服务器暂无回执，可重试' };
export function PendingPanel({ state, call, close }: { state: State; call: Call; close: () => void }) {
  const [removing, setRemoving] = useState<string | null>(null);
  return <Modal title="待确认消息" onClose={close} wide><p className="muted">记录仅保留在内存中。重连会核对原发送结果；不会自动重发正文。</p>
    {!state.pending.length && <div className="empty-small"><Check size={28} /><p>没有待确认消息</p></div>}
    {state.pending.map(record => <section className="pending-card" key={record.id}><div className="pending-title"><strong>{record.key.kind === 'group' ? state.groups[record.key.target]?.group_name || record.key.target : record.key.target}</strong>
      <span className="warning">{statusLabels[record.status] || record.status}</span></div><p className="prewrap pending-body">{record.text}</p>
      <span className="caption">{clock(record.createdAt, true)}</span><div className="actions"><Button variant="danger" disabled={record.status === 'sending' || record.status === 'checking'} onClick={() => setRemoving(record.id)}>移除记录</Button>
        <AsyncButton variant="primary" disabled={!state.connected || !record.receipts || record.status === 'sending' || record.status === 'checking'} action={() => call('send.recover', { id: record.id })}>
          {record.status === 'retry' ? '重试发送' : '核对原结果'}</AsyncButton></div>
      {removing === record.id && <div className="confirm-box"><p>移除不会撤回消息，也不能证明服务器是否保存。确定移除此记录？</p>
        <div className="actions"><Button onClick={() => setRemoving(null)}>取消</Button><AsyncButton variant="danger" action={async () => { await call('send.dismiss', { id: record.id }); setRemoving(null); }}>确认移除</AsyncButton></div></div>}
    </section>)}
  </Modal>;
}

export function RecoveryPanel({ call, close }: { call: Call; close: () => void }) {
  const [mode, setMode] = useState('import');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [old, setOld] = useState('');
  const [local, setLocal] = useState('');
  const [again, setAgain] = useState('');
  return <Modal title="恢复与迁移" onClose={close}><div className="segmented">{[['import', '恢复备份'], ['migrate', '迁移旧账号'], ['unlock', '解锁旧密钥']].map(([key, title]) =>
    <button key={key} aria-pressed={mode === key} onClick={() => { setMode(key); setPassword(''); setOld(''); setLocal(''); setAgain(''); }}>{title}</button>)}</div>
    <p className="muted">操作使用登录页当前选择的服务器。请先核实服务器配置与账号。</p>
    <Field label="原账号用户名" value={username} onChange={event => setUsername(event.target.value)} autoComplete="username" />
    {mode === 'import' && <><Field label="导出备份时的密码 / 口令" type="password" value={password} onChange={event => setPassword(event.target.value)} />
      <div className="actions"><AsyncButton variant="primary" disabled={!username.trim() || !password} action={async () => { if (await call('keys.import', { username, password })) close(); }}><Upload size={16} />选择备份文件</AsyncButton></div></>}
    {mode === 'migrate' && <><Field label="旧账号登录密码" type="password" value={old} onChange={event => setOld(event.target.value)} />
      <Field label="原本机密钥口令 · 未启用过加密可留空" type="password" value={local} onChange={event => setLocal(event.target.value)} />
      <Field label="新统一密码 · 8–128 个字符" type="password" value={password} maxLength={128} onChange={event => setPassword(event.target.value)} autoComplete="new-password" />
      <Field label="再次输入新密码" type="password" value={again} onChange={event => setAgain(event.target.value)} autoComplete="new-password" />
      <div className="actions"><AsyncButton variant="primary" disabled={!username.trim() || !old || password.length < 8 || password === old || password !== again} action={async () => {
        await call('auth.migrate', { username, password, oldPassword: old, legacyPassphrase: local }); close();
      }}>迁移账号</AsyncButton></div></>}
    {mode === 'unlock' && <><Field label="原本机密钥口令" type="password" value={local} onChange={event => setLocal(event.target.value)} />
      <div className="actions"><AsyncButton variant="primary" disabled={!username.trim() || local.length < 8} action={async () => {
        await call('auth.unlockLegacy', { username, passphrase: local }); close();
      }}>准备解锁</AsyncButton></div><p className="caption">准备完成后，使用当前统一密码登录。原文件只在验证成功后升级。</p></>}
  </Modal>;
}
