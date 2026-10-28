"""Private desktop preferences, without credentials or message contents."""
from copy import deepcopy
from contextlib import contextmanager
from dataclasses import asdict, dataclass
import errno
import ipaddress
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import time


_LOCK_TIMEOUT = 1.0


@contextmanager
def _preferences_lock(path):
    """Lock a stable sibling inode while the JSON file is atomically replaced."""
    descriptor = os.open(path.with_name(path.name + '.lock'), os.O_CREAT | os.O_RDWR, 0o600)
    locked = False
    try:
        if os.name == 'nt':
            import msvcrt

            # Windows byte-range locking requires a byte to lock. Never remove
            # this file: another process may already be waiting on its inode.
            def acquire():
                if os.fstat(descriptor).st_size == 0:
                    os.lseek(descriptor, 0, os.SEEK_SET)
                    os.write(descriptor, b'\0')
                os.lseek(descriptor, 0, os.SEEK_SET)
                msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)

            def release():
                os.lseek(descriptor, 0, os.SEEK_SET)
                msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            def acquire():
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)

            def release():
                fcntl.flock(descriptor, fcntl.LOCK_UN)

        deadline = time.monotonic() + _LOCK_TIMEOUT
        while True:
            try:
                acquire()
                locked = True
                break
            except OSError as error:
                if error.errno not in (errno.EACCES, errno.EAGAIN, errno.EWOULDBLOCK):
                    raise
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise PreferencesError('客户端设置正由其他进程保存，请稍后重试') from error
                time.sleep(min(0.02, remaining))
        yield
    finally:
        try:
            if locked:
                release()
        finally:
            os.close(descriptor)


class PreferencesError(ValueError):
    """A preference could not be validated, read, or safely written."""


def _bounded_integer(value):
    return type(value) is int and 0 <= value <= 9223372036854775807


@dataclass(frozen=True)
class ServerProfile:
    name: str
    host: str
    port: int
    fingerprint: str | None = None

    def __post_init__(self):
        if not isinstance(self.name, str) or not 1 <= len(self.name.strip()) <= 64:
            raise PreferencesError('配置名称须为 1–64 个字符')
        if any(ord(character) < 32 for character in self.name):
            raise PreferencesError('配置名称不能包含控制字符')
        if not isinstance(self.host, str):
            raise PreferencesError('请输入服务器地址')
        host = self.host.strip()
        if host.startswith('[') and host.endswith(']'):
            host = host[1:-1]
        if not host or len(host) > 253 or any(character.isspace() for character in host):
            raise PreferencesError('请输入有效的 IP 地址或域名')
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            try:
                encoded = host.encode('idna').decode('ascii')
            except UnicodeError as error:
                raise PreferencesError('请输入有效的 IP 地址或域名') from error
            labels = encoded.rstrip('.').split('.')
            if any(not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', label) for label in labels):
                raise PreferencesError('服务器地址应为 IP 或域名，不包含协议、路径或端口')
            host = encoded.lower().rstrip('.')
            loopback = host == 'localhost'
        else:
            host = str(address)
            # Match protocol.check_server_public_key's trust boundary. Other
            # loopback aliases remain usable with an explicitly pinned key.
            loopback = host in ('127.0.0.1', '::1')
        if type(self.port) is not int or not 1 <= self.port <= 65535:
            raise PreferencesError('端口必须是 1–65535 之间的整数')
        fingerprint = self.fingerprint
        if fingerprint is not None:
            if not isinstance(fingerprint, str):
                raise PreferencesError('公钥指纹必须是 SHA-256 十六进制字符串')
            fingerprint = re.sub(r'[:\s]', '', fingerprint).lower()
            fingerprint = fingerprint or None
        if fingerprint is not None and re.fullmatch(r'[0-9a-f]{64}', fingerprint) is None:
            raise PreferencesError('公钥指纹须为 64 位 SHA-256 十六进制字符')
        if not loopback and fingerprint is None:
            raise PreferencesError('连接非本机服务器必须填写经过核实的 SHA-256 公钥指纹')
        object.__setattr__(self, 'name', self.name.strip())
        object.__setattr__(self, 'host', host)
        object.__setattr__(self, 'fingerprint', fingerprint)


def default_config_path():
    override = os.environ.get('CHATROOM_CONFIG_DIR')
    if override:
        return Path(override).expanduser() / 'client.json'
    if sys.platform == 'win32':
        root = Path(os.environ.get('APPDATA') or Path.home() / 'AppData' / 'Roaming')
        return root / 'Chatroom' / 'client.json'
    if sys.platform == 'darwin':
        return Path.home() / 'Library' / 'Application Support' / 'Chatroom' / 'client.json'
    root = Path(os.environ.get('XDG_CONFIG_HOME') or Path.home() / '.config')
    return root / 'chatroom' / 'client.json'


def _validate_account(value):
    if not isinstance(value, dict) or value.keys() - {'activity', 'sync_cursor'}:
        raise PreferencesError('账号元数据只能保存已读位置、未读消息编号和同步位置')
    if 'sync_cursor' in value and not _bounded_integer(value['sync_cursor']):
        raise PreferencesError('同步位置格式错误')
    if 'activity' not in value:
        return
    activity = value['activity']
    if not isinstance(activity, dict) or activity.keys() - {'conversations', 'initialized'}:
        raise PreferencesError('消息状态格式错误')
    if 'initialized' in activity and type(activity['initialized']) is not bool:
        raise PreferencesError('消息状态格式错误')
    conversations = activity.get('conversations', [])
    if not isinstance(conversations, list) or len(conversations) > 10000:
        raise PreferencesError('会话状态格式错误')
    identities = set()
    for conversation in conversations:
        if not isinstance(conversation, dict) or conversation.keys() - {'kind', 'target', 'read_id', 'unread_ids'}:
            raise PreferencesError('会话状态格式错误')
        kind, target = conversation.get('kind'), conversation.get('target')
        if kind not in ('private', 'group') or not isinstance(target, str) or not 1 <= len(target) <= 256:
            raise PreferencesError('会话标识格式错误')
        if (kind, target) in identities:
            raise PreferencesError('会话状态重复')
        identities.add((kind, target))
        if not _bounded_integer(conversation.get('read_id', 0)):
            raise PreferencesError('已读位置格式错误')
        unread = conversation.get('unread_ids', [])
        if not isinstance(unread, list) or len(unread) > 100000 or any(not _bounded_integer(item) or item == 0 for item in unread):
            raise PreferencesError('未读消息编号格式错误')


class PreferencesStore:
    """Copy-on-write JSON preferences. Failed writes do not change live state.

    Persistent mutations reload the latest file under a cross-process lock.
    ``persistent=False`` never reads or creates a user configuration directory.
    Activity writes preserve a broken source file until an explicit settings save.
    """

    def __init__(self, path=None, *, default_profile=None, persistent=True):
        self.persistent = persistent
        self.path = Path(path) if path is not None else (default_config_path() if persistent else None)
        first = default_profile or ServerProfile('Python 本机', '127.0.0.1', 12345)
        if not isinstance(first, ServerProfile):
            raise PreferencesError('默认服务器配置格式错误')
        profiles = [asdict(first)]
        go = ServerProfile('Go 本机', '127.0.0.1', 12346)
        if (first.host, first.port, first.fingerprint) != (go.host, go.port, go.fingerprint):
            if first.name == go.name:
                go = ServerProfile('Go 本机（12346）', go.host, go.port)
            profiles.append(asdict(go))
        self._data = {'version': 1, 'theme': 'light', 'profiles': profiles, 'selected_profile': first.name,
                      'notifications': {'enabled': True, 'do_not_disturb': False, 'preview': 'sender'}, 'accounts': {}}
        self.warning = None
        self._blocked = False
        if persistent:
            self._load()

    def _load(self):
        try:
            candidate = self._read()
        except FileNotFoundError:
            return
        except (OSError, ValueError, TypeError, KeyError, RecursionError) as error:
            self.warning = f'无法读取已保存的客户端设置，已使用默认值。原文件已保留；点击保存设置可重新建立配置。原因：{error}'
            self._blocked = True
            return
        self._data = candidate

    def _read(self):
        with self.path.open('rb') as source:
            raw = source.read(8 * 1024 * 1024 + 1)
        if len(raw) > 8 * 1024 * 1024:
            raise PreferencesError('配置文件超过大小限制')
        candidate = json.loads(raw.decode('utf-8'))
        self._validate(candidate)
        return candidate

    @staticmethod
    def _validate(data):
        if not isinstance(data, dict) or type(data.get('version')) is not int or data['version'] != 1:
            raise PreferencesError('不支持的客户端配置格式')
        if data.keys() - {'version', 'theme', 'profiles', 'selected_profile', 'notifications', 'accounts'}:
            raise PreferencesError('配置文件包含不支持的字段')
        theme = data.get('theme', 'light')
        if not isinstance(theme, str) or theme not in ('light', 'dark'):
            raise PreferencesError('主题须为 light 或 dark')
        data['theme'] = theme
        profiles = data.get('profiles')
        if not isinstance(profiles, list) or not 1 <= len(profiles) <= 100:
            raise PreferencesError('服务器配置列表格式错误')
        validated = [ServerProfile(**item) for item in profiles]
        names = {profile.name for profile in validated}
        if len(names) != len(validated) or data.get('selected_profile') not in names:
            raise PreferencesError('服务器配置名称重复或当前配置不存在')
        data['profiles'] = [asdict(profile) for profile in validated]
        notifications = data.get('notifications', {})
        if not isinstance(notifications, dict) or notifications.keys() - {'enabled', 'do_not_disturb', 'preview'}:
            raise PreferencesError('提醒设置格式错误')
        if any(type(notifications[key]) is not bool for key in ('enabled', 'do_not_disturb') if key in notifications):
            raise PreferencesError('提醒设置格式错误')
        preview = notifications.get('preview', 'sender')
        if not isinstance(preview, str) or preview not in ('generic', 'sender', 'message'):
            raise PreferencesError('通知内容须为 generic、sender 或 message')
        data['notifications'] = {'enabled': notifications.get('enabled', True),
                                 'do_not_disturb': notifications.get('do_not_disturb', False), 'preview': preview}
        accounts = data.get('accounts', {})
        if not isinstance(accounts, dict) or len(accounts) > 10000:
            raise PreferencesError('账号状态格式错误')
        for key, value in accounts.items():
            try:
                endpoint = json.loads(key)
            except (ValueError, TypeError) as error:
                raise PreferencesError('账号标识格式错误') from error
            if (not isinstance(endpoint, list) or len(endpoint) != 3 or
                    not isinstance(endpoint[0], str) or not endpoint[0] or
                    type(endpoint[1]) is not int or not 1 <= endpoint[1] <= 65535 or
                    not isinstance(endpoint[2], str) or not endpoint[2]):
                raise PreferencesError('账号标识格式错误')
            _validate_account(value)
        data['accounts'] = accounts

    def _mutate(self, mutation, *, explicit):
        """Apply one operation to fresh data while holding the process lock."""
        if not self.persistent:
            candidate = deepcopy(self._data)
            result = mutation(candidate)
            self._commit(candidate, explicit=explicit)
            return result
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            with _preferences_lock(self.path):
                try:
                    candidate = self._read()
                except FileNotFoundError:
                    if self._blocked and not explicit:
                        raise PreferencesError('原配置文件未能读取；请先在服务器设置中明确保存设置，再保存消息状态')
                    candidate = deepcopy(self._data)
                except (OSError, ValueError, TypeError, KeyError, RecursionError) as error:
                    if not explicit:
                        raise PreferencesError('原配置文件未能读取；请先在服务器设置中明确保存设置，再保存消息状态') from error
                    candidate = deepcopy(self._data)
                result = mutation(candidate)
                self._commit(candidate, explicit=explicit)
                # Another instance may have explicitly repaired a broken file.
                self._blocked = False
                self.warning = None
                return result
        except PreferencesError:
            raise
        except (OSError, ValueError) as error:
            raise PreferencesError(f'保存客户端设置失败：{error}') from error

    def _commit(self, candidate, *, explicit):
        self._validate(candidate)
        payload = (json.dumps(candidate, ensure_ascii=False, indent=2) + '\n').encode('utf-8')
        if len(payload) > 8 * 1024 * 1024:
            raise PreferencesError('客户端设置超过大小限制，未修改已保存的配置')
        if self.persistent:
            temporary = None
            try:
                descriptor, temporary = tempfile.mkstemp(prefix='.client-', suffix='.tmp', dir=self.path.parent)
                with os.fdopen(descriptor, 'wb') as target:
                    target.write(payload)
                    target.flush()
                    os.fsync(target.fileno())
                os.replace(temporary, self.path)
                temporary = None
            except (OSError, ValueError) as error:
                raise PreferencesError(f'保存客户端设置失败：{error}') from error
            finally:
                if temporary is not None:
                    try:
                        os.unlink(temporary)
                    except OSError:
                        pass
        self._data = candidate
        if explicit:
            self._blocked = False
            self.warning = None

    @property
    def profiles(self):
        return [ServerProfile(**item) for item in self._data['profiles']]

    def get_profile(self, name):
        for profile in self.profiles:
            if profile.name == name:
                return profile
        raise PreferencesError('服务器配置不存在')

    @property
    def selected_profile(self):
        return self.get_profile(self._data['selected_profile'])

    def save_profile(self, profile, *, replace_name=None, select=True):
        if not isinstance(profile, ServerProfile):
            raise PreferencesError('服务器配置格式错误')

        def mutation(candidate):
            existing = [item['name'] for item in candidate['profiles']]
            if replace_name is not None and replace_name not in existing:
                raise PreferencesError('要修改的服务器配置不存在')
            if profile.name in existing and profile.name != replace_name:
                raise PreferencesError('服务器配置名称已存在')
            if replace_name is None:
                candidate['profiles'].append(asdict(profile))
            else:
                index = existing.index(replace_name)
                candidate['profiles'][index] = asdict(profile)
            if select or candidate['selected_profile'] == replace_name:
                candidate['selected_profile'] = profile.name
            return profile

        return self._mutate(mutation, explicit=True)

    def select_profile(self, name):
        def mutation(candidate):
            for item in candidate['profiles']:
                if item['name'] == name:
                    candidate['selected_profile'] = name
                    return ServerProfile(**item)
            raise PreferencesError('服务器配置不存在')

        return self._mutate(mutation, explicit=True)

    def delete_profile(self, name):
        def mutation(candidate):
            if not any(profile['name'] == name for profile in candidate['profiles']):
                raise PreferencesError('服务器配置不存在')
            if len(candidate['profiles']) == 1:
                raise PreferencesError('至少保留一个服务器配置')
            candidate['profiles'] = [profile for profile in candidate['profiles'] if profile['name'] != name]
            if candidate['selected_profile'] == name:
                candidate['selected_profile'] = candidate['profiles'][0]['name']

        self._mutate(mutation, explicit=True)
        return self.selected_profile

    @property
    def theme(self):
        return self._data['theme']

    def set_theme(self, mode):
        if not isinstance(mode, str) or mode not in ('light', 'dark'):
            raise PreferencesError('主题须为 light 或 dark')

        def mutation(candidate):
            candidate['theme'] = mode
            return mode

        return self._mutate(mutation, explicit=True)

    @property
    def notifications(self):
        return dict(self._data['notifications'])

    @property
    def notifications_enabled(self):
        return self._data['notifications']['enabled']

    @property
    def do_not_disturb(self):
        return self._data['notifications']['do_not_disturb']

    def set_notifications(self, *, enabled=None, do_not_disturb=None, preview=None):
        for key, value in (('enabled', enabled), ('do_not_disturb', do_not_disturb)):
            if value is not None and type(value) is not bool:
                raise PreferencesError('提醒设置格式错误')
        if preview is not None and (not isinstance(preview, str) or preview not in ('generic', 'sender', 'message')):
            raise PreferencesError('通知内容须为 generic、sender 或 message')

        def mutation(candidate):
            for key, value in (('enabled', enabled), ('do_not_disturb', do_not_disturb)):
                if value is not None:
                    candidate['notifications'][key] = value
            if preview is not None:
                candidate['notifications']['preview'] = preview

        self._mutate(mutation, explicit=True)
        return self.notifications

    @staticmethod
    def _account_key(endpoint, username):
        if (not isinstance(endpoint, (tuple, list)) or len(endpoint) != 2 or
                not isinstance(endpoint[0], str) or not endpoint[0] or
                type(endpoint[1]) is not int or not 1 <= endpoint[1] <= 65535 or
                not isinstance(username, str) or not username):
            raise PreferencesError('账号标识格式错误')
        return json.dumps([endpoint[0].lower(), endpoint[1], username], ensure_ascii=False, separators=(',', ':'))

    def account(self, endpoint, username):
        return deepcopy(self._data['accounts'].get(self._account_key(endpoint, username), {}))

    def update_account(self, endpoint, username, changes, *, explicit=False):
        _validate_account(changes)
        key = self._account_key(endpoint, username)

        def mutation(candidate):
            value = candidate['accounts'].setdefault(key, {})
            value.update(deepcopy(changes))
            return deepcopy(value)

        return self._mutate(mutation, explicit=explicit)

    def account_metadata(self, host, port, username):
        return self.account((host, port), username)

    def update_account_metadata(self, host, port, username, changes, *, explicit=False):
        return self.update_account((host, port), username, changes, explicit=explicit)
