"""Shared Python/Go storage v1: randomized AES-256-GCM fields and keyed name indexes."""
import base64
import hashlib
import hmac
import os
from pathlib import Path
import sqlite3

from Crypto.Cipher import AES

_store = None
CHECK_TEXT = 'chatroom storage v1'


def context(*parts):
    return b'chatroom-storage-v1\0' + b''.join(
        str(len(str(p).encode('utf-8'))).encode() + b':' + str(p).encode('utf-8') for p in parts)


def connect(path='chat.db'):
    db = sqlite3.connect(path)
    try:
        if Path(path).is_file():
            os.chmod(path, 0o600)
        db.execute('PRAGMA secure_delete=ON')
        db.execute('PRAGMA temp_store=MEMORY')
        return db
    except Exception:
        db.close()
        raise


class Storage:
    def __init__(self, key):
        self.key = hmac.digest(key, b'chatroom/storage/v1/encryption', 'sha256')
        self.lookup_key = hmac.digest(key, b'chatroom/storage/v1/lookup', 'sha256')

    def seal(self, value, *parts):
        nonce = os.urandom(12)
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        cipher.update(context(*parts))
        body, tag = cipher.encrypt_and_digest(value.encode('utf-8'))
        return 'enc1:' + base64.b64encode(nonce + body + tag).decode('ascii')

    def open(self, value, *parts):
        if not isinstance(value, str) or not value.startswith('enc1:'):
            raise ValueError('Unencrypted or invalid storage field')
        data = base64.b64decode(value[5:], validate=True)
        if len(data) < 28:
            raise ValueError('Truncated storage field')
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=data[:12])
        cipher.update(context(*parts))
        return cipher.decrypt_and_verify(data[12:-16], data[-16:]).decode('utf-8')

    def token(self, username):
        return 'u1:' + hmac.new(self.lookup_key, username.encode('utf-8'), hashlib.sha256).hexdigest()

    def put_name(self, db, username):
        token = self.token(username)
        db.execute('INSERT OR IGNORE INTO storage_names(token,value) VALUES(?,?)',
                   (token, self.seal(username, 'names', token)))
        return token

    def name(self, db, token):
        row = db.execute('SELECT value FROM storage_names WHERE token=?', (token,)).fetchone()
        if row is None:
            raise ValueError('Unknown storage identity')
        name = self.open(row[0], 'names', token)
        if not hmac.compare_digest(self.token(name), token):
            raise ValueError('Invalid storage identity')
        return name


def _read_key(path, encrypted):
    path = Path(path)
    try:
        data = path.read_bytes()
    except FileNotFoundError:
        if encrypted:
            raise RuntimeError('Storage key is missing; restore the original key before starting')
        data = os.urandom(32)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, 'wb') as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            if os.name != "nt":
                directory = os.open(path.parent, os.O_RDONLY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
        except Exception:
            path.unlink(missing_ok=True)
            raise
    if len(data) != 32:
        raise RuntimeError('Storage key must contain exactly 32 bytes')
    os.chmod(path, 0o600)
    return data


def initialize(db, db_path='chat.db'):
    global _store
    db.execute('CREATE TABLE IF NOT EXISTS storage_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL)')
    db.execute('CREATE TABLE IF NOT EXISTS storage_names(token TEXT PRIMARY KEY,value TEXT NOT NULL)')
    db.commit()
    meta = dict(db.execute('SELECT key,value FROM storage_meta'))
    if meta.get('version') not in (None, '1'):
        raise RuntimeError('Unsupported storage version')
    encrypted = meta.get('version') == '1'
    if not encrypted and (meta or db.execute('SELECT 1 FROM storage_names LIMIT 1').fetchone()):
        raise RuntimeError('Invalid storage metadata; startup stopped')
    key_path = os.environ.get('CHATROOM_STORAGE_KEY_FILE') or str(db_path) + '.key'
    store = Storage(_read_key(key_path, encrypted))
    if encrypted:
        try:
            if store.open(meta['key_check'], 'meta', 'key_check') != CHECK_TEXT:
                raise ValueError('Invalid key check')
        except (KeyError, ValueError, UnicodeError) as e:
            raise RuntimeError('Storage key mismatch or corrupt database; startup stopped') from e
    else:
        if db.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchone()[0]:
            raise RuntimeError('Database is busy; storage cleanup stopped')
        if db.execute('PRAGMA journal_mode=DELETE').fetchone()[0].lower() != 'delete':
            raise RuntimeError('Cannot leave WAL mode for storage migration')
        db.execute('BEGIN IMMEDIATE')
        try:
            _migrate(db, store)
            for k, v in [('version', '1'), ('key_check', store.seal(CHECK_TEXT, 'meta', 'key_check')),
                         ('cleanup_pending', '1')]:
                db.execute('INSERT INTO storage_meta VALUES(?,?)', (k, v))
            db.commit()
            meta['cleanup_pending'] = '1'
        except Exception:
            db.rollback()
            raise
    # Recover a crash between the migration commit and removal of old free pages.
    if meta.get('cleanup_pending') == '1':
        if db.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchone()[0]:
            raise RuntimeError('Database is busy; storage cleanup stopped')
        if db.execute('PRAGMA journal_mode=DELETE').fetchone()[0].lower() != 'delete':
            raise RuntimeError('Cannot finish storage cleanup')
        db.execute('VACUUM')
        db.execute("UPDATE storage_meta SET value='0' WHERE key='cleanup_pending'")
        db.commit()
    _store = store


def _migrate(db, store):
    specs = [
        ('users', ['username', 'password'], ['username'], ['password']),
        ('friends', ['user', 'friend'], ['user', 'friend'], []),
        ('groups', ['gid', 'group_name', 'owner', 'members', 'created_at'], [], ['group_name', 'owner', 'members', 'created_at']),
        ('messages', ['id', 'chat_type', 'from_user', 'to_user', 'gid', 'message', 'timestamp'], ['from_user', 'to_user'], ['message', 'timestamp']),
        ('pending_friend_requests', ['requester', 'target'], ['requester', 'target'], []),
        ('pending_group_invites', ['gid', 'target', 'inviter'], ['target', 'inviter'], []),
    ]
    for table, columns, names, secrets in specs:
        after = 0
        while True:
            rows = db.execute('SELECT rowid,' + ','.join(columns) + ' FROM ' + table +
                              ' WHERE rowid>? ORDER BY rowid LIMIT 256', (after,)).fetchall()
            if not rows:
                break
            for row in rows:
                after, values = row[0], dict(zip(columns, row[1:]))
                for col in names:
                    if values[col] is not None and values[col] != '':
                        values[col] = store.put_name(db, values[col])
                for col in secrets:
                    if table == 'messages' and col == 'message':
                        parts = message_context(values['id'], values['chat_type'], values['from_user'], values['to_user'], values['gid'])
                    else:
                        key = values['username'] if table == 'users' else values['gid'] if table == 'groups' else values['id']
                        parts = (table, col, key)
                    values[col] = store.seal(values[col], *parts)
                changed = names + secrets
                db.execute('UPDATE ' + table + ' SET ' + ','.join(c + '=?' for c in changed) + ' WHERE rowid=?',
                           [values[c] for c in changed] + [after])


def message_context(message_id, kind, sender, recipient, gid):
    return ('messages', 'message', message_id, kind, sender or '', recipient or '', gid or '')


def token(username):
    return _store.token(username)


def put_name(db, username):
    return _store.put_name(db, username)


def name(db, value):
    return _store.name(db, value) if value else value


def seal(value, *parts):
    return _store.seal(value, *parts)


def open_field(value, *parts):
    return _store.open(value, *parts)


def save_message(db, kind, sender, recipient, gid, message, timestamp):
    sender = put_name(db, sender)
    recipient = put_name(db, recipient) if recipient else recipient
    cursor = db.execute('INSERT INTO messages(chat_type,from_user,to_user,gid,message,timestamp) VALUES(?,?,?,?,?,?)',
                        (kind, sender, recipient, gid, '', ''))
    message_id = cursor.lastrowid
    db.execute('UPDATE messages SET message=?,timestamp=? WHERE id=?',
               (seal(message, *message_context(message_id, kind, sender, recipient, gid)),
                seal(timestamp, 'messages', 'timestamp', message_id), message_id))
    return message_id


def decode_message(db, row):
    mid, kind, sender, recipient, gid, body, timestamp = row
    body = open_field(body, *message_context(mid, kind, sender, recipient, gid))
    return (mid, kind, name(db, sender), name(db, recipient), gid, body,
            open_field(timestamp, 'messages', 'timestamp', mid))


def decode_group(row):
    gid, group_name, owner, members, *rest = row
    result = [gid] + [open_field(v, 'groups', col, gid) for col, v in
                      [('group_name', group_name), ('owner', owner), ('members', members)]]
    if rest:
        result.append(open_field(rest[0], 'groups', 'created_at', gid))
    return result
