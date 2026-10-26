"""Durable, account-scoped send receipts committed with their chat message."""
import json
import re

import storage
from chatroom_client.e2ee_crypto import canonical_json


SCHEMA = '''CREATE TABLE IF NOT EXISTS send_receipts (
    sender TEXT NOT NULL, receipt_key TEXT NOT NULL, chat_type TEXT NOT NULL,
    target TEXT NOT NULL, payload_hash TEXT NOT NULL, message_id INTEGER NOT NULL,
    PRIMARY KEY(sender, receipt_key))'''


def valid_key(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{32}', value) is not None


def receipt_token(key):
    return storage.token('chatroom/send/v1/request\0' + key)


def save(db, kind, sender, recipient, gid, body, timestamp, *, e2ee, key):
    if not valid_key(key):
        raise ValueError('消息标识格式错误')
    target = gid if kind == 'group' else recipient
    content = json.loads(body) if e2ee else body
    fingerprint = storage.token('chatroom/send/v1/payload\0' + canonical_json(
        [kind, recipient or '', gid or '', bool(e2ee), content]).decode('ascii'))
    who, token = storage.token(sender), receipt_token(key)
    # Serialize the lookup and insert, including across SQLite connections.
    db.execute('BEGIN IMMEDIATE')
    old = db.execute('SELECT payload_hash,message_id FROM send_receipts WHERE sender=? AND receipt_key=?',
                     (who, token)).fetchone()
    if old is not None:
        if old[0] != fingerprint:
            raise ValueError('消息标识已用于其他内容，请核对发送结果')
        at = db.execute('SELECT timestamp FROM messages WHERE id=?', (old[1],)).fetchone()
        if at is None:
            raise ValueError('消息回执对应的记录缺失，请核对数据库')
        return old[1], True, storage.open_field(at[0], 'messages', 'timestamp', old[1])
    mid = storage.save_message(db, kind, sender, recipient, gid, body, timestamp, e2ee=e2ee)
    db.execute('INSERT INTO send_receipts VALUES(?,?,?,?,?,?)',
               (who, token, kind, storage.token(target), fingerprint, mid))
    return mid, False, timestamp


def lookup(db, sender, key, kind, target):
    row = db.execute('''SELECT r.message_id,m.timestamp FROM send_receipts r
        JOIN messages m ON m.id=r.message_id WHERE r.sender=? AND r.receipt_key=?
        AND r.chat_type=? AND r.target=?''',
                     (storage.token(sender), receipt_token(key), kind, storage.token(target))).fetchone()
    if row is None:
        return None
    return row[0], storage.open_field(row[1], 'messages', 'timestamp', row[0])
