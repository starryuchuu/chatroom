"""OPAQUE account storage and bounded, connection-local authentication exchanges.

Only opaque-ke registration records and client-encrypted identity backups enter
this module. The new unified password and its export key never enter the server.
"""
from contextlib import closing
from dataclasses import dataclass, field
import base64
import json
import re
import time

import storage

MAX_FIELD = 128 * 1024
LEGACY_DISABLED = '!opaque-v1!'
AUTH_ERROR = '认证失败，请核对凭据后重试'
START_TYPES = frozenset(('opaque_register_start', 'opaque_login_start',
                         'opaque_migrate_start', 'opaque_change_start'))


def _call(message):
    import opaque_runtime
    return opaque_runtime.call(message)


def _binary(value, *, size=None):
    if not isinstance(value, str) or not 0 < len(value) <= MAX_FIELD:
        raise ValueError('invalid authentication field')
    raw = base64.b64decode(value, validate=True)
    if not raw or (size is not None and len(raw) != size):
        raise ValueError('invalid authentication field')
    return value


def _username(value):
    if not isinstance(value, str) or not 2 <= len(value) <= 20:
        raise ValueError('invalid account')
    value.encode('utf-8')
    return value


def validate_backup(backup, username, server_id):
    expected = {'v', 'kind', 'server_id', 'username', 'salt', 'nonce', 'data'}
    if (not isinstance(backup, dict) or set(backup) != expected
            or type(backup['v']) is not int or backup['v'] != 1
            or backup['kind'] != 'opaque-identity'
            or backup['username'] != username or backup['server_id'] != server_id
            or not re.fullmatch(r'[0-9a-f]{64}', server_id)):
        raise ValueError('invalid encrypted backup')
    _binary(backup['salt'], size=16)
    _binary(backup['nonce'], size=12)
    if len(base64.b64decode(_binary(backup['data']), validate=True)) < 16:
        raise ValueError('invalid encrypted backup')
    encoded = json.dumps(backup, sort_keys=True, separators=(',', ':'),
                         ensure_ascii=True, allow_nan=False)
    if len(encoded.encode('utf-8')) > MAX_FIELD:
        raise ValueError('encrypted backup too large')
    return encoded


def initialize():
    """Create the shared schema and retain the original server setup forever."""
    with closing(storage.connect()) as db:
        db.execute('BEGIN IMMEDIATE')
        try:
            db.execute('CREATE TABLE IF NOT EXISTS opaque_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS opaque_accounts(username TEXT PRIMARY KEY,record TEXT NOT NULL,backup TEXT NOT NULL,generation INTEGER NOT NULL)')
            row = db.execute("SELECT value FROM opaque_meta WHERE key='setup_v1'").fetchone()
            if row is None:
                if db.execute('SELECT 1 FROM opaque_accounts LIMIT 1').fetchone():
                    raise ValueError('OPAQUE server setup is missing; restore the original database')
                setup = _binary(_call({'op': 'server_setup'})['setup'])
                db.execute('INSERT INTO opaque_meta(key,value) VALUES(?,?)',
                           ('setup_v1', storage.seal(setup, 'opaque_meta', 'setup_v1')))
            else:
                _binary(storage.open_field(row[0], 'opaque_meta', 'setup_v1'))
            db.commit()
        except Exception:
            db.rollback()
            raise


def get_setup():
    with closing(storage.connect()) as db:
        row = db.execute("SELECT value FROM opaque_meta WHERE key='setup_v1'").fetchone()
    if row is None:
        raise ValueError('OPAQUE server setup is unavailable')
    return _binary(storage.open_field(row[0], 'opaque_meta', 'setup_v1'))


def get_account(username):
    token = storage.token(username)
    with closing(storage.connect()) as db:
        row = db.execute('SELECT record,backup,generation FROM opaque_accounts WHERE username=?',
                         (token,)).fetchone()
    if row is None:
        return None
    record = _binary(storage.open_field(row[0], 'opaque_accounts', 'record', token))
    backup = json.loads(storage.open_field(row[1], 'opaque_accounts', 'backup', token))
    if type(row[2]) is not int or row[2] < 1:
        raise ValueError('invalid OPAQUE generation')
    return {'record': record, 'backup': backup, 'generation': row[2]}


def has_account(username):
    with closing(storage.connect()) as db:
        return db.execute('SELECT 1 FROM opaque_accounts WHERE username=?',
                          (storage.token(username),)).fetchone() is not None


def legacy_snapshot(username):
    with closing(storage.connect()) as db:
        token = storage.token(username)
        row = db.execute('SELECT password FROM users WHERE username=? AND NOT EXISTS '
                         '(SELECT 1 FROM opaque_accounts WHERE username=?)', (token, token)).fetchone()
    return row[0] if row is not None else None


def store_account(username, record, backup, server_id, *, legacy=None, generation=None, deadline=None):
    """Commit the credential and backup as one pair; CAS guards both updates."""
    _username(username)
    _binary(record)
    _call({'op': 'record_validate', 'record': record})
    encoded_backup = validate_backup(backup, username, server_id)
    if deadline is not None and time.monotonic() >= deadline:
        raise TimeoutError('authentication expired')
    if generation is not None and (type(generation) is not int or not 1 <= generation < 2**63 - 1):
        raise ValueError('invalid account generation')
    with closing(storage.connect()) as db:
        db.execute('BEGIN IMMEDIATE')
        try:
            token = storage.put_name(db, username)
            sealed_record = storage.seal(record, 'opaque_accounts', 'record', token)
            sealed_backup = storage.seal(encoded_backup, 'opaque_accounts', 'backup', token)
            if generation is not None:
                changed = db.execute('UPDATE opaque_accounts SET record=?,backup=?,generation=generation+1 '
                                     'WHERE username=? AND generation=?',
                                     (sealed_record, sealed_backup, token, generation)).rowcount
                if changed != 1:
                    raise ValueError('account changed concurrently')
            else:
                disabled = storage.seal(LEGACY_DISABLED, 'users', 'password', token)
                if legacy is None:
                    db.execute('INSERT INTO users(username,password) VALUES(?,?)', (token, disabled))
                else:
                    changed = db.execute('UPDATE users SET password=? WHERE username=? AND password=? '
                                         'AND NOT EXISTS(SELECT 1 FROM opaque_accounts WHERE username=?)',
                                         (disabled, token, legacy, token)).rowcount
                    if changed != 1:
                        raise ValueError('account changed concurrently')
                db.execute('INSERT INTO opaque_accounts(username,record,backup,generation) VALUES(?,?,?,1)',
                           (token, sealed_record, sealed_backup))
            if deadline is not None and time.monotonic() >= deadline:
                raise TimeoutError('authentication expired')
            db.commit()
        except Exception:
            db.rollback()
            raise
    return {'backup': backup, 'generation': generation + 1 if generation is not None else 1}


@dataclass(frozen=True)
class AuthResult:
    username: str | None = None
    fields: dict = field(default_factory=dict)
    failed: bool = False


def authenticate(first, *, receive, send, server_id, decrypt_legacy, verify_legacy,
                 get_identity, deadline):
    """One exchange owns this connection and its deadline until it terminates."""
    kind = first.get('type') if isinstance(first, dict) else None
    failure_type = ('register_result' if kind == 'opaque_register_start' else
                    'opaque_change_result' if kind == 'opaque_change_start' else 'login_result')

    def check_deadline():
        if time.monotonic() >= deadline:
            raise TimeoutError('authentication expired')

    def crypto(op, **fields):
        check_deadline()
        result = _call({'op': op, **fields})
        check_deadline()
        return result

    def read(expected):
        check_deadline()
        packet = receive()
        check_deadline()
        if not isinstance(packet, dict) or packet.get('type') != expected:
            raise ValueError('unexpected authentication step')
        return packet

    try:
        if kind not in START_TYPES:
            raise ValueError('unsupported authentication exchange')
        username = _username(first.get('from'))
        request = _binary(first.get('request'))
        setup = get_setup()
        if kind == 'opaque_register_start':
            if legacy_snapshot(username) is not None or has_account(username):
                raise ValueError('account already exists')
            result = crypto('registration_respond', setup=setup, username=username,
                            server_id=server_id, request=request)
            send({'type': 'opaque_register_challenge', 'response': result['response']})
            final = read('opaque_register_finish')
            check_deadline()
            store_account(username, _binary(final.get('record')), final.get('backup'), server_id,
                          deadline=deadline)
            send({'type': 'register_result', 'success': True})
            return AuthResult()

        if kind == 'opaque_migrate_start':
            legacy = legacy_snapshot(username)
            encrypted = first.get('legacy_data')
            if legacy is None or not isinstance(encrypted, str) or not 0 < len(encrypted) <= MAX_FIELD:
                raise ValueError('legacy authentication rejected')
            value = json.loads(decrypt_legacy(encrypted))
            password = value.get('password') if isinstance(value, dict) else None
            if not isinstance(password, str) or not 6 <= len(password) <= 64 or not verify_legacy(username, password):
                raise ValueError('legacy authentication rejected')
            result = crypto('registration_respond', setup=setup, username=username,
                            server_id=server_id, request=request)
            send({'type': 'opaque_migrate_challenge', 'response': result['response'],
                  'e2ee_identity': get_identity(username)})
            final = read('opaque_migrate_finish')
            check_deadline()
            account = store_account(username, _binary(final.get('record')), final.get('backup'),
                                    server_id, legacy=legacy, deadline=deadline)
            return AuthResult(username, {'opaque_backup': account['backup'],
                                         'opaque_generation': account['generation']})

        account = get_account(username)
        if account is None and legacy_snapshot(username) is not None:
            send({'type': failure_type, 'success': False, 'migration_required': True,
                  'error': '旧账号需要迁移：请使用旧账号迁移入口设置新的统一密码'})
            return AuthResult(failed=True)
        result = crypto('login_respond', setup=setup, username=username, server_id=server_id,
                        record=account['record'] if account else None, request=request)
        changing = kind == 'opaque_change_start'
        send({'type': 'opaque_change_challenge' if changing else 'opaque_login_challenge',
              'response': result['response']})
        final = read('opaque_change_finish' if changing else 'opaque_login_finish')
        crypto('login_verify', state=result['state'], finalization=_binary(final.get('finalization')))
        if account is None:
            raise ValueError('authentication rejected')
        # A concurrent credential change invalidates an in-flight login as well.
        current = get_account(username)
        if current is None or current['generation'] != account['generation']:
            raise ValueError('account changed concurrently')
        if not changing:
            return AuthResult(username, {'opaque_backup': account['backup'],
                                         'opaque_generation': account['generation']})
        send({'type': 'opaque_change_verified', 'backup': account['backup'],
              'generation': account['generation'], 'e2ee_identity': get_identity(username)})
        request = _binary(read('opaque_change_register_start').get('request'))
        result = crypto('registration_respond', setup=setup, username=username,
                        server_id=server_id, request=request)
        send({'type': 'opaque_change_register_challenge', 'response': result['response']})
        final = read('opaque_change_register_finish')
        if type(final.get('generation')) is not int or final['generation'] != account['generation']:
            raise ValueError('account changed concurrently')
        check_deadline()
        store_account(username, _binary(final.get('record')), final.get('backup'), server_id,
                      generation=account['generation'], deadline=deadline)
        send({'type': 'opaque_change_result', 'success': True})
        return AuthResult()
    except Exception:
        # Never log authentication inputs, helper messages or exception strings.
        send({'type': failure_type, 'success': False, 'error': AUTH_ERROR})
        return AuthResult(failed=True)
