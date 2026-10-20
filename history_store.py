"""Bounded keyset pages of currently authorized chat history."""
from contextlib import closing
import json
import storage

PAGE_SIZE = 100


def _authorization(db, username, kind=None, target=None):
    rows = db.execute('SELECT gid,members FROM groups').fetchall()
    gids = [gid for gid, members in rows
            if username in json.loads(storage.open_field(members, "groups", "members", gid))]
    if kind == 'group':
        gids = [gid for gid in gids if gid == target]
        private, args = '0', []
    else:
        private = "(chat_type='private' AND (from_user=? OR to_user=?) AND EXISTS (SELECT 1 FROM friends WHERE user=? AND friend=CASE WHEN from_user=? THEN to_user ELSE from_user END))"
        args = [storage.token(username)] * 4
        if kind == 'private':
            private += ' AND (from_user=? OR to_user=?)'
            args += [storage.token(target)] * 2
            gids = []
    group = '0'
    if gids:
        group = "(chat_type='group' AND gid IN (" + ','.join('?' for _ in gids) + '))'
        args += gids
    return '((' + private + ') OR ' + group + ')', args


def page(username, boundary, *, before=None, kind=None, target=None):
    with closing(storage.connect()) as db:
        authorized, args = _authorization(db, username, kind, target)
        condition = 'id<=?'
        prefix = [boundary]
        if before is not None:
            condition += ' AND id<?'
            prefix.append(before)
        query = 'SELECT id,chat_type,from_user,to_user,gid,message,timestamp,e2ee FROM messages WHERE ' + condition + ' AND ' + authorized + ' ORDER BY id DESC LIMIT ?'
        records = db.execute(query, prefix+args+[PAGE_SIZE+1]).fetchall()
        decoded = [storage.decode_message(db, r) for r in reversed(records[:PAGE_SIZE])]
    return decoded, len(records)>PAGE_SIZE


def sync_page(username, after, boundary):
    """Walk forward to a fixed boundary without a login snapshot's 100-row cap."""
    with closing(storage.connect()) as db:
        authorized, args = _authorization(db, username)
        query = ('SELECT id,chat_type,from_user,to_user,gid,message,timestamp,e2ee '
                 'FROM messages WHERE id>? AND id<=? AND ' + authorized +
                 ' ORDER BY id ASC LIMIT ?')
        records = db.execute(query, [after, boundary] + args + [PAGE_SIZE + 1]).fetchall()
        decoded = [storage.decode_message(db, row) for row in records[:PAGE_SIZE]]
    return decoded, len(records) > PAGE_SIZE
