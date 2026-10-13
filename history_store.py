"""Bounded, backwards keyset pagination of authorized chat history."""
from contextlib import closing
import json
import sqlite3

PAGE_SIZE = 100


def page(username, boundary, *, before=None, kind=None, target=None):
    with closing(sqlite3.connect('chat.db')) as db:
        rows = db.execute('SELECT gid,members FROM groups').fetchall()
        gids = [gid for gid,members in rows if username in json.loads(members)]
        if kind == 'group':
            gids = [gid for gid in gids if gid == target]
            private = '0'
            args = []
        else:
            private = "(chat_type='private' AND (from_user=? OR to_user=?) AND EXISTS (SELECT 1 FROM friends WHERE user=? AND friend=CASE WHEN from_user=? THEN to_user ELSE from_user END))"
            args = [username,username,username,username]
            if kind == 'private':
                private += ' AND (from_user=? OR to_user=?)'
                args += [target,target]
                gids = []
        group = '0'
        if gids:
            group = "(chat_type='group' AND gid IN (" + ','.join('?' for _ in gids) + '))'
            args += gids
        condition = 'id<=?'
        prefix = [boundary]
        if before is not None:
            condition += ' AND id<?'
            prefix.append(before)
        query = 'SELECT id,chat_type,from_user,to_user,gid,message,timestamp FROM messages WHERE ' + condition + ' AND ((' + private + ') OR ' + group + ') ORDER BY id DESC LIMIT ?'
        records = db.execute(query, prefix+args+[PAGE_SIZE+1]).fetchall()
    return list(reversed(records[:PAGE_SIZE])), len(records)>PAGE_SIZE
