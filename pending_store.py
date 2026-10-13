"""Durable pending requests shared by the Python and Go implementations."""
from contextlib import closing
import sqlite3
import time

TTL = 24 * 3600
SCHEMA = '''
CREATE TABLE IF NOT EXISTS pending_friend_requests (
    requester TEXT NOT NULL, target TEXT NOT NULL, created_at REAL NOT NULL,
    PRIMARY KEY(requester, target)
);
CREATE TABLE IF NOT EXISTS pending_group_invites (
    gid TEXT NOT NULL, target TEXT NOT NULL, inviter TEXT NOT NULL, created_at REAL NOT NULL,
    PRIMARY KEY(gid, target)
);
CREATE INDEX IF NOT EXISTS pending_friends_target ON pending_friend_requests(target);
CREATE INDEX IF NOT EXISTS pending_invites_target ON pending_group_invites(target);
'''


def load():
    with closing(sqlite3.connect('chat.db')) as db, db:
        cutoff = time.time() - TTL
        db.execute('DELETE FROM pending_friend_requests WHERE created_at<=?', (cutoff,))
        db.execute('DELETE FROM pending_group_invites WHERE created_at<=?', (cutoff,))
        friends = db.execute('SELECT requester,target,created_at FROM pending_friend_requests').fetchall()
        invites = db.execute('SELECT gid,target,inviter,created_at FROM pending_group_invites').fetchall()
    return friends, invites


def save_friend(requester, target, created):
    with closing(sqlite3.connect('chat.db')) as db, db:
        db.execute('INSERT OR REPLACE INTO pending_friend_requests VALUES(?,?,?)', (requester,target,created))


def decline_friend(requester, target):
    with closing(sqlite3.connect('chat.db')) as db, db:
        db.execute('DELETE FROM pending_friend_requests WHERE requester=? AND target=?', (requester,target))


def save_invite(gid, target, inviter, created):
    with closing(sqlite3.connect('chat.db')) as db, db:
        db.execute('INSERT OR REPLACE INTO pending_group_invites VALUES(?,?,?,?)', (gid,target,inviter,created))


def decline_invite(gid, target):
    with closing(sqlite3.connect('chat.db')) as db, db:
        db.execute('DELETE FROM pending_group_invites WHERE gid=? AND target=?', (gid,target))
