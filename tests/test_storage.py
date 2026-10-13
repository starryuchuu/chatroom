"""At-rest confidentiality, fail-closed reads, atomic migration and key recovery."""
from contextlib import closing
import os
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import patch

from argon2 import PasswordHasher
import storage


def legacy_fixture(db):
    db.executescript('''
    CREATE TABLE users(id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT UNIQUE NOT NULL,password TEXT NOT NULL);
    CREATE TABLE messages(id INTEGER PRIMARY KEY AUTOINCREMENT,chat_type TEXT NOT NULL,from_user TEXT NOT NULL,to_user TEXT,gid TEXT,message TEXT NOT NULL,timestamp TEXT NOT NULL);
    CREATE TABLE friends(user TEXT NOT NULL,friend TEXT NOT NULL,UNIQUE(user,friend));
    CREATE TABLE groups(gid TEXT PRIMARY KEY,group_name TEXT NOT NULL,owner TEXT NOT NULL,members TEXT NOT NULL,created_at TEXT NOT NULL);
    CREATE TABLE pending_friend_requests(requester TEXT NOT NULL,target TEXT NOT NULL,created_at REAL NOT NULL,PRIMARY KEY(requester,target));
    CREATE TABLE pending_group_invites(gid TEXT NOT NULL,target TEXT NOT NULL,inviter TEXT NOT NULL,created_at REAL NOT NULL,PRIMARY KEY(gid,target));
    ''')
    for user in ('alice-private-name','bob-private-name'):
        db.execute('INSERT INTO users(username,password) VALUES(?,?)',(user,PasswordHasher().hash('legacy password')))
    db.execute("INSERT INTO messages VALUES(1,'private','bob-private-name','alice-private-name',NULL,'保密聊天正文 uniquely-secret-message','secret-date')")
    db.executemany('INSERT INTO friends VALUES(?,?)',[('alice-private-name','bob-private-name'),('bob-private-name','alice-private-name')])
    db.execute('INSERT INTO groups VALUES(?,?,?,?,?)',('g','保密群名称 uniquely-secret-group','alice-private-name','["alice-private-name", "bob-private-name"]','secret-date'))
    db.execute('INSERT INTO pending_friend_requests VALUES(?,?,?)',('bob-private-name','alice-private-name',time.time()))
    db.execute('INSERT INTO pending_group_invites VALUES(?,?,?,?)',('g','bob-private-name','alice-private-name',time.time()))
    db.commit()


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.path=Path(self.tmp.name)/'chat.db'
        self.key=Path(str(self.path)+'.key')
        self.env=patch.dict(os.environ, {'CHATROOM_STORAGE_KEY_FILE':''})
        self.env.start()
        self.old_store=storage._store
        self.db=storage.connect(self.path)
        legacy_fixture(self.db)

    def tearDown(self):
        self.db.close()
        storage._store=self.old_store
        self.env.stop()
        self.tmp.cleanup()

    def initialize(self):
        storage.initialize(self.db,self.path)

    def test_migration_encrypts_sensitive_fields_and_removes_old_pages(self):
        self.initialize()
        row=self.db.execute('SELECT id,chat_type,from_user,to_user,gid,message,timestamp FROM messages').fetchone()
        decoded=storage.decode_message(self.db,row)
        self.assertEqual(decoded[2:4],('bob-private-name','alice-private-name'))
        self.assertEqual(decoded[5:7],('保密聊天正文 uniquely-secret-message','secret-date'))
        self.assertEqual(storage.decode_group(self.db.execute('SELECT * FROM groups').fetchone())[1], '保密群名称 uniquely-secret-group')
        token=storage.token('alice-private-name')
        encoded=self.db.execute('SELECT password FROM users WHERE username=?',(token,)).fetchone()[0]
        self.assertTrue(PasswordHasher().verify(storage.open_field(encoded,'users','password',token),'legacy password'))
        raw=self.path.read_bytes()
        for secret in ('alice-private-name','bob-private-name','uniquely-secret-message','uniquely-secret-group','secret-date','$argon2id$'):
            self.assertNotIn(secret.encode(),raw)
        self.assertEqual(len(self.key.read_bytes()),32)
        if os.name!='nt': self.assertEqual(self.key.stat().st_mode & 0o777,0o600)
        before=list(self.db.execute('SELECT * FROM messages'))
        self.initialize()
        self.assertEqual(before,list(self.db.execute('SELECT * FROM messages')))

    def test_randomized_encryption_rejects_tamper_plaintext_and_row_swap(self):
        self.initialize()
        with self.db:
            first=storage.save_message(self.db,'private','bob-private-name','alice-private-name',None,'same secret','now')
            second=storage.save_message(self.db,'private','bob-private-name','alice-private-name',None,'same secret','now')
        rows=self.db.execute('SELECT id,chat_type,from_user,to_user,gid,message,timestamp FROM messages WHERE id>?',(1,)).fetchall()
        self.assertNotEqual(rows[0][5],rows[1][5])
        for body in (rows[1][5],'plaintext','enc1:broken',rows[0][5][:-2]+'AA'):
            changed=list(rows[0]);changed[5]=body
            with self.assertRaises((ValueError,UnicodeError)):
                storage.decode_message(self.db,changed)
        changed=list(rows[0]);changed[2]=storage.token('alice-private-name')
        with self.assertRaises(ValueError):storage.decode_message(self.db,changed)

    def test_missing_wrong_or_truncated_key_stops_without_data_loss(self):
        self.initialize()
        raw=self.path.read_bytes();key=self.key.read_bytes()
        self.key.unlink()
        with self.assertRaisesRegex(RuntimeError,'missing'):self.initialize()
        self.assertFalse(self.key.exists())
        self.assertEqual(raw,self.path.read_bytes())
        for bad in (b'x'*32,b'bad'):
            self.key.write_bytes(bad)
            with self.assertRaises(RuntimeError):self.initialize()
            self.assertEqual(raw,self.path.read_bytes())
            self.assertEqual(bad,self.key.read_bytes())
        self.key.write_bytes(key);self.initialize()

    def test_migration_failure_rolls_back_and_recovers_cleanup(self):
        original=storage.Storage.seal
        calls=0
        def fail(store,*args):
            nonlocal calls
            calls+=1
            if calls==4:raise OSError('simulated storage failure')
            return original(store,*args)
        with patch.object(storage.Storage,'seal',fail):
            with self.assertRaises(OSError):self.initialize()
        self.assertEqual(self.db.execute('SELECT username FROM users ORDER BY id').fetchall(),[('alice-private-name',),('bob-private-name',)])
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM storage_names').fetchone()[0],0)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM storage_meta').fetchone()[0],0)
        self.initialize()
        with self.db:self.db.execute("UPDATE storage_meta SET value='1' WHERE key='cleanup_pending'")
        self.initialize()
        self.assertEqual(self.db.execute("SELECT value FROM storage_meta WHERE key='cleanup_pending'").fetchone()[0],'0')

    def test_explicit_external_key_location(self):
        external=Path(self.tmp.name)/'external.key'
        with patch.dict(os.environ, {'CHATROOM_STORAGE_KEY_FILE':str(external)}):
            self.initialize()
            self.assertTrue(external.exists());self.assertFalse(self.key.exists())
            self.initialize()


if __name__=='__main__':unittest.main()
