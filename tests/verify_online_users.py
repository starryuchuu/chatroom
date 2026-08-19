# -*- coding: utf-8 -*-
"""
在线用户功能端到端验证：
- 在真实 server.py（真实 pycryptodome）上跑真实协议客户端
- 验证登录/断开时 online_users 广播的内容正确
- 验证 client.py 中 receive_msg 对 online_users 消息的分发与列表渲染逻辑
- 并发压力测试：多人同时登录/退出时 broadcast_online_users 是否出现
  "dictionary changed size during iteration" 类竞态异常，以及登录响应是否被
  online_users 推送抢先（修复回归测试）

运行方式：python tests/verify_online_users.py （可从任意目录运行，
数据库与密钥文件写入 ROOT/.verify_online_tmp 下的临时子目录）。
"""
import os
import sys
import socket
import struct
import json
import threading
import time
import base64
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
# argon2-cffi 未安装时：追加 tests/mocks 到 sys.path 末尾，
# 仅当真实 argon2 不存在时才会命中 mock；真实 Crypto（pycryptodome）仍在 site-packages 中优先命中。
MOCKS = os.path.join(ROOT, 'tests', 'mocks')
sys.path.append(MOCKS)

import server as S  # noqa: E402

PASS, FAIL = [], []


def check(name, cond, extra=''):
    (PASS if cond else FAIL).append(name)
    print(('  PASS | ' if cond else '  FAIL | ') + name + ('' if cond else '  <-- ' + str(extra)))


# ---------- 协议客户端 ----------
class Client:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect(('127.0.0.1', 12345))
        self.session_key = None

    def exchange(self):
        msg = S.recv_msg(self.sock)
        assert msg and msg.get('type') == 'public_key', msg
        from Crypto.PublicKey import RSA
        from Crypto.Cipher import PKCS1_OAEP
        pub = RSA.import_key(msg['key'].encode('utf-8'))
        self.session_key = os.urandom(16)
        enc = PKCS1_OAEP.new(pub).encrypt(self.session_key)
        S.send_msg(self.sock, {'type': 'session_key', 'key': base64.b64encode(enc).decode('utf-8')})

    def register(self, user, pwd):
        enc = S.encrypt_message(json.dumps({'from': user, 'password': pwd}), self.session_key)
        S.send_msg(self.sock, {'type': 'encrypted_register', 'data': enc})
        return S.recv_msg(self.sock)

    def login(self, user, pwd):
        enc = S.encrypt_message(json.dumps({'from': user, 'password': pwd}), self.session_key)
        S.send_msg(self.sock, {'type': 'encrypted_login', 'data': enc})
        return S.recv_msg(self.sock)

    def recv_until(self, mtype, timeout=3.0):
        """接收消息直到遇到指定类型（丢弃中间的其他推送消息）。"""
        self.sock.settimeout(timeout)
        try:
            while True:
                msg = S.recv_msg(self.sock)
                if msg is None:
                    return None
                if isinstance(msg, dict) and msg.get('type') == mtype:
                    return msg
        except socket.timeout:
            return None

    def close(self):
        try:
            self.sock.close()
        except Exception:
            pass


# ---------- 客户端 GUI 逻辑桩 ----------
class FakeListbox:
    def __init__(self):
        self.items = []

    def delete(self, a, b):
        self.items = []

    def insert(self, idx, item):
        self.items.append(item)


class FakeMaster:
    def __init__(self):
        self.calls = []

    def after(self, delay, fn):
        self.calls.append(fn)
        fn()  # 立即执行，模拟 Tk 主循环回调


def make_gui_client(sock):
    """构造一个绕过 __init__（不建真实 Tk 窗口）的 ChatClient，仅用于验证消息分发逻辑。"""
    import client as C
    c = object.__new__(C.ChatClient)
    c.running = True
    c.sock = sock
    c.session_key = b'0123456789abcdef'
    c.master = FakeMaster()
    c.online_listbox = FakeListbox()
    c.friends_listbox = FakeListbox()
    c.group_listbox = FakeListbox()
    c.friends = []
    c.groups = {}
    c.current_group = None
    c.current_friend = None
    c.disconnect = lambda: setattr(c, '_disconnected', True)
    # 屏蔽可能弹窗的调用
    import client as C2
    C2.messagebox.showerror = lambda *a, **k: None
    return c


# ---------- 服务器线程异常捕获（用于竞态检测） ----------
thread_exceptions = []
_orig_excepthook = threading.excepthook


def _excepthook(args):
    thread_exceptions.append(args.exc_value)
    _orig_excepthook(args)


def main():
    # 把数据库文件重定向到工作区临时子目录，避免污染仓库根目录（与 bug_hunt_verify.py 相同做法）
    tmp_root = os.path.join(ROOT, '.verify_online_tmp')
    tmp = os.path.join(tmp_root, 'run_%d' % int(time.time()))
    os.makedirs(tmp, exist_ok=True)
    _real_connect = S.sqlite3.connect

    def patched_connect(db, *a, **k):
        if isinstance(db, str) and not os.path.isabs(db):
            db = os.path.join(tmp, db)
        return _real_connect(db, *a, **k)

    S.sqlite3.connect = patched_connect
    print('server data dir:', tmp)
    S.AUTH_TIMEOUT_SECONDS = 5
    S.RATE_LIMIT_MAX_ATTEMPTS = 100000
    S.SESSION_TIMEOUT_MINUTES = 30

    t = threading.Thread(target=S.main, daemon=True)
    t.start()
    time.sleep(1.5)

    # ---------- 1. 注册三个用户 ----------
    for u in ('alice', 'bob', 'carol'):
        c = Client(); c.exchange()
        r = c.register(u, 'secret123')
        check(f'注册 {u} 成功', isinstance(r, dict) and r.get('success') is True, r)
        c.close()

    # ---------- 2. 依次登录，验证 online_users 广播 ----------
    alice = Client(); alice.exchange()
    r = alice.login('alice', 'secret123')
    check('alice 登录成功', isinstance(r, dict) and r.get('success') is True, r)
    r = alice.recv_until('online_users', timeout=3)
    check('alice 登录后收到 online_users',
          isinstance(r, dict) and r.get('type') == 'online_users' and set(r.get('users', [])) == {'alice'}, r)

    bob = Client(); bob.exchange()
    r = bob.login('bob', 'secret123')
    check('bob 登录成功', isinstance(r, dict) and r.get('success') is True, r)
    r_bob = bob.recv_until('online_users', timeout=3)
    check('bob 登录后收到 online_users(含自己)',
          isinstance(r_bob, dict) and set(r_bob.get('users', [])) == {'alice', 'bob'}, r_bob)
    r_alice = alice.recv_until('online_users', timeout=3)
    check('bob 登录后 alice 收到更新',
          isinstance(r_alice, dict) and set(r_alice.get('users', [])) == {'alice', 'bob'}, r_alice)

    carol = Client(); carol.exchange()
    r = carol.login('carol', 'secret123')
    check('carol 登录成功', isinstance(r, dict) and r.get('success') is True, r)
    for name, cli in (('carol', carol), ('alice', alice), ('bob', bob)):
        r = cli.recv_until('online_users', timeout=3)
        check(f'{name} 在 carol 登录后收到更新(3人在线)',
              isinstance(r, dict) and set(r.get('users', [])) == {'alice', 'bob', 'carol'}, r)

    # ---------- 3. 断开连接，验证广播 ----------
    bob.close()  # 直接断开（服务器 finally 中清理并广播）
    r_alice = alice.recv_until('online_users', timeout=3)
    check('bob 断开后 alice 收到更新(仅2人)',
          isinstance(r_alice, dict) and set(r_alice.get('users', [])) == {'alice', 'carol'}, r_alice)
    r_carol = carol.recv_until('online_users', timeout=3)
    check('bob 断开后 carol 收到更新(仅2人)',
          isinstance(r_carol, dict) and set(r_carol.get('users', [])) == {'alice', 'carol'}, r_carol)

    # ---------- 4. 客户端 receive_msg 分发与列表渲染 ----------
    print('== 客户端 receive_msg 对 online_users 的处理 ==')
    a, b = socket.socketpair()
    gc = make_gui_client(a)
    thread = threading.Thread(target=gc.receive_msg, daemon=True)
    thread.start()
    S.send_msg(b, {'type': 'online_users', 'users': ['alice', 'bob', 'carol']})
    time.sleep(0.3)
    check('客户端 online_listbox 被更新为3人',
          set(gc.online_listbox.items) == {'alice', 'bob', 'carol'}, gc.online_listbox.items)
    S.send_msg(b, {'type': 'online_users', 'users': ['alice']})
    time.sleep(0.3)
    check('客户端 online_listbox 被更新为1人(增量覆盖)',
          gc.online_listbox.items == ['alice'], gc.online_listbox.items)
    gc.running = False
    b.close()
    time.sleep(0.2)

    # ---------- 5. 并发压力测试：竞态检测 ----------
    print('== 并发登录/退出压力测试（broadcast_online_users 竞态检测） ==')
    threading.excepthook = _excepthook
    errors = []
    n_workers = 24
    barrier = threading.Barrier(n_workers)

    def worker(idx):
        try:
            barrier.wait(timeout=5)
            for _ in range(5):
                c = Client(); c.exchange()
                u = f'u{idx}'
                try:
                    c.register(u, 'secret123')
                except Exception:
                    pass
                c.close()
                c = Client(); c.exchange()
                r = None
                for _try in range(3):
                    r = c.login(u, 'secret123')
                    if isinstance(r, dict) and r.get('success'):
                        break
                    # 登录失败（如"该用户已登录"）时服务器会关闭该连接，
                    # 必须换新连接重试，不能在已关闭的 socket 上重发。
                    c.close()
                    time.sleep(0.2)
                    c = Client(); c.exchange()
                if not (isinstance(r, dict) and r.get('success')):
                    errors.append(('login-fail', idx, r))
                    print(f'[worker {idx}] login failed, last r = {r}', flush=True)
                # 收到 online_users（自己必须在列表中，且列表中无重复用户名）
                r = c.recv_until('online_users', timeout=3)
                if not (isinstance(r, dict) and u in r.get('users', [])):
                    errors.append(('online-list-wrong', idx, r))
                elif len(r.get('users', [])) != len(set(r.get('users', []))):
                    errors.append(('online-list-duplicate', idx, r.get('users')))
                c.close()  # 触发 finally 广播
                time.sleep(0.03)
        except Exception as e:
            errors.append(('worker-exc', idx, repr(e)))

    ws = [threading.Thread(target=worker, args=(i,)) for i in range(n_workers)]
    for w in ws:
        w.start()
    for w in ws:
        w.join(timeout=90)

    time.sleep(1.0)
    threading.excepthook = _orig_excepthook
    check('并发压力测试无客户端侧异常', not errors, errors[:3])
    check('并发压力测试无服务器线程异常(竞态)',
          not thread_exceptions, [repr(e) for e in thread_exceptions[:3]])

    # ---------- 6. 最终服务器内存状态 ----------
    alice.close(); carol.close()
    time.sleep(0.5)
    check('全部断开后 usernames 为空', len(S.usernames) == 0, S.usernames)

    print()
    print(f'总结果: {len(PASS)} PASS, {len(FAIL)} FAIL')
    if FAIL:
        print('失败的检查:', FAIL)
        sys.exit(1)
    print('所有在线用户功能检查通过。')


if __name__ == '__main__':
    main()
