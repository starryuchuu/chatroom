# -*- coding: utf-8 -*-
"""
针对性 bug 验证（修复后回归）：在 mock 加密依赖下运行真实 server.py。

- Bug A: 离线好友请求应在对方上线后补发；请求方重发应仍被 pending 拦截（待对方处理）
- Bug B: 会话过期改为滑动过期：活跃会话不应被强制踢出
- Bug C: group_create 应拒绝非好友/未同意成员入群
- Bug G: 离线群邀请应在对方上线后补发
- 对照: 非成员群聊仍被拒；正常好友/私聊流程不受影响
"""
import os
import sys
import socket
import json
import threading
import time
import base64

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MOCKS = os.path.join(ROOT, 'tests', 'mocks')
sys.path.insert(0, MOCKS)
sys.path.insert(0, ROOT)

PASS, FAIL = [], []


def check(name, cond, extra=''):
    (PASS if cond else FAIL).append(name)
    print(('  PASS | ' if cond else '  FAIL | ') + name + ('' if cond else '  <-- ' + str(extra)[:200]))


class Client:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect(('127.0.0.1', 12345))
        self.session_key = None
        self.username = None
        self.exchange()

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
        self.username = user
        return S.recv_msg(self.sock)

    def send(self, msg):
        S.send_msg(self.sock, msg)

    def recv_until(self, mtype, timeout=2.0):
        self.sock.settimeout(timeout)
        while True:
            msg = S.recv_msg(self.sock)
            if msg is None:
                return None
            if isinstance(msg, dict) and msg.get('type') == mtype:
                return msg

    def close(self):
        try:
            self.sock.close()
        except Exception:
            pass


def drain(conn, mtype, timeout=2.0):
    """收集消息直到遇到指定类型或超时/关闭；返回 (目标消息或None, 收到的类型列表)"""
    got = []
    conn.sock.settimeout(timeout)
    while True:
        msg = S.recv_msg(conn.sock)
        if msg is None:
            break
        if isinstance(msg, dict):
            got.append(msg.get('type'))
            if msg.get('type') == mtype:
                return msg, got
    return None, got


def setup_user(user, pwd='secret123'):
    c = Client()
    c.register(user, pwd)
    c.close()


def make_friends(a, b):
    """a 请求 b，b 接受，建立好友关系（双方在线）"""
    a.send({'type': 'friend_request', 'to': b.username})
    r = b.recv_until('friend_request')
    assert r is not None, 'friend_request not delivered'
    b.send({'type': 'friend_response', 'to': a.username, 'accepted': True})
    b.recv_until('friend_update')
    a.recv_until('friend_response')


def main():
    tmp_root = os.path.join(ROOT, '.bugtest_tmp')
    tmp = os.path.join(tmp_root, 'run_%d' % int(time.time()))
    os.makedirs(tmp, exist_ok=True)
    _real_connect = S.sqlite3.connect
    def patched_connect(db, *a, **k):
        if isinstance(db, str) and not os.path.isabs(db):
            db = os.path.join(tmp, db)
        return _real_connect(db, *a, **k)
    S.sqlite3.connect = patched_connect
    S.AUTH_TIMEOUT_SECONDS = 5
    S.RATE_LIMIT_MAX_ATTEMPTS = 100000

    t = threading.Thread(target=S.main, daemon=True)
    t.start()
    time.sleep(1.2)

    for u in ('alice', 'bob', 'carol', 'dave', 'erin'):
        setup_user(u)

    print('== A. 离线好友请求 ==')
    alice = Client(); alice.login('alice', 'secret123'); alice.recv_until('friends_list')
    # bob 离线，alice 发好友请求
    alice.send({'type': 'friend_request', 'to': 'bob'})
    r = alice.recv_until('friend_request_result')
    check('A1 离线请求返回 success（提示"对方离线，上线后可见"）', isinstance(r, dict) and r.get('success') is True, r)
    # 重发仍被 pending 拦截（等待对方处理）
    alice.send({'type': 'friend_request', 'to': 'bob'})
    r = alice.recv_until('friend_request_result')
    check('A2 重发被拒（pending 生效，等待对方处理）', isinstance(r, dict) and r.get('success') is False, r)
    # bob 上线，应收到好友请求（修复后补发）
    bob = Client(); bob.login('bob', 'secret123'); bob.recv_until('friends_list')
    r, got = drain(bob, 'friend_request', timeout=2.0)
    check('A3 离线好友请求在对方上线后送达（修复生效）', r is not None and r.get('from') == 'alice', (r, got))
    # bob 接受请求，好友关系建立
    bob.send({'type': 'friend_response', 'to': 'alice', 'accepted': True})
    r = bob.recv_until('friend_update')
    r2 = alice.recv_until('friend_response')
    check('A4 补发请求可正常响应并建立好友关系', isinstance(r2, dict) and r2.get('accepted') is True, (r, r2))

    print('== B. 会话过期（活跃会话不应被踢） ==')
    old_timeout = S.SESSION_TIMEOUT_MINUTES
    S.SESSION_TIMEOUT_MINUTES = 0.05  # 3 秒
    alice.close()
    alice = Client(); alice.login('alice', 'secret123'); alice.recv_until('friends_list')
    t0 = time.time()
    dropped_at = None
    deadline = t0 + 6.0
    alice.sock.settimeout(2.0)
    while time.time() < deadline:
        try:
            alice.send({'type': 'private_chat', 'to': 'bob',
                        'content': S.encrypt_message('ping', alice.session_key),
                        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')})
        except Exception:
            dropped_at = time.time() - t0
            break
        try:
            msg = S.recv_msg(alice.sock)
        except Exception:
            msg = None
        if msg is None:
            dropped_at = time.time() - t0
            break
        if isinstance(msg, dict) and msg.get('type') == 'error':
            dropped_at = time.time() - t0
            break
        time.sleep(0.3)
    check('B1 活跃会话超过超时点后连接保持（滑动过期生效）', dropped_at is None, (dropped_at,))
    # 超时窗口后会话仍可用
    try:
        alice.send({'type': 'private_chat', 'to': 'bob',
                    'content': S.encrypt_message('still alive', alice.session_key),
                    'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')})
        echo = S.recv_msg(alice.sock)
    except Exception as e:
        echo = e
    check('B2 超时窗口后仍可正常收发（会话未被踢出）',
          isinstance(echo, dict) and echo.get('type') == 'private_chat', echo)
    S.SESSION_TIMEOUT_MINUTES = old_timeout
    alice.close()  # 关闭 B 段连接，释放用户名
    time.sleep(0.5)  # 等待服务器线程处理 FIN 并清理用户名（异步清理竞态）

    print('== C. 群组创建：非好友/未同意成员 ==')
    alice2 = Client(); alice2.login('alice', 'secret123'); alice2.recv_until('friends_list')
    alice2.send({'type': 'group_create', 'group_name': 'ghost-group', 'members': ['carol']})
    r = alice2.recv_until('group_create_result')
    check('C1 将非好友 carol 加入群组被拒绝（修复生效）', isinstance(r, dict) and r.get('success') is False, r)
    # 合法建群：成员必须是好友（alice 与 dave 尚非好友 → 也应被拒）
    alice2.send({'type': 'group_create', 'group_name': 'g2', 'members': ['dave']})
    r = alice2.recv_until('group_create_result')
    check('C1b 非好友成员同样被拒（含"成员不是您的好友"提示）',
          isinstance(r, dict) and r.get('success') is False and '好友' in str(r.get('error', '')), r)
    # carol 上线，不应收到任何群组通知
    carol = Client(); carol.login('carol', 'secret123'); carol.recv_until('friends_list')
    r2, got = drain(carol, 'group_create_result', timeout=1.5)
    check('C2 被拒绝的成员未收到任何群组通知（未越权入群）', r2 is None, (r2, got))
    carol.close()

    print('== G. 离线群邀请 ==')
    # erin 上线与 alice 成为好友后离线
    erin = Client(); erin.login('erin', 'secret123'); erin.recv_until('friends_list')
    make_friends(alice2, erin)
    erin.close()
    time.sleep(0.5)  # 等待服务器清理 erin 会话，避免重登竞态
    # dave 上线与 alice 成为好友（作为群成员）
    dave = Client(); dave.login('dave', 'secret123'); dave.recv_until('friends_list')
    make_friends(alice2, dave)
    # alice 建群（成员 dave 为好友，通过校验）
    alice2.send({'type': 'group_create', 'group_name': 'inv-group', 'members': ['dave']})
    r = alice2.recv_until('group_create_result')
    gid2 = r.get('gid') if isinstance(r, dict) else None
    check('G0 建群成功（合法好友成员）', isinstance(r, dict) and r.get('success') is True and gid2, r)
    # 邀请离线的 erin
    alice2.send({'type': 'group_invite', 'to': 'erin', 'gid': gid2})
    r = alice2.recv_until('group_invite_result')
    check('G1 离线邀请返回 success（提示"上线后可申请加入"）', isinstance(r, dict) and r.get('success') is True, r)
    # erin 上线，应收到群邀请（修复后补发）
    erin = Client(); erin.login('erin', 'secret123'); erin.recv_until('friends_list')
    r, got = drain(erin, 'group_invite', timeout=2.0)
    check('G2 离线群邀请在对方上线后送达（修复生效）',
          r is not None and r.get('gid') == gid2 and r.get('from') == 'alice', (r, got))
    # erin 接受邀请加入群
    if r is not None:
        erin.send({'type': 'group_join', 'gid': gid2})
        rj = erin.recv_until('group_join_result')
        check('G3 erin 接受邀请加入群成功', isinstance(rj, dict) and rj.get('success') is True, rj)

    print('== 对照：非成员群聊被拒 / 正常私聊仍可用 ==')
    carol = Client(); carol.login('carol', 'secret123'); carol.recv_until('friends_list')
    carol.send({'type': 'group_chat', 'gid': gid2,
                'content': S.encrypt_message('intrude', carol.session_key),
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')})
    r = carol.recv_until('group_chat_result')
    check('对照1 非成员群聊被拒', isinstance(r, dict) and r.get('success') is False, r)

    alice2.send({'type': 'private_chat', 'to': 'dave',
                 'content': S.encrypt_message('hello dave', alice2.session_key),
                 'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')})
    r = dave.recv_until('private_chat')
    check('对照2 好友间私聊仍可达', isinstance(r, dict) and r.get('type') == 'private_chat', r)

    print()
    print('总结果: %d PASS, %d FAIL' % (len(PASS), len(FAIL)))
    if FAIL:
        print('失败的检查:', FAIL)
        sys.exit(1)
    print('所有回归检查通过。')


if __name__ == '__main__':
    import server as S  # noqa: E402
    main()
