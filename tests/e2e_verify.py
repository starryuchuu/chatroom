# -*- coding: utf-8 -*-
"""
端到端验证：在 mock 加密依赖下运行真实 server.py，
验证已修复的漏洞行为与正常功能未受影响。
运行前需将 tests/mocks 加入 sys.path（脚本内已处理）。
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

MOCKS = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'mocks')
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, MOCKS)
sys.path.insert(0, ROOT)

import server as S  # noqa: E402

PASS = []
FAIL = []


def check(name, cond, extra=''):
    (PASS if cond else FAIL).append(name)
    print(('  PASS | ' if cond else '  FAIL | ') + name + ('' if cond else '  <-- ' + str(extra)))


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

    def login(self, user, pwd, encrypted=True):
        if encrypted:
            enc = S.encrypt_message(json.dumps({'from': user, 'password': pwd}), self.session_key)
            S.send_msg(self.sock, {'type': 'encrypted_login', 'data': enc})
        else:
            S.send_msg(self.sock, {'type': 'login', 'from': user, 'password': pwd})
        return S.recv_msg(self.sock)

    def send(self, msg):
        S.send_msg(self.sock, msg)

    def recv(self):
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
        self.sock.close()


def drain_until_close(sock, timeout=3.0):
    """读取直到连接关闭，返回 (是否关闭, 收到的字节)"""
    sock.settimeout(timeout)
    data = b''
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                return True, data
            data += chunk
    except socket.timeout:
        return False, data


def main():
    tmp = tempfile.mkdtemp(prefix='chatroom_e2e_')
    os.chdir(tmp)
    S.AUTH_TIMEOUT_SECONDS = 2  # 缩短认证超时以便测试
    S.RATE_LIMIT_MAX_ATTEMPTS = 1000  # 测试期间避免速率限制误伤

    t = threading.Thread(target=S.main, daemon=True)
    t.start()
    time.sleep(1.2)

    print('== 1. 注册与登录 ==')
    c = Client(); c.exchange()
    r = c.register('alice', 'secret123')
    check('注册 alice 成功', isinstance(r, dict) and r.get('success') is True, r)
    c.close()

    c = Client(); c.exchange()
    r = c.register('bob', '123')  # 密码过短
    check('短密码(3位)注册被拒绝', isinstance(r, dict) and r.get('success') is False, r)
    c.close()

    c = Client(); c.exchange()
    r = c.register('bob', 'secret123')
    check('注册 bob 成功', isinstance(r, dict) and r.get('success') is True, r)
    c.close()

    alice = Client(); alice.exchange()
    r = alice.login('alice', 'secret123')
    check('加密登录(encrypted_login)成功', isinstance(r, dict) and r.get('success') is True, r)
    alice.recv_until('friends_list')  # 排空登录后的初始化推送

    alice2 = Client(); alice2.exchange()
    r = alice2.login('alice', 'secret123', encrypted=False)
    check('重复登录被拒绝(明文login)', isinstance(r, dict) and r.get('success') is False, r)
    alice2.close()

    print('== 2. 好友响应防伪 ==')
    alice.send({'type': 'friend_response', 'to': 'nobody', 'accepted': True})
    r = alice.recv_until('friend_response_result')
    check('伪造好友响应(无待处理请求)被拒绝',
          isinstance(r, dict) and r.get('type') == 'friend_response_result' and r.get('success') is False, r)

    print('== 3. 群组越权防护 ==')
    alice.send({'type': 'group_create', 'group_name': 'g1', 'members': ['alice']})
    r = alice.recv_until('group_create_result')
    check('创建群组成功', isinstance(r, dict) and r.get('success') is True, r)
    gid = r.get('gid')

    bob = Client(); bob.exchange()
    r = bob.login('bob', 'secret123')
    check('bob 登录成功', isinstance(r, dict) and r.get('success') is True, r)
    bob.recv_until('friends_list')  # 排空初始化推送

    bob.send({'type': 'group_join', 'gid': gid})
    r = bob.recv_until('group_join_result')
    check('未受邀加入群组被拒绝', isinstance(r, dict) and r.get('type') == 'group_join_result' and r.get('success') is False, r)

    bob.send({'type': 'group_info', 'gid': gid})
    r = bob.recv_until('group_info')
    check('非成员查看群组信息被拒绝', isinstance(r, dict) and 'error' in r, r)
    print('== 4. 消息长度限制 ==')
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.connect(('127.0.0.1', 12345))
    S.recv_msg(raw)  # 接收公钥
    raw.sendall(struct.pack('!I', 0xFFFFFFFF))  # 声明 4GB
    closed, data = drain_until_close(raw)
    check('4GB 长度头连接被服务器关闭', closed, data[:60])
    raw.close()

    print('== 5. 认证超时 ==')
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.connect(('127.0.0.1', 12345))
    S.recv_msg(raw)  # 接收公钥后静默
    closed, data = drain_until_close(raw, timeout=5.0)
    check('认证阶段静默连接被关闭(超时)', closed, data[:60])
    raw.close()

    print('== 6. 正常好友/私聊流程仍可用 ==')
    bob.send({'type': 'friend_request', 'to': 'alice'})
    r = bob.recv_until('friend_request_result')
    check('bob 发送好友申请成功', isinstance(r, dict) and r.get('success') is True, r)
    r = alice.recv_until('friend_request')
    check('alice 收到好友申请', isinstance(r, dict) and r.get('type') == 'friend_request', r)

    alice.send({'type': 'friend_response', 'to': 'bob', 'accepted': True})
    r = alice.recv_until('friend_update')  # alice 收到 friend_update
    r2 = bob.recv_until('friend_response')  # bob 收到 friend_response
    check('好友关系正常建立', isinstance(r2, dict) and r2.get('type') == 'friend_response' and r2.get('accepted') is True, (r, r2))

    alice.send({'type': 'private_chat', 'to': 'bob',
                'content': S.encrypt_message('hello bob', alice.session_key),
                'timestamp': '2026-01-01 00:00:00'})
    r = bob.recv_until('private_chat')
    check('好友间私聊可达', isinstance(r, dict) and r.get('type') == 'private_chat', r)

    carol = Client(); carol.exchange()
    carol.register('carol', 'secret123')
    carol.close()
    carol = Client(); carol.exchange()
    r = carol.login('carol', 'secret123')
    check('carol 登录成功', isinstance(r, dict) and r.get('success') is True, r)
    carol.recv_until('friends_list')
    carol.send({'type': 'private_chat', 'to': 'alice',
                'content': S.encrypt_message('hi', carol.session_key),
                'timestamp': '2026-01-01 00:00:00'})
    r = carol.recv_until('private_chat_result')
    check('非好友私聊被拒绝', isinstance(r, dict) and r.get('type') == 'private_chat_result' and r.get('success') is False, r)

    print('== 7. 会话状态清理（内存泄漏修复） ==')
    alice.close()
    bob.close()
    carol.close()
    time.sleep(0.3)
    check('finally 清理 session_timestamps', len(S.session_timestamps) == 0, S.session_timestamps)
    check('finally 清理 usernames', len(S.usernames) == 0, S.usernames)
    check('finally 清理 session_keys', len(S.session_keys) == 0, S.session_keys)

    print()
    print('总结果: %d PASS, %d FAIL' % (len(PASS), len(FAIL)))
    if FAIL:
        print('失败的检查:', FAIL)
        sys.exit(1)
    print('所有端到端检查通过。')


if __name__ == '__main__':
    main()


