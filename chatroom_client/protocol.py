"""TCP framing, credential/body encryption and server identity verification."""
import base64
import hashlib
import json
import logging
import socket
import struct
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
import transport

MAX_RECV_MSG_LEN = transport.MAX_PAYLOAD_LEN
authenticated_sockets = set()

def recvall(sock, n):
    """
    从套接字接收指定字节数的数据。
    参数:
        sock: 套接字对象
        n: 需要接收的字节数
    返回:
        接收到的数据，如果连接关闭则返回None
    """
    data = b''
    while len(data) < n:
        try:
            packet = sock.recv(n - len(data))
        except socket.timeout:
            if sock in authenticated_sockets:
                continue
            raise
        if not packet:
            return None
        data += packet
    return data

def send_msg(sock, msg):
    """
    向套接字发送消息，消息前附加长度头部。
    参数:
        sock: 套接字对象
        msg: 要发送的消息字符串或字典
    """
    if isinstance(msg, dict):
        data = json.dumps(msg).encode('utf-8')
    else:
        data = str(msg).encode('utf-8')  # 修复：原来是'极-8'
    if len(data) > MAX_RECV_MSG_LEN:
        raise ValueError('消息包超过 1 MiB，请缩短内容')
    header = struct.pack('!I', len(data))
    transport.send_packet(sock, header + data)

def recv_msg(sock):
    """
    从套接字接收消息，首先读取长度头部，然后接收完整消息。
    参数:
        sock: 套接字对象
    返回:
        接收到的消息字符串或字典，如果连接关闭则返回None
    """
    header = recvall(sock, 4)
    if not header:
        return None
    msg_len = struct.unpack('!I', header)[0]
    if msg_len > transport.MAX_WIRE_LEN:
        logging.warning(f"收到超大消息长度 {msg_len} 字节（上限 {MAX_RECV_MSG_LEN}），视为异常连接")
        return None
    data = recvall(sock, msg_len)
    if not data:
        return None
    data = transport.decode(sock, data)
    try:
        return json.loads(data.decode('utf-8'))
    except Exception:
        return data.decode('utf-8')

def encrypt_message(message, key):
    """
    使用AES-GCM模式加密消息。
    参数:
        message: 要加密的消息字符串
        key: 会话密钥
    返回:
        加密后的消息 (nonce, ciphertext, tag)，base64编码
    """
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode('utf-8'))
    return base64.b64encode(cipher.nonce + ciphertext + tag).decode('utf-8')

def decrypt_message(encrypted_message, key):
    """
    使用AES-GCM模式解密消息。
    参数:
        encrypted_message: 加密的消息，base64编码
        key: 会话密钥
    返回:
        解密后的消息字符串
    """
    data = base64.b64decode(encrypted_message)
    nonce = data[:16]
    ciphertext = data[16:-16]
    tag = data[-16:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')

def check_server_public_key(public_key_data, *, host, expected_fingerprint):
    """
    校验服务器下发的公钥消息。
    参数:
        public_key_data: recv_msg 收到的公钥消息
    返回:
        (public_key, None) 校验通过；或 (None, 错误消息) 校验失败
    """
    if not isinstance(public_key_data, dict) or public_key_data.get("type") != "public_key":
        return None, "未能从服务器获取公钥"

    if public_key_data.get("protocol") != transport.VERSION:
        return None, "服务器协议版本不兼容，请同时升级客户端和服务端"
    public_key = RSA.import_key(public_key_data["key"])

    # 验证服务器公钥指纹（防止中间人攻击）
    public_key_bytes = public_key.export_key(format='DER')
    key_fingerprint = hashlib.sha256(public_key_bytes).hexdigest()
    logging.info(f"Server public key fingerprint: {key_fingerprint}")

    if expected_fingerprint is None:
        # 未配置指纹时：仅允许本机回环连接，连接非本机服务器则拒绝（防止中间人攻击）
        if host not in ('127.0.0.1', 'localhost', '::1'):
            return None, ("未配置服务器公钥指纹（EXPECTED_SERVER_KEY_FINGERPRINT），\n"
                          "连接非本机服务器时无法防止中间人攻击，连接已终止。\n\n"
                          "请在 client.py 中设置 EXPECTED_SERVER_KEY_FINGERPRINT 为服务器公钥指纹。")
        logging.warning("警告: EXPECTED_SERVER_KEY_FINGERPRINT 未设置，仅本机回环连接放行（无法防中间人攻击）。")
    else:
        if key_fingerprint != expected_fingerprint:
            return None, (f"服务器公钥指纹不匹配！\n\n预期：{expected_fingerprint}\n"
                          f"实际：{key_fingerprint}\n\n可能遭受中间人攻击，连接已终止。")
        logging.info("Server public key fingerprint verified successfully.")

    return public_key, None
