"""Messaging handlers; dependencies and shared locks are explicit in ctx."""
import datetime
import logging

import e2ee_server
import send_receipts


def handle_message_status(ctx, sock, username, msg):
    kind, target, key = msg.get('chat_type'), msg.get('target'), msg.get('idempotency_key')
    reply = {'type': 'message_status_result', 'request_id': msg.get('request_id'),
             'idempotency_key': key, 'chat_type': kind, 'target': target, 'success': False}
    if (not send_receipts.valid_key(key) or kind not in ('private', 'group')
            or not isinstance(target, str) or not target or len(target) > 256):
        reply['error'] = '消息查询参数错误'
    else:
        try:
            receipt = ctx.lookup_send_receipt(username, key, kind, target)
            reply.update(success=True, status='saved' if receipt is not None else 'not_found')
            if receipt is not None:
                reply.update(message_id=receipt[0], timestamp=receipt[1])
        except Exception:
            logging.error('Send receipt lookup failed')
            reply['error'] = '暂时无法核对发送结果，请稍后重试'
    ctx.send_msg(sock, reply)


def persist_chat(ctx, request, kind, sender, recipient, gid, body, timestamp, encrypted):
    if 'idempotency_key' in request:
        key = request['idempotency_key']
        if not send_receipts.valid_key(key):
            raise e2ee_server.E2EEError('消息标识格式错误')
        return ctx.save_message_once(kind, sender, recipient, gid, body, timestamp,
                                     e2ee=encrypted, key=key)
    return ctx.save_message(kind, sender, recipient, gid, body, timestamp, e2ee=encrypted), False, timestamp

def handle_e2ee_identity_publish(ctx, client_sock, current_username, msg):
    ctx.handle_e2ee_identity(client_sock, current_username, msg)

def handle_e2ee_keys_request(ctx, client_sock, current_username, msg):
    ctx.handle_e2ee_keys(client_sock, current_username, msg)

def handle_sync_request(ctx, client_sock, current_username, msg):
    ctx.send_sync(client_sock, current_username, msg)

def handle_history_request(ctx, client_sock, current_username, msg):
    request_id = msg.get('request_id')
    kind, target, before = msg.get('chat_type'), msg.get('target'), msg.get('before_id')
    if (('request_id' in msg and not ctx.valid_history_request_id(request_id)) or kind not in ('private','group') or not isinstance(target,str) or not target or type(before) is not int or not 0<before<=9223372036854775807):
        ctx.send_history_error(client_sock, '历史查询参数错误', kind=kind, target=target, request_id=request_id)
        return
    if kind == 'private':
        with ctx.user_friends_lock:
            allowed = target in ctx.user_friends.get(current_username,set())
    else:
        group = ctx.get_group_db(target)
        allowed = bool(group and current_username in group['members'])
    if not allowed:
        ctx.send_history_error(client_sock, '无权读取该会话历史', kind=kind, target=target, request_id=request_id)
        return
    ctx.send_history(client_sock,current_username,kind=kind,target=target,before=before,request_id=request_id)

def handle_private_chat(ctx, client_sock, current_username, msg):
    message_id = None
    try:
        ctx.group_ops_lock.acquire()
        to_user = msg.get("to")
        # 使用服务器时间，不信任客户端提供的时间戳（可被伪造污染历史记录排序）
        now = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

        if to_user == current_username: # 不能给自己发私聊
            logging.warning('Private message rejected: self target')
            ctx.send_msg(client_sock, {"type": "private_chat_result", "success": False, "request_id": msg.get("request_id"), "error": "消息未保存，请检查目标和消息内容"})
            return

        # 检查是否是好友关系（持锁读取，与 friend_response 的写入保持一致）
        with ctx.user_friends_lock:
            is_friend = to_user in ctx.user_friends.get(current_username, set())
        if not is_friend:
            ctx.send_msg(client_sock, {"type": "private_chat_result", "request_id": msg.get("request_id"), "success": False, "error": f"您和 {to_user} 不是好友关系"})
            logging.warning('Private message rejected: unauthorized target')
            return

        sender_session_key = ctx.session_keys.get(client_sock)
        if not sender_session_key:
            logging.error('Private message rejected: session unavailable')
            ctx.send_msg(client_sock, {"type": "private_chat_result", "success": False, "request_id": msg.get("request_id"), "error": "消息未保存，请检查目标和消息内容"})
            return

        stored_content, encrypted_end_to_end = ctx.prepare_chat_content(
            msg, current_username, 'private', to_user, [current_username, to_user],
            sender_session_key, now)
        message_id, duplicate, now = persist_chat(ctx, msg, 'private', current_username,
                                                 to_user, None, stored_content, now, encrypted_end_to_end)
        ctx.send_msg(client_sock, {"type": "private_chat_result", "success": True, "request_id": msg.get("request_id"), "message_id": message_id})
        logging.info('Private message saved')

        # 为接收者准备消息
        to_sock = ctx.get_sock_by_username(to_user)
        if to_sock and not duplicate:
            recipient_session_key = ctx.session_keys.get(to_sock)
            if recipient_session_key:
                message_for_recipient = {
                    "type": "private_chat",
                    "from": current_username,
                    "to": to_user,
                    "timestamp": now,
                    "message_id": message_id,
                    "history": False
                }
                message_for_recipient.update(ctx.chat_content(
                    stored_content, recipient_session_key, e2ee=encrypted_end_to_end))
                ctx.send_msg(to_sock, message_for_recipient)
                logging.info('Private message forwarded')
            else:
                logging.warning('Private message recipient session unavailable')

        # 为发送者准备消息（用于客户端显示）
        message_for_sender = {
            "type": "private_chat",
            "from": current_username,
            "to": to_user,
            "timestamp": now,
            "message_id": message_id,
            "history": False
        }
        message_for_sender.update(ctx.chat_content(
            stored_content, sender_session_key, e2ee=encrypted_end_to_end))
        ctx.send_msg(client_sock, message_for_sender)
    except Exception as e:
        logging.error('Private message processing failed')
        if message_id is None:
            ctx.send_msg(client_sock, {"type": "private_chat_result", "success": False, "request_id": msg.get("request_id"),
                                   "error": str(e) if isinstance(e, e2ee_server.E2EEError) else "消息保存失败，请重试"})
    finally:
        ctx.group_ops_lock.release()

def handle_group_chat(ctx, client_sock, current_username, msg):
    message_id = None
    try:
        ctx.group_ops_lock.acquire()
        gid = msg.get("gid")
        # 使用服务器时间，不信任客户端提供的时间戳（可被伪造污染历史记录排序）
        now = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        from_user = current_username

        if gid == "all":
            ctx.send_msg(client_sock, {"type": "group_chat_result", "request_id": msg.get("request_id"), "success": False, "error": "全体群组功能已禁用"})
            return

        group = ctx.get_group_db(gid)
        if not group:
            ctx.send_msg(client_sock, {"type": "group_chat_result", "request_id": msg.get("request_id"), "success": False, "error": "群组不存在"})
            logging.warning('Group message rejected: unknown group')
            return

        # 检查用户是否是群成员
        if from_user not in group["members"]:
            ctx.send_msg(client_sock, {"type": "group_chat_result", "request_id": msg.get("request_id"), "success": False, "error": "您不是该群成员"})
            logging.warning('Group message rejected: membership required')
            return

        sender_session_key = ctx.session_keys.get(client_sock)
        if not sender_session_key:
            logging.error('Group message rejected: session unavailable')
            ctx.send_msg(client_sock, {"type": "group_chat_result", "success": False, "request_id": msg.get("request_id"), "error": "消息未保存，请检查目标和消息内容"})
            return

        stored_content, encrypted_end_to_end = ctx.prepare_chat_content(
            msg, from_user, 'group', gid, group['members'], sender_session_key, now)
        message_id, duplicate, now = persist_chat(ctx, msg, 'group', from_user, None, gid,
                                                 stored_content, now, encrypted_end_to_end)
        ctx.send_msg(client_sock, {"type": "group_chat_result", "success": True, "request_id": msg.get("request_id"), "message_id": message_id})
        logging.info('Group message saved')

        # 为每个群成员单独加密并发送消息
        for member in group["members"]:
            if duplicate and member != current_username:
                continue
            sock = ctx.get_sock_by_username(member)
            if sock:
                member_session_key = ctx.session_keys.get(sock)
                if member_session_key:
                    message_to_send = {
                        "type": "group_chat",
                        "from": from_user,
                        "gid": gid,
                        "timestamp": now,
                        "message_id": message_id,
                        "history": False
                    }
                    message_to_send.update(ctx.chat_content(
                        stored_content, member_session_key, e2ee=encrypted_end_to_end))
                    try:
                        ctx.send_msg(sock, message_to_send)
                    except Exception as e:
                        logging.error('Group message delivery failed')
                else:
                    logging.warning('Group message recipient session unavailable')
    except Exception as e:
        logging.error('Group message processing failed')
        if message_id is None:
            ctx.send_msg(client_sock, {"type": "group_chat_result", "success": False, "request_id": msg.get("request_id"),
                                   "error": str(e) if isinstance(e, e2ee_server.E2EEError) else "消息保存失败，请重试"})
    finally:
        ctx.group_ops_lock.release()
