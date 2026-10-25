"""Friends handlers; dependencies and shared locks are explicit in ctx."""
import logging
import time
from contextlib import closing

import pending_store
import storage

def handle_friend_request(ctx, client_sock, current_username, msg):
    try:
        to_user = msg.get("to")
        sender = current_username
        logging.info('Friend request received')
        if not isinstance(to_user, str) or not to_user:
            ctx.send_msg(client_sock, {"type": "friend_request_result", "success": False, "error": "目标用户格式错误"})
            return
        if to_user == sender:
            ctx.send_msg(client_sock, {"type": "friend_request_result", "success": False, "error": "不能添加自己为好友"})
            logging.warning('Friend request rejected: self request')
            return
        if not ctx.user_exists(to_user):
            ctx.send_msg(client_sock, {"type": "friend_request_result", "success": False, "error": f"用户 {to_user} 不存在"})
            logging.warning('Friend request rejected: unknown target')
            return
        # 与接受请求共用锁，使好友检查和保存申请成为一次操作，
        # 防止并发接受后重试申请重新创建已失效的待处理记录。
        with ctx.pending_friend_requests_lock:
            with closing(storage.connect("chat.db")) as conn:
                already_friends = conn.execute(
                    "SELECT 1 FROM friends WHERE user=? AND friend=?",
                    (storage.token(sender), storage.token(to_user))).fetchone() is not None
            if already_friends:
                ctx.send_msg(client_sock, {"type": "friend_request_result", "success": False, "error": f"您和 {to_user} 已是好友"})
                return
            ts = ctx.pending_friend_requests.get((sender, to_user))
            if ts is not None and time.time() - ts <= ctx.PENDING_REQUEST_TIMEOUT_SECONDS:
                ctx.send_msg(client_sock, {"type": "friend_request_result", "success": False, "error": "已发送过好友申请，请等待对方处理"})
                return
            created = time.time()
            pending_store.save_friend(sender, to_user, created)
            ctx.pending_friend_requests[(sender, to_user)] = created
        to_sock = ctx.get_sock_by_username(to_user)
        if to_sock and sender:
            ctx.send_msg(to_sock, {"type": "friend_request", "from": sender})
            ctx.send_msg(client_sock, {"type": "friend_request_result", "success": True, "message": f"已向 {to_user} 发送好友申请"})
            logging.info('Friend request delivered')
        else:
            # 对方离线：记录请求，待对方上线后提示
            ctx.send_msg(client_sock, {"type": "friend_request_result", "success": True, "message": f"已向 {to_user} 发送好友申请（对方离线，上线后可见）"})
            logging.warning('Offline friend request stored')
    except Exception as e:
        logging.error('Friend request processing failed')
        ctx.send_msg(client_sock, {"type":"friend_request_result", "success":False, "error":"好友申请保存失败，请重试"})

def handle_friend_response(ctx, client_sock, current_username, msg):
    try:
        from_user = msg.get("to") # 这里的to是请求发起者
        accepted = msg.get("accepted")
        responder = current_username # 响应者
        logging.info('Friend response received')

        if not isinstance(from_user, str) or not from_user or not isinstance(accepted, bool):
            ctx.send_msg(client_sock, {"type": "friend_response_result", "success": False, "error": "响应数据格式错误"})
            return
        # 防伪校验：仅当对方确实向本用户发送过好友请求时才允许响应
        with ctx.pending_friend_requests_lock:
            ts = ctx.pending_friend_requests.get((from_user, responder))
            if ts is None or time.time() - ts > ctx.PENDING_REQUEST_TIMEOUT_SECONDS:
                ctx.send_msg(client_sock, {"type": "friend_response_result", "success": False, "error": "没有来自该用户的好友请求，无法响应"})
                logging.warning('Friend response rejected: no pending request')
                return
            if accepted:
                ctx.save_friend_relationship(responder, from_user)
                # Publish authorization before either user can react
                # to an acceptance notification or a new login snapshot.
                with ctx.user_friends_lock:
                    ctx.user_friends.setdefault(responder, set()).add(from_user)
                    if from_user in ctx.user_friends:
                        ctx.user_friends[from_user].add(responder)
            else:
                pending_store.decline_friend(from_user, responder)
            del ctx.pending_friend_requests[(from_user, responder)]
            if accepted:
                ctx.pending_friend_requests.pop((responder, from_user), None)

        from_sock = ctx.get_sock_by_username(from_user)
        if from_sock:
            ctx.send_msg(from_sock, {"type": "friend_response", "from": responder, "accepted": accepted})
            logging.info('Friend response delivered')

        if accepted:
            logging.info('Friend relationship saved')

            # 通知双方更新好友列表
            responder_sock = ctx.get_sock_by_username(responder)
            if responder_sock:
                ctx.send_msg(responder_sock, {"type": "friend_update", "friend": from_user})
            if from_sock: # from_sock 在前面已经获取
                ctx.send_msg(from_sock, {"type": "friend_update", "friend": responder})
    except Exception as e:
        logging.error('Friend response processing failed')
        ctx.send_msg(client_sock, {"type": "friend_response_result", "success": False, "error": "好友关系保存失败，请重试"})
