"""Groups handlers; dependencies and shared locks are explicit in ctx."""
import logging
import time

import pending_store
import storage

def handle_group_create(ctx, client_sock, current_username, msg):
    try:
        group_name, members = ctx.validate_group_creation(
            current_username, msg.get('group_name'), msg.get('members', []))
    except ValueError as error:
        ctx.send_msg(client_sock, {'type': 'group_create_result', 'success': False,
                               'error': str(error)})
        logging.warning('Group creation input rejected')
        return
    try:
        ctx.group_ops_lock.acquire()
        owner = current_username
        if not ctx.group_members_are_friends(owner, members):
            ctx.send_msg(client_sock, {"type": "group_create_result", "success": False,
                                   "error": "成员必须是您的好友，无法加入群聊"})
            logging.warning('Group creation membership rejected')
            return
        gid = ctx.create_group_db(owner, group_name, members)
        if gid:
            with ctx.groups_data_lock:
                ctx.groups_data[gid] = {"group_name": group_name, "owner": owner, "members": members}
            # 创建一个包含所有必要信息的消息负载
            payload = {
                "type": "group_create_result",
                "success": True,
                "gid": gid,
                "group_name": group_name,
                "owner": owner,  # 添加群主信息
                "members": members
            }
            ctx.send_msg(client_sock, payload)
            logging.info('Group created')
            # 通知所有成员群组已创建
            for member in members:
                sock = ctx.get_sock_by_username(member)
                if sock and sock != client_sock:
                    ctx.send_msg(sock, payload) # 发送包含群主信息的完整负载
                    logging.info('Group creation notification delivered')
        else:
            ctx.send_msg(client_sock, {"type": "group_create_result", "success": False, "error": "创建群聊失败"})
            logging.error('Group creation failed')
    except Exception as e:
        logging.error('Group creation processing failed')
        ctx.send_msg(client_sock, {"type": "group_create_result", "success": False, "error": "操作处理失败，请重试"})
    finally:
        ctx.group_ops_lock.release()

def handle_group_invite(ctx, client_sock, current_username, msg):
    try:
        ctx.group_ops_lock.acquire()
        to_user = msg.get("to")
        gid = msg.get("gid")
        inviter = current_username
        logging.info('Group invitation received')

        group = ctx.get_group_db(gid)
        if not group:
            ctx.send_msg(client_sock, {"type": "group_invite_result", "success": False, "error": "群组不存在"})
            logging.warning('Group invitation rejected: unknown group')
            return
        if inviter not in group["members"]:
            ctx.send_msg(client_sock, {"type": "group_invite_result", "success": False, "error": "您不是该群成员，无法邀请"})
            logging.warning('Group invitation rejected: membership required')
            return
        if to_user in group["members"]:
            ctx.send_msg(client_sock, {"type": "group_invite_result", "success": False, "error": f"用户 {to_user} 已是群成员"})
            logging.warning('Group invitation rejected: target already joined')
            return
        if len(set(group['members'])) >= ctx.MAX_GROUP_MEMBERS:
            ctx.send_msg(client_sock, {'type': 'group_invite_result', 'success': False,
                                   'error': ctx.GROUP_CAPACITY_ERROR})
            logging.warning('Group invitation rejected: capacity reached')
            return
        if not ctx.user_exists(to_user):
            ctx.send_msg(client_sock, {"type": "group_invite_result", "success": False, "error": f"用户 {to_user} 不存在"})
            logging.warning('Group invitation rejected: unknown target')
            return

        # 检查是否是好友关系（直接查询数据库而不是依赖内存中的好友列表）
        conn = None
        try:
            conn = storage.connect("chat.db")
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM friends WHERE user=? AND friend=?", (storage.token(inviter), storage.token(to_user)))
            count = cursor.fetchone()[0]
        finally:
            if conn:
                conn.close()
        if count == 0:
            ctx.send_msg(client_sock, {"type": "group_invite_result", "success": False, "error": f"您和 {to_user} 不是好友关系"})
            logging.warning('Group invitation rejected: friendship required')
            return

        # 记录待加入请求（仅收到过邀请的用户才能 join，防止越权加入）
        # 保存邀请者与创建时间，离线补发并限制有效期
        with ctx.group_pending_joins_lock:
            if gid not in ctx.group_pending_joins:
                ctx.group_pending_joins[gid] = {}
            created = time.time()
            pending_store.save_invite(gid, to_user, inviter, created)
            ctx.group_pending_joins[gid][to_user] = (inviter, created)

        to_sock = ctx.get_sock_by_username(to_user)
        if to_sock:
            ctx.send_msg(to_sock, {"type": "group_invite", "from": inviter, "gid": gid, "group_name": group["group_name"]})
            ctx.send_msg(client_sock, {"type": "group_invite_result", "success": True, "message": f"已向 {to_user} 发送邀请"})
            logging.info('Group invitation delivered')
        else:
            ctx.send_msg(client_sock, {"type": "group_invite_result", "success": True, "message": f"已向 {to_user} 发送邀请（对方离线，上线后可申请加入）"})
            logging.warning('Offline group invitation stored')
    except Exception as e:
        logging.error('Group invitation processing failed')
        ctx.send_msg(client_sock, {"type": "group_invite_result", "success": False, "error": "操作处理失败，请重试"})
    finally:
        ctx.group_ops_lock.release()

def handle_group_invite_response(ctx, client_sock, current_username, msg):
    ctx.group_ops_lock.acquire()
    try:
        gid = msg.get("gid")
        if not isinstance(gid, str) or msg.get("accepted") is not False:
            ctx.send_msg(client_sock, {"type":"group_invite_response_result", "success":False, "error":"邀请响应格式错误"})
            return
        with ctx.group_pending_joins_lock:
            pending_store.decline_invite(gid, current_username)
            ctx.group_pending_joins.get(gid, {}).pop(current_username, None)
        ctx.send_msg(client_sock, {"type": "group_invite_response_result", "success": True, "gid": gid})
    except Exception:
        ctx.send_msg(client_sock, {"type":"group_invite_response_result", "success":False, "error":"邀请处理失败，请重试"})
    finally:
        ctx.group_ops_lock.release()

def handle_group_join(ctx, client_sock, current_username, msg):
    joined_history_gid = None
    try:
        ctx.group_ops_lock.acquire()
        gid = msg.get("gid")
        user_to_join = current_username
        logging.info('Group join received')

        group = ctx.get_group_db(gid)
        if not group:
            ctx.send_msg(client_sock, {"type": "group_join_result", "success": False, "error": "群组不存在"})
            logging.warning('Group join rejected: unknown group')
            return
        if user_to_join in group["members"]:
            ctx.send_msg(client_sock, {"type": "group_join_result", "success": False, "error": "您已是该群成员"})
            logging.warning('Group join rejected: already joined')
            return
        # 防越权：仅收到过邀请的用户可加入群组（先校验，成功写库后才消费邀请，
        # 避免 DB 写失败时邀请丢失导致无法重试）
        with ctx.group_pending_joins_lock:
            if gid not in ctx.group_pending_joins or user_to_join not in ctx.group_pending_joins.get(gid, {}):
                ctx.send_msg(client_sock, {"type": "group_join_result", "success": False, "error": "您未被邀请加入该群组"})
                logging.warning('Group join rejected: invitation required')
                return

        invitation = ctx.group_pending_joins[gid][user_to_join]
        if isinstance(invitation, tuple) and time.time() - invitation[1] > ctx.PENDING_REQUEST_TIMEOUT_SECONDS:
            with ctx.group_pending_joins_lock:
                ctx.group_pending_joins[gid].pop(user_to_join, None)
            ctx.send_msg(client_sock, {"type": "group_join_result", "success": False, "error": "邀请已过期"})
            return
        if len(set(group['members'])) >= ctx.MAX_GROUP_MEMBERS:
            ctx.send_msg(client_sock, {'type': 'group_join_result', 'success': False,
                                   'error': ctx.GROUP_CAPACITY_ERROR})
            logging.warning('Group join rejected: capacity reached')
            return
        group["members"].append(user_to_join)
        if ctx.update_group_members_db(gid, group["members"], joined_user=user_to_join):
            with ctx.group_pending_joins_lock:
                ctx.group_pending_joins.get(gid, {}).pop(user_to_join, None)
            with ctx.groups_data_lock:
                ctx.groups_data[gid] = group # 更新内存中的群组数据
            payload = {
                "type": "group_join_result",
                "success": True,
                "gid": gid,
                "group_name": group["group_name"],
                "owner": group["owner"],
                "members": group["members"]
            }
            ctx.send_msg(client_sock, payload)
            joined_history_gid = gid
            logging.info('Group join completed')

            # 向所有成员广播群组更新信息
            update_payload = {"type": "group_update", "gid": gid, "group_name": group["group_name"], "owner": group["owner"], "members": group["members"]}
            for member in group["members"]:
                sock = ctx.get_sock_by_username(member)
                if sock:
                    ctx.send_msg(sock, update_payload)
        else:
            ctx.send_msg(client_sock, {"type": "group_join_result", "success": False, "error": "加入失败"})
            logging.error('Group join persistence failed')
    except Exception as e:
        logging.error('Group join processing failed')
        ctx.send_msg(client_sock, {"type": "group_join_result", "success": False, "error": "操作处理失败，请重试"})
    finally:
        ctx.group_ops_lock.release()
    if joined_history_gid is not None:
        ctx.send_history(client_sock, current_username, only_gid=joined_history_gid)

def handle_group_leave(ctx, client_sock, current_username, msg):
    try:
        ctx.group_ops_lock.acquire()
        gid = msg.get("gid")
        user_to_leave = current_username
        logging.info('Group leave received')

        group = ctx.get_group_db(gid)
        if not group:
            ctx.send_msg(client_sock, {"type": "group_leave_result", "success": False, "error": "群组不存在"})
            logging.warning('Group leave rejected: unknown group')
            return
        if user_to_leave not in group["members"]:
            ctx.send_msg(client_sock, {"type": "group_leave_result", "success": False, "error": "您不是该群成员"})
            logging.warning('Group leave rejected: membership required')
            return

        if user_to_leave == group["owner"]:
            ctx.send_msg(client_sock, {"type": "group_leave_result", "success": False, "error": "群主不能直接退出群聊，请先解散群聊或转让群主"})
            logging.warning('Group leave rejected: owner must transfer or disband')
            return

        group["members"].remove(user_to_leave)
        if ctx.update_group_members_db(gid, group["members"]):
            with ctx.groups_data_lock:
                ctx.groups_data[gid] = group # 更新内存中的群组数据
            ctx.send_msg(client_sock, {"type": "group_leave_result", "success": True, "gid": gid})
            logging.info('Group leave completed')

            # 向所有剩余成员广播群组更新信息
            update_payload = {"type": "group_update", "gid": gid, "group_name": group["group_name"], "owner": group["owner"], "members": group["members"]}
            for member in group["members"]:
                sock = ctx.get_sock_by_username(member)
                if sock:
                    ctx.send_msg(sock, update_payload)
        else:
            ctx.send_msg(client_sock, {"type": "group_leave_result", "success": False, "error": "退出失败"})
            logging.error('Group leave persistence failed')
    except Exception as e:
        logging.error('Group leave processing failed')
        ctx.send_msg(client_sock, {"type": "group_leave_result", "success": False, "error": "操作处理失败，请重试"})
    finally:
        ctx.group_ops_lock.release()

def handle_group_kick(ctx, client_sock, current_username, msg):
    try:
        ctx.group_ops_lock.acquire()
        gid = msg.get("gid")
        kick_user = msg.get("kick")
        requester = current_username
        logging.info('Group removal received')

        group = ctx.get_group_db(gid)
        if not group:
            ctx.send_msg(client_sock, {"type": "group_kick_result", "success": False, "error": "群组不存在"})
            logging.warning('Group removal rejected: unknown group')
            return
        if requester != group["owner"]:
            ctx.send_msg(client_sock, {"type": "group_kick_result", "success": False, "error": "只有群主才能踢人"})
            logging.warning('Group removal rejected: owner required')
            return
        if kick_user not in group["members"]:
            ctx.send_msg(client_sock, {"type": "group_kick_result", "success": False, "error": "该用户不是群成员"})
            logging.warning('Group removal rejected: target not a member')
            return
        if kick_user == requester:
            ctx.send_msg(client_sock, {"type": "group_kick_result", "success": False, "error": "不能踢自己"})
            logging.warning('Group removal rejected: self target')
            return

        group["members"].remove(kick_user)
        if ctx.update_group_members_db(gid, group["members"]):
            with ctx.groups_data_lock:
                ctx.groups_data[gid] = group # 更新内存中的群组数据

            # 通知被踢者
            kicked_sock = ctx.get_sock_by_username(kick_user)
            if kicked_sock:
                ctx.send_msg(kicked_sock, {"type": "group_kick_notification", "gid": gid, "group_name": group["group_name"]})

            # 向群主确认
            ctx.send_msg(client_sock, {"type": "group_kick_result", "success": True, "gid": gid, "kick": kick_user})
            logging.info('Group member removed')

            # 向所有剩余成员广播群组更新信息
            update_payload = {"type": "group_update", "gid": gid, "group_name": group["group_name"], "owner": group["owner"], "members": group["members"]}
            for member in group["members"]:
                sock = ctx.get_sock_by_username(member)
                if sock:
                    ctx.send_msg(sock, update_payload)
        else:
            ctx.send_msg(client_sock, {"type": "group_kick_result", "success": False, "error": "踢人失败"})
            logging.error('Group removal persistence failed')
    except Exception as e:
        logging.error('Group removal processing failed')
        ctx.send_msg(client_sock, {"type": "group_kick_result", "success": False, "error": "操作处理失败，请重试"})
    finally:
        ctx.group_ops_lock.release()

def handle_group_info(ctx, client_sock, current_username, msg):
    ctx.group_ops_lock.acquire()
    try:
        gid = msg.get("gid")
        logging.info('Group information requested')
        group = ctx.get_group_db(gid)
        if group:
            # 权限校验：仅群成员可查看群组信息（防止成员列表泄露）
            if current_username not in group["members"]:
                ctx.send_msg(client_sock, {"type": "group_info", "gid": gid, "error": "您不是该群成员，无法查看群组信息"})
                logging.warning('Group information rejected: membership required')
                return
            ctx.send_msg(client_sock, {"type": "group_info", "gid": gid, "group_name": group["group_name"], "owner": group["owner"], "members": group["members"]})
            logging.info('Group information delivered')
        else:
            ctx.send_msg(client_sock, {"type": "group_info", "gid": gid, "error": "群组不存在"})
            logging.warning('Group information rejected: unknown group')
    except Exception as e:
        logging.error('Group information processing failed')
        ctx.send_msg(client_sock, {"type": "group_info", "gid": msg.get("gid"), "error": "操作处理失败，请重试"})
    finally:
        ctx.group_ops_lock.release()

def handle_group_disband(ctx, client_sock, current_username, msg):
    try:
        ctx.group_ops_lock.acquire()
        gid = msg.get("gid")
        requester = current_username
        logging.info('Group disband received')

        group = ctx.get_group_db(gid)
        if not group:
            ctx.send_msg(client_sock, {"type": "group_disband_result", "success": False, "error": "群组不存在"})
            logging.warning('Group disband rejected: unknown group')
            return
        if requester != group["owner"]:
            ctx.send_msg(client_sock, {"type": "group_disband_result", "success": False, "error": "只有群主才能解散群聊"})
            logging.warning('Group disband rejected: owner required')
            return

        if ctx.delete_group_db(gid):
            # 从内存中删除群组数据
            with ctx.groups_data_lock:
                if gid in ctx.groups_data:
                    del ctx.groups_data[gid]
            # 清理该群的待加入记录，防止内存泄漏
            with ctx.group_pending_joins_lock:
                ctx.group_pending_joins.pop(gid, None)

            # 通知所有成员群组已解散
            disband_notification = {
                "type": "group_disband_notification",
                "gid": gid,
                "group_name": group["group_name"]
            }
            for member in group["members"]:
                sock = ctx.get_sock_by_username(member)
                if sock and sock is not client_sock:
                    ctx.send_msg(sock, disband_notification)

            ctx.send_msg(client_sock, {"type": "group_disband_result", "success": True, "gid": gid})
            logging.info('Group disband completed')
        else:
            ctx.send_msg(client_sock, {"type": "group_disband_result", "success": False, "error": "解散群聊失败"})
            logging.error('Group disband persistence failed')
    except Exception as e:
        logging.error('Group disband processing failed')
        ctx.send_msg(client_sock, {"type": "group_disband_result", "success": False, "error": "操作处理失败，请重试"})
    finally:
        ctx.group_ops_lock.release()

def handle_group_transfer(ctx, client_sock, current_username, msg):
    try:
        ctx.group_ops_lock.acquire()
        gid = msg.get("gid")
        new_owner = msg.get("new_owner")
        requester = current_username
        logging.info('Group ownership transfer received')

        group = ctx.get_group_db(gid)
        if not group:
            ctx.send_msg(client_sock, {"type": "group_transfer_result", "success": False, "error": "群组不存在"})
            logging.warning('Group ownership transfer rejected: unknown group')
            return
        if requester != group["owner"]:
            ctx.send_msg(client_sock, {"type": "group_transfer_result", "success": False, "error": "只有群主才能转让群聊"})
            logging.warning('Group ownership transfer rejected: owner required')
            return
        if new_owner not in group["members"]:
            ctx.send_msg(client_sock, {"type": "group_transfer_result", "success": False, "error": "新群主必须是群成员"})
            logging.warning('Group ownership transfer rejected: target not a member')
            return
        if new_owner == requester:
            ctx.send_msg(client_sock, {"type": "group_transfer_result", "success": False, "error": "不能转让给自己"})
            logging.warning('Group ownership transfer rejected: self target')
            return

        if ctx.transfer_group_ownership_db(gid, new_owner):
            # 更新内存中的群组数据（持锁）
            group["owner"] = new_owner
            with ctx.groups_data_lock:
                if gid in ctx.groups_data:
                    ctx.groups_data[gid] = group

            # 通知所有成员群主已变更
            transfer_notification = {
                "type": "group_transfer_notification",
                "gid": gid,
                "old_owner": requester,
                "new_owner": new_owner,
                "group_name": group["group_name"]
            }
            for member in group["members"]:
                sock = ctx.get_sock_by_username(member)
                if sock and sock is not client_sock:
                    ctx.send_msg(sock, transfer_notification)

            ctx.send_msg(client_sock, {"type": "group_transfer_result", "success": True, "gid": gid, "new_owner": new_owner})
            logging.info('Group ownership transferred')
        else:
            ctx.send_msg(client_sock, {"type": "group_transfer_result", "success": False, "error": "转让群主失败"})
            logging.error('Group ownership transfer persistence failed')
    except Exception as e:
        logging.error('Group ownership transfer processing failed')
        ctx.send_msg(client_sock, {"type": "group_transfer_result", "success": False, "error": "操作处理失败，请重试"})
    finally:
        ctx.group_ops_lock.release()

def handle_group_rename(ctx, client_sock, current_username, msg):
    try:
        ctx.group_ops_lock.acquire()
        gid = msg.get("gid")
        new_name = msg.get("new_name")
        requester = current_username
        logging.info('Group rename received')

        group = ctx.get_group_db(gid)
        if not group:
            ctx.send_msg(client_sock, {"type": "group_rename_result", "success": False, "error": "群组不存在"})
            logging.warning('Group rename rejected: unknown group')
            return
        if requester != group["owner"]:
            ctx.send_msg(client_sock, {"type": "group_rename_result", "success": False, "error": "只有群主才能修改群聊名称"})
            logging.warning('Group rename rejected: owner required')
            return
        if not isinstance(new_name, str) or not new_name.strip() or len(new_name) > ctx.GROUP_NAME_MAX_LEN:
            ctx.send_msg(client_sock, {"type": "group_rename_result", "success": False, "error": "群聊名称须为1至128个字符"})
            logging.warning('Group rename rejected: invalid name')
            return

        if ctx.update_group_name_db(gid, new_name):
            # 保存旧名称用于通知
            old_name = group["group_name"][:ctx.GROUP_NAME_MAX_LEN]
            # 更新内存中的群组数据（持锁）
            group["group_name"] = new_name
            with ctx.groups_data_lock:
                if gid in ctx.groups_data:
                    ctx.groups_data[gid] = group

            # 通知所有成员群组名称已变更
            rename_notification = {
                "type": "group_rename_notification",
                "gid": gid,
                "old_name": old_name,
                "new_name": new_name,
                "owner": requester
            }
            for member in group["members"]:
                sock = ctx.get_sock_by_username(member)
                if sock and sock is not client_sock:
                    ctx.send_msg(sock, rename_notification)

            ctx.send_msg(client_sock, {"type": "group_rename_result", "success": True, "gid": gid, "old_name": old_name, "new_name": new_name})
            logging.info('Group renamed')
        else:
            ctx.send_msg(client_sock, {"type": "group_rename_result", "success": False, "error": "修改群聊名称失败"})
            logging.error('Group rename persistence failed')
    except Exception as e:
        logging.error('Group rename processing failed')
        ctx.send_msg(client_sock, {"type": "group_rename_result", "success": False, "error": "操作处理失败，请重试"})
    finally:
        ctx.group_ops_lock.release()
