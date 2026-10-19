"""Server event handlers. All handlers run on the controller's owner thread."""
import json
import logging

from .models import ChatKey, Message
from .protocol import decrypt_message


class ServerEvents:
    def __init__(self, controller):
        self.controller = controller
        self.state, self.view = controller.state, controller.view
        self.handlers = {
            'online_users': self.online_users,
            'user_groups_chunk': self.group_chunk,
            'user_groups_list': self.group_snapshot,
            'friends_list': self.friend_snapshot,
            'private_chat': self.chat_message,
            'group_chat': self.chat_message,
            'private_chat_result': self.chat_result,
            'group_chat_result': self.chat_result,
            'send_failed': self.send_failed,
            'group_create_result': self.group_created,
            'group_info': self.group_info,
            'group_invite': self.group_invite,
            'group_join_result': self.group_joined,
            'group_update': self.group_update,
            'group_leave_result': self.group_left,
            'group_kick_result': self.group_kicked,
            'group_kick_notification': self.kick_notification,
            'group_disband_result': self.group_disbanded,
            'group_disband_notification': self.disband_notification,
            'group_transfer_result': self.group_transferred,
            'group_transfer_notification': self.transfer_notification,
            'group_rename_result': self.group_renamed,
            'group_rename_notification': self.rename_notification,
            'friend_request': self.friend_request,
            'friend_response': self.friend_response,
            'friend_update': self.friend_update,
            'friend_request_result': self.friend_requested,
            'friend_response_result': self.friend_answered,
            'group_invite_result': self.group_invited,
            'group_invite_response_result': self.ignore,
            'error': self.server_error,
        }

    def handle(self, message):
        if not isinstance(message, dict) or not isinstance(message.get('type'), str):
            logging.warning('收到格式异常的消息，已忽略: %s', str(message)[:100])
            return
        if self.controller.history.handle(message):
            return
        handler = self.handlers.get(message['type'])
        if handler is None:
            logging.warning('收到未知格式消息: %s', message)
            return
        handler(message)

    def online_users(self, message):
        self.view.update_online_users(message.get('users', []))

    def friend_snapshot(self, message):
        self.state.friends = list(message.get('friends', []))
        self.view.update_friends_listbox()

    def group_chunk(self, message):
        if message.get('first'):
            self.state.group_sync_chunks.clear()
        self.state.group_sync_chunks.append(message['data'])
        if message.get('last'):
            encoded = ''.join(self.state.group_sync_chunks)
            self.state.group_sync_chunks.clear()
            self.handle(json.loads(encoded))

    def group_snapshot(self, message):
        groups = {group['gid']: dict(group) for group in message.get('groups', [])}
        for gid in self.state.groups.keys() - groups.keys():
            self.remove_group(gid, refresh=False)
        self.state.groups = groups
        self.view.refresh_groups()

    def chat_message(self, message):
        key = ChatKey('group', message['gid']) if message['type'] == 'group_chat' else ChatKey(
            'private', message.get('to') if message.get('from') == self.state.username else message.get('from'))
        session_key = self.controller.connection.session_key
        if not session_key:
            return
        try:
            content = decrypt_message(message.get('content'), session_key)
        except Exception:
            logging.exception('消息解密失败')
            content = '[消息解密失败]'
        item = Message(message.get('from'), content, message.get('timestamp', ''),
                       message.get('message_id'), message.get('from') == self.state.username)
        conversation = self.state.conversation(key)
        index = conversation.add(item)
        if index is None:
            return
        if key.kind == 'private' and key.target not in self.state.friends:
            self.state.friends.append(key.target)
            self.view.update_friends_listbox()
        if key.kind == 'group' and key.target not in self.state.groups:
            self.controller.request_group_info(key.target)
        if self.state.current_chat == key and not self.state.history_syncing:
            if index == len(conversation.messages) - 1:
                self.view.append_message(key, item)
            else:
                self.view.render_conversation(key)

    def chat_result(self, message):
        self.controller.finish_pending(message)
        if not message.get('success'):
            kind = '私聊' if message['type'] == 'private_chat_result' else '群聊'
            self.view.notify(kind + '失败', message.get('error', kind + '消息发送失败'))

    def send_failed(self, message):
        self.controller.finish_pending(message)

    def failed(self, message, title, fallback):
        if message.get('success'):
            return False
        self.view.notify(title, message.get('error', fallback))
        return True

    def set_group(self, message, default_name):
        gid = message['gid']
        self.state.groups[gid] = {'group_name': message.get('group_name', default_name),
                                  'owner': message.get('owner'), 'members': list(message.get('members', []))}
        self.view.refresh_groups()
        return gid

    def group_created(self, message):
        if self.failed(message, '创建群聊失败', '创建群聊失败'):
            return
        gid = self.set_group(message, '新群聊')
        if message.get('owner') == self.state.username:
            self.view.notify('群聊创建', f"群聊 '{self.state.groups[gid]['group_name']}' 创建成功！ID: {gid}")

    def group_info(self, message):
        gid = message.get('gid')
        if not gid or 'error' in message:
            self.state.group_info_requests.discard(gid)
            self.view.notify('群组信息', message.get('error', '获取群组信息失败'))
            return
        self.state.groups[gid] = dict(message)
        self.view.refresh_groups()
        if gid in self.state.group_info_requests:
            self.state.group_info_requests.discard(gid)
            if gid not in self.view.groups_ui.windows:
                self.view.groups_ui.show(gid)

    def group_joined(self, message):
        if self.failed(message, '加入群聊失败', '加入群聊失败'):
            return
        gid = self.set_group(message, '未知群聊')
        self.view.notify('加入群聊', f"成功加入群聊: {self.state.groups[gid]['group_name']}")

    def group_update(self, message):
        self.set_group(message, message['gid'])

    def remove_group(self, gid, *, refresh=True):
        selected = self.state.current_chat == ChatKey('group', gid)
        self.state.remove_group(gid)
        self.view.remove_conversation(ChatKey('group', gid))
        if selected:
            self.view.clear_selection()
        if refresh:
            self.view.refresh_groups()

    def group_left(self, message):
        if not self.failed(message, '退出群聊失败', '退出群聊失败'):
            self.remove_group(message['gid'])
            self.view.notify('退出群聊', f"成功退出群聊: {message['gid']}")

    def group_kicked(self, message):
        if self.failed(message, '踢出成员失败', '踢出成员失败'):
            return
        gid, kicked = message['gid'], message.get('kick')
        group = self.state.groups.get(gid)
        if group is not None and kicked in group.get('members', []):
            group['members'].remove(kicked)
        if kicked == self.state.username:
            self.remove_group(gid)
        else:
            self.view.refresh_groups()
        self.view.notify('踢出成员', f'已将 {kicked} 从群聊 {gid} 踢出')

    def kick_notification(self, message):
        self.remove_group(message['gid'])
        self.view.notify('群聊通知', f"您已被从群聊 {message.get('group_name')} 移除")

    def group_disbanded(self, message):
        if not self.failed(message, '解散群聊失败', '解散群聊失败'):
            self.remove_group(message['gid'])
            self.view.notify('解散群聊', '群聊已成功解散')

    def disband_notification(self, message):
        self.remove_group(message['gid'])
        self.view.notify('群聊通知', f"群聊 {message.get('group_name')} 已被解散")

    def group_transferred(self, message):
        if self.failed(message, '转让群主失败', '转让群主失败'):
            return
        group = self.state.groups.get(message['gid'])
        if group is not None:
            group['owner'] = message.get('new_owner')
        self.view.refresh_groups()
        self.view.notify('转让群主', f"群主已成功转让给 {message.get('new_owner')}")

    def transfer_notification(self, message):
        group = self.state.groups.get(message['gid'])
        if group is not None:
            group['owner'] = message.get('new_owner')
        self.view.refresh_groups()
        self.view.notify('群聊通知', f"群聊 {message.get('group_name')} 的群主已由 {message.get('old_owner')} 转让给 {message.get('new_owner')}")

    def group_renamed(self, message):
        if self.failed(message, '修改群聊失败', '修改群聊失败'):
            return
        gid, name = message['gid'], message.get('new_name')
        if gid in self.state.groups:
            self.state.groups[gid]['group_name'] = name
        self.view.refresh_groups()
        self.view.notify('修改群聊名称', f"群聊名称已从 '{message.get('old_name', gid)}' 修改为 '{name}'")

    def rename_notification(self, message):
        gid = message['gid']
        if gid in self.state.groups:
            self.state.groups[gid]['group_name'] = message.get('new_name')
        self.view.refresh_groups()
        self.view.notify('群聊通知', f"群聊名称已由群主 {message.get('owner')} 从 '{message.get('old_name')}' 修改为 '{message.get('new_name')}'")

    def friend_request(self, message):
        username = message.get('from')
        self.view.ask_request(('friend', username), '好友申请', f'{username} 请求添加你为好友',
                              lambda accepted: self.controller.try_send({'type': 'friend_response', 'to': username, 'accepted': accepted}))

    def friend_response(self, message):
        username = message.get('from')
        if message.get('accepted'):
            self.friend_update({'friend': username})
            self.view.notify('好友申请', f'{username} 已同意你的好友申请！')
        else:
            self.view.notify('好友申请', f'{username} 拒绝了你的好友申请')

    def friend_update(self, message):
        friend = message.get('friend')
        if friend and friend not in self.state.friends:
            self.state.friends.append(friend)
            self.view.update_friends_listbox()

    def friend_requested(self, message):
        if not self.failed(message, '好友申请失败', '好友申请失败'):
            self.view.notify('好友申请', message.get('message', '好友申请发送成功'))

    def friend_answered(self, message):
        self.failed(message, '好友响应失败', '好友响应失败')

    def group_invite(self, message):
        gid = message.get('gid')
        self.view.ask_request(('group', gid), '群聊邀请', f"{message.get('from')} 邀请你加入群聊",
                              lambda accepted: self.controller.try_send({'type': 'group_join' if accepted else 'group_invite_response',
                                                                         'gid': gid, 'accepted': accepted}))

    def group_invited(self, message):
        self.failed(message, '群邀请失败', '群邀请失败')

    def server_error(self, message):
        self.controller.disconnect()
        self.view.notify('服务器通知', message.get('message', '服务器错误'))

    @staticmethod
    def ignore(message):
        pass
