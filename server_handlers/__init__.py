"""Business dispatch after authentication; no socket or database initialization."""
import logging

from . import friends, groups, messaging
from .services import HandlerServices


HANDLERS = {
    'e2ee_identity_publish': messaging.handle_e2ee_identity_publish,
    'e2ee_keys_request': messaging.handle_e2ee_keys_request,
    'sync_request': messaging.handle_sync_request,
    'history_request': messaging.handle_history_request,
    'friend_request': friends.handle_friend_request,
    'friend_response': friends.handle_friend_response,
    'private_chat': messaging.handle_private_chat,
    'group_create': groups.handle_group_create,
    'group_chat': messaging.handle_group_chat,
    'group_invite': groups.handle_group_invite,
    'group_invite_response': groups.handle_group_invite_response,
    'group_join': groups.handle_group_join,
    'group_leave': groups.handle_group_leave,
    'group_kick': groups.handle_group_kick,
    'group_info': groups.handle_group_info,
    'group_disband': groups.handle_group_disband,
    'group_transfer': groups.handle_group_transfer,
    'group_rename': groups.handle_group_rename,
}


def dispatch(services, client_sock, username, message):
    kind = message.get("type")
    handler = HANDLERS.get(kind) if isinstance(kind, str) else None
    if handler is None:
        logging.warning("Unknown client message type rejected")
        return False
    handler(services, client_sock, username, message)
    return True
