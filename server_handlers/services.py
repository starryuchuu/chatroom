"""Dependencies captured at dispatch; shared state and lock objects retain ownership."""
from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True, repr=False)
class HandlerServices:
    GROUP_CAPACITY_ERROR: str
    GROUP_NAME_MAX_LEN: int
    MAX_GROUP_MEMBERS: int
    PENDING_REQUEST_TIMEOUT_SECONDS: int
    chat_content: Callable
    create_group_db: Callable
    delete_group_db: Callable
    get_group_db: Callable
    get_sock_by_username: Callable
    group_members_are_friends: Callable
    group_ops_lock: object
    group_pending_joins: dict
    group_pending_joins_lock: object
    groups_data: dict
    groups_data_lock: object
    handle_e2ee_identity: Callable
    handle_e2ee_keys: Callable
    pending_friend_requests: dict
    pending_friend_requests_lock: object
    prepare_chat_content: Callable
    save_friend_relationship: Callable
    save_message: Callable
    send_history: Callable
    send_history_error: Callable
    send_msg: Callable
    send_sync: Callable
    session_keys: dict
    transfer_group_ownership_db: Callable
    update_group_members_db: Callable
    update_group_name_db: Callable
    user_exists: Callable
    user_friends: dict
    user_friends_lock: object
    valid_history_request_id: Callable
    validate_group_creation: Callable
