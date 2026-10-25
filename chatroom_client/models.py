"""Client session data. This module has no UI, socket or encryption dependencies."""
from bisect import bisect_left, bisect_right
from dataclasses import dataclass, field
from typing import Literal


@dataclass(frozen=True)
class ChatKey:
    kind: Literal['private', 'group']
    target: str

    def __post_init__(self):
        if self.kind not in ('private', 'group') or not isinstance(self.target, str) or not self.target:
            raise ValueError('Invalid conversation')


@dataclass(frozen=True)
class Message:
    author: str
    content: str
    timestamp: str = ''
    message_id: int | None = None
    is_self: bool = False
    encryption: str = 'legacy'


@dataclass
class Conversation:
    messages: list[Message] = field(default_factory=list)
    cursor: int | None = None
    exhausted: bool = False
    _order: list[int] = field(default_factory=list, repr=False)
    _seen: set[int] = field(default_factory=set, repr=False)
    read_id: int = 0
    unread_ids: set[int] = field(default_factory=set, repr=False)
    _anonymous_unread: int = field(default=0, repr=False)

    @property
    def unread_count(self):
        return len(self.unread_ids) + self._anonymous_unread

    @property
    def latest_message(self):
        return self.messages[-1] if self.messages else None

    @property
    def preview(self):
        """A short, single-line preview kept in memory with the conversation."""
        message = self.latest_message
        if message is None:
            return ''
        text = ' '.join(message.content.split())
        return text if len(text) <= 60 else text[:59] + '…'

    @property
    def message_ids(self):
        return [message.message_id for message in self.messages if type(message.message_id) is int]

    @property
    def before_id(self):
        if self.cursor is not None:
            return self.cursor
        return min(self.message_ids, default=9223372036854775807)

    def add(self, message):
        """Insert by server ID, or recover a failed entry after E2EE verification."""
        message_id = message.message_id
        numbered = type(message_id) is int
        if numbered and message_id in self._seen:
            if message.encryption == 'e2ee':
                for index in range(bisect_left(self._order, message_id), len(self.messages)):
                    if self._order[index] != message_id:
                        break
                    previous = self.messages[index]
                    if type(previous.message_id) is int and previous.message_id == message_id:
                        if previous.encryption == 'failed' and previous.author == message.author:
                            self.messages[index] = message
                            return index
                        break
            return None
        order = message_id if numbered else (self._order[-1] + 1 if self._order else 0)
        index = bisect_right(self._order, order)
        self._order.insert(index, order)
        self.messages.insert(index, message)
        if numbered:
            self._seen.add(message_id)
        return index


@dataclass
class ClientState:
    username: str | None = None
    friends: list[str] = field(default_factory=list)
    groups: dict[str, dict] = field(default_factory=dict)
    conversations: dict[ChatKey, Conversation] = field(default_factory=dict)
    current_chat: ChatKey | None = None
    pending_messages: dict[str, str] = field(default_factory=dict)
    history_syncing: bool = False
    pending_history: ChatKey | None = None
    group_info_requests: set[str] = field(default_factory=set)
    group_sync_chunks: list[str] = field(default_factory=list)
    group_generations: dict[str, int] = field(default_factory=dict, repr=False)
    drafts: dict[tuple[str, int, str], str] = field(default_factory=dict)

    @property
    def total_unread(self):
        return sum(conversation.unread_count for conversation in self.conversations.values())

    def conversation(self, key):
        return self.conversations.setdefault(key, Conversation())

    def remove_group(self, gid):
        key = ChatKey('group', gid)
        self.group_generations[gid] = self.group_generations.get(gid, 0) + 1
        self.groups.pop(gid, None)
        self.conversations.pop(key, None)
        self.group_info_requests.discard(gid)
        if self.pending_history == key:
            self.pending_history = None
            self.history_syncing = False
        if self.current_chat == key:
            self.current_chat = None

    def reset_session(self, username=None):
        """Clear account data together; endpoint/account drafts outlive a login."""
        self.username = username
        self.friends.clear()
        self.groups.clear()
        self.conversations.clear()
        self.current_chat = None
        self.pending_messages.clear()
        self.history_syncing = False
        self.pending_history = None
        self.group_info_requests.clear()
        self.group_sync_chunks.clear()
        self.group_generations.clear()
