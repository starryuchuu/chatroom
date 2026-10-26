"""Client session data. This module has no UI, socket or encryption dependencies."""
from bisect import bisect_left, bisect_right
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import ClassVar, Literal


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
    MAX_MESSAGES: ClassVar[int] = 2000
    MAX_BYTES: ClassVar[int] = 8 * 1024 * 1024
    messages: list[Message] = field(default_factory=list)
    cursor: int | None = None
    exhausted: bool = False
    _order: list[int] = field(default_factory=list, repr=False)
    _seen: set[int] = field(default_factory=set, repr=False)
    read_id: int = 0
    unread_ids: set[int] = field(default_factory=set, repr=False)
    _anonymous_unread: int = field(default=0, repr=False)
    _sizes: list[int] = field(default_factory=list, repr=False)
    cached_bytes: int = 0
    older_evicted: bool = False
    newer_evicted: bool = False
    cache_evicted: bool = False
    _summary: Message | None = field(default=None, repr=False)
    _summary_order: int | None = field(default=None, repr=False)
    _used: int = field(default=0, repr=False)

    @property
    def unread_count(self):
        return len(self.unread_ids) + self._anonymous_unread

    @property
    def latest_message(self):
        return (self.messages[-1] if self._order and self._order[-1] == self._summary_order
                else self._summary)

    @property
    def preview(self):
        """A short, single-line preview kept in memory with the conversation."""
        return self._summary.content if self._summary is not None else ''

    @property
    def message_ids(self):
        return [message.message_id for message in self.messages if type(message.message_id) is int]

    @property
    def before_id(self):
        if self.cursor is not None:
            return self.cursor
        return min(self.message_ids, default=9223372036854775807)

    def add(self, message, *, retain='latest'):
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
                            size = len(message.content.encode('utf-8')) + 128
                            self.cached_bytes += size - self._sizes[index]
                            self._sizes[index] = size
                            self.messages[index] = message
                            self._update_summary(message, self._order[index])
                            return self._trim(index, retain)
                        break
            return None
        order = message_id if numbered else (self._order[-1] + 1 if self._order else 0)
        index = bisect_right(self._order, order)
        self._order.insert(index, order)
        self.messages.insert(index, message)
        size = len(message.content.encode('utf-8')) + 128
        self._sizes.insert(index, size)
        self.cached_bytes += size
        self._update_summary(message, order)
        self.cache_evicted = False
        if numbered:
            self._seen.add(message_id)
        return self._trim(index, retain)

    def _update_summary(self, message, order):
        if self._summary_order is None or order >= self._summary_order:
            self._summary_order = order
            text = ' '.join(message.content[:256].split())
            text = text if len(text) <= 60 else text[:59] + '…'
            self._summary = Message(message.author, text, message.timestamp, message.message_id,
                                    message.is_self, message.encryption)

    def _trim(self, index, retain):
        start, end, size = 0, len(self.messages), self.cached_bytes
        while end > start and (end - start > self.MAX_MESSAGES or size > self.MAX_BYTES):
            if retain == 'older':
                end -= 1
                size -= self._sizes[end]
            else:
                size -= self._sizes[start]
                start += 1
        if start or end < len(self.messages):
            self.older_evicted |= start > 0
            self.newer_evicted |= end < len(self.messages)
            self.messages, self._order, self._sizes = (values[start:end] for values in
                                                      (self.messages, self._order, self._sizes))
            self._seen = {item.message_id for item in self.messages if type(item.message_id) is int}
            self.cached_bytes = size
            if start:
                self.cursor = min(self.message_ids, default=None)
                self.exhausted = False
        self.newer_evicted = bool(self._summary is not None and
                                  (not self._order or self._summary_order > self._order[-1]))
        return index - start if start <= index < end else -1

    def clear_cache(self, *, reload_latest=False):
        self.messages.clear()
        self._order.clear()
        self._sizes.clear()
        self._seen.clear()
        self.cached_bytes = 0
        self.cursor = None
        self.exhausted = False
        self.cache_evicted = not reload_latest
        self.older_evicted = self.newer_evicted = False


@dataclass
class ClientState:
    MAX_CACHED_MESSAGES: ClassVar[int] = 8000
    MAX_CACHED_BYTES: ClassVar[int] = 32 * 1024 * 1024
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
    drafts: dict[tuple[str, int, str, ChatKey | None], str] = field(default_factory=dict, repr=False)
    _cache_clock: int = field(default=0, repr=False)
    _received: OrderedDict = field(default_factory=OrderedDict, repr=False)

    def observe_message(self, key, message_id):
        if type(message_id) is not int:
            return True
        marker = key, message_id
        fresh = marker not in self._received
        self._received[marker] = None
        self._received.move_to_end(marker)
        while len(self._received) > 10000:
            self._received.popitem(last=False)
        return fresh

    @property
    def total_unread(self):
        return sum(conversation.unread_count for conversation in self.conversations.values())

    def conversation(self, key):
        conversation = self.conversations.setdefault(key, Conversation())
        self._cache_clock += 1
        conversation._used = self._cache_clock
        return conversation

    def enforce_cache_limits(self):
        count = sum(len(item.messages) for item in self.conversations.values())
        size = sum(item.cached_bytes for item in self.conversations.values())
        evicted = []
        inactive = sorted(((key, item) for key, item in self.conversations.items()
                           if key != self.current_chat and key != self.pending_history and item.messages),
                          key=lambda pair: pair[1]._used)
        for key, item in inactive:
            if count <= self.MAX_CACHED_MESSAGES and size <= self.MAX_CACHED_BYTES:
                break
            count -= len(item.messages)
            size -= item.cached_bytes
            item.clear_cache()
            evicted.append(key)
        return evicted

    def remove_group(self, gid):
        key = ChatKey('group', gid)
        self.group_generations[gid] = self.group_generations.get(gid, 0) + 1
        self.groups.pop(gid, None)
        self.conversations.pop(key, None)
        self.group_info_requests.discard(gid)
        for marker in list(self._received):
            if marker[0] == key:
                self._received.pop(marker)
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
        self._received.clear()
