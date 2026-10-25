"""Immutable request ownership, shared by owner-thread async controllers."""
from dataclasses import dataclass, field
import uuid


@dataclass(frozen=True)
class SessionContext:
    sock: object = field(repr=False)
    username: str | None
    key: object = None
    group_generation: int | None = None

    @classmethod
    def capture(cls, state, connection, key=None):
        generation = (state.group_generations.get(key.target, 0)
                      if key is not None and key.kind == 'group' else None)
        return cls(connection.sock, state.username, key, generation)

    def matches(self, state, connection):
        return (connection.sock is self.sock and state.username == self.username
                and (self.group_generation is None or (
                    self.key.target in state.groups
                    and state.group_generations.get(self.key.target, 0) == self.group_generation)))


@dataclass(frozen=True)
class RequestToken:
    context: SessionContext | None = None
    request_id: str = field(default_factory=lambda: uuid.uuid4().hex)

    def matches(self, request_id):
        return isinstance(request_id, str) and request_id == self.request_id
