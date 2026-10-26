"""Bounded plaintext caches retain pagination and independent unread metadata."""
import unittest

from chatroom_client.models import ChatKey, ClientState, Conversation, Message


class MessageCacheTests(unittest.TestCase):
    def test_ten_thousand_messages_keep_bounded_latest_body_and_dedup_indexes(self):
        conversation = Conversation(exhausted=True)
        for mid in range(1, 10001):
            conversation.add(Message('synthetic-peer', f'Synthetic message {mid}', message_id=mid))
        self.assertEqual(len(conversation.messages), conversation.MAX_MESSAGES)
        self.assertEqual(len(conversation._seen), conversation.MAX_MESSAGES)
        self.assertEqual(conversation.before_id, 10001 - conversation.MAX_MESSAGES)
        self.assertEqual(conversation.latest_message.message_id, 10000)
        self.assertFalse(conversation.exhausted)
        self.assertTrue(conversation.older_evicted)

    def test_unicode_body_budget_also_bounds_fewer_large_messages(self):
        conversation = Conversation()
        conversation.MAX_BYTES = 120000
        for mid in range(100):
            conversation.add(Message('synthetic-peer', '界' * 20000, message_id=mid))
        self.assertLessEqual(conversation.cached_bytes, conversation.MAX_BYTES)
        self.assertEqual(conversation.message_ids, [99])
        self.assertEqual(conversation.cached_bytes, 60128)

    def test_older_page_evicts_newer_body_without_rewinding_retry_cursor_or_summary(self):
        conversation = Conversation(cursor=10, read_id=12, unread_ids={13})
        conversation.MAX_MESSAGES = 4
        for mid in range(10, 14):
            conversation.add(Message('peer', f'Synthetic {mid}', message_id=mid))
        for mid in (9, 8):
            conversation.add(Message('peer', f'Synthetic {mid}', message_id=mid), retain='older')
        self.assertEqual(conversation.message_ids, [8, 9, 10, 11])
        self.assertTrue(conversation.newer_evicted)
        self.assertEqual(conversation.cursor, 10)
        self.assertEqual(conversation.latest_message.message_id, 13)
        self.assertEqual(conversation.unread_ids, {13})
        self.assertEqual(conversation.read_id, 12)

    def test_global_budget_evicts_least_recent_inactive_cache_and_retains_unread(self):
        state = ClientState()
        state.MAX_CACHED_MESSAGES = 5
        keys = [ChatKey('private', name) for name in ('a', 'b', 'c')]
        for key in keys:
            conversation = state.conversation(key)
            for mid in (1, 2):
                conversation.add(Message(key.target, 'Synthetic cache body', message_id=mid))
        state.current_chat = keys[-1]
        state.conversation(keys[0])
        victim = state.conversations[keys[1]]
        victim.read_id, victim.unread_ids = 91, {92}
        self.assertEqual(state.enforce_cache_limits(), [keys[1]])
        self.assertFalse(victim.messages or victim._seen)
        self.assertTrue(victim.cache_evicted)
        self.assertIsNone(victim.cursor)
        self.assertEqual((victim.read_id, victim.unread_ids), (91, {92}))
        self.assertEqual(victim.preview, 'Synthetic cache body')
        self.assertEqual(len(state.conversations[keys[-1]].messages), 2)

    def test_evicted_body_can_be_loaded_again_without_permanent_seen_tombstones(self):
        conversation = Conversation()
        conversation.MAX_MESSAGES = 2
        for mid in range(1, 5):
            conversation.add(Message('peer', str(mid), message_id=mid))
        self.assertNotIn(1, conversation._seen)
        self.assertIsNotNone(conversation.add(Message('peer', '1', message_id=1), retain='older'))
        self.assertEqual(conversation.message_ids, [1, 3])
        self.assertEqual(len(conversation._sizes), len(conversation.messages))

    def test_partial_replay_after_eviction_exposes_known_newer_history(self):
        conversation = Conversation()
        conversation.add(Message('peer', 'Known newest summary', message_id=500))
        conversation.clear_cache()
        conversation.add(Message('peer', 'Partial older replay', message_id=100))
        self.assertTrue(conversation.newer_evicted)
        self.assertEqual(conversation.latest_message.message_id, 500)
        conversation.add(Message('peer', 'Known newest summary', message_id=500))
        self.assertFalse(conversation.newer_evicted)

    def test_clear_for_latest_reload_keeps_markers_but_resets_page_exhaustion(self):
        conversation = Conversation(cursor=4, exhausted=True, read_id=3, unread_ids={4})
        conversation.add(Message('peer', 'Synthetic preview', message_id=4))
        conversation.clear_cache(reload_latest=True)
        self.assertFalse(conversation.messages or conversation.exhausted or conversation.cache_evicted)
        self.assertEqual(conversation.before_id, 9223372036854775807)
        self.assertEqual(conversation.unread_ids, {4})
        self.assertEqual(conversation.latest_message.message_id, 4)

    def test_verified_recovery_updates_budget_and_can_still_trim_other_rows(self):
        conversation = Conversation()
        conversation.MAX_BYTES = 1000
        conversation.add(Message('peer', 'failed', message_id=1, encryption='failed'))
        conversation.add(Message('peer', 'short', message_id=2))
        conversation.add(Message('peer', 'x' * 800, message_id=1, encryption='e2ee'), retain='older')
        self.assertLessEqual(conversation.cached_bytes, 1000)
        self.assertEqual(conversation.message_ids, [1])
        self.assertEqual(conversation.messages[0].encryption, 'e2ee')

    def test_global_byte_budget_drops_inactive_body_without_affecting_pending_history(self):
        state = ClientState()
        state.MAX_CACHED_BYTES = 500
        a, b = ChatKey('private', 'a'), ChatKey('private', 'b')
        state.conversation(a).add(Message('a', 'x' * 400, message_id=1))
        state.conversation(b).add(Message('b', 'x' * 100, message_id=2))
        state.current_chat = state.pending_history = b
        self.assertEqual(state.enforce_cache_limits(), [a])
        self.assertEqual(state.pending_history, b)
        self.assertEqual(state.conversations[b].message_ids, [2])
