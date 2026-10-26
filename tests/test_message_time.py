"""Aware timestamps display locally; legacy wall times remain explicitly unknown."""
from contextlib import contextmanager
from datetime import datetime, timedelta
import os
import time
import unittest
from unittest.mock import patch

import test_client_scrolling as scrolling
from chatroom_client.message_rows import continues, full_time, message_time
from chatroom_client.models import ChatKey, Message


@contextmanager
def local_timezone(name):
    try:
        with patch.dict(os.environ, {'TZ': name}):
            time.tzset()
            yield
    finally:
        time.tzset()


class MessageTimeTests(unittest.TestCase):
    def test_aware_time_converts_to_local_and_keeps_original_in_details(self):
        stamp = '2026-10-26T22:15:00Z'
        message = Message('peer', 'Synthetic time body', stamp)
        self.assertEqual(message_time(message), datetime.fromisoformat(stamp).astimezone())
        self.assertIn('本地时间', full_time(message))
        self.assertIn(stamp, full_time(message))

    def test_legacy_time_is_not_assigned_a_guessed_timezone(self):
        message = Message('peer', 'Synthetic legacy body', '2020-01-02 03:04:05')
        self.assertIsNone(message_time(message).tzinfo)
        self.assertIn('时区未记录', full_time(message))
        self.assertIn(message.timestamp, full_time(message))
        aware = Message('peer', 'Synthetic aware body', '2020-01-02T03:05:05Z')
        self.assertFalse(continues(message, aware))

    def test_offsets_representing_same_instant_group_and_invalid_times_are_safe(self):
        first = Message('peer', 'Synthetic UTC', '2026-10-26T00:00:00Z')
        second = Message('peer', 'Synthetic offset', '2026-10-26T08:01:00+08:00')
        self.assertTrue(continues(first, second))
        for stamp in ('invalid', '', None):
            message = Message('peer', 'Synthetic invalid time', stamp)
            self.assertIsNone(message_time(message))
            self.assertIsInstance(full_time(message), str)

    @unittest.skipUnless(hasattr(time, 'tzset'), 'Process timezone selection requires tzset')
    def test_local_dates_and_dst_use_offset_of_each_message(self):
        with local_timezone('Asia/Shanghai'):
            value = message_time(Message('peer', '', '2026-10-26T22:15:00Z'))
            self.assertEqual((value.day, value.hour), (27, 6))
            self.assertEqual(value.utcoffset(), timedelta(hours=8))
        with local_timezone('America/New_York'):
            summer = message_time(Message('peer', '', '2026-07-01T12:00:00Z'))
            winter = message_time(Message('peer', '', '2026-01-01T12:00:00Z'))
            self.assertEqual((summer.hour, winter.hour), (8, 7))


class MessageTimeViewTests(unittest.TestCase):
    setUp = scrolling.ClientScrollingTests.setUp
    tearDown = scrolling.ClientScrollingTests.tearDown
    wait_for_geometry = scrolling.ClientScrollingTests.wait_for_geometry

    def test_date_header_clock_and_inline_details_use_local_time(self):
        stamp = '2026-10-26T22:15:00Z'
        expected = datetime.fromisoformat(stamp).astimezone()
        key = ChatKey('private', 'synthetic-peer')
        self.app.state.conversation(key).add(Message(key.target, 'Synthetic timezone body', stamp, 1))
        self.app.select_chat(key)
        self.root.update()
        row = self.view.current_chat_frame.pack_slaves()[0]
        self.assertEqual(row._chat_date.cget('text'), f'{expected.year:04d}年{expected.month:02d}月{expected.day:02d}日')
        self.assertEqual(row._chat_meta.cget('text'), expected.strftime('%H:%M'))
        self.view.message_rows.toggle_details(row)
        self.assertIn(expected.isoformat(' ', timespec='seconds'), row._chat_details.cget('text'))
        self.assertIn(stamp, row._chat_details.cget('text'))
