"""Bounded, plain-text notification previews, prepared on the core owner thread."""
import unicodedata


def single_line(value, limit):
    # Bound work before normalization; strip invisible direction overrides as well
    # as control characters. Keep ZWJ so emoji sequences remain intact.
    text = ''.join(char for char in str(value or '')[:2048]
                   if char.isspace() or (unicodedata.category(char) not in ('Cc', 'Cs')
                       and char not in '\u061c\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069'))
    text = ' '.join(text.split())
    return text if len(text) <= limit else text[:limit - 1] + '…'


def message_preview(key, message, groups, preview):
    if preview == 'generic':
        return 'Chatroom 新消息', '你收到了一条新消息，请打开聊天室查看。'
    author = single_line(message.author, 48) or '联系人'
    title = author
    if key.kind == 'group':
        title = single_line(groups.get(key.target, {}).get('group_name'), 64) or '群聊'
    if message.encryption == 'failed':
        body = '消息未通过安全验证，请打开会话查看。'
    elif preview == 'message':
        body = single_line(message.content, 140) or '收到一条新消息'
    else:
        body = '发来一条新消息'
    if key.kind == 'group':
        body = author + '：' + body
    return title, body
