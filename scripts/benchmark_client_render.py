"""Measure synthetic long-conversation rendering without user files or a server.

Run under a desktop or xvfb-run. Python allocation figures exclude Tcl/Tk's
    native allocations and the model constructed before tracing; compare runs in the same environment rather than setting
cross-platform timing assertions in the test suite.
"""
import argparse
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import socket
import sys
from time import perf_counter
import tracemalloc

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import client
from chatroom_client.models import ChatKey, Message
from chatroom_client.preferences import PreferencesStore


def measure(count, *, lines=1, authors=1):
    root = client.tk.Tk()
    root.withdraw()
    app = client.ChatClient(root, preferences=PreferencesStore(persistent=False), encryption=False)
    app.connection.sock = socket.socket()
    app.connection.running = True
    app.state.username = 'benchmark-user'
    key = ChatKey('private', 'benchmark-peer')
    app.state.friends = [key.target]
    app.state.current_chat = key
    conversation = app.state.conversation(key)
    epoch = datetime(2026, 10, 26, tzinfo=timezone.utc)
    tracemalloc.start()
    for mid in range(2, count + 2):
        author = key.target if authors == 1 else f'synthetic-author-{mid % authors}'
        body = '\n'.join(f'Synthetic benchmark message {mid}, line {line}' for line in range(lines))
        conversation.add(Message(author, body, (epoch + timedelta(seconds=mid)).isoformat(), message_id=mid))
    model_peak = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    app.view.build_chat()
    root.geometry('1120x760')
    root.deiconify()
    root.update()
    timings = {'cached_messages': len(conversation.messages), 'cached_body_bytes': conversation.cached_bytes,
               'model_peak_python_bytes': model_peak}
    tracemalloc.start()
    try:
        for stage in ('initial', 'unchanged', 'prepend_one'):
            old_rows = list(app.view.chat_frames[key].winfo_children()) if key in app.view.chat_frames else []
            if stage == 'prepend_one':
                conversation.add(Message(key.target, 'Synthetic earlier message', message_id=1))
            start = perf_counter()
            app.view.render_conversation(key)
            root.update_idletasks()
            rows = app.view.chat_frames[key].winfo_children()
            timings[stage] = {'seconds': round(perf_counter() - start, 6), 'rows': len(rows),
                              'retained_rows': len(set(old_rows).intersection(rows))}
        timings['peak_python_bytes'] = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
        app.close()
    return timings


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--messages', type=int, nargs='+', default=[200, 1000])
    parser.add_argument('--lines', type=int, default=1)
    parser.add_argument('--authors', type=int, default=1)
    parser.add_argument('--repeat', type=int, default=1)
    args = parser.parse_args()
    if any(not 1 <= count <= 10000 for count in args.messages):
        parser.error('message counts must be in 1..10000')
    if not 1 <= args.lines <= 4 or not 1 <= args.authors <= 100 or not 1 <= args.repeat <= 10:
        parser.error('lines must be in 1..4, authors in 1..100, repeat in 1..10')
    print(json.dumps({str(count): [measure(count, lines=args.lines, authors=args.authors)
                                 for _ in range(args.repeat)] for count in args.messages}, indent=2))
