"""Measure synthetic long-conversation rendering without user files or a server.

Run under a desktop or xvfb-run. Python allocation figures exclude Tcl/Tk's
    native allocations and the model constructed before tracing; compare runs in the same environment rather than setting
cross-platform timing assertions in the test suite.
"""
import argparse
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


def measure(count):
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
    for mid in range(2, count + 2):
        conversation.add(Message(key.target, 'Synthetic benchmark message ' + str(mid), message_id=mid))
    app.view.build_chat()
    root.geometry('1120x760')
    root.deiconify()
    root.update()
    timings = {}
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
    args = parser.parse_args()
    if any(not 1 <= count <= 10000 for count in args.messages):
        parser.error('message counts must be in 1..10000')
    print(json.dumps({str(count): measure(count) for count in args.messages}, indent=2))
