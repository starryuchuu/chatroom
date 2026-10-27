"""Isolated real server for desktop end-to-end tests, alive until stdin EOF."""
from pathlib import Path
import json
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), str(ROOT / 'tests')]
from test_system_reliability import Service

service = Service('python')
try:
    service.start()
    print(json.dumps({'port': service.port}), flush=True)
    sys.stdin.read()
finally:
    service.close()
