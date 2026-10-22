"""Boundaries of the password-handling WebAssembly host."""
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import wasmtime

import opaque_runtime


def module_for_response(response, *, run=None, import_text=None, memory='1'):
    data = json.dumps(response, separators=(',', ':')).encode()
    literal = ''.join('\\%02x' % x for x in data)
    imports = import_text or '(import "env" "chatroom_random" (func $random (param i32 i32) (result i32)))'
    run = run or f'i64.const {(256 << 32) | len(data)}'
    return f'''(module
      {imports}
      (memory (export "memory") {memory})
      (data (i32.const 256) "{literal}")
      (func (export "alloc") (param i32) (result i32) i32.const 1024)
      (func (export "dealloc") (param i32 i32))
      (func (export "run") (param i32 i32) (result i64) {run}))'''


class OpaqueRuntimeBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / 'test-core.wasm'
        self.patcher = patch.object(opaque_runtime, '_wasm_path', return_value=self.path)
        self.patcher.start()
        self.addCleanup(self.patcher.stop)
        self.addCleanup(opaque_runtime._compile.cache_clear)

    def write_module(self, wat):
        self.path.write_bytes(wasmtime.wat2wasm(wat))
        opaque_runtime._compile.cache_clear()

    def assert_private_failure(self, request):
        with self.assertRaises(opaque_runtime.OpaqueError) as raised:
            opaque_runtime.call(request)
        self.assertEqual(str(raised.exception), 'authentication_failed')
        self.assertNotIn('synthetic-secret', str(raised.exception))

    def test_json_response_and_independent_concurrent_stores(self):
        self.write_module(module_for_response({'ok': True}))
        with ThreadPoolExecutor(max_workers=4) as pool:
            responses = list(pool.map(opaque_runtime.call, [{'op': 'probe'}] * 8))
        self.assertEqual(responses, [{'ok': True}] * 8)

    def test_os_randomness_is_available_without_wasi(self):
        response = {'ok': True}
        size = len(json.dumps(response, separators=(',', ':')).encode())
        self.write_module(module_for_response(
            response, run=f'''i32.const 512 i32.const 32 call $random
                if unreachable end i64.const {(256 << 32) | size}'''))
        self.assertEqual(opaque_runtime.call({'op': 'probe'}), response)

    def test_guest_error_and_trap_never_echo_password(self):
        self.write_module(module_for_response({'error': 'synthetic-secret'}))
        self.assert_private_failure({'password': 'synthetic-secret'})
        self.write_module(module_for_response({}, run='unreachable'))
        self.assert_private_failure({'password': 'synthetic-secret'})

    def test_invalid_and_oversize_guest_responses_are_rejected(self):
        for run in ('i64.const 4294967295',
                    f'i64.const {(256 << 32) | (opaque_runtime.MAX_MESSAGE_SIZE + 1)}'):
            with self.subTest(run=run):
                self.write_module(module_for_response({}, run=run))
                self.assert_private_failure({'password': 'synthetic-secret'})
        self.write_module(module_for_response(['unexpected-array']))
        self.assert_private_failure({'password': 'synthetic-secret'})

    def test_memory_growth_is_hard_limited(self):
        response = {'ok': True}
        size = len(json.dumps(response, separators=(',', ':')).encode())
        self.write_module(module_for_response(
            response, memory='4096', run=f'''i32.const 1 memory.grow
            i32.const -1 i32.ne if unreachable end
            i64.const {(256 << 32) | size}'''))
        self.assertEqual(opaque_runtime.call({'op': 'probe'}), response)

    def test_unknown_imports_are_rejected(self):
        self.write_module(module_for_response(
            {}, import_text='(import "wasi_snapshot_preview1" "fd_write" (func (param i32 i32) (result i32)))'))
        self.assert_private_failure({'password': 'synthetic-secret'})

    def test_input_bounds_do_not_compile_or_expose_input(self):
        for value in ([], {'password': 'synthetic-secret' * opaque_runtime.MAX_MESSAGE_SIZE},
                      {'password': float('nan')}):
            with self.subTest(kind=type(value).__name__):
                self.assert_private_failure(value)

    def test_frozen_path_uses_packaged_core(self):
        with patch.object(opaque_runtime.sys, '_MEIPASS', self.directory.name, create=True):
            self.patcher.stop()
            try:
                self.assertEqual(opaque_runtime._wasm_path(),
                                 Path(self.directory.name) / 'chatroom_client' / 'opaque_core.wasm')
            finally:
                self.patcher.start()


if __name__ == '__main__':
    unittest.main()
