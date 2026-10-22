"""Run the shared OPAQUE core in an isolated, bounded WebAssembly instance.

The module has no filesystem, network, clock, or WASI access. Its only host
capability is operating-system randomness. Passwords and protocol state stay
in process memory and are never passed through command-line arguments.
"""
from functools import lru_cache
import json
from pathlib import Path
import secrets
import sys
import threading


MAX_MESSAGE_SIZE = 128 * 1024
MAX_MEMORY_SIZE = 256 * 1024 * 1024
_MAX_FUEL = 20_000_000_000
_compile_lock = threading.Lock()


class OpaqueError(ValueError, RuntimeError):
    """A deliberately non-diagnostic authentication failure."""

    def __init__(self):
        super().__init__('authentication_failed')


def _wasm_path():
    root = Path(getattr(sys, '_MEIPASS', Path(__file__).resolve().parent))
    return root / 'chatroom_client' / 'opaque_core.wasm'


@lru_cache(maxsize=4)
def _compile(path):
    import wasmtime

    configuration = wasmtime.Config()
    configuration.consume_fuel = True
    engine = wasmtime.Engine(configuration)
    module = wasmtime.Module.from_file(engine, path)
    imports = module.imports
    if len(imports) != 1:
        raise OpaqueError()
    imported = imports[0]
    expected = wasmtime.FuncType(
        [wasmtime.ValType.i32(), wasmtime.ValType.i32()],
        [wasmtime.ValType.i32()],
    )
    if (imported.module != 'env' or imported.name != 'chatroom_random'
            or not isinstance(imported.type, wasmtime.FuncType)
            or imported.type.params != expected.params
            or imported.type.results != expected.results):
        raise OpaqueError()
    return engine, module


def _compiled_module():
    # lru_cache is thread-safe, but can duplicate its initial computation;
    # serialize compilation while keeping every Store entirely independent.
    with _compile_lock:
        return _compile(str(_wasm_path()))


def _range_valid(memory, store, pointer, length):
    return (isinstance(pointer, int) and isinstance(length, int)
            and pointer > 0 and length >= 0
            and pointer + length <= memory.data_len(store))


def call(request):
    """Execute one JSON operation, returning its object or a fixed error.

    A fresh Store and instance are used for every operation, so guest heap
    state cannot cross accounts, threads, or authentication attempts.
    """
    try:
        return _call(request)
    except Exception:
        # Never expose Wasmtime diagnostics, input fragments, passwords, or
        # serialized protocol state to the caller or application logs.
        raise OpaqueError() from None


def _call(request):
    import wasmtime

    if not isinstance(request, dict):
        raise OpaqueError()
    payload = json.dumps(request, ensure_ascii=False, separators=(',', ':'),
                         allow_nan=False).encode('utf-8')
    if not payload or len(payload) > MAX_MESSAGE_SIZE:
        raise OpaqueError()
    engine, module = _compiled_module()
    store = wasmtime.Store(engine)
    store.set_limits(memory_size=MAX_MEMORY_SIZE, instances=1, memories=1,
                     tables=1, table_elements=10000)
    store.set_fuel(_MAX_FUEL)
    linker = wasmtime.Linker(engine)

    def random_bytes(caller, pointer, length):
        try:
            memory = caller.get('memory')
            if (not isinstance(memory, wasmtime.Memory)
                    or not 0 <= length <= MAX_MESSAGE_SIZE
                    or not _range_valid(memory, caller, pointer, length)):
                return -1
            memory.write(caller, secrets.token_bytes(length), pointer)
            return 0
        except Exception:
            return -1

    linker.define_func(
        'env', 'chatroom_random',
        wasmtime.FuncType([wasmtime.ValType.i32(), wasmtime.ValType.i32()],
                          [wasmtime.ValType.i32()]),
        random_bytes, access_caller=True,
    )
    try:
        instance = linker.instantiate(store, module)
        exports = instance.exports(store)
        memory = exports['memory']
        allocate, release, run = exports['alloc'], exports['dealloc'], exports['run']
        if not isinstance(memory, wasmtime.Memory):
            raise OpaqueError()
        input_pointer = allocate(store, len(payload))
        if not _range_valid(memory, store, input_pointer, len(payload)):
            raise OpaqueError()
        output_pointer = output_length = None
        try:
            memory.write(store, payload, input_pointer)
            packed = run(store, input_pointer, len(payload)) & ((1 << 64) - 1)
            output_pointer, output_length = packed >> 32, packed & 0xffffffff
            if (not 0 < output_length <= MAX_MESSAGE_SIZE
                    or not _range_valid(memory, store, output_pointer, output_length)):
                raise OpaqueError()
            raw = bytes(memory.read(store, output_pointer,
                                    output_pointer + output_length))
            response = json.loads(raw.decode('utf-8'))
            if not isinstance(response, dict) or 'error' in response:
                raise OpaqueError()
            return response
        finally:
            # The instance will be destroyed even if guest cleanup traps.
            try:
                if (output_pointer is not None and output_length is not None
                        and 0 < output_length <= MAX_MESSAGE_SIZE
                        and _range_valid(memory, store, output_pointer, output_length)):
                    release(store, output_pointer, output_length)
            finally:
                release(store, input_pointer, len(payload))
    finally:
        store.close()
