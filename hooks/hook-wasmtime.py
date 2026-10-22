"""Include Wasmtime's native library on every supported desktop platform.

PyInstaller's default Linux library glob is ``lib*.so``, whereas Wasmtime
ships ``_libwasmtime.so``. Without this explicit pattern, --collect-all
copies the Python modules but omits the library loaded through ctypes.
"""
from PyInstaller.utils.hooks import collect_dynamic_libs


binaries = collect_dynamic_libs(
    'wasmtime', search_patterns=['*.so', '*.dll', '*.dylib'],
)
