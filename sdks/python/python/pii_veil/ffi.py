"""Low-level C-ABI FFI wrapper for pii-veil shared library."""

import ctypes
import os
import platform
import sys
from typing import Optional


class VeilHandle(ctypes.Structure):
    pass


class VeilStreamingRestorer(ctypes.Structure):
    pass


def _find_library() -> str:
    """Finds the pii_veil_ffi shared library across standard locations."""
    system = platform.system()
    if system == "Windows":
        lib_name = "pii_veil_ffi.dll"
    elif system == "Darwin":
        lib_name = "libpii_veil_ffi.dylib"
    else:
        lib_name = "libpii_veil_ffi.so"

    # 1. Environment variable override
    env_path = os.environ.get("PII_VEIL_LIB_PATH")
    if env_path and os.path.isfile(env_path):
        return env_path

    # 2. Check packaged directory
    current_dir = os.path.dirname(os.path.abspath(__file__))
    packaged = [
        os.path.join(current_dir, lib_name),
        os.path.join(current_dir, "lib", lib_name),
    ]
    for p in packaged:
        if os.path.isfile(p):
            return p

    # 3. Walk up parent directories looking for workspace `target/release` or `target/debug`
    search_dir = current_dir
    for _ in range(6):
        for sub in ["release", "debug"]:
            target_candidate = os.path.join(search_dir, "target", sub, lib_name)
            if os.path.isfile(target_candidate):
                return os.path.abspath(target_candidate)
        parent = os.path.dirname(search_dir)
        if parent == search_dir:
            break
        search_dir = parent

    # 4. Fallback to system search path
    return lib_name


_lib: Optional[ctypes.CDLL] = None


def get_ffi() -> ctypes.CDLL:
    """Returns the loaded ctypes CDLL instance."""
    global _lib
    if _lib is not None:
        return _lib

    lib_path = _find_library()
    try:
        _lib = ctypes.CDLL(lib_path)
    except OSError as err:
        raise RuntimeError(
            f"Could not load pii-veil native library '{lib_path}'. "
            f"Ensure pii-veil-ffi is compiled (`cargo build -p pii-veil-ffi`) or install prebuilt wheel. Error: {err}"
        ) from err

    # Declare argument and return types
    _lib.veil_new.argtypes = [ctypes.c_uint32, ctypes.c_char_p]
    _lib.veil_new.restype = ctypes.POINTER(VeilHandle)

    _lib.veil_free.argtypes = [ctypes.POINTER(VeilHandle)]
    _lib.veil_free.restype = None

    _lib.veil_redact.argtypes = [ctypes.POINTER(VeilHandle), ctypes.c_char_p]
    _lib.veil_redact.restype = ctypes.c_void_p

    _lib.veil_restore.argtypes = [ctypes.POINTER(VeilHandle), ctypes.c_char_p]
    _lib.veil_restore.restype = ctypes.c_void_p

    _lib.veil_redact_json.argtypes = [ctypes.POINTER(VeilHandle), ctypes.c_char_p]
    _lib.veil_redact_json.restype = ctypes.c_void_p

    _lib.veil_string_free.argtypes = [ctypes.c_void_p]
    _lib.veil_string_free.restype = None

    _lib.veil_vault_len.argtypes = [ctypes.POINTER(VeilHandle)]
    _lib.veil_vault_len.restype = ctypes.c_size_t

    _lib.veil_vault_clear.argtypes = [ctypes.POINTER(VeilHandle)]
    _lib.veil_vault_clear.restype = None

    _lib.veil_streaming_restorer_new.argtypes = [ctypes.POINTER(VeilHandle)]
    _lib.veil_streaming_restorer_new.restype = ctypes.POINTER(VeilStreamingRestorer)

    _lib.veil_streaming_restorer_push.argtypes = [
        ctypes.POINTER(VeilStreamingRestorer),
        ctypes.c_char_p,
    ]
    _lib.veil_streaming_restorer_push.restype = ctypes.c_void_p

    _lib.veil_streaming_restorer_finish.argtypes = [ctypes.POINTER(VeilStreamingRestorer)]
    _lib.veil_streaming_restorer_finish.restype = ctypes.c_void_p

    _lib.veil_streaming_restorer_free.argtypes = [ctypes.POINTER(VeilStreamingRestorer)]
    _lib.veil_streaming_restorer_free.restype = None

    return _lib
