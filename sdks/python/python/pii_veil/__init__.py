"""GLASTOR® pii-veil — Sub-millisecond Reversible PII & Secret Anonymizer for Python.

Supports Luhn Credit Cards, Mod-97 IBAN, DNI, CUIT, Regional IDs, DB URIs, and API Keys.
Integrates with LangChain, LlamaIndex, CrewAI, OpenAI, and Anthropic.
"""

from __future__ import annotations

import ctypes
from enum import IntEnum
from typing import Any, Dict, Iterator, Optional, Union

from .ffi import get_ffi, VeilHandle, VeilStreamingRestorer


class RedactionMode(IntEnum):
    """Anonymization mode."""
    PLACEHOLDER = 0  # Reversible semantic placeholders: [CREDIT_CARD_1], [EMAIL_1]
    SYNTHETIC = 1    # Valid format-preserving synthetic data (valid Luhn & IBAN checksums)
    MASK = 2         # One-way irreversible masking: 4532-****-****-0366


def _free_and_decode(ffi: Any, ptr: Optional[int]) -> str:
    """Reads a C string pointer, copies it to Python str, and frees the C memory."""
    if not ptr:
        return ""
    try:
        val = ctypes.cast(ptr, ctypes.c_char_p).value
        return val.decode("utf-8") if val else ""
    finally:
        ffi.veil_string_free(ptr)


class StreamingRestorer:
    """Restores placeholders split across mid-token streaming LLM chunks."""

    def __init__(self, restorer_ptr: Any, ffi: Any) -> None:
        self._ptr = restorer_ptr
        self._ffi = ffi

    def push(self, chunk: str) -> str:
        """Pushes an incoming streaming chunk and returns newly restored text."""
        if not self._ptr:
            return chunk
        chunk_bytes = chunk.encode("utf-8")
        raw_ptr = self._ffi.veil_streaming_restorer_push(self._ptr, chunk_bytes)
        return _free_and_decode(self._ffi, raw_ptr)

    def finish(self) -> str:
        """Flushes any remaining buffered tokens at the end of the stream."""
        if not self._ptr:
            return ""
        raw_ptr = self._ffi.veil_streaming_restorer_finish(self._ptr)
        return _free_and_decode(self._ffi, raw_ptr)

    def close(self) -> None:
        """Frees the native streaming restorer."""
        if self._ptr:
            self._ffi.veil_streaming_restorer_free(self._ptr)
            self._ptr = None

    def __enter__(self) -> "StreamingRestorer":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    def __del__(self) -> None:
        self.close()


class Veil:
    """Veil DLP Engine with session-isolated reversible Vault."""

    def __init__(
        self,
        mode: Union[RedactionMode, int] = RedactionMode.PLACEHOLDER,
        secret_key: Optional[str] = None,
    ) -> None:
        self._handle = None
        self._ffi = get_ffi()
        mode_val = int(mode)
        key_bytes = secret_key.encode("utf-8") if secret_key else None
        self._handle = self._ffi.veil_new(mode_val, key_bytes)
        if not self._handle:
            raise RuntimeError("Failed to allocate native VeilHandle")

    def redact(self, text: str) -> str:
        """Anonymizes sensitive entities in `text` and records reverse mappings in vault."""
        if not text:
            return ""
        raw_ptr = self._ffi.veil_redact(self._handle, text.encode("utf-8"))
        return _free_and_decode(self._ffi, raw_ptr)

    def restore(self, text: str) -> str:
        """Restores placeholders in `text` back to original raw values using the session vault."""
        if not text:
            return ""
        raw_ptr = self._ffi.veil_restore(self._handle, text.encode("utf-8"))
        return _free_and_decode(self._ffi, raw_ptr)

    def redact_json(self, json_str: str) -> str:
        """Redacts JSON payload preserving keys and sanitizing sensitive values."""
        if not json_str:
            return "{}"
        raw_ptr = self._ffi.veil_redact_json(self._handle, json_str.encode("utf-8"))
        return _free_and_decode(self._ffi, raw_ptr)

    def streaming_restorer(self) -> StreamingRestorer:
        """Creates a streaming restorer snapshot for token-by-token LLM SSE streams."""
        ptr = self._ffi.veil_streaming_restorer_new(self._handle)
        if not ptr:
            raise RuntimeError("Failed to allocate native StreamingRestorer")
        return StreamingRestorer(ptr, self._ffi)

    def restore_stream(self, chunk_iterator: Iterator[str]) -> Iterator[str]:
        """Generator that restores chunks from any streaming LLM iterable on the fly."""
        with self.streaming_restorer() as restorer:
            for chunk in chunk_iterator:
                restored = restorer.push(chunk)
                if restored:
                    yield restored
            tail = restorer.finish()
            if tail:
                yield tail

    @property
    def vault_size(self) -> int:
        """Number of entities currently protected in the session vault."""
        return int(self._ffi.veil_vault_len(self._handle))

    def clear(self) -> None:
        """Clears all mappings in the session vault."""
        self._ffi.veil_vault_clear(self._handle)

    def close(self) -> None:
        """Frees the native handle."""
        if self._handle:
            self._ffi.veil_free(self._handle)
            self._handle = None

    def __enter__(self) -> "Veil":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    def __del__(self) -> None:
        self.close()


__all__ = ["Veil", "RedactionMode", "StreamingRestorer"]
