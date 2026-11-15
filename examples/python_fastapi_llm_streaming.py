"""
Example: FastAPI + OpenAI/Anthropic Streaming Middleware with `pii-veil`
========================================================================
Demonstrates how to:
1. Redact user prompts before sending them to an external LLM API.
2. Restore tokens in real time as the LLM streams back Server-Sent Events (SSE)
   using `vault.streaming_restorer()` (handling split tokens like `[EMA` + `IL_1]`).
3. Persist the session vault encrypted in Redis using `vault.to_encrypted_json(...)`.
"""

from typing import AsyncIterator
from pii_veil import Veil, Vault

veil = Veil(mode="placeholder")
veil.add_allowlist("@example.com")


async def simulated_llm_sse_stream(sanitized_prompt: str) -> AsyncIterator[str]:
    """Simulates an LLM streaming tokens back where placeholders get split across chunks."""
    chunks = [
        "Hola! Revisé tu consulta (",
        sanitized_prompt[:15],
        "...) y envié el comprobante a [EMA",
        "IL_1] tras verificar la tarjeta [CREDIT_",
        "CARD_1] y el CUIT [NATIONAL_",
        "ID_1].",
    ]
    for chunk in chunks:
        yield chunk


async def chat_stream_endpoint(user_prompt: str, vault_passphrase: str) -> None:
    # 1. Redact sensitive PII & secrets before calling OpenAI / Claude
    safe_prompt, vault = veil.redact(user_prompt)
    print(f"[Safe Prompt sent to LLM]: {safe_prompt}")

    # 2. Optional: Save encrypted vault for multi-turn state in Redis / DB
    encrypted_vault_blob = vault.to_encrypted_json(vault_passphrase)
    restored_vault = Vault.from_encrypted_json(encrypted_vault_blob, vault_passphrase)

    # 3. Stream-restore LLM SSE chunks in real time without cutting split tokens
    restorer = restored_vault.streaming_restorer()
    output_chunks = []
    async for token_chunk in simulated_llm_sse_stream(safe_prompt):
        ready_text = restorer.push_chunk(token_chunk)
        if ready_text:
            output_chunks.append(ready_text)

    tail = restorer.finish()
    if tail:
        output_chunks.append(tail)

    print(f"[Restored Stream to User]: {''.join(output_chunks)}")
