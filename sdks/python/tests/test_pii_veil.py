"""Unit tests for the official Python SDK (pii-veil)."""

import os
import sys

# Ensure local package is in Python path for testing
current_dir = os.path.dirname(os.path.abspath(__file__))
pkg_dir = os.path.abspath(os.path.join(current_dir, "../python"))
if pkg_dir not in sys.path:
    sys.path.insert(0, pkg_dir)

import unittest
from pii_veil import RedactionMode, Veil
from pii_veil.decorators import veil_protect
from pii_veil.integrations.langchain import VeilCallbackHandler
from pii_veil.integrations.llamaindex import VeilTransformComponent
from pii_veil.integrations.crewai import VeilStepCallback


class TestPiiVeil(unittest.TestCase):
    def test_basic_roundtrip(self):
        with Veil(mode=RedactionMode.PLACEHOLDER) as veil:
            raw = "Mi correo es sofia@fintech.io y mi tarjeta es 4532-0151-1283-0366."
            sanitized = veil.redact(raw)

            # Assert PII is redacted
            self.assertNotIn("sofia@fintech.io", sanitized)
            self.assertNotIn("4532-0151-1283-0366", sanitized)
            self.assertIn("[EMAIL_1]", sanitized)
            self.assertIn("[CREDIT_CARD_1]", sanitized)
            self.assertEqual(veil.vault_size, 2)

            # Assert LLM reply with placeholders restores perfectly
            llm_reply = f"Confirmamos el cobro de {sanitized}"
            restored = veil.restore(llm_reply)
            self.assertEqual(restored, f"Confirmamos el cobro de {raw}")

    def test_streaming_restorer_split_chunks(self):
        with Veil() as veil:
            prompt = "Clave privada en sk-proj-1234567890abcdef1234567890abcdef y mail dev@corp.com"
            sanitized = veil.redact(prompt)
            self.assertIn("[OPENAI_KEY_1]", sanitized)
            self.assertIn("[EMAIL_1]", sanitized)

            # Simulate LLM streaming chunks with placeholders cut in half mid-token!
            chunks = [
                "Generando respuesta para: ",
                "clave [OPEN",
                "AI_KEY_1] y correo ",
                "[EMA",
                "IL_1] verificado.",
            ]

            restored_chunks = list(veil.restore_stream(iter(chunks)))
            full_restored = "".join(restored_chunks)

            self.assertEqual(
                full_restored,
                "Generando respuesta para: clave sk-proj-1234567890abcdef1234567890abcdef y correo dev@corp.com verificado.",
            )

    def test_json_redaction(self):
        with Veil() as veil:
            payload = '{"user": "Laura", "email": "laura@example.com", "dni": "00000000T"}'
            redacted_json = veil.redact_json(payload)
            self.assertNotIn("laura@example.com", redacted_json)
            self.assertIn("[EMAIL_1]", redacted_json)

    def test_decorator_veil_protect(self):
        @veil_protect()
        def mock_llm_call(prompt: str) -> str:
            # The LLM receives the sanitized prompt!
            self.assertNotIn("carlos@fintech.com", prompt)
            self.assertIn("[EMAIL_1]", prompt)
            return f"Processed query from {prompt}"

        raw_prompt = "Hola, mi correo es carlos@fintech.com."
        output = mock_llm_call(raw_prompt)
        # The caller receives the restored response!
        self.assertEqual(output, f"Processed query from {raw_prompt}")

    def test_integrations_instantiation(self):
        lc_handler = VeilCallbackHandler()
        self.assertIsNotNone(lc_handler.veil)
        lc_handler.close()

        llama_transform = VeilTransformComponent()
        self.assertIsNotNone(llama_transform.veil)
        llama_transform.close()

        crew_cb = VeilStepCallback()
        self.assertIsNotNone(crew_cb.veil)
        crew_cb.close()


if __name__ == "__main__":
    unittest.main()
