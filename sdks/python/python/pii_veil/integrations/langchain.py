"""LangChain callback handler for transparent PII anonymization & streaming token restoration."""

from typing import Any, Dict, List, Optional, Union
from .. import RedactionMode, Veil

try:
    from langchain_core.callbacks import BaseCallbackHandler
    from langchain_core.outputs import LLMResult
    _HAS_LANGCHAIN = True
except ImportError:
    # Graceful fallback base class if langchain_core is not installed
    class BaseCallbackHandler:  # type: ignore
        pass
    class LLMResult:  # type: ignore
        pass
    _HAS_LANGCHAIN = False


class VeilCallbackHandler(BaseCallbackHandler):
    """LangChain callback handler that redacts PII before prompts hit the LLM

    and restores placeholders in the final output or during streaming tokens.

    Usage:
        from langchain_openai import ChatOpenAI
        from pii_veil.integrations.langchain import VeilCallbackHandler

        handler = VeilCallbackHandler()
        llm = ChatOpenAI(callbacks=[handler])
        response = llm.invoke("Cobrar a diego@fintech.ar con tarjeta 4532-0151-1283-0366")
    """

    def __init__(
        self,
        mode: Union[RedactionMode, int] = RedactionMode.PLACEHOLDER,
        secret_key: Optional[str] = None,
    ) -> None:
        super().__init__()
        self.veil = Veil(mode=mode, secret_key=secret_key)
        self._stream_restorer = None

    def on_llm_start(
        self, serialized: Dict[str, Any], prompts: List[str], **kwargs: Any
    ) -> None:
        """Redacts all outgoing prompts in place before LLM transmission."""
        for i, prompt in enumerate(prompts):
            prompts[i] = self.veil.redact(prompt)
        # Initialize streaming restorer for this run
        self._stream_restorer = self.veil.streaming_restorer()

    def on_llm_new_token(self, token: str, **kwargs: Any) -> str:
        """Restores placeholders split across mid-token streaming chunks."""
        if self._stream_restorer:
            return self._stream_restorer.push(token)
        return token

    def on_llm_end(self, response: LLMResult, **kwargs: Any) -> None:
        """Restores placeholders in the final completed generations."""
        if self._stream_restorer:
            self._stream_restorer.finish()
            self._stream_restorer.close()
            self._stream_restorer = None

        if hasattr(response, "generations"):
            for generation_list in response.generations:
                for gen in generation_list:
                    if hasattr(gen, "text"):
                        gen.text = self.veil.restore(gen.text)
                    if hasattr(gen, "message") and hasattr(gen.message, "content"):
                        gen.message.content = self.veil.restore(gen.message.content)

    def close(self) -> None:
        self.veil.close()
