"""LlamaIndex transformation component for PII anonymization in indexing and querying."""

from typing import Any, List, Optional, Sequence, Union
from .. import RedactionMode, Veil

try:
    from llama_index.core.schema import BaseComponent, BaseNode, Document
    _HAS_LLAMAINDEX = True
except ImportError:
    class BaseComponent:  # type: ignore
        pass
    class BaseNode:  # type: ignore
        pass
    class Document:  # type: ignore
        pass
    _HAS_LLAMAINDEX = False


class VeilTransformComponent(BaseComponent):
    """LlamaIndex node transform component that sanitizes document text and metadata

    before indexing, RAG embedding, or synthesizer query pipelines.

    Usage:
        from llama_index.core import VectorStoreIndex
        from pii_veil.integrations.llamaindex import VeilTransformComponent

        anonymizer = VeilTransformComponent()
        nodes = anonymizer.transform([doc])
    """

    def __init__(
        self,
        mode: Union[RedactionMode, int] = RedactionMode.PLACEHOLDER,
        secret_key: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self.veil = Veil(mode=mode, secret_key=secret_key)

    def transform(self, nodes: Sequence[Any], **kwargs: Any) -> Sequence[Any]:
        """Iterates over document nodes and redacts text."""
        for node in nodes:
            if hasattr(node, "text") and isinstance(node.text, str):
                node.text = self.veil.redact(node.text)
            elif hasattr(node, "get_content"):
                content = node.get_content()
                if isinstance(content, str):
                    node.set_content(self.veil.redact(content))
        return nodes

    def restore_response(self, text: str) -> str:
        """Restores placeholders in synthesized query responses."""
        return self.veil.restore(text)

    def close(self) -> None:
        self.veil.close()
