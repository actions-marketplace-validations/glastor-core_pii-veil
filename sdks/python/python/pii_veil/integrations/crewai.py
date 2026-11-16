"""CrewAI step callback for agent task and tool execution DLP protection."""

from typing import Any, Dict, Optional, Union
from .. import RedactionMode, Veil


class VeilStepCallback:
    """CrewAI step callback that redacts sensitive PII from agent memory,

    task outputs, and inter-agent messages while preserving restoration capabilities.

    Usage:
        from crewai import Agent, Crew, Task
        from pii_veil.integrations.crewai import VeilStepCallback

        dlp_callback = VeilStepCallback()
        agent = Agent(
            role="Billing Assistant",
            goal="Process refunds",
            step_callback=dlp_callback
        )
    """

    def __init__(
        self,
        mode: Union[RedactionMode, int] = RedactionMode.PLACEHOLDER,
        secret_key: Optional[str] = None,
    ) -> None:
        self.veil = Veil(mode=mode, secret_key=secret_key)

    def __call__(self, step_output: Any) -> Any:
        """Callback invoked by CrewAI after each agent tool execution or reasoning step."""
        if isinstance(step_output, str):
            return self.veil.redact(step_output)

        # Handle CrewAI AgentAction / AgentFinish or custom dict step outputs
        if hasattr(step_output, "text") and isinstance(step_output.text, str):
            step_output.text = self.veil.redact(step_output.text)
        if hasattr(step_output, "output") and isinstance(step_output.output, str):
            step_output.output = self.veil.redact(step_output.output)
        if hasattr(step_output, "tool_input") and isinstance(step_output.tool_input, str):
            step_output.tool_input = self.veil.redact(step_output.tool_input)

        return step_output

    def restore(self, text: str) -> str:
        """Restores placeholders in the final Crew execution output."""
        return self.veil.restore(text)

    def close(self) -> None:
        self.veil.close()
