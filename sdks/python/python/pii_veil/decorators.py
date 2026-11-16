"""Decorators for seamless zero-code LLM prompt anonymization and response restoration."""

import functools
from typing import Any, Callable, Optional, Union

from . import RedactionMode, Veil


def veil_protect(
    mode: Union[RedactionMode, int] = RedactionMode.PLACEHOLDER,
    secret_key: Optional[str] = None,
) -> Callable:
    """Decorator that automatically sanitizes prompts before calling an LLM function

    and restores real values in the LLM response.

    Example:
        @veil_protect()
        def ask_llm(prompt: str) -> str:
            response = client.chat.completions.create(
                model="gpt-4o",
                messages=[{"role": "user", "content": prompt}]
            )
            return response.choices[0].message.content
    """
    def decorator(fn: Callable) -> Callable:
        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            with Veil(mode=mode, secret_key=secret_key) as veil:
                # Sanitize positional string arguments
                new_args = []
                for arg in args:
                    if isinstance(arg, str):
                        new_args.append(veil.redact(arg))
                    else:
                        new_args.append(arg)

                # Sanitize keyword arguments
                new_kwargs = {}
                for k, v in kwargs.items():
                    if isinstance(v, str):
                        new_kwargs[k] = veil.redact(v)
                    else:
                        new_kwargs[k] = v

                # Call original function with sanitized prompt
                result = fn(*new_args, **new_kwargs)

                # Restore response if string
                if isinstance(result, str):
                    return veil.restore(result)

                # If result has content or text attribute (like OpenAI / LangChain message)
                if hasattr(result, "content") and isinstance(result.content, str):
                    result.content = veil.restore(result.content)
                    return result

                return result

        return wrapper

    return decorator
