# GLASTOR® `pii-veil` — Python SDK

Sub-millisecond Reversible PII & Secret Anonymizer for LLMs (Luhn Credit Cards, Mod-97 IBAN, DNI, CUIT, Regional IDs, DB URIs, and API Keys).

Includes native integrations for **LangChain**, **LlamaIndex**, and **CrewAI**, plus a zero-code `@veil_protect` decorator.

---

## 📦 Installation

```bash
pip install glastor-pii-veil
```

*(Optional framework integrations: `pip install "pii-veil[all]"`)*

---

## ⚡ Quick Start

```python
from pii_veil import Veil, RedactionMode

with Veil(mode=RedactionMode.PLACEHOLDER) as veil:
    # 1. Redact prompt before sending to OpenAI/Claude
    prompt = "Cobrar a diego@fintech.ar con tarjeta 4532-0151-1283-0366."
    sanitized = veil.redact(prompt)
    print(sanitized)
    # => "Cobrar a [EMAIL_1] con tarjeta [CREDIT_CARD_1]."

    # 2. LLM responds using the placeholders
    llm_response = f"Pago procesado para {sanitized}"

    # 3. Restore response with real values in sub-millisecond time
    restored = veil.restore(llm_response)
    print(restored)
    # => "Pago procesado para Cobrar a diego@fintech.ar con tarjeta 4532-0151-1283-0366."
```

---

## 🛡 Zero-Code Decorator (`@veil_protect`)

Wrap any function that calls an LLM. It automatically anonymizes prompts and restores responses:

```python
from pii_veil.decorators import veil_protect
from openai import OpenAI

client = OpenAI()

@veil_protect()
def query_agent(prompt: str) -> str:
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": prompt}]
    )
    return response.choices[0].message.content

# Outgoing prompt to OpenAI contains ONLY placeholders; caller gets real values!
result = query_agent("Contáctame a dev@acme.com con mi API key sk-proj-1234567890abcdef1234567890abcdef")
print(result)
```

---

## 🌊 Real-Time Streaming Restoration (SSE / Tokens)

When receiving chunks where placeholders are split mid-token (e.g. `"[EMA"` followed by `"IL_1]"`), `StreamingRestorer` buffers and restores them on the fly:

```python
with Veil() as veil:
    sanitized = veil.redact(prompt)
    
    # In an LLM stream (OpenAI stream=True):
    for restored_chunk in veil.restore_stream(response_stream):
        print(restored_chunk, end="", flush=True)
```

---

## 🤖 Framework Integrations

### 🦜 LangChain
```python
from langchain_openai import ChatOpenAI
from pii_veil.integrations.langchain import VeilCallbackHandler

handler = VeilCallbackHandler()
llm = ChatOpenAI(callbacks=[handler])

# Automatically anonymizes inputs on on_llm_start and restores on on_llm_end / on_llm_new_token
response = llm.invoke("Enviar balance a cliente@fintech.mx")
```

### 🦙 LlamaIndex
```python
from llama_index.core import VectorStoreIndex, SimpleDirectoryReader
from pii_veil.integrations.llamaindex import VeilTransformComponent

anonymizer = VeilTransformComponent()
documents = SimpleDirectoryReader("./data").load_data()
sanitized_nodes = anonymizer.transform(documents)
index = VectorStoreIndex(sanitized_nodes)
```

### 👥 CrewAI
```python
from crewai import Agent, Task, Crew
from pii_veil.integrations.crewai import VeilStepCallback

dlp_guard = VeilStepCallback()

agent = Agent(
    role="Fintech Support Agent",
    goal="Handle confidential account questions",
    step_callback=dlp_guard
)
```

---

## 📄 License
Licensed under Apache 2.0 or MIT at your option. Part of the **GLASTOR® Core** ecosystem.
