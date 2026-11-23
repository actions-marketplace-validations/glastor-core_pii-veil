# 🇧🇷 Guia de Conformidade LGPD (Lei Geral de Proteção de Dados)

Como garantir conformidade com a **Lei Geral de Proteção de Dados Pessoais do Brasil (LGPD — Lei nº 13.709/2018)** em sistemas de Inteligência Artificial, LLMs e Engenharia de Dados com `pii-veil`.

---

## ⚖ Artigos Chave da LGPD e a Abordagem do `pii-veil`

### 1. Artigo 11 e 13 — Tratamento de Dados Pessoais Sensíveis
> *"O tratamento de dados pessoais sensíveis somente poderá ocorrer... para a realização de estudos por órgão de pesquisa, garantida, sempre que possível, a anonimização dos dados pessoais sensíveis."*

- **O Problema**: O envio de CPF, RG, dados bancários e e-mails para provedores de IA sem anonimização pode incorrer em multas severas da ANPD (Autoridade Nacional de Proteção de Dados).
- **A Solução com `pii-veil`**: O motor detecta e anonimiza automaticamente documentos regionais brasileiros e latino-americanos:
  - **CPF (Cadastro de Pessoas Físicas)**: Validação do dígito verificador Mod-11.
  - **CNPJ / CUIT / RUT**: Documentos empresariais e fiscais.
  - **Chaves PIX**: Identificação de e-mails, telefones e UUIDs usados em pagamentos instantâneos.

---

### 2. Artigo 16 — Eliminação dos Dados e Pseudonimização
> *"Os dados pessoais serão eliminados após o término de seu tratamento... autorizada a conservação para: I - estudo por órgão de pesquisa, garantida, sempre que possível, a anonimização..."*

- O `pii-veil` oferece dois modos essenciais:
  1. **Anonimização Irreversível (`mode: mask`)**: Para armazenamento definitivo em logs, data lakes e bancos vetoriais.
  2. **Pseudonimização Reversível (`mode: placeholder`)**: Mantém a correlação no cofre de sessão (`Vault`) durante a conversa com o LLM e restaura a resposta para o usuário final em < 1 milissegundo.

---

## 💻 Exemplo em Python (FastAPI / LangChain)

```python
from pii_veil import Veil, RedactionMode

dados_cliente = "Cliente João da Silva, CPF 123.456.789-00, chave PIX joao.silva@banco.com.br."

with Veil(mode=RedactionMode.PLACEHOLDER) as veil:
    prompt_seguro = veil.redact(dados_cliente)
    # prompt_seguro: "Cliente João da Silva, CPF [NATIONAL_ID_1], chave PIX [EMAIL_1]."
    
    # Enviar ao LLM (OpenAI / Claude) sem violar a LGPD
    resposta_ia = chamar_llm(prompt_seguro)
    
    # Restaurar dados no retorno para a interface do atendente
    resposta_final = veil.restore(resposta_ia)
```
