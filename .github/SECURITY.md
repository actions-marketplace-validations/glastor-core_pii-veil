# 🛡️ Política de Seguridad (Security Policy) — GLASTOR® pii-veil

En el proyecto **GLASTOR® pii-veil** (`glastor-core/pii-veil`), desarrollado por `GLASTOR-DEV` (división de ingeniería de **GLASTOR® Core**), la prevención de fuga de datos (DLP), la integridad criptográfica de las bóvedas reversibles (`Vault`) y la seguridad de la cadena de suministro son prioridades inquebrantables.

El motor central (`crates/veil-core`) y el binario CLI/MCP/Proxy (`crates/veil-cli`) están implementados en **Rust 100% seguro** (sin bloques `unsafe`), previniendo vulnerabilidades de corrupción de memoria y denegación de servicio por expresiones regulares catastróficas (ReDoS) mediante el autómata finito determinista de `regex` y `aho-corasick`.

---

## 📦 Versiones Soportadas

Mantenemos actualizaciones de seguridad activas para las versiones estables de `pii-veil` en todos sus canales (`crates.io`, `PyPI`, `npm` y `Go`):

| Versión | Estado de Soporte | Tipo de Soporte |
| :--- | :--- | :--- |
| `0.1.x` | :white_check_mark: | Soporte activo y parches inmediatos |
| `< 0.1` | :x: No soportada | Versiones de desarrollo previas |

---

## 🚨 Reporte Responsable de Vulnerabilidades

Si descubres una vulnerabilidad de seguridad o un fallo que comprometa la integridad de `pii-veil` (por ejemplo: evasión/bypass de redacción de PII en el proxy HTTP/SSE o servidor MCP, debilidad en el cifrado autenticado de `.vault` con `--vault-pass`, fuga de tokens en `StreamingRestorer`, o fallo de memoria en la frontera C-ABI `crates/veil-ffi`), te solicitamos **no abrir un issue público**. En su lugar, activa nuestro protocolo de divulgación coordinada:

### Opción 1: GitHub Private Vulnerability Reporting (Recomendado)

Accede directamente a la herramienta oficial de GitHub:
👉 [Reportar vulnerabilidad privada en pii-veil](https://github.com/glastor-core/pii-veil/security/advisories/new)

### Opción 2: Correo Electrónico Seguro

Envía los detalles técnicos a nuestro equipo de seguridad:
📧 **[engineering@glastor.io](mailto:engineering@glastor.io)** o **[glastor.info@gmail.com](mailto:glastor.info@gmail.com)**

### Información a Incluir en el Reporte

Para acelerar el triaje y la mitigación, incluye:
- Descripción clara del vector de ataque, bypass de DLP o fallo criptográfico.
- Pasos mínimos de reproducción o prueba de concepto (PoC) utilizando datos sintéticos (nunca PII real).
- Componente afectado (`veil-core`, `veil mcp`, `veil proxy`, `veil-ffi`, `veil-py`, `veil-node` o `sdks/go`).
- Parche o mitigación sugerida (si está disponible).

---

## ⏱️ SLA y Compromiso de Respuesta

- **Recepción y acuse de recibo inicial:** $\le$ 24 horas hábiles.
- **Triaje y evaluación de severidad (CVSS):** $\le$ 48 horas hábiles.
- **Publicación de parche de seguridad:** Prioridad inmediata con aviso público a través de GitHub Security Advisory y actualización sincronizada en `crates.io`, `PyPI` y `npm`.

---

© 2026 Andrés Antonio Cardoso — GLASTOR-DEV / GLASTOR® Core Organization.
