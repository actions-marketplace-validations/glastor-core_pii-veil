# 🏛 Gobernanza, Escalabilidad y Sostenibilidad Técnica — GLASTOR® pii-veil

![Contributors](https://img.shields.io/github/contributors/glastor-core/pii-veil)
![Stars](https://img.shields.io/github/stars/glastor-core/pii-veil)
![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)
![Rust 2021](https://img.shields.io/badge/Rust-2021%20Edition-orange.svg)

`GLASTOR-DEV` (división de ingeniería de **GLASTOR® Core**) concibe **pii-veil** como la infraestructura definitiva de detección, anonimización determinista y restauración reversible de datos sensibles (PII y secretos) de sub-milisegundo para el ecosistema **Rust, IA/LLMs, Agentes MCP, Python, Node.js y Go**.

Nuestra arquitectura **6-en-1** se sustenta en tres pilares inquebrantables:
1. **Rendimiento Sub-Milisegundo y Streaming $O(1)$**: Pre-filtrado en una sola pasada mediante `RegexSet`, restauración lineal $O(N)$ con autómatas `aho-corasick` y reconstrucción en tiempo real de streams SSE (`StreamingRestorer`) en ~39 µs por operación.
2. **Verificación Matemática y Criptográfica**: Validación algorítmica real para evitar falsos positivos (tarjetas con **ISO/IEC 7812 Luhn**, cuentas **ISO 13616 Mod-97 IBAN**, **DNI/NIE Mod-23**, **CUIT/CUIL Mod-11**, **RUT Mod-11**) y persistencia de bóvedas cifradas y autenticadas (`--vault-pass`).
3. **Arquitectura Multi-Mercado 6-en-1**: Un único núcleo en Rust (`crates/veil-core`) que impulsa el binario CLI + servidor MCP + proxy HTTP/SSE (`crates/veil-cli`), la biblioteca C-ABI (`crates/veil-ffi`), los paquetes nativos de Python (`crates/veil-py`) y Node.js (`crates/veil-node`), y el SDK de Go (`sdks/go`).

---

### 👥 Liderazgo y Dirección de Ingeniería

El desarrollo y dirección estratégica de GLASTOR® pii-veil es coordinado por:

- **Andrés Antonio Cardoso** ([@glastor-dev](https://github.com/glastor-dev))
  - *Lead Software Architect & Project Maintainer*
  - Responsable de la visión arquitectónica, el motor DLP/Vault de baja latencia y la interoperabilidad con el ecosistema `glastor-core` (`specter`, `byte-gauge`, `vortex`, `strata`).

---

### 🚀 Framework de Contribución (Rust-First & Multi-Language DX)

Incentivamos una **Developer Experience (DX)** de clase mundial para la comunidad de código abierto:

1. **Núcleo Modular y Auditable**: Todo se construye y valida mediante `cargo build --workspace`, `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings` y `go test ./...` en `sdks/go`.
2. **Seguridad Criptográfica y FFI Verificada**: Todo bloque `unsafe` en la capa C-ABI (`crates/veil-ffi`) valida explícitamente punteros nulos y fronteras UTF-8, y las bóvedas cifradas (`Vault::to_encrypted_json`) verifican etiquetas MAC de 128 bits antes de descifrar.
3. **Contratos Auditados en el Ecosistema**: Ningún cambio puede romper las firmas públicas de `VeilEngine`, `Vault`, las herramientas JSON-RPC de `veil mcp` o la cabecera `pii_veil.h` sin cumplir estrictamente con SemVer 2.0.0.
4. **Protección de Rama Principal (`main`)**: Todos los aportes deben canalizarse mediante Pull Request con revisión aprobada y la suite completa de CI en verde.

Para contribuir con nuevos detectores regionales, estrategias de anonimización, adaptadores de streaming o bindings, consulta nuestra guía en [.github/CONTRIBUTING.md](.github/CONTRIBUTING.md) y abre un Pull Request hacia la rama `main`.

---

### 💎 Ecosistema GLASTOR® Core

| Módulo / Crate | Propósito | Integración |
| :--- | :--- | :--- |
| **`pii-veil`** | Motor DLP, anonimizador reversible, servidor MCP y proxy HTTP/SSE | Workspace multi-crate en `crates/` y `sdks/go` |
| **`vortex`** | Orquestación predictiva de CI y guardián de regresión de rendimiento | CI en `.github/workflows/ci.yml` |
| **`specter`** | Diffing de contratos de API y cumplimiento estricto de SemVer | Auditoría de API pública |
| **`byte-gauge`** | Auditoría de hardening binario, entropía y secciones de memoria | Auditoría de artefactos de release |

---

© 2026 GLASTOR Core Organization — Security & Infrastructure Team.
