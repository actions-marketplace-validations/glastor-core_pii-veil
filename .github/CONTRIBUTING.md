# 🌌 Guía de Contribución y Estándares de Ingeniería — GLASTOR® pii-veil

Gracias por sumarte a la misión de construir y optimizar **GLASTOR® pii-veil** dentro del ecosistema de `GLASTOR-DEV` (división de ingeniería de **GLASTOR® Core**).

`pii-veil` es el motor de anonimización reversible, prevención de fuga de datos (DLP), servidor MCP y proxy HTTP/SSE de sub-milisegundo diseñado bajo una arquitectura **6-en-1** (`veil-core`, `veil-cli`, `veil-ffi`, `veil-py`, `veil-node` y `sdks/go`).

---

## 🛡 Política de Protección de Rama (`main`)

Para garantizar la máxima estabilidad y la calidad del código en producción:
- **La rama `main` está protegida**: No se permiten envíos directos (`git push origin main`) ni modificaciones forzadas (`--force`) sin validación previa.
- **Todo cambio debe ingresar mediante Pull Request (PR)**:
  - Debe crearse una rama temática (`feat/nombre`, `fix/nombre`, `perf/nombre`).
  - La suite automatizada de GitHub Actions ([ci.yml](./workflows/ci.yml): formato, Clippy sin warnings, tests del workspace en Linux/Windows/macOS y tests de integración del SDK de Go) debe finalizar en estado verde (`[PASS]`).
  - Se requiere al menos una revisión aprobada por los mantenedores ([CODEOWNERS](./CODEOWNERS)).

---

## 💻 Setup del Entorno de Desarrollo

### Requisitos Previos

- **Rust**: Versión estable 1.80+ (`rustup`, `cargo`, `rustfmt`, `clippy`).
- **Go** *(opcional para `sdks/go`)*: 1.22+.
- **Python 3.9+ & `maturin`** *(opcional para `crates/veil-py`)*.
- **Node.js 20+ & `@napi-rs/cli`** *(opcional para `crates/veil-node`)*.

### 1. Clonación del Repositorio

```bash
git clone https://github.com/glastor-core/pii-veil.git
cd pii-veil
```

### 2. Comandos de Trabajo y Verificación

```bash
# Compilar todo el workspace de Rust (veil-core, veil-cli, veil-ffi)
cargo build --workspace --all-targets

# Ejecutar todas las pruebas unitarias y de integración en Rust
cargo test --workspace

# Verificar cumplimiento de formato oficial
cargo fmt --all -- --check

# Ejecutar auditoría estricta de Clippy (cero warnings permitidos)
cargo clippy --workspace --all-targets -- -D warnings

# Ejecutar demo interactiva y benchmark de rendimiento en modo release
cargo run --release -p pii-veil-cli -- demo
cargo run --release -p pii-veil-cli -- bench

# Ejecutar pruebas unitarias y de integración MCP en el SDK de Go
cd sdks/go && go test -v -race ./...
```

---

## 📐 Estándares de Código, Privacidad y Manejo de `unsafe`

1. **Cero Falsos Positivos con Validación Matemática**:
   - Todo nuevo detector de documentos financieros o de identidad (tarjetas, IBAN, DNI, CUIT, RUT, etc.) debe ir acompañado de su función verificadora de dígito de control en `crates/veil-core/src/detector.rs` y su generador sintético válido en `crates/veil-core/src/strategy.rs`.
2. **Prohibición de PII o Credenciales Reales en Tests**:
   - Todos los casos de prueba, ejemplos y benchmarks deben utilizar exclusivamente datos sintéticos de prueba (por ejemplo, tarjetas de prueba Luhn `4532-0151-1283-0366`, dominios `@example.com` / `@fintech.io`, claves ficticias).
3. **Mandato de Seguridad en FFI (`crates/veil-ffi`)**:
   - El núcleo (`veil-core`) y el CLI (`veil-cli`) son 100% Rust seguro.
   - Los bloques `unsafe` están restringidos exclusivamente a la frontera C-ABI en `crates/veil-ffi/src/lib.rs` y deben documentar sus invariantes bajo una sección `# Safety` verificando punteros nulos antes de desreferenciar.

---

## 🤝 Proceso de Envío de Pull Requests

1. Crea una rama descriptiva a partir de la versión más reciente de `main`:
   ```bash
   git checkout main
   git pull origin main
   git checkout -b feat/nuevo-detector-regional
   ```
2. Realiza tus cambios asegurando que las pruebas en Rust y Go pasen al 100%.
3. Escribe mensajes de commit bajo el estándar [Conventional Commits](./COMMIT_CONVENTION.md).
4. Abre el Pull Request en GitHub seleccionando como destino la rama `main` y completa el formulario de [PULL_REQUEST_TEMPLATE.md](./PULL_REQUEST_TEMPLATE.md).

---

© 2026 GLASTOR Core Organization — Security & Infrastructure Team.
