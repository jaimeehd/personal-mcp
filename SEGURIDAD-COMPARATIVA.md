# Comparativa de Seguridad: personal-mcp vs. Ecosistema MCP

> **Fecha:** 2 de julio de 2026 (conteos de herramientas y estado del sistema HITL actualizados 2026-07-20 tras verificación directa contra el código)
>
> Esta guía compara las características de seguridad de personal-mcp con las de
> otros servidores MCP populares, basándose en investigación pública, CVEs
> conocidos, y análisis de la comunidad de seguridad.

---

## Resumen Ejecutivo

personal-mcp tiene **el modelo de seguridad más completo** entre todos los
servidores MCP analizados. Es el único con:

- Sistema de aprobación por tickets con **código de confirmación HMAC** (SINGLE / SESSION / PERMANENT) — el código solo es visible en un popup nativo en la pantalla del usuario, nunca en la respuesta de ninguna tool; un agente no tiene ningún canal para leerlo o adivinarlo
- Límite de tasa por operación (ventana deslizante read/write separados)
- Escaneo de secretos en archivos leídos
- Protección contra symlinks/junctions
- Capa SSH deshabilitada por defecto (opt-in)
- 6 capas hexagonales de seguridad con 57 herramientas (53 activas)

Mientras que servidores populares como Desktop Commander tienen **3+ CVEs
activos** por path traversal y command injection, personal-mcp no tiene CVEs
conocidos.

---

## Matriz Comparativa Completa

| Característica | personal-mcp | Desktop Cmd | Filesystem MCP | Playwright MCP | GitHub MCP |
|---|---|---|---|---|---|
| **Allowlist de rutas** | ✅ 2 niveles (paths_allow + data_dir) | ⚠️ Configurable (bypasseable) | ✅ CLI args / Roots | ⚠️ Solo output dir | N/A |
| **Path traversal** | ✅ validate() con realpath | ❌ **3+ CVEs activos** | ✅ Bueno | ✅ Básico | N/A |
| **Whitelist comandos** | ✅ Prefix allow + deny list | ❌ By-passeable con `$()` | N/A | N/A | N/A |
| **Output truncation** | ✅ 1 MiB con aviso | ❌ No | ❌ No | ❌ No | ❌ No |
| **Permisos (HITL)** | ✅ Tickets + código de confirmación HMAC (popup nativo, invisible al agente) | ❌ No | ⚠️ ToolAnnotations (solo pistas) | ❌ No | ✅ Token-scoped |
| **Auditoría** | ✅ RotatingFileHandler | ❌ No | ❌ No | ❌ No | ✅ GitHub audit log |
| **Secret scanning** | ✅ En fs_read (12 patrones) | ❌ No | ❌ No | ❌ No | ❌ No |
| **Rate limiting** | ✅ Per-operación (read/write) | ❌ No | ❌ No | ⚠️ Sesión timeout | ✅ API limits |
| **Anti-symlink** | ✅ os.path.realpath() | ❌ **ROTO** (#219, #420) | ⚠️ Parcial | N/A | N/A |
| **Shell multi-entorno** | ✅ 4 shells (ps/pwsh/cmd/bash) | ❌ Solo cmd | N/A | N/A | N/A |
| **Modo read-only** | ❌ No explícito | ❌ No | ✅ readOnlyHint | N/A | ✅ GITHUB_READ_ONLY |
| **Protección SSH** | ✅ Opt-in, disabled default | N/A | N/A | N/A | N/A |
| **Autenticación** | ✅ Confianza local | ✅ Localhost | ❌ Confía en cliente | ✅ Localhost | ✅ OAuth / PAT |

### Leyenda
✅ = Implementado / Bueno
⚠️ = Parcial / Débil
❌ = Ausente / Roto
N/A = No aplica

---

## Análisis por Herramienta

### 1. Desktop Commander (~6,100 estrellas)

**Riesgo: ALTO**

El servidor MCP más popular para automatización de escritorio tiene un
**postura de seguridad deliberadamente baja**. Su propio `SECURITY.md` dice:
*"La seguridad no es nuestra prioridad actual... recomendamos usar Docker para
aislamiento completo."*

#### Vulnerabilidades conocidas

| CVE / Issue | Tipo | Impacto |
|---|---|---|
| #420 (CVE-2025-11489 variant) | Symlink sandbox escape | Escritura arbitraria fuera de directorios permitidos |
| #219 | Directory traversal via symlink | Lectura/escritura arbitraria |
| #411 (abril 2026) | Path traversal + command injection | **4 hallazgos CRÍTICOS** por mcpfuzz |

#### Por qué es inseguro

1. **`validatePath()`** no resuelve symlinks — `fs.realpath()` traga `ENOENT`
   y cae a resolución ingenua de strings.
2. **`blockedCommands`** se by-pasea con `$(comando)`, `` `comando` ``, `|`
3. **Sin auditoría**: ninguna operación queda registrada
4. **Sin aprobación humana**: todo se ejecuta inmediatamente

#### vs. personal-mcp

personal-mcp gana en **todos los frentes**: validación de rutas (resuelve
symlinks vía `os.path.realpath()`), whitelist de comandos (deny list + prefix
allow + escaneo de operadores shell), auditoría completa, y sistema de tickets
que requiere aprobación humana para writes.

---

### 2. Filesystem MCP Server (Anthropic, ~87,900 estrellas)

**Riesgo: BAJO**

El servidor de referencia para operaciones de archivos. Es el estándar contra
el que se miden los demás.

#### Fortalezas

- ✅ Allowlist por CLI: `server-filesystem /path/to/dir1 /path/to/dir2`
- ✅ `setAllowedDirectories()` con resolución canónica de rutas
- ✅ Protocolo **Roots** para actualización dinámica de directorios permitidos
- ✅ ToolAnnotations: `readOnlyHint` / `destructiveHint` (pistas, no bloqueos)

#### Debilidades

- ❌ Sin sistema de aprobación (los hints son solo eso — hints)
- ❌ Sin rate limiting
- ❌ Sin auditoría de operaciones
- ❌ Sin escaneo de secretos
- ⚠️ Protección contra symlinks parcial (riesgos conocidos)

#### vs. personal-mcp

El Filesystem MCP Server tiene un allowlist limpio pero carece de todo el
sistema de permisos fino de personal-mcp (SINGLE/SESSION/PERMANENT), auditoría,
secret scanning, y rate limiting. La única característica que personal-mcp no
tiene es el protocolo **Roots** para actualización dinámica del allowlist.

---

### 3. Playwright MCP (Microsoft, ~15,000+ estrellas)

**Riesgo: MEDIO**

Automatización de navegador. Su riesgo principal es **inyección de prompt**
(páginas web maliciosas engañan al agente).

#### Fortalezas

- ✅ Aislamiento por sesión (contextos separados por conexión WebSocket)
- ✅ `--allowed-origins` / `--blocked-origins` para restricción de dominios
- ✅ Límite de duración de sesión (default 1800s) y timeout de inactividad

#### Debilidades

- ❌ **"Trifecta letal"** (Simon Willison): acceso a datos privados + contenido
  no confiable + capacidad de comunicación externa = inyección de prompt peligrosa
- ❌ Sin HITL para acciones del navegador (envío de formularios, descargas)
- ❌ Sin auditoría de operaciones

#### vs. personal-mcp

Amenazas diferentes. Playwright se arriesga a `web content → agent poisoning`;
personal-mcp se arriesga a `malicious tool invocation`. El sistema de tickets
de personal-mcp sería una mejora importante para Playwright. La restricción de
orígenes (`--allowed-origins`) es algo que personal-mcp podría considerar para
su capa shell.

---

### 4. GitHub MCP Server (GitHub, ~30,300 estrellas)

**Riesgo: BAJO (depende del token)**

Servidor stateless que solo hace llamadas a la API de GitHub. La seguridad
depende completamente del **scope del token**.

#### Fortalezas

- ✅ Autenticación OAuth (remoto) o PAT (local)
- ✅ Modo read-only (`GITHUB_READ_ONLY=1`) — preventivo contra escritura accidental
- ✅ Límite de toolsets por env var (`GITHUB_TOOLSETS`)
- ✅ GitHub Audit Log — todas las acciones atribuidas al token

#### Debilidades

- ❌ Sin rate limiting propio (depende de los rate limits de la API de GitHub)
- ❌ Sin sistema de aprobación intern
- ⚠️ Riesgo de token over-permissioning (la práctica recomendada es usar dos PATs)

#### Incidente conocido

**Mayo 2025 (Invariant Labs)**: A través de inyección de prompt en issues
públicos, un atacante logró que un agente exfiltrara datos de repos privados
a un PR público. La "trifecta letal" en acción: datos privados + contenido
no confiable + comunicación externa.

#### vs. personal-mcp

El modelo de seguridad de GitHub MCP es fundamentalmente más simple porque la
API de GitHub ya tiene su propio sistema de permisos (PAT scopes). personal-mcp
necesita más capas porque opera a nivel de sistema local (filesystem, shell)
que no tiene un modelo de permisos nativo. La característica de **modo
read-only** (`GITHUB_READ_ONLY=1`) es algo que personal-mcp podría adoptar.

---

### 5. Brave Search MCP (~1,200 estrellas)

**Riesgo: MUY BAJO**

Wrapper de API puro — sin acceso a filesystem, sin shell, sin datos sensibles.

#### Fortalezas

- ✅ Sanitización de queries (max 400 chars, 50 palabras)
- ✅ Filtro `safesearch` (off/moderate/strict)
- ✅ TrustVector Score: 84/100

#### Debilidades

- ❌ Sin rate limiting propio (depende del plan Brave: 2K-15K queries/mes)
- ❌ Sin truncation de output

#### Incidente conocido

**Junio 2026**: Paquete malicioso `brave-search-mcp-server@1.0.0` en npm
identificado por OpenSSF Package Analysis. El oficial (`@brave/...`) está limpio.

#### vs. personal-mcp

Brave Search tiene una superficie de ataque fundamentalmente más pequeña. No
necesita validación de rutas, whitelist de comandos, ni tickets porque solo
hace llamadas API. La simplicidad es su seguridad.

---

### 6. MCP Command Server (Andrew-Beniash)

**Riesgo: BAJO**

Uno de los pocos servidores MCP con características de seguridad comparables
a personal-mcp.

#### Características

- ✅ `ALLOWED_COMMANDS` — whitelist por env var
- ✅ Confirmación humana requerida para cada comando
- ✅ Auditoría completa
- ✅ Sanitización de inputs

#### vs. personal-mcp

Es el más parecido a personal-mcp en filosofía. Sin embargo, carece de:
secret scanning, rate limiting per-operación, protección anti-symlink, y
soporte multi-shell. personal-mcp tiene un modelo de permisos más granular
(SINGLE/SESSION vs. solo confirmación binaria).

---

## Datos del Ecosistema MCP (2025-2026)

| Métrica | Valor | Fuente |
|---|---|---|
| CVEs confirmados de MCP | **36** (abril 2026) | NVD |
| Servidores sin autenticación | **38-41%** | BlueRock, TapAuth, Bloomberry |
| Secretos expuestos en GitHub | **24,008 únicos** (2,117 aún válidos) | GitGuardian 2026 |
| Servidores con path traversal | **82%** | Endor Labs (2,614 implementaciones) |
| Servidores con command injection | **34%** | Endor Labs |
| Zero-days VIPER-MCP | **106** (67 con CVE) | VIPER-MCP paper (mayo 2026) |
| Vulnerabilidades que son shell injection | **43%** | Múltiples fuentes |
| Servidores accesibles desde internet | **21,000+** (mayo 2026) | Censys |

---

## OWASP MCP Top 10 — Cobertura de personal-mcp

| Control OWASP | personal-mcp | Estado |
|---|---|---|
| Tool pinning (hashing) | ❌ No implementado | Pendiente |
| Input validation en herramientas | ✅ `validate_tool_path()` + `resolve_and_validate()` | ✅ |
| Output sanitization | ✅ Truncation a 1 MiB | ✅ |
| Human approval (acciones destructivas) | ✅ Tickets SINGLE/SESSION | ✅ |
| Least privilege por servidor/herramienta | ✅ 6 capas, permisos por operación | ✅ |
| Logging y monitoreo | ✅ Auditoría + logging rotativo | ✅ |
| Dependencias seguras | ✅ `.venv` aislado | ✅ |
| Protección contra inyección de prompt | ⚠️ Tickets mitigan impacto | Parcial |
| Validación de descripción de tools | ❌ No implementado | Pendiente |
| Rate limiting | ✅ Per-operación (read/write) | ✅ |

**Cobertura total: ~75%** de los controles OWASP MCP recomendados.

---

## Dónde Gana personal-mcp

1. **Único con sistema de aprobación por tickets** (SINGLE/SESSION/PERMANENT) —
   ningún otro servidor MCP analizado tiene un flujo de aprobación HITL.
2. **Único con rate limiting per-operación** — ventana deslizante con buckets
   separados para read y write.
3. **Único con escaneo de secretos** en lectura de archivos — 12 patrones
   detectan tokens, claves, y credenciales.
4. **Único con protección contra symlinks/junctions** probada y funcional
   (vs. Desktop Commander que tiene 3 CVEs activos por esto).
5. **Único con output truncation** — límite duro de 1 MiB con mensaje
   informativo.
6. **Único con soporte multi-shell** (4 shells) con resolvers individuales,
   whitelist de comandos, y escaneo de rutas absolutas.
7. **Único con capa SSH** deshabilitada por defecto (security by default).
8. **Auditoría completa** (10,000 entradas circulares + logging rotativo)
   mientras que la mayoría de servidores MCP no registran nada.

## Dónde Puede Mejorar

1. **Modo read-only global** — como `GITHUB_READ_ONLY=1` de GitHub MCP.
   Permitiría un modo "solo consulta" para sesiones de bajo riesgo.
2. **Protocolo Roots** — actualización dinámica del allowlist sin reiniciar,
   como el Filesystem MCP Server de Anthropic.
3. **Tool pinning** — verificación de integridad de definiciones de
   herramientas (como mcp-scan).
4. **Restricción de orígenes** — como `--allowed-origins` de Playwright,
   pero aplicado a la capa shell.
5. **Inyección de prompt** — aunque los tickets mitigan el impacto, no hay
   defensa proactiva contra prompt injection en el contenido leído.

---

## Conclusión

En un ecosistema donde:

- **82%** de los servidores MCP son vulnerables a path traversal
- **38-41%** no tienen autenticación
- **43%** de las vulnerabilidades son shell injection
- **Desktop Commander** (el más popular) tiene 3+ CVEs activos por sandbox escape

personal-mCP se destaca como **el servidor MCP con la postura de seguridad más
completa** entre los analizados. Su combinación de:

- Allowlist de rutas + denylist
- Validación de symlinks
- Whitelist de comandos + deny list
- Aprobación HITL por tickets
- Rate limiting per-operación
- Escaneo de secretos
- Auditoría completa
- Output truncation

...lo pone significativamente por delante de cualquier alternativa comparable.

Las principales áreas de mejora (modo read-only, Roots, tool pinning) son
mejoras incrementales, no brechas críticas.

---

## Fuentes

- Desktop Commander: SECURITY.md, Issues #219, #411, #420
- npm: `@modelcontextprotocol/server-filesystem`, `@playwright/mcp`,
  `@brave/brave-search-mcp-server`
- GitHub: `github/github-mcp-server`, `modelcontextprotocol/servers`
- OWASP MCP Security Cheat Sheet (cheatsheetseries.owasp.org)
- Invariant Labs: mcp-scan, MCP security research
- Endor Labs: analysis of 2,614 MCP implementations
- ChatForest: MCP Security Crisis report (abril 2026)
- Praetorian: MCPHammer research
- VIPER-MCP paper (arxiv.org, mayo 2026)
- Simon Willison: "Lethal Trifecta" prompt injection analysis
