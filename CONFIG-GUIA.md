# Guía del archivo de configuración (para no-técnicos)

Este documento explica, en lenguaje simple, qué significa cada parte del archivo
`config.json`. No necesitas saber programar para entender esto.

> IMPORTANTE: el archivo que de verdad controla el comportamiento del asistente
> está en tu carpeta de usuario, no en este repositorio:
>
> **Windows:** `C:\Users\TuUsuario\.personal-mcp\config.json`
>
> **Linux:** `~/.personal-mcp/config.json`  (ej: `/home/tuusuario/.personal-mcp/config.json`)
>
> **macOS:** `~/.personal-mcp/config.json`  (ej: `/Users/tuusuario/.personal-mcp/config.json`)
>
> El archivo `config.json` que está aquí, junto a esta guía, es solo una copia de
> lectura para que puedas revisarla sin salir del repositorio. Si la editas aquí,
> no cambia nada en el comportamiento real. Para actualizar el espejo con los
> cambios más recientes:
>
> - **Windows:** ejecuta `sync-config.ps1` desde esta carpeta
> - **Linux/macOS:** ejecuta `./sync-config.sh` desde esta carpeta

---

## Un límite que conviene saber desde el principio

Este sistema de permisos protege las herramientas de este proyecto: los popups
y códigos de confirmación se aplican a las operaciones que el asistente hace
con **estas** herramientas. Pero el cliente (Claude Desktop) puede tener
también habilitado el **conector oficial de archivos** de Anthropic, que
escribe en las carpetas permitidas de su propia configuración **sin pasar por
este sistema**: sin popup, sin código, sin registro en `audit.json`. Si ambos
están habilitados sobre las mismas carpetas, el conector oficial es una puerta
paralela que no tiene las mismas protecciones. No es un error del proyecto: es
una decisión del cliente. Si quieres que todas las escrituras pasen por el
sistema de permisos, quita la carpeta del conector oficial en la configuración
del cliente (o deshabilita el conector).

---

## Qué es este archivo, en una frase

Es la lista de "permisos" del asistente: qué carpetas puede tocar, qué comandos
puede ejecutar, y qué límites de seguridad tiene. Es el manual de reglas que el
asistente debe obedecer siempre.

---

## Sección security (seguridad)

### paths_allow — Carpetas permitidas

Carpetas donde el asistente sí puede leer, escribir o modificar archivos. Si una
carpeta no está en esta lista, el asistente no puede tocarla, sin importar qué
se le pida.

**Windows (valor por defecto para una instalación nueva):**
| Ruta | Qué es |
|---|---|
| `C:\Users\TuUsuario\Repos` | Carpeta de proyectos donde se guardan los repositorios |
| `C:\Users\TuUsuario\Desktop` | Tu Escritorio (solo si existe) |
| `C:\Users\TuUsuario\OneDrive` | Tu OneDrive (solo si existe) |
| `C:\Users\TuUsuario\.personal-mcp` | Carpeta interna del asistente |

> ⚠️ Esto es el valor por defecto que recibe una instalación **nueva**. La config oficial
> de este equipo en particular puede ser distinta (más amplia o más restringida) si alguien
> la editó manualmente después de instalar — revisa siempre `~/.personal-mcp/config.json`
> para saber qué está realmente permitido, esta tabla no lo reemplaza.

**Linux/macOS (valor por defecto):**
| Ruta | Qué es |
|---|---|
| `~` (tu home) | Tu carpeta personal completa (`/home/tuusuario` o `/Users/tuusuario`). Incluye Documentos, Descargas, proyectos, etc. |

> ⚠️ En Windows, si necesitas acceso a Escritorio, OneDrive u otras carpetas,
> agrégalas explícitamente a `paths_allow` en el config oficial. En Linux/macOS,
> el valor por defecto (`~`) ya cubre todo.

> ⚠️ Si `paths_allow` incluye una raíz de disco completa (ej. `C:\`), la tool
> `project_git_status` sin `path` no escanea — devuelve el guard pidiendo un
> `path` puntual (comportamiento por diseño). Pasar siempre `path` a esa tool,
> ej.: `project_git_status(path="C:\Users\TuUsuario\Repos")`.

### paths_deny — Carpetas prohibidas (incluso dentro de una permitida)

Aunque una carpeta esté "por dentro" de una carpeta permitida, si coincide con
uno de estos patrones, queda bloqueada igual. Es una segunda capa de seguridad.

**Comunes a todos los sistemas:**
| Patrón | Qué bloquea |
|---|---|
| `**/node_modules/**` | Carpetas de dependencias de JavaScript |
| `**/.git/**` | Archivos internos de control de versiones de Git |
| `**/bin/**` | Carpetas de archivos compilados |
| `**/obj/**` | Carpetas temporales de compilación de .NET |
| `**/.ssh/**` | Claves y configuración SSH |
| `**/.aws/**` | Credenciales AWS |
| `**/.azure/**` | Credenciales Azure |
| `**/.kube/**` | Configuración Kubernetes |
| `**/.gnupg/**` | Claves GPG |
| `**/.docker/config.json` | Credenciales Docker |
| `**/.git-credentials` | Credenciales Git guardadas |
| `**/.netrc` | Credenciales de red (curl, etc.) |
| `**/.npmrc` | Token npm |
| `**/.pypirc` | Token PyPI |
| `**/.env*` | Archivos de variables de entorno |
| `**/*.pem` | Claves PEM (certificados) |
| `**/id_rsa*` | Claves SSH RSA |
| `**/id_ed25519*` | Claves SSH Ed25519 |

**Solo Windows:**
| Patrón | Qué bloquea |
|---|---|
| `**/AppData/**` | Carpeta interna de configuración de Windows, en cualquier parte del disco y con todo su contenido (el patrón con `**` cubre lo que hay dentro, no solo la carpeta literal) |

**Solo Linux/macOS:**
| Patrón | Qué bloquea |
|---|---|
| `~/.config/Code/User/globalStorage` | Tokens de VS Code |
| `~/.config/google-chrome` | Datos Chrome/Chromium |
| `~/.config/chromium` | Datos Chromium |
| `~/.mozilla` | Datos Firefox |

### paths_deny_exceptions — Excepciones puntuales a las carpetas prohibidas

Cuando un patrón de `paths_deny` bloquea una carpeta que en realidad necesitas
usar, puedes agregar una excepción acotada aquí. Ejemplo: un proyecto con
carpetas `bin` y `obj` (que los patrones generales
`**/bin/**` y `**/obj/**` bloquean), pero los archivos compilados que contiene
hay que poder leerlos para revisar el proyecto.

**Reglas de la excepción (importante):**
- Aplica SOLO a operaciones de lectura (abrir archivos, buscarlos, ver
  información). Nunca a escribir, modificar ni borrar — esas operaciones
  siguen bloqueadas en esas carpetas.
- Aplica SOLO a archivos con las extensiones de la lista
  `paths_deny_exception_extensions` (por defecto: `.dll`, `.exe`, `.pdb`).
- Si `paths_deny_exceptions` está vacía (valor por defecto), no hay ninguna
  excepción: todo sigue bloqueado igual que siempre.

Ejemplo de configuración:
```json
"paths_deny_exceptions": [
  "C:\\Users\\TuUsuario\\Repos\\MiProyecto\\**\\bin\\**",
  "C:\\Users\\TuUsuario\\Repos\\MiProyecto\\bin\\**",
  "C:\\Users\\TuUsuario\\Repos\\MiProyecto\\**\\obj\\**",
  "C:\\Users\\TuUsuario\\Repos\\MiProyecto\\obj\\**"
],
"paths_deny_exception_extensions": [".dll", ".exe", ".pdb"]
```

### commands — Qué comandos puede ejecutar en la terminal

- **allow_prefix (lista blanca):** define qué comandos SÍ puede ejecutar el
  asistente. Si tiene nombres adentro (por ejemplo `git`, `npm`, `python`),
  SOLO esos están permitidos — cualquier otro comando queda bloqueado
  automáticamente, incluso si no aparece en `deny`.
  ⚠️ Si esta lista queda vacía, el efecto NO es "todo permitido" — es
  exactamente lo contrario: el asistente no puede ejecutar ningún comando en
  absoluto, porque una lista vacía se interpreta como "ningún comando está
  autorizado". Por eso, en la práctica, esta lista casi nunca debería dejarse
  vacía si quieres poder usar la terminal.

- **readonly_prefix (lista de solo lectura):** lista aparte y más estricta que la
  anterior. Controla lo que puede ejecutar `sh_script`, la herramienta que envía
  una secuencia completa de comandos de una sola vez. Para que la secuencia se
  acepte, TODAS sus líneas deben estar formadas únicamente por comandos de esta
  lista — una sola línea que no esté en la lista rechaza la secuencia completa,
  antes de ejecutar nada. En la práctica son comandos que solo leen información
  (estado de git, listados, versiones): no hay forma de modificar ni borrar nada
  a través de `sh_script`.

  Lista actual en la configuración oficial de este equipo:
  ```json
  "readonly_prefix": [
    "git status", "git log", "git diff", "git show", "git branch", "git remote -v",
    "ls", "dir", "cat", "type", "echo",
    "docker ps", "docker images", "docker version",
    "npm list", "npm --version", "npm ls",
    "dotnet --version", "dotnet --info",
    "node --version", "pnpm --version", "pnpm list",
    "flutter --version", "flutter doctor",
    "python --version",
    "gh run list", "gh pr view", "gh repo view"
  ]
  ```
  💡 **Relación con las otras listas:** `allow_prefix` define qué se puede
  ejecutar en una llamada individual (`sh_exec`); `readonly_prefix` define qué
  se puede ejecutar dentro de una secuencia (`sh_script`) y es deliberadamente
  más corta. Un comando puede estar en `allow_prefix` y no en
  `readonly_prefix` (por ejemplo `npm install` o `git push`): funciona en
  llamadas individuales, pero no dentro de una secuencia.

- **deny (lista negra):** comandos que nunca se permiten. Incluye apagar el equipo,
  reiniciar, formatear discos, borrar todo de forma forzada, y modificar
  cuentas de usuario/administradores.

  💡 **Ya aplicado en la config oficial (agregado 2026-07-05):** si usas `python` o `node`, patrones específicos de operaciones peligrosas que esos programas pueden ejecutar por dentro ya están sumados al `deny` — por ejemplo `os.system`,
  `subprocess.run`, `shutil.rmtree`, `child_process`. La idea, tomada del
  mismo enfoque que usa Desktop Commander (otro asistente similar): no es una
  protección perfecta — alguien decidido a evadirla puede reescribir el código
  de otra forma — pero es gratis (solo texto en una lista) y frena el error
  honesto, que es el riesgo más probable en el uso diario. Estos son los patrones
  que ya están en el `deny` real de este equipo:
  ```json
  "os.system", "subprocess.run", "subprocess.Popen", "subprocess.call",
  "shutil.rmtree", "child_process", "require('fs').unlink", "curl * | ",
  "wget * | ", "iex (", "Invoke-Expression"
  ```
  Si estás configurando una instalación **nueva** desde `install.ps1`, revisa si estos
  patrones ya están en tu `deny` — el instalador no los agrega automáticamente todavía,
  así que en un equipo recién instalado sí tendrías que sumarlos a mano.

- **require_flag_approval:** banderas de comandos (como `-force` o `/f`) que obligan
  a una confirmación extra porque suelen ser destructivas.

### approval_required_prefix — Pedir permiso antes de usar programas "todopoderosos" (agregado 2026-07-05)

`python`, `node` y `bash` son distintos al resto de los comandos permitidos:
una vez que se les deja correr, pueden hacer casi cualquier cosa por dentro —
son como una navaja suiza, no una herramienta de un solo uso como `git status`.

Por eso, además de estar en la lista de comandos permitidos, estos tres
requieren un permiso aparte la primera vez que se usan en cada sesión de
conversación — igual que ya te pide permiso para borrar un archivo. Una vez
que dices que sí, no te vuelve a preguntar por ese mismo programa en esa
sesión (salvo que uses `fs_approve` con "una sola vez" en lugar de "toda la
sesión").

⚠️ **Importante, para que no haya sorpresas:** esto NO convierte a `python`/
`node`/`bash` en programas seguros. Solo agrega el paso de preguntarte antes
de la primera vez. Una vez que dices que sí, siguen siendo tan potentes como
siempre — de ahí que la recomendación de la lista negra de arriba siga
siendo útil incluso después de aprobar.

Si quieres que esto NO te pida permiso (por ejemplo, si tienes algo automático
corriendo sin supervisión), puedes vaciar esta lista en tu config oficial. Si
la vacías, `python`/`node`/`bash` vuelven a correr sin preguntar, igual que
`git` o `npm` hoy.

### rate_limit_commands_per_minute — Límite de comandos por minuto

Actualmente: 60. Si activas 0, se desactiva el límite. El límite se aplica por
separado para operaciones de lectura y escritura (no se mezclan los contadores).

### rate_limit_files_per_operation — Límite de archivos por operación

Actualmente: 100. La mayoría de las operaciones que tocan varios archivos a la
vez no pueden pasar de 100 en una sola llamada.

⚠️ **Excepción:** `fs_delete_batch` (borrado múltiple) **no tiene este límite**
desde el 2026-07-19 — puede procesar cualquier cantidad de archivos en una
sola llamada. Cada borrado sigue exigiendo su propio código de confirmación
igual que siempre; lo único que cambió es que no se trocea automáticamente
en grupos de 100.

### secret_scanning_enabled — Detección automática de secretos

Actualmente: true (activado). Cuando el asistente lee un archivo, escanea el
contenido buscando tokens, claves privadas, contraseñas en texto plano,
credenciales de bases de datos y otros secretos. Si encuentra algo, lo avisa
pero NO bloquea la lectura. Si no quieres esta función, puedes ponerla en
false.

---

## Sección shell (la terminal que usa el asistente)

| Campo | Significado | Valor actual (Windows) | Valor actual (Linux/macOS) |
|---|---|---|---|
| enabled | Si el asistente puede usar la terminal | Sí | Sí |
| default_shell | Terminal por defecto | `powershell` | `bash` |
| shell_map | Rutas personalizadas para otras terminales | Ninguna configurada | Ninguna configurada |
| session_timeout_seconds | Segundos de inactividad antes de cerrar una sesión | 600 (10 min) | 600 (10 min) |
| command_timeout_seconds | Segundos antes de cancelar un comando que no termina | 120 (2 min) | 120 (2 min) |

**Shells disponibles por plataforma:**
- **Windows:** `powershell`, `pwsh` (PowerShell Core), `cmd`, `bash` (via Git Bash)
- **Linux/macOS:** `bash`, `zsh`, `fish`, `sh`

Puedes cambiar de shell en tiempo de ejecución pasando el parámetro `shell` a
`sh_exec`, `sh_script` o `sh_session_start`.

---

## Sección ssh

| Campo | Significado | Valor actual |
|---|---|---|
| enabled | Si el asistente puede conectarse a OTRAS computadoras por SSH | No |

Apagado por defecto por seguridad — conectarse a otras máquinas es más sensible
que trabajar en la tuya.

**Archivo de configuración SSH (`~/.ssh/config`):**
Para usar SSH, necesitas definir tus hosts en:
- **Windows:** `C:\Users\TuUsuario\.ssh\config`
- **Linux/macOS:** `~/.ssh/config`

Se creó un archivo de ejemplo con plantillas comentadas — edítalo, descomenta los
hosts que uses y pon tus datos reales (IP/hostname, usuario, puerto, clave).
Ver la sección "Si quiero activar SSH" abajo.

---

## Si quiero activar SSH

1. Edita `~/.ssh/config` y descomenta/agrega tus hosts reales.
2. Asegúrate de tener las claves privadas correspondientes en `~/.ssh/`.
3. En el config oficial (`~/.personal-mcp/config.json`), pon:
   ```json
   "ssh": { "enabled": true }
   ```
4. Reinicia Claude Desktop.
5. Ejecuta `sync-config.ps1` (Windows) o `./sync-config.sh` (Linux/macOS) si quieres actualizar la copia del repo.

> ⚠️ **Solo activa SSH si confías en los hosts destino.** El asistente valida
> los comandos contra `remote_allow_prefix` (lista blanca remota) antes de
> enviarlos, pero una vez en el host remoto corren con los privilegios de ese
> usuario SSH — no hay contención real desde aquí.

---

## Sección journal (tu diario/bitácora personal)

| Campo | Significado | Valor actual |
|---|---|---|
| enabled | Si la función de diario está activa | Sí |
| path | Dónde se guardan las entradas | Windows: `C:\Users\TuUsuario\.personal-mcp\data\journal`<br>Linux/macOS: `~/.personal-mcp/data/journal` |

---

## Campos generales

| Campo | Significado | Valor actual |
|---|---|---|
| audit_max_entries | Cuántas operaciones recientes quedan registradas (como caja negra de avión) | 10,000 |
| data_dir | Carpeta donde el asistente guarda diario, historial y snapshots | Windows: `C:\Users\TuUsuario\.personal-mcp\data`<br>Linux/macOS: `~/.personal-mcp/data` |
| config_path | Campo técnico interno, normalmente vacío. No necesitas tocarlo. | (vacío) |

💡 **El registro se conserva entre reinicios.** Desde las versiones 1.4.71 y
1.4.72, la caja negra recupera correctamente el historial al reiniciar el
asistente (antes podía perderlo todo) y cada entrada identifica qué proceso la
generó — así se puede distinguir lo que hizo una sesión real de lo que hicieron
las pruebas automáticas del proyecto.

---

## El proceso de aprobación de permisos (el código de 6 dígitos)

Cuando el asistente quiere hacer algo que **cambia** archivos — escribir, editar,
borrar, mover, crear carpetas — o ejecutar un programa interpretado
(`python`, `node`, `bash`), no puede hacerlo solo: aparece una ventana de
confirmación en tu pantalla con un **código de 6 dígitos**. Este proceso se llama
"solicitud de permiso" y funciona así:

### 1. Cuándo aparece

| Situación | ¿Pide permiso? |
|---|---|
| Leer, listar, buscar, ver información de archivos | No |
| Ejecutar comandos de la lista blanca (`git status`, `npm`, etc.) | No |
| Escribir, editar, mover o borrar un archivo | Sí |
| Borrar varios archivos a la vez (`fs_delete_batch`) | Sí |
| Crear una carpeta | Sí |
| Ejecutar `python`, `node` o `bash` | Sí (además de la lista blanca) |

### 2. Qué pasa paso a paso

1. El asistente intenta la operación y el servidor crea una **solicitud pendiente**.
2. Aparece en tu pantalla una ventana del sistema (popup) que muestra qué
   recurso se quiere tocar, qué operación es, y el **código de confirmación**.
   Si la solicitud es de varios archivos, la ventana muestra la lista (hasta 10;
   si son más, indica cuántos hay en total).
3. **El asistente nunca ve ese código.** Solo aparece en la ventana de tu
   pantalla. Ninguna respuesta de las herramientas lo devuelve — es el único
   canal donde se muestra.
4. Tú le pasas el código al asistente (escríbelo en la conversación), o le dices
   que no. El asistente lo usa para confirmar la aprobación con `fs_approve`.

### 3. Las dos duraciones de un permiso

| Opción | Qué autoriza | Cuándo usar |
|---|---|---|
| **Una sola vez** | Exactamente esa operación sobre ese recurso | Lo normal: autorizar sin comprometer el resto de la sesión |
| **Toda la sesión** | La misma operación mientras dure la conversación/ventana | Tareas repetitivas sobre la misma carpeta (ej. varios borrados en una sesión de limpieza) |

No existe la opción "siempre" desde las herramientas: el permiso permanente solo
se puede dar editando `config.json` a mano (agregando la ruta a `paths_allow`).

### 4. Situaciones especiales

- **La ventana desapareció:** se puede consultar las solicitudes pendientes con
  `security_pending` y el código se vuelve a mostrar al intentar aprobar.
- **Caducidad:** una solicitud sin responder vence a los **5 minutos**. Si
  vence, el asistente puede crear una nueva.
- **Reinicio del servidor:** las solicitudes pendientes sobreviven al reinicio,
  pero con un **código nuevo** — la ventana vuelve a aparecer.
- **Intentos fallidos:** después de 10 intentos con un código incorrecto, la
  solicitud se rechaza sola.
- **Permiso para `python`/`node`/`bash`:** se pide la primera vez que se usan en
  la sesión. Si se aprueba con "toda la sesión", no vuelve a preguntar por ese
  programa hasta la próxima conversación; si se aprueba con "una sola vez",
  vuelve a preguntar en cada uso (misma regla que la sección de arriba).
- **Borrado de carpetas completas:** antes de pedir el código, el servidor
  muestra cuántos archivos y cuánto espacio ocupará el borrado, para que la
  decisión sea informada.

### 5. La parte honesta

El código no es una cerradura: el asistente puede crear solicitudes las veces
que quiera, y tú podrías escribir el código sin mirar la ventana. Su función
real es garantizar que **nada destructivo ocurre sin que veas una ventana** —
un recordatorio obligatorio, no un veto. Si quieres una protección más fuerte,
revisa los conectores paralelos habilitados en el cliente (ver la nota al
inicio de esta guía sobre el conector Filesystem).

---

## Si quiero cambiar algo

1. Edita el archivo oficial:
   - **Windows:** `C:\Users\TuUsuario\.personal-mcp\config.json`
   - **Linux/macOS:** `~/.personal-mcp/config.json`
   (NO el de este repositorio).
2. Guarda el archivo.
3. Reinicia Claude Desktop completo para que tome el cambio.
4. Opcional:
   - **Windows:** ejecuta `sync-config.ps1` en este repo.
   - **Linux/macOS:** ejecuta `./sync-config.sh` en este repo.

---

## Cómo verifico que un cambio se aplicó

1. **Reinicia Claude Desktop completo** (cierra la aplicación y ábrela de nuevo).
   El servidor lee el `config.json` **solo al arrancar**: editar el archivo no
   afecta a un servidor ya en marcha.
2. **Pídele al asistente que muestre la configuración real** con la herramienta
   `health_config` — devuelve el config tal como lo cargó el proceso en marcha.
   Compara el valor que cambiaste (por ejemplo, `rate_limit_commands_per_minute`
   o `paths_allow`).
3. **Si algo falla al arrancar**, revisa el registro del servidor con `mcp_log`
   (o el archivo `server.log` en `data_dir`): la causa aparece en las últimas
   líneas.
4. **Actualiza el espejo del repo** con `sync-config.ps1` / `sync-config.sh`
   solo después de confirmar que el config carga bien — el script se detiene
   sin tocar el espejo si el JSON está roto.

---

## Cómo mantengo la copia del repo actualizada

**Windows (PowerShell):**
```
cd C:\Users\TuUsuario\Repos\.personal-mcp
.\sync-config.ps1
```

**Linux/macOS (bash):**
```bash
cd /ruta/a/.personal-mcp
./sync-config.sh
```

Copia el archivo oficial hacia la copia del repo. Nunca al revés. El script
valida primero que el JSON oficial sea correcto: si está roto, se detiene sin
tocar el espejo.

### Sincronización automática (al iniciar sesión o cada día)

**Windows — tarea programada (iniciar sesión):**
```
schtasks /create /tn "personal-mcp-sync-config" /tr "powershell -NoProfile -ExecutionPolicy Bypass -File C:\Users\TuUsuario\Repos\.personal-mcp\sync-config.ps1" /sc onlogon /f
```
(o con `/sc daily /st 09:00` si prefieres diaria a una hora fija).
Para quitarla: `schtasks /delete /tn "personal-mcp-sync-config" /f`.

**Linux — systemd usuario (timer diario):**
1. Crea `~/.config/systemd/user/personal-mcp-sync.service`:
   ```
   [Unit]
   Description=Sincroniza el espejo de config de personal-mcp

   [Service]
   Type=oneshot
   ExecStart=/bin/bash /ruta/a/.personal-mcp/sync-config.sh
   ```
2. Crea `~/.config/systemd/user/personal-mcp-sync.timer`:
   ```
   [Unit]
   Description=Ejecuta la sincronizacion a las 09:00

   [Timer]
   OnCalendar=*-*-* 09:00:00
   Persistent=true

   [Install]
   WantedBy=timers.target
   ```
3. Activa: `systemctl --user enable --now personal-mcp-sync.timer`
   (y `systemctl --user list-timers` para verificar).

**macOS — launchd (al iniciar sesión):**
1. Crea `~/Library/LaunchAgents/com.personal-mcp.syncconfig.plist`:
   ```xml
   <?xml version="1.0" encoding="UTF-8"?>
   <plist version="1.0">
   <dict>
     <key>Label</key><string>com.personal-mcp.syncconfig</string>
     <key>ProgramArguments</key>
     <array><string>/bin/bash</string><string>/ruta/a/.personal-mcp/sync-config.sh</string></array>
     <key>RunAtLoad</key><true/>
     <key>StartInterval</key><integer>86400</integer>
   </dict>
   </plist>
   ```
2. Carga: `launchctl load ~/Library/LaunchAgents/com.personal-mcp.syncconfig.plist`

> La tarea solo refresca el **espejo del repo**. El archivo real se sigue
> editando a mano, igual que antes.

---

## Instalación y actualización del servidor

### Instalación inicial (Windows)

1. Instala **Python 3.10 o superior** si no lo tienes.
2. Clona (o copia) este repositorio, por ejemplo en `C:\Users\TuUsuario\Repos\.personal-mcp`.
3. Ejecuta desde esa carpeta:
   ```
   .\install.ps1
   ```
   El instalador hace 6 pasos: verifica Python, crea el entorno virtual
   (`.venv`), instala las dependencias, crea la estructura de carpetas, genera
   el `config.json` inicial (solo si no existe), y registra el servidor con
   Claude Desktop.
4. **Reinicia Claude Desktop completo** para que tome el servidor.

**Sobre el config inicial que genera el instalador:** usa rutas propias
(`source\repos`, `Documents\GitHub`, `repos` si existen, más Escritorio,
OneDrive si existe, y `.personal-mcp`) — distintas de las que muestra la tabla
de `paths_allow` de esta guía (que son las del código por defecto). Por eso la
regla de siempre: revisa `~/.personal-mcp/config.json` para saber qué está
realmente permitido.

**Varias cuentas/ventanas de Claude Desktop:** el instalador acepta rutas
extra de datos de usuario:
```
.\install.ps1 -UserDataDirs "C:\Users\TuUsuario\Claude-Cuenta2","C:\Users\TuUsuario\Claude-Cuenta3"
```
Cada cuenta tendrá su propio servidor registrado (y su propio proceso, que
escribe en los mismos archivos de registro).

### Actualización a una versión nueva

1. Actualiza el código: `git pull` dentro de `C:\Users\TuUsuario\Repos\.personal-mcp`.
2. Actualiza las dependencias (por si la versión nueva agregó alguna):
   ```
   .\.venv\Scripts\python -m pip install -r requirements.txt
   ```
3. **Reinicia Claude Desktop completo.** El instalador se puede re-ejecutar
   cuando quieras: es seguro repetirlo, no sobrescribe un config existente y
   solo vuelve a registrar el servidor en Claude Desktop.
4. Verifica la versión: pídele al asistente `mcp_list_tools` y comprueba que
   las herramientas nuevas de la versión aparecen (el detalle de cada versión
   está en el `CHANGELOG.md` del repo).

> No hace falta desinstalar nada para actualizar. Si quieres eliminar el
> servidor por completo, basta con quitar la entrada `personal-mcp` de
> `claude_desktop_config.json` y borrar la carpeta `~/.personal-mcp`.