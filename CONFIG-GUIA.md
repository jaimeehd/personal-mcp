# Guía del archivo de configuración (para no-técnicos)

Este documento explica, en lenguaje simple, qué significa cada parte del archivo
`config.json`. No necesitas saber programar para entender esto.

> IMPORTANTE: el archivo que de verdad controla el comportamiento del asistente
> está en tu carpeta de usuario, no en este repositorio:
>
> `C:\Users\User\.personal-mcp\config.json`
>
> El archivo `config.json` que está aquí, junto a esta guía, es solo una copia de
> lectura para que puedas revisarla sin salir del repositorio. Si la editas aquí,
> no cambia nada en el comportamiento real. Para actualizar el espejo con los
> cambios más recientes, ejecuta `sync-config.ps1` desde esta misma carpeta.

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

| Ruta | Qué es |
|---|---|
| C:\Repos | Tu carpeta de repositorios/proyectos. **Todo** lo que esté dentro — cualquier subcarpeta, sin importar cuántos niveles — queda accesible automáticamente. No hace falta listar cada proyecto por separado. |

⚠️ **Nota de corrección (2026-07-04):** una versión anterior de esta guía
listaba 7 rutas separadas (`C:\Users\User\Repos`, `Desktop`, `OneDrive`,
`C:\Users\User\.personal-mcp`, y 3 subcarpetas de `C:\Repos`). Esa lista ya
**no coincide** con la configuración real: hoy el asistente **no** puede
acceder a tu Escritorio, OneDrive, ni a `C:\Users\User\Repos` — solo a lo que
esté dentro de `C:\Repos`. Si necesitas que el asistente trabaje en alguna de
esas carpetas, hay que agregarlas explícitamente a `paths_allow` en el config
oficial (`C:\Users\User\.personal-mcp\config.json`), no en esta copia de
lectura.

### paths_deny — Carpetas prohibidas (incluso dentro de una permitida)

Aunque una carpeta esté "por dentro" de una carpeta permitida, si coincide con
uno de estos patrones, queda bloqueada igual. Es una segunda capa de seguridad.

| Patrón | Qué bloquea |
|---|---|
| **\node_modules\** | Carpetas de dependencias de JavaScript |
| **\.git\** | Archivos internos de control de versiones de Git |
| **\bin\** | Carpetas de archivos compilados |
| **\obj\** | Carpetas temporales de compilación de .NET |
| C:\Users\User\AppData | Carpeta interna de configuración de Windows |

### commands — Qué comandos puede ejecutar en la terminal

- allow_prefix (lista blanca): define qué comandos SÍ puede ejecutar el
  asistente. Si tiene nombres adentro (por ejemplo `git`, `npm`, `python`),
  SOLO esos están permitidos — cualquier otro comando queda bloqueado
  automáticamente, incluso si no aparece en `deny`.
  ⚠️ Si esta lista queda vacía, el efecto NO es "todo permitido" — es
  exactamente lo contrario: el asistente no puede ejecutar ningún comando en
  absoluto, porque una lista vacía se interpreta como "ningún comando está
  autorizado". Por eso, en la práctica, esta lista casi nunca debería dejarse
  vacía si quieres poder usar la terminal.
- deny (lista negra): comandos que nunca se permiten. Incluye apagar el equipo,
  reiniciar, formatear discos, borrar todo de forma forzada, y modificar
  cuentas de usuario de Windows.

  💡 **Recomendación (agregada 2026-07-05):** si usás `python` o `node`, vale
  la pena sumar patrones específicos de operaciones peligrosas que esos
  programas pueden ejecutar por dentro — por ejemplo `os.system`,
  `subprocess.run`, `shutil.rmtree`, `child_process`. La idea, tomada del
  mismo enfoque que usa Desktop Commander (otro asistente similar): no es una
  protección perfecta — alguien decidido a evadirla puede reescribir el código
  de otra forma — pero es gratis (solo texto en una lista) y frena el error
  honesto, que es el riesgo más probable en el uso diario. Ejemplo de lista
  ampliada, agregable a `deny`:
  ```json
  "os.system", "subprocess.run", "subprocess.Popen", "subprocess.call",
  "shutil.rmtree", "child_process", "require('fs').unlink", "curl * | ",
  "wget * | ", "iex (", "Invoke-Expression"
  ```
- require_flag_approval: banderas de comandos (como -force o /f) que obligan
  a una confirmación extra porque suelen ser destructivas.

### approval_required_prefix — Pedir permiso antes de usar programas "todopoderosos" (agregado 2026-07-05)

`python`, `node` y `bash` son distintos al resto de los comandos permitidos:
una vez que se les deja correr, pueden hacer casi cualquier cosa por dentro —
son como una navaja suiza, no una herramienta de un solo uso como `git status`.

Por eso, además de estar en la lista de comandos permitidos, estos tres
requieren un permiso aparte la primera vez que se usan en cada sesión de
conversación — igual que ya te pide permiso para borrar un archivo. Una vez
que decís que sí, no te vuelve a preguntar por ese mismo programa en esa
sesión (salvo que uses `fs_approve` con "una sola vez" en lugar de "toda la
sesión").

⚠️ **Importante, para que no haya sorpresas:** esto NO convierte a `python`/
`node`/`bash` en programas seguros. Solo agrega el paso de preguntarte antes
de la primera vez. Una vez que decís que sí, siguen siendo tan potentes como
siempre — de ahí que la recomendación de la lista negra de arriba siga
siendo útil incluso después de aprobar.

Si querés que esto NO te pida permiso (por ejemplo, si tenés algo automático
corriendo sin supervisión), podés vaciar esta lista en tu config oficial. Si
la vaciás, `python`/`node`/`bash` vuelven a correr sin preguntar, igual que
`git` o `npm` hoy.

### rate_limit_commands_per_minute — Límite de comandos por minuto

Actualmente: 60. Si activas 0, se desactiva el límite. El límite se aplica por
separado para operaciones de lectura y escritura (no se mezclan los contadores).

### rate_limit_files_per_operation — Límite de archivos por operación

Actualmente: 100. Ninguna operación puede tocar más de 100 archivos a la vez.

### secret_scanning_enabled — Detección automática de secretos

Actualmente: true (activado). Cuando el asistente lee un archivo, escanea el
contenido buscando tokens, claves privadas, contraseñas en texto plano,
credenciales de bases de datos y otros secretos. Si encuentra algo, lo avisa
pero NO bloquea la lectura. Si no quieres esta función, puedes ponerla en
false.

---

## Sección shell (la terminal que usa el asistente)

| Campo | Significado | Valor actual |
|---|---|---|
| enabled | Si el asistente puede usar la terminal | Sí |
| default_shell | Terminal por defecto | PowerShell |
| shell_map | Rutas personalizadas para otras terminales | Ninguna configurada |
| session_timeout_seconds | Segundos de inactividad antes de cerrar una sesión | 600 (10 min) |
| command_timeout_seconds | Segundos antes de cancelar un comando que no termina | 120 (2 min) |

---

## Sección ssh

| Campo | Significado | Valor actual |
|---|---|---|
| enabled | Si el asistente puede conectarse a OTRAS computadoras por SSH | No |

Apagado por defecto por seguridad — conectarse a otras máquinas es más sensible
que trabajar en la tuya.

---

## Sección journal (tu diario/bitácora personal)

| Campo | Significado | Valor actual |
|---|---|---|
| enabled | Si la función de diario está activa | Sí |
| path | Dónde se guardan las entradas | C:\Users\User\.personal-mcp\data\journal |

---

## Campos generales

| Campo | Significado | Valor actual |
|---|---|---|
| audit_max_entries | Cuántas operaciones recientes quedan registradas (como caja negra de avión) | 10,000 |
| data_dir | Carpeta donde el asistente guarda diario, historial y snapshots | C:\Users\User\.personal-mcp\data |
| config_path | Campo técnico interno, normalmente vacío. No necesitas tocarlo. | (vacío) |

---

## Si quiero cambiar algo

1. Edita el archivo oficial: C:\Users\User\.personal-mcp\config.json (no el de este repositorio).
2. Guarda el archivo.
3. Reinicia Claude Desktop completo para que tome el cambio.
4. Opcional: ejecuta sync-config.ps1 en este repo para que la copia de lectura quede al día.

## Cómo mantengo la copia del repo actualizada

Manualmente, desde PowerShell:

```
cd C:\Repos\.personal-mcp
.\sync-config.ps1
```

Copia el archivo oficial hacia la copia del repo. Nunca al revés.

Si quieres que esto pase automáticamente al iniciar sesión en Windows, pregúntame
y lo configuro contigo — requiere crear una tarea programada de Windows, así que
prefiero confirmarlo antes de tocar esa parte del sistema.
