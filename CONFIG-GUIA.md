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
| C:\Users\User\Repos | Tu carpeta personal de proyectos |
| C:\Users\User\Desktop | Tu escritorio |
| C:\Users\User\OneDrive | Tu carpeta de OneDrive |
| C:\Users\User\.personal-mcp | Carpeta interna del propio asistente (su config y sus datos) |
| C:\Repos\HikBioAccess | Tu proyecto de control de acceso biométrico |
| C:\Repos\.personal-mcp | El código fuente de este mismo asistente |
| C:\Repos\doc-pipeline\knowledge-base | Tu base de conocimiento de documentación |

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

- allow_prefix (lista blanca): si está vacía (como ahora), todos los comandos
  están permitidos por defecto, excepto los que aparecen en deny. Si tuviera
  nombres de comandos adentro, sería lo opuesto: solo esos estarían permitidos.
- deny (lista negra): comandos que nunca se permiten. Incluye apagar el equipo,
  reiniciar, formatear discos, borrar todo de forma forzada, y modificar
  cuentas de usuario de Windows.
- require_flag_approval: banderas de comandos (como -force o /f) que obligan
  a una confirmación extra porque suelen ser destructivas.

### rate_limit_commands_per_minute — Límite de comandos por minuto

Actualmente: 60. Protección contra bucles descontrolados.

### rate_limit_files_per_operation — Límite de archivos por operación

Actualmente: 100. Ninguna operación puede tocar más de 100 archivos a la vez.

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
