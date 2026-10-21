# 🛡️ php2shell-remediation

**[🇪🇸 Español](#es)** · **[🇬🇧 English](#en)**

---

<a id="es"></a>

## 🇪🇸 Español

### 🤔 ¿Qué es esto?

**php2shell** (CVE-2026-109618 / CVE-2026-109619) es una vulnerabilidad crítica de PHP (CVSS 9.2) que permite a un atacante **ejecutar código en tu servidor sin iniciar sesión**. Los reportes apuntan a una función poco usada: `session.upload_progress` (la barra de progreso de subidas).

Este repo **apaga esa función** en tus servidores mientras llega el parche oficial.

> 🔒 Piénsalo como poner un candado en una puerta que nadie usa, mientras llega el cerrajero a cambiar la cerradura.

> ⚠️ **Esto NO sustituye el parche.** La solución real es actualizar PHP a **8.2.35 / 8.3.36 / 8.4.27 / 8.5.12**.

### 🧩 Cómo funciona

Son dos scripts:

| Script | Dónde corre | Qué hace |
|--------|-------------|----------|
| 🤖 `php2shell-mitigate.sh` | En cada servidor | Aplica la mitigación |
| 🎛️ `php2shell-run-all.sh` | En tu máquina | Corre el agente en todos tus servidores por SSH y junta los resultados |

Lo que hace el agente, paso a paso:

1. 🔍 **Detecta** tu hosting: DreamHost, cPanel o genérico.
2. 🔧 **Apaga** la función vulnerable: `session.upload_progress.enabled = 0` + `session.use_strict_mode = 1`
   - DreamHost → un `phprc` por versión de PHP (`~/.php/<versión>/phprc`)
   - cPanel / genérico → un `.user.ini` en cada sitio
3. 🔐 **Protege** ese archivo con `.htaccess` para que nadie lo descargue desde internet.
4. ✅ **Comprueba** que funcionó: pregunta a cada sitio vía HTTP con un archivo temporal que luego borra.
5. 📝 **Reporta** el resultado.

💾 Todo lo que toca queda respaldado: `--rollback` lo deshace.

### 🚀 Inicio rápido

#### 📋 Requisitos

- 🐚 Bash 4+ y `curl` en los servidores
- 🔑 Acceso SSH **por llave** (nunca pide contraseñas)
- 👤 Correr como **cada usuario de hosting** que sirva sitios (no necesita root)

#### 🖥️ Un solo servidor

```bash
ssh usuario@servidor 'bash -s' < php2shell-mitigate.sh                  # 🔧 aplicar
ssh usuario@servidor 'bash -s -- --dry-run' < php2shell-mitigate.sh     # 👀 simular (no cambia nada)
ssh usuario@servidor 'bash -s -- --verify' < php2shell-mitigate.sh      # ✅ solo verificar
ssh usuario@servidor 'bash -s -- --rollback' < php2shell-mitigate.sh    # ↩️ revertir
```

> 💡 Las opciones van **dentro de las comillas, después de `--`**. Si las pones fuera, `bash` las rechaza.

#### 🌐 Muchos servidores

**1.** Crea tu lista de servidores:

```bash
cp servers.example.txt servers.txt
```

```
usuario@servidor.ejemplo.com
usuario@otro-servidor.ejemplo.com:2222
```

> 🙈 `servers.txt` y los resultados están en `.gitignore`: tus hosts reales nunca se suben al repo.

**2.** Ejecuta:

```bash
./php2shell-run-all.sh servers.txt --dry-run    # 👀 simular primero
./php2shell-run-all.sh servers.txt              # 🔧 aplicar (5 servidores a la vez)
./php2shell-run-all.sh servers.txt --verify     # ✅ verificar (espera 5 min, ver abajo)
./php2shell-run-all.sh servers.txt --rollback   # ↩️ revertir
```

**3.** Revisa los resultados:

| Archivo | Contenido |
|---------|-----------|
| 📊 `php2shell-consolidado.csv` | Una fila por servidor: estado y métricas |
| 📄 `results/reporte-<usuario>-<host>.md` | Detalle por servidor y por sitio |

### ⚙️ Opciones

Sirven para ambos scripts.

| Opción | Qué hace |
|--------|----------|
| *(ninguna)* | 🔧 Aplica la mitigación |
| `--dry-run` | 👀 Muestra qué haría, sin tocar nada |
| `--verify` | ✅ Comprueba la configuración sin cambiarla (crea y borra un archivo de prueba por sitio) |
| `--rollback` | ↩️ Restaura los respaldos y elimina lo que el script creó |
| `--php-versions 8.3,8.4` | 🎯 Fuerza las versiones de PHP (DreamHost) si la detección no las encuentra |
| `--domains s1.com,s2.com` | 🎯 Fuerza la lista de sitios (carpetas `~/<dominio>`) |

### 🚦 Cómo leer los resultados

**Estado por servidor** (columna `estado` del CSV):

| Estado | Significado |
|--------|-------------|
| 🟢 `OK` | El agente corrió bien |
| 🔴 `SSH_FAIL` | No se pudo conectar; revisa la llave SSH |
| 🟠 `AGENT_ERROR` | El agente terminó con error; revisa el reporte |
| 🟠 `NO_SUMMARY` / `MODE_MISMATCH` | Salida inesperada del agente |

**Estado por sitio** (en el reporte):

| Estado | Significado |
|--------|-------------|
| 🟢 `OK` | Verificado: la función está apagada |
| 🟡 `STALE` | Aún muestra el valor viejo; espera 5 min y re-corre `--verify` |
| 🟠 `UNREACHABLE` | No respondió por HTTP; verifícalo manualmente con `phpinfo()` |
| 🔴 `ABSENT` | Esta build de PHP no tiene la directiva; revisa la versión |

> ⏱️ **Espera 5 minutos.** `.user.ini` tarda hasta **300 s** en recargarse. Justo después de aplicar es normal ver `STALE`; corre `--verify` cinco minutos después.

### 📁 Qué archivos toca

| Archivo | Acción | Respaldo |
|---------|--------|----------|
| `~/.php/<versión>/phprc` | Añade las 2 directivas | `phprc.bak-php2shell` |
| `<sitio>/.user.ini` | Añade las 2 directivas (o lo crea) | `.user.ini.bak-php2shell` |
| `<sitio>/.htaccess` | Añade un bloque `# BEGIN/END php2shell protection` que bloquea el acceso web a `.user.ini*` | `.htaccess.bak-php2shell-<fecha>` |
| Archivo de prueba | Se crea y **se borra solo** | — |

- 🔁 **Puedes correrlo varias veces:** no duplica cambios, y un archivo ya mitigado no se toca.
- 🔒 Los respaldos de `phprc` y `.user.ini` quedan con permisos `600` (solo tu usuario los lee).

### 🚧 Limitaciones conocidas

- 🧪 **cPanel:** la detección de sitios vía `uapi` aún no se ha validado en un servidor cPanel real. Prueba primero con `--dry-run` y confirma que diga `N docroot(s) en lista`.
- 🌐 **Verificación en `public_html`:** el dominio se deduce del nombre de la carpeta padre (el usuario), así que el sitio principal puede salir como `UNREACHABLE`. Verifícalo manualmente.
- 📄 **`phprc` con secciones:** si tu `phprc` termina en una sección `[PATH=…]` o `[HOST=…]`, las directivas quedan dentro de esa sección. Revísalo a mano.
- 🎯 **`--domains` en cPanel:** solo busca carpetas `~/<dominio>`, no rutas dentro de `public_html`.

### 📝 Lo que tienes que hacer tú

- [ ] 🎫 **Ticket al proveedor** (DreamHost / cPanel / CloudLinux): ¿cuándo despliegan el PHP parcheado? ¿Hay backport para versiones antiguas?
- [ ] ⬆️ **Actualizar PHP** a 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12. En Debian/Ubuntu el fix llega backporteado y **el número de versión no cambia**: revisa el changelog de seguridad, no `php -v`.
- [ ] 🧓 **PHP 5.x / 7.x / 8.0 / 8.1** no reciben parche: migra, aísla de internet o pide backport al proveedor.
- [ ] 🧱 **WAF:** restringe `multipart/form-data` en rutas que no reciben archivos.
- [ ] 👁️ **Detección:** alerta sobre procesos hijos raros de php-fpm, segfaults y conexiones salientes inesperadas.
- [ ] ✅ Corre `--verify` otra vez después del parche.

📘 Guía completa paso a paso: [`docs/guia-remediacion.md`](docs/guia-remediacion.md)

---

<a id="en"></a>

## 🇬🇧 English

### 🤔 What is this?

**php2shell** (CVE-2026-109618 / CVE-2026-109619) is a critical PHP vulnerability (CVSS 9.2) that lets an attacker **run code on your server without logging in**. Reports point to a rarely used feature: `session.upload_progress` (the native upload progress bar).

This repo **turns that feature off** on your servers until the official patch is installed.

> 🔒 Think of it as padlocking a door nobody uses while you wait for the locksmith to replace the lock.

> ⚠️ **This does NOT replace the patch.** The real fix is upgrading PHP to **8.2.35 / 8.3.36 / 8.4.27 / 8.5.12**.

### 🧩 How it works

There are two scripts:

| Script | Runs on | What it does |
|--------|---------|--------------|
| 🤖 `php2shell-mitigate.sh` | Each server | Applies the mitigation |
| 🎛️ `php2shell-run-all.sh` | Your machine | Runs the agent on all your servers over SSH and collects the results |

What the agent does, step by step:

1. 🔍 **Detects** your hosting: DreamHost, cPanel or generic.
2. 🔧 **Turns off** the vulnerable feature: `session.upload_progress.enabled = 0` + `session.use_strict_mode = 1`
   - DreamHost → one `phprc` per PHP version (`~/.php/<version>/phprc`)
   - cPanel / generic → one `.user.ini` per site
3. 🔐 **Protects** that file with `.htaccess` so nobody can download it from the web.
4. ✅ **Checks** that it worked: asks each site over HTTP using a temporary file it deletes afterwards.
5. 📝 **Reports** the result.

💾 Everything it touches is backed up: `--rollback` undoes it.

### 🚀 Quick start

#### 📋 Requirements

- 🐚 Bash 4+ and `curl` on the servers
- 🔑 **Key-based** SSH access (it never asks for passwords)
- 👤 Run it as **each hosting user** that serves sites (no root needed)

#### 🖥️ Single server

```bash
ssh user@server 'bash -s' < php2shell-mitigate.sh                  # 🔧 apply
ssh user@server 'bash -s -- --dry-run' < php2shell-mitigate.sh     # 👀 simulate (changes nothing)
ssh user@server 'bash -s -- --verify' < php2shell-mitigate.sh      # ✅ verify only
ssh user@server 'bash -s -- --rollback' < php2shell-mitigate.sh    # ↩️ roll back
```

> 💡 Options go **inside the quotes, after `--`**. Outside the quotes, `bash` rejects them.

#### 🌐 Many servers

**1.** Create your server list:

```bash
cp servers.example.txt servers.txt
```

```
user@server.example.com
user@another-server.example.com:2222
```

> 🙈 `servers.txt` and the results are in `.gitignore`: your real hosts are never committed.

**2.** Run:

```bash
./php2shell-run-all.sh servers.txt --dry-run    # 👀 simulate first
./php2shell-run-all.sh servers.txt              # 🔧 apply (5 servers at a time)
./php2shell-run-all.sh servers.txt --verify     # ✅ verify (wait 5 min, see below)
./php2shell-run-all.sh servers.txt --rollback   # ↩️ roll back
```

**3.** Check the results:

| File | Contents |
|------|----------|
| 📊 `php2shell-consolidado.csv` | One row per server: status and metrics |
| 📄 `results/reporte-<user>-<host>.md` | Per-server and per-site details |

### ⚙️ Options

They work with both scripts.

| Option | What it does |
|--------|--------------|
| *(none)* | 🔧 Applies the mitigation |
| `--dry-run` | 👀 Shows what it would do without touching anything |
| `--verify` | ✅ Checks the configuration without changing it (creates and deletes one test file per site) |
| `--rollback` | ↩️ Restores the backups and removes what the script created |
| `--php-versions 8.3,8.4` | 🎯 Forces the PHP versions (DreamHost) when detection misses them |
| `--domains s1.com,s2.com` | 🎯 Forces the site list (`~/<domain>` folders) |

### 🚦 Reading the results

**Per-server status** (`estado` column in the CSV):

| Status | Meaning |
|--------|---------|
| 🟢 `OK` | The agent ran fine |
| 🔴 `SSH_FAIL` | Could not connect; check the SSH key |
| 🟠 `AGENT_ERROR` | The agent exited with an error; check the report |
| 🟠 `NO_SUMMARY` / `MODE_MISMATCH` | Unexpected agent output |

**Per-site status** (in the report):

| Status | Meaning |
|--------|---------|
| 🟢 `OK` | Verified: the feature is off |
| 🟡 `STALE` | Still shows the old value; wait 5 min and run `--verify` again |
| 🟠 `UNREACHABLE` | No HTTP response; check it manually with `phpinfo()` |
| 🔴 `ABSENT` | This PHP build lacks the directive; check the version |

> ⏱️ **Wait 5 minutes.** `.user.ini` takes up to **300 s** to reload. Seeing `STALE` right after applying is normal; run `--verify` five minutes later.

### 📁 Files it touches

| File | Action | Backup |
|------|--------|--------|
| `~/.php/<version>/phprc` | Adds the 2 directives | `phprc.bak-php2shell` |
| `<site>/.user.ini` | Adds the 2 directives (or creates it) | `.user.ini.bak-php2shell` |
| `<site>/.htaccess` | Adds a `# BEGIN/END php2shell protection` block that denies web access to `.user.ini*` | `.htaccess.bak-php2shell-<date>` |
| Test file | Created and **deleted automatically** | — |

- 🔁 **Safe to run repeatedly:** it never duplicates changes, and an already mitigated file is left alone.
- 🔒 `phprc` and `.user.ini` backups get `600` permissions (only your user can read them).

### 🚧 Known limitations

- 🧪 **cPanel:** site detection via `uapi` has not been validated on a live cPanel server yet. Try `--dry-run` first and confirm it prints `N docroot(s) en lista`.
- 🌐 **Verification on `public_html`:** the domain is guessed from the parent folder name (the username), so the main site may show `UNREACHABLE`. Check it manually.
- 📄 **`phprc` with sections:** if your `phprc` ends with a `[PATH=…]` or `[HOST=…]` section, the directives land inside that section. Review it by hand.
- 🎯 **`--domains` on cPanel:** it only looks for `~/<domain>` folders, not paths inside `public_html`.

### 📝 What you still need to do

- [ ] 🎫 **Ticket your provider** (DreamHost / cPanel / CloudLinux): when will patched PHP ship? Is there a backport for older versions?
- [ ] ⬆️ **Upgrade PHP** to 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12. On Debian/Ubuntu the fix is backported and **the version number does not change**: check the security changelog, not `php -v`.
- [ ] 🧓 **PHP 5.x / 7.x / 8.0 / 8.1** get no patch: migrate, isolate from the internet, or ask your provider for a backport.
- [ ] 🧱 **WAF:** restrict `multipart/form-data` on routes that don't accept uploads.
- [ ] 👁️ **Detection:** alert on unusual php-fpm child processes, segfaults and unexpected outbound connections.
- [ ] ✅ Run `--verify` again after patching.

📘 Full step-by-step guide: [`docs/remediation-guide.md`](docs/remediation-guide.md)

---

## 📚 CVE / Referencias / References

| | |
|---|---|
| 🆔 CVEs | CVE-2026-109618 / CVE-2026-109619 |
| 🔥 CVSS v4.0 | **9.2 Critical** (both) |
| 🎯 Class / Clase | Unauthenticated RCE in PHP core |
| 📦 Affects / Afecta | PHP 5.4+ (only 8.x gets a patch) |
| 🩹 Patch / Parche | Emergency release 2026-10-21 14:00 UTC |
| 🧭 Reported vector / Vector | `session.upload_progress` (community; not officially confirmed) |

- PHP — emergency release: https://www.php.net/archive/2026.php#2026-10-20-1
- Sansec — "PHP2Shell": https://sansec.io/research/php2shell
- Huntress — Rapid Response: https://www.huntress.com/blog/php2shell-leaked-critical-php-vulnerabilities
- SecureLayer7 — analysis: https://blog.securelayer7.net/php-rce-cve-2026-109618-109619/
- DreamHost — phprc: https://help.dreamhost.com/hc/en-us/articles/214200688-php-ini-overview
- PHP — `.user.ini`: https://www.php.net/manual/en/configuration.file.per-user.php

## ⚖️ Licencia / License

MIT — see [LICENSE](LICENSE).

> ⚠️ **ES:** Úsalo solo en sistemas que **administres o tengas autorización escrita para modificar**. Es una mitigación temporal basada en análisis de la comunidad no confirmado; el único fix completo es actualizar PHP.
>
> ⚠️ **EN:** Use only on systems you **own or are authorized in writing to modify**. This is a temporary mitigation based on unconfirmed community analysis; the only complete fix is upgrading PHP.
