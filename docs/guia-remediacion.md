# Guía de Remediación — php2shell (CVE-2026-109618 / CVE-2026-109619)

🇬🇧 [English version](remediation-guide.md)

**Severidad:** CVSS v4.0 9.2 (Crítica) × 2 — RCE no autenticado en el núcleo de PHP
**Afecta:** PHP 5.4 en adelante (solo 8.x recibe parche oficial)
**Versiones fijas:** 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 (release de emergencia PHP: 21-oct-2026 14:00 UTC)
**Nota:** La causa raíz publicada (UAF en `session.upload_progress`) es de comunidad, no confirmada oficialmente. Aplica TODAS las capas de mitigación; ninguna sola es garantía.

---

## FASE 0 — Inventario (hacer primero, todo lo demás depende de esto)

En cada servidor, identificar versiones y SAPI:

```bash
# Versiones de PHP instaladas (Debian/Ubuntu)
ls /etc/php/ && for v in $(ls /etc/php/); do echo "PHP $v:"; /usr/bin/php$v -v 2>/dev/null | head -1; done

# SAPI: ¿FPM, mod_php, cgi?
dpkg -l | grep -E 'php.*-(fpm|cgi|cli)' ; apachectl -M 2>/dev/null | grep php

# ¿Quién sirve PHP al web? (process list)
ps aux | grep -E 'php-fpm|php-cgi|lsphp'

# Docker: revisar imágenes base
docker ps --format '{{.Image}}' | sort -u

# Verificar el setting activo en un request REAL (no CLI):
echo '<?php phpinfo();' > /tmp/check.php   # servir temporalmente y revisar:
# session.upload_progress.enabled  → debe decir Off después del fix
```

Para cPanel/panel: revisar por sitio qué versión está seleccionada (MultiPHP Manager / Select PHP Version). **Sitios con PHP fijado manualmente a 7.x/8.0/8.1 no recibirán parche** aunque el proveedor actualice.

---

## FASE 1 — Mitigación inmediata (hoy, sin ventana de mantenimiento)

### A. Servidores con PHP-FPM (lo más común)

Crear drop-in global (Debian/Ubuntu):

```bash
for v in /etc/php/*/fpm/conf.d; do
  cat > "$v/99-php2shell-mitigation.ini" <<'EOF'
session.upload_progress.enabled = 0
session.use_strict_mode = 1
EOF
done
systemctl reload php*-fpm
```

En pools específicos (`/etc/php/8.x/fpm/pool.d/*.conf`) alternativamente:

```ini
php_admin_flag[session.upload_progress.enabled] = off
php_admin_flag[session.use_strict_mode] = on
```

### B. Apache con mod_php

Editar php.ini (o añadir a `.htaccess` para modo PERDIR):

```ini
session.upload_progress.enabled = 0
session.use_strict_mode = 1
```
```bash
apachectl configtest && systemctl restart apache2
```

### C. PHP-CGI / LiteSpeed / CloudLinux (shared hosting)

- cPanel → MultiPHP INI Editor (o "Select PHP Version" → Options) → añadir:
  `session.upload_progress.enabled = Off`
- Alternativa portable: `.user.ini` en el document root:
  ```ini
  session.upload_progress.enabled = 0
  session.use_strict_mode = 1
  ```
  (surte efecto en ≤5 min por user_ini.cache_ttl; protegerlo con `.htaccess`: `<Files ".user.ini"> Require all denied </Files>`)
- CloudLinux CageFS: recrear tras el cambio (`cagefsctl --force-update`).

### D. Docker / contenedores

Añadir al dockerfile/entrypoint o montar un ini:
```bash
echo -e "session.upload_progress.enabled=0\nsession.use_strict_mode=1" \
  > /usr/local/etc/php/conf.d/99-php2shell.ini
```
Recrear contenedores; reconstruir imágenes que hardcodean versiones < 8.2.

### Impacto funcional: NINGUNO
Solo desactiva las barras nativas de progreso de subida. WordPress, WooCommerce, Magento, Shopware, Laravel no las usan. `use_strict_mode` es la recomendación por defecto de PHP. Excepción: sesiones en Redis/DB no implementan el check de strict mode (el setting queda inofensivo/inoperante ahí).

---

## FASE 2 — Mitigación en el borde (WAF / reverse proxy)

Porque puede existir una segunda ruta en el parser multipart que corre aunque el setting esté Off:

- **Nginx** (delante de PHP): rate-limit a `multipart/form-data`:
  ```nginx
  location ~ \.php$ {
      limit_req zone=multipart burst=5 nodelay;  # ajustar a rutas con upload real
      ...
  }
  ```
- **Bloquear multipart en rutas sin uploads** (wp-login.php, /api/*, /admin/* sin upload): regla WAF (ModSecurity / Cloudflare / AWS WAF) — `Content-Type: multipart/form-data` + URI no-lista → block/JS-challenge.
- **ModSecurity**: subir paranoía y/o regla de rate por IP sobre POST multipart.
- Restringir a VPN/allowlist los paneles admin y tools internos en PHP mientras no haya parche.

---

## FASE 3 — Parche definitivo (cuando el release esté disponible)

1. Confirmar en php.net las versiones fijas publicadas y si tu distro **backporteó** (Debian/Ubuntu pueden mantener el número de versión: checar `apt changelog php8.3-fpm` o security.ubuntu.com — aquí **el número de versión NO cambia**, verifica el changelog).
2. Orden de parcheo: **internet-facing primero**, luego interno.
   ```bash
   apt update && apt install --only-upgrade php8.3-fpm php8.3-common   # ej. Ubuntu
   systemctl reload php8.3-fpm
   ```
3. Quitar el drop-in de mitigación NO es necesario (puede quedarse permanente; es best-practice).
4. Verificación post-parche: phpinfo en request real + smoke test de login/upload de cada app.

### PHP 5.x / 7.x / 8.0 / 8.1 — sin parche oficial. Solo 3 caminos:
1. **Migrar** a 8.2+ (única solución real)
2. **Aislar**: sacar de internet / poner detrás de VPN+WAF mientras se migra
3. **Backport del proveedor**: en CloudLinux/alt-php y distros enterprise el vendor puede backportear el fix a versiones viejas — **preguntar al proveedor explícitamente** (si el proveedor afirma genéricamente que las versiones antiguas están parcheadas, exigir confirmación escrita de que esto incluye este CVE)

---

## FASE 4 — Detección (mientras dura la ventana pre-parche)

```bash
# Procesos anómalos: php-fpm spawn de shells/downloaders (la señal #1)
auditd / osquery: execve de /bin/sh, curl, wget con padre php-fpm
# Herramienta rápida: process-watcher de Florian Roth en modo observe

# Conexiones salientes inesperadas del web tier
ss -tnp | grep php-fpm   # comparar contra baseline

# Errores/segfaults de php-fpm
journalctl -u php*-fpm --since today | grep -iE 'segfault|signal|core'

# Webshells y archivos nuevos en webroot (post-cambio)
find /var/www -mtime -1 -type f -name '*.php' -newer /var/log/  # revisar manualmente
# Verificar integridad de core de WP/etc: wp core verify-checksums
```

Si hay indicador de compromiso: aislar el host, preservar logs web+PHP, buscar webshells, cron jobs nuevos, cuentas nuevas.

---

## FASE 5 — Shared hosting (Verpex / DreamHost) — procedimiento específico

### Verpex (cPanel + CloudLinux/LiteSpeed lsphp + panel Enhance)

- **Aplica: SÍ.** El PoC filtrado trae offsets exactos para builds oficiales LiteSpeed `lsphp82` (bookworm/noble/jammy) — el stack de este tipo de hosting es target directo.
- **Mitigación (la haces tú, hoy):**
  - cPanel → Software → Select PHP Version → Options → `session.upload_progress.enabled = Off`
  - O panel Enhance: Websites → Advanced → Developer tools → php.ini editor → Add directive → `session.upload_progress.enabled` = Disable → **PHP → Restart PHP container** (obligatorio en Enhance para que aplique)
  - Verificar con un `info.php` servido por el sitio (no confiar en el valor del panel)
- **Parche (es del proveedor):** abrir ticket a soporte preguntando: (1) ¿cuándo despliegan lsphp82/83/84 parcheado? (2) ¿el fix llega por backport a alt-php para las versiones legacy en uso? (3) ¿qué versión exacta quedará tras el update? CloudLinux suele despachar fixes de LiteSpeed/alt-php rápido, pero **exigir confirmación escrita**.
- No confiar en sitios con PHP fijado manualmente (SetHandler alt-php en .htaccess): revisar cada handler.

### DreamHost (sin mod_php; PHP como CGI/FastCGI por usuario; config vía `phprc`)

- **Aplica: SÍ** — PHP afecta igual; el SAPI cambia el mecanismo de config, no el riesgo.
- **Mitigación (la haces tú, hoy):**
  - SSH: `mkdir -p ~/.php/<version>` (ej. `~/.php/8.2`) → crear `phprc` con:
    ```ini
    session.upload_progress.enabled = 0
    session.use_strict_mode = 1
    ```
  - Un phprc **por versión de PHP** en uso — repetir para cada versión que corra algún sitio
  - Reciclar procesos PHP para que tome efecto (matar `php<ver>.cgi` o esperar reciclaje; DreamHost lo documenta como paso obligatorio)
  - Verificar con phpinfo.php servido por el sitio
  - Sin SSH: crear el archivo vía SFTP (archivo oculto, activar "ver ocultos")
- **Parche (es del proveedor):** DreamHost gestiona el runtime en shared — **no puedes actualizar PHP tú mismo**. Acciones: (1) revisar sus anuncios/status page para el update de versiones; (2) ticket preguntando fecha del despliegue; (3) si algún sitio está en **PHP Extended Support** (versiones EOL), preguntar si recibirán backport o migrar a 8.2+ ya.
- DreamPress (WP administrado): el patch es 100% del proveedor — solo monitorear anuncios + verificar versión tras su aviso.

### ¿Hay que aplicar algo del lado del cliente en shared hosting?
**Sí, tres cosas, en este orden:**
1. **Mitigación user-side hoy** (phprc/php.ini editor según proveedor) — es lo único que controlas y cierra la ruta principal reportada
2. **Ticket al proveedor** pidiendo timeline del parche + confirmación de backport para versiones legacy — queda como evidencia de diligencia
3. **Verificación post-update del proveedor** (phpinfo real por sitio) — "el host dijo que ya" no es verificación

---

## Checklist ejecutivo (copiar/pegar en tu ticket de seguimiento)

- [ ] Inventario de versiones/SAPI PHP en todos los hosts y contenedores
- [ ] Sitios con PHP < 8.2 identificados (no reciben parche oficial)
- [ ] `session.upload_progress.enabled=0` + `use_strict_mode=1` aplicado y VERIFICADO en request real
- [ ] WAF/reverse proxy: multipart restringido en rutas sin uploads
- [ ] Paneles/admin sacados de internet público hasta el parche
- [ ] Tickets al proveedor de hosting (timeline + backport) — guardados
- [ ] Detección activa: process-watcher en observe, alertas de segfault php-fpm, conexiones salientes
- [ ] Plan de parcheo con ventana definida para 8.2.35/8.3.36/8.4.27/8.5.12
- [ ] Plan de migración para EOL (5.x/7.x/8.0/8.1)
- [ ] Post-parche: phpinfo verificado por sitio + smoke tests
