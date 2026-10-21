# Remediation Guide — php2shell (CVE-2026-109618 / CVE-2026-109619)

🇪🇸 [Versión en español](guia-remediacion.md)

**Severity:** CVSS v4.0 9.2 (Critical) × 2 — unauthenticated RCE in the PHP core
**Affects:** PHP 5.4 and later (only 8.x receives an official patch)
**Fixed versions:** 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 (PHP emergency release: 2026-10-21 14:00 UTC)
**Note:** The published root cause (UAF in `session.upload_progress`) comes from the community and is not officially confirmed. Apply ALL mitigation layers; no single one is a guarantee.

---

## PHASE 0 — Inventory (do this first; everything else depends on it)

On each server, identify versions and SAPI:

```bash
# Installed PHP versions (Debian/Ubuntu)
ls /etc/php/ && for v in $(ls /etc/php/); do echo "PHP $v:"; /usr/bin/php$v -v 2>/dev/null | head -1; done

# SAPI: FPM, mod_php, cgi?
dpkg -l | grep -E 'php.*-(fpm|cgi|cli)' ; apachectl -M 2>/dev/null | grep php

# Who serves PHP to the web? (process list)
ps aux | grep -E 'php-fpm|php-cgi|lsphp'

# Docker: review base images
docker ps --format '{{.Image}}' | sort -u

# Check the active setting on a REAL request (not CLI):
echo '<?php phpinfo();' > /tmp/check.php   # serve it temporarily and check:
# session.upload_progress.enabled  → must show Off after the fix
```

For cPanel/panels: check which version is selected per site (MultiPHP Manager / Select PHP Version). **Sites manually pinned to PHP 7.x/8.0/8.1 will not get the patch** even when the provider upgrades.

---

## PHASE 1 — Immediate mitigation (today, no maintenance window)

### A. Servers with PHP-FPM (most common)

Create a global drop-in (Debian/Ubuntu):

```bash
for v in /etc/php/*/fpm/conf.d; do
  cat > "$v/99-php2shell-mitigation.ini" <<'EOF'
session.upload_progress.enabled = 0
session.use_strict_mode = 1
EOF
done
systemctl reload php*-fpm
```

Alternatively, in specific pools (`/etc/php/8.x/fpm/pool.d/*.conf`):

```ini
php_admin_flag[session.upload_progress.enabled] = off
php_admin_flag[session.use_strict_mode] = on
```

### B. Apache with mod_php

Edit php.ini (or add to `.htaccess` for PERDIR mode):

```ini
session.upload_progress.enabled = 0
session.use_strict_mode = 1
```
```bash
apachectl configtest && systemctl restart apache2
```

### C. PHP-CGI / LiteSpeed / CloudLinux (shared hosting)

- cPanel → MultiPHP INI Editor (or "Select PHP Version" → Options) → add:
  `session.upload_progress.enabled = Off`
- Portable alternative: `.user.ini` in the document root:
  ```ini
  session.upload_progress.enabled = 0
  session.use_strict_mode = 1
  ```
  (takes effect within 5 min due to user_ini.cache_ttl; protect it with `.htaccess`: `<Files ".user.ini"> Require all denied </Files>`)
- CloudLinux CageFS: rebuild after the change (`cagefsctl --force-update`).

### D. Docker / containers

Add to the Dockerfile/entrypoint or mount an ini file:
```bash
echo -e "session.upload_progress.enabled=0\nsession.use_strict_mode=1" \
  > /usr/local/etc/php/conf.d/99-php2shell.ini
```
Recreate containers; rebuild images that hardcode versions < 8.2.

### Functional impact: NONE
It only disables native upload progress bars. WordPress, WooCommerce, Magento, Shopware and Laravel do not use them. `use_strict_mode` is PHP's default recommendation. Exception: sessions stored in Redis/DB do not implement the strict mode check (the setting is harmless/inert there).

---

## PHASE 2 — Edge mitigation (WAF / reverse proxy)

Because there may be a second path in the multipart parser that runs even with the setting Off:

- **Nginx** (in front of PHP): rate-limit `multipart/form-data`:
  ```nginx
  location ~ \.php$ {
      limit_req zone=multipart burst=5 nodelay;  # tune to routes with real uploads
      ...
  }
  ```
- **Block multipart on routes without uploads** (wp-login.php, /api/*, /admin/* without uploads): WAF rule (ModSecurity / Cloudflare / AWS WAF) — `Content-Type: multipart/form-data` + URI not on the allowlist → block/JS challenge.
- **ModSecurity**: raise the paranoia level and/or add a per-IP rate rule on multipart POSTs.
- Restrict admin panels and internal PHP tools to VPN/allowlist until patched.

---

## PHASE 3 — Definitive patch (once the release is available)

1. Confirm on php.net the published fixed versions and whether your distro **backported** the fix (Debian/Ubuntu may keep the version number: check `apt changelog php8.3-fpm` or security.ubuntu.com — here **the version number does NOT change**, check the changelog).
2. Patching order: **internet-facing first**, then internal.
   ```bash
   apt update && apt install --only-upgrade php8.3-fpm php8.3-common   # e.g. Ubuntu
   systemctl reload php8.3-fpm
   ```
3. Removing the mitigation drop-in is NOT necessary (it can stay permanently; it is best practice).
4. Post-patch verification: phpinfo on a real request + login/upload smoke test for each app.

### PHP 5.x / 7.x / 8.0 / 8.1 — no official patch. Only 3 paths:
1. **Migrate** to 8.2+ (the only real fix)
2. **Isolate**: take it off the internet / put it behind VPN+WAF while migrating
3. **Provider backport**: on CloudLinux/alt-php and enterprise distros the vendor may backport the fix to old versions — **ask the provider explicitly** (if the provider generically claims older versions are patched, demand written confirmation that this includes this CVE)

---

## PHASE 4 — Detection (during the pre-patch window)

```bash
# Anomalous processes: php-fpm spawning shells/downloaders (signal #1)
auditd / osquery: execve of /bin/sh, curl, wget with a php-fpm parent
# Quick tool: Florian Roth's process-watcher in observe mode

# Unexpected outbound connections from the web tier
ss -tnp | grep php-fpm   # compare against a baseline

# php-fpm errors/segfaults
journalctl -u php*-fpm --since today | grep -iE 'segfault|signal|core'

# Webshells and new files in the webroot (post-change)
find /var/www -mtime -1 -type f -name '*.php' -newer /var/log/  # review manually
# Check WP/etc core integrity: wp core verify-checksums
```

If there is an indicator of compromise: isolate the host, preserve web+PHP logs, look for webshells, new cron jobs and new accounts.

---

## PHASE 5 — Shared hosting (Verpex / DreamHost) — specific procedure

### Verpex (cPanel + CloudLinux/LiteSpeed lsphp + Enhance panel)

- **Applies: YES.** The leaked PoC ships exact offsets for official LiteSpeed `lsphp82` builds (bookworm/noble/jammy) — this type of hosting stack is a direct target.
- **Mitigation (you do it, today):**
  - cPanel → Software → Select PHP Version → Options → `session.upload_progress.enabled = Off`
  - Or Enhance panel: Websites → Advanced → Developer tools → php.ini editor → Add directive → `session.upload_progress.enabled` = Disable → **PHP → Restart PHP container** (required in Enhance for it to apply)
  - Verify with an `info.php` served by the site (do not trust the panel value)
- **Patch (the provider's job):** open a support ticket asking: (1) when will patched lsphp82/83/84 be deployed? (2) will the fix be backported to alt-php for the legacy versions in use? (3) what exact version will be installed after the update? CloudLinux usually ships LiteSpeed/alt-php fixes quickly, but **demand written confirmation**.
- Do not trust sites with manually pinned PHP (SetHandler alt-php in .htaccess): review every handler.

### DreamHost (no mod_php; PHP as per-user CGI/FastCGI; config via `phprc`)

- **Applies: YES** — PHP is equally affected; the SAPI changes the config mechanism, not the risk.
- **Mitigation (you do it, today):**
  - SSH: `mkdir -p ~/.php/<version>` (e.g. `~/.php/8.2`) → create `phprc` with:
    ```ini
    session.upload_progress.enabled = 0
    session.use_strict_mode = 1
    ```
  - One phprc **per PHP version** in use — repeat for every version that runs a site
  - Recycle PHP processes so it takes effect (kill `php<ver>.cgi` or wait for recycling; DreamHost documents this as a required step)
  - Verify with a phpinfo.php served by the site
  - Without SSH: create the file via SFTP (hidden file; enable "show hidden files")
- **Patch (the provider's job):** DreamHost manages the runtime on shared hosting — **you cannot upgrade PHP yourself**. Actions: (1) watch their announcements/status page for the version update; (2) open a ticket asking for the deployment date; (3) if any site is on **PHP Extended Support** (EOL versions), ask whether they will get a backport, or migrate to 8.2+ now.
- DreamPress (managed WP): the patch is 100% the provider's — just watch announcements + verify the version after their notice.

### Is there anything to apply on the customer side in shared hosting?
**Yes, three things, in this order:**
1. **User-side mitigation today** (phprc/php.ini editor depending on the provider) — it is the only thing you control and it closes the main reported path
2. **Ticket to the provider** asking for the patch timeline + backport confirmation for legacy versions — it serves as evidence of due diligence
3. **Verification after the provider's update** (real phpinfo per site) — "the host said it's done" is not verification

---

## Executive checklist (copy/paste into your tracking ticket)

- [ ] Inventory of PHP versions/SAPI on all hosts and containers
- [ ] Sites with PHP < 8.2 identified (they get no official patch)
- [ ] `session.upload_progress.enabled=0` + `use_strict_mode=1` applied and VERIFIED on a real request
- [ ] WAF/reverse proxy: multipart restricted on routes without uploads
- [ ] Admin panels taken off the public internet until patched
- [ ] Tickets to the hosting provider (timeline + backport) — saved
- [ ] Active detection: process-watcher in observe mode, php-fpm segfault alerts, outbound connections
- [ ] Patching plan with a defined window for 8.2.35/8.3.36/8.4.27/8.5.12
- [ ] Migration plan for EOL versions (5.x/7.x/8.0/8.1)
- [ ] Post-patch: phpinfo verified per site + smoke tests
