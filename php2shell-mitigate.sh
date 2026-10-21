#!/usr/bin/env bash
# ============================================================================
#  php2shell-mitigate.sh v2 — Mitigación CVE-2026-109618 / 109619
#  (php2shell: mitigación de session.upload_progress, causa raíz reportada
#   por la comunidad y NO confirmada oficialmente — el parche es el único
#   fix completo)
#
#  Entornos: DreamHost (phprc por versión), cPanel/CloudLinux (.user.ini vía
#  uapi), y genéricos FastCGI/CGI.
#
#  USO:
#    php2shell-mitigate.sh                          # aplicar
#    php2shell-mitigate.sh --verify                 # solo verificar
#    php2shell-mitigate.sh --rollback               # restaurar respaldos / eliminar lo creado
#    php2shell-mitigate.sh --dry-run                # mostrar acciones sin ejecutarlas
#    php2shell-mitigate.sh --php-versions 8.3,8.4   # forzar versiones (phprc)
#    php2shell-mitigate.sh --domains s1.com,s2.com  # forzar docroots/domínios
#
#  Correr como cada usuario de hosting:
#    ssh usuario@servidor 'bash -s' < php2shell-mitigate.sh
#
#  Idempotente. Respalda todo como *.bak-php2shell. Toca solo: phprc,
#  .user.ini, .htaccess (bloque delimitado) y temporales que él borra.
#  Última línea parseable:
#  SUMMARY env=... mode=... phprc=N userini=N verified=N failed=N rollback=N
# ============================================================================

set -u

MODE="apply"
DRY_RUN=0
FORCED_VERSIONS=""
FORCED_DOMAINS=""

while [ $# -gt 0 ]; do
  case "$1" in
    --verify)       MODE="verify" ;;
    --rollback)     MODE="rollback" ;;
    --dry-run)      DRY_RUN=1 ;;
    --php-versions) FORCED_VERSIONS="${2:-}"; shift ;;
    --domains)      FORCED_DOMAINS="${2:-}"; shift ;;
    *) echo "Opción desconocida: $1" >&2; exit 1 ;;
  esac
  shift
done

MIT_LINES='session.upload_progress.enabled = 0
session.use_strict_mode = 1'

TS="$(date +%Y%m%d-%H%M%S)"
HOSTNAME="$(hostname 2>/dev/null || echo unknown)"
USER_NAME="$(whoami)"
REPORT="php2shell-reporte-${USER_NAME}-${TS}.md"
USER_INI_TTL_NOTE=".user.ini tarda hasta 300s en recargarse (user_ini.cache_ttl): si la verificación muestra el valor viejo, re-corre --verify 5 minutos después."

ENV_DETECTED="generico"
DH_CGI_DIR="${DH_CGI_DIR:-/dh/cgi-system}"   # binarios php<XY>.cgi de DreamHost
STATS_PHPRC=0; STATS_USERINI=0; STATS_VERIFIED=0; STATS_FAILED=0; STATS_ROLLBACK=0
VERIFY_ROWS=""

log(){  echo "  $*"; }
ok(){   echo "  [OK]    $*"; }
warn(){ echo "  [AVISO] $*"; }

# escribe MIT_LINES en archivo nuevo (o merge en existente), respetando dry-run.
# Si ya tiene ambas directivas no lo toca: re-correr no debe respaldar la
# propia mitigación como si fuera el original.
merge_ini(){
  local f="$1"
  # respaldos creados por versiones previas pudieron quedar 644: cerrarlos siempre
  [ "$DRY_RUN" -eq 0 ] && [ -f "$f.bak-php2shell" ] && chmod 600 "$f.bak-php2shell" 2>/dev/null
  if [ -f "$f" ] && grep -qxF 'session.upload_progress.enabled = 0' "$f" \
     && grep -qxF 'session.use_strict_mode = 1' "$f"; then
    log "$f ya mitigado, sin cambios"; return
  fi
  if [ "$DRY_RUN" -eq 1 ]; then log "(dry-run) escribiría $f"; return; fi
  if [ -f "$f" ]; then
    if [ ! -f "$f.bak-php2shell" ]; then
      cp "$f" "$f.bak-php2shell"
      chmod 600 "$f.bak-php2shell" 2>/dev/null || true   # puede quedar en un docroot
    fi
    grep -vE '^\s*session\.(upload_progress\.enabled|use_strict_mode)' "$f" > "$f.tmp2s" 2>/dev/null || true
    { cat "$f.tmp2s" 2>/dev/null; echo ""; echo "$MIT_LINES"; } > "$f"
    rm -f "$f.tmp2s"
  else
    printf '%s\n' "$MIT_LINES" > "$f"
  fi
  chmod 644 "$f" 2>/dev/null || true
}

echo "============================================================"
echo " php2shell mitigación v2 | $(date '+%Y-%m-%d %H:%M:%S')"
echo " host: $HOSTNAME | usuario: $USER_NAME | modo: $MODE$([ $DRY_RUN -eq 1 ] && echo ' (dry-run)')"
echo "============================================================"

# ---------------------------------------------------------------------------
# 1. DETECCIÓN DE ENTORNO
# ---------------------------------------------------------------------------
log "== Detectando entorno =="
# /dh/cgi-system es exclusivo de DreamHost — señal confiable incluso si
# ~/.php no existe todavía.
if [ -d "$DH_CGI_DIR" ]; then
  ENV_DETECTED="dreamhost"
elif [ -d "/usr/local/cpanel" ] || command -v uapi >/dev/null 2>&1; then
  ENV_DETECTED="cpanel"
elif [ -d "$HOME/.php" ] && ls -d "$HOME/.php"/*/ >/dev/null 2>&1; then
  ENV_DETECTED="phprc-style"
fi
ok "Entorno: $ENV_DETECTED"

# ---------------------------------------------------------------------------
# 2. phprc por versión (DreamHost / estilo phprc / --php-versions)
# ---------------------------------------------------------------------------
PHP_VERSIONS=""
if [ -n "$FORCED_VERSIONS" ]; then
  PHP_VERSIONS="$(echo "$FORCED_VERSIONS" | tr ',' '\n' | sed 's/ //g')"
elif [ "$ENV_DETECTED" = "dreamhost" ] || [ "$ENV_DETECTED" = "phprc-style" ]; then
  PHP_VERSIONS="$({
    # carpetas ya existentes
    [ -d "$HOME/.php" ] && find "$HOME/.php" -mindepth 1 -maxdepth 1 -type d -exec basename {} \;
    # versiones instaladas en el servidor: cubre las elegidas desde el panel,
    # que no dejan rastro en ~/.php ni en .htaccess
    [ -d "$DH_CGI_DIR" ] && find "$DH_CGI_DIR" -maxdepth 1 -name 'php[0-9][0-9].cgi' -exec basename {} \; \
      | sed 's/php\([0-9]\)\([0-9]\)\.cgi/\1.\2/'
    # versiones referenciadas por FCGIWrapper en .htaccess (home y docroots)
    find "$HOME" -maxdepth 2 -name '.htaccess' -type f 2>/dev/null \
      | while IFS= read -r ht; do
          grep -hoE 'php[0-9]{2}\.cgi' "$ht" 2>/dev/null | sed 's/php\([0-9]\)\([0-9]\)\.cgi/\1.\2/'
        done
  } 2>/dev/null | sort -u)"
fi

if [ -n "$PHP_VERSIONS" ] || [ "$MODE" = "rollback" ]; then
  echo ""
  log "== A) phprc por versión =="
  [ "$MODE" != "rollback" ] && [ ! -d "$HOME/.php" ] && {
    [ "$DRY_RUN" -eq 1 ] && log "(dry-run) crearía $HOME/.php" || mkdir -p "$HOME/.php"
  }

  # here-string (no pipe): el loop corre en este shell y STATS_ROLLBACK persiste
  while IFS= read -r ver; do
    [ -z "$ver" ] && continue
    dir="$HOME/.php/$ver"
    case "$MODE" in
      verify)
        if [ -f "$dir/phprc" ] && grep -q 'session.upload_progress.enabled *= *0' "$dir/phprc" 2>/dev/null; then
          ok "phprc $ver: PRESENTE"
        else
          warn "phprc $ver: AUSENTE"
        fi ;;
      rollback)
        if [ -f "$dir/phprc.bak-php2shell" ]; then
          if [ "$DRY_RUN" -eq 1 ]; then log "(dry-run) restauraría $dir/phprc"
          else mv "$dir/phprc.bak-php2shell" "$dir/phprc"; chmod 644 "$dir/phprc" 2>/dev/null; echo "  [OK]    phprc $ver restaurado"; STATS_ROLLBACK=$((STATS_ROLLBACK+1)); fi
        elif [ -f "$dir/phprc" ] && [ "$(cat "$dir/phprc" 2>/dev/null)" = "$MIT_LINES" ]; then
          if [ "$DRY_RUN" -eq 1 ]; then log "(dry-run) eliminaría $dir/phprc (creado por este script)"
          else rm -f "$dir/phprc"; echo "  [OK]    phprc $ver eliminado"; STATS_ROLLBACK=$((STATS_ROLLBACK+1)); fi
        fi ;;
      *)
        [ "$DRY_RUN" -eq 1 ] || mkdir -p "$dir"
        merge_ini "$dir/phprc"
        echo "  [OK]    phprc $ver ($dir/phprc)" ;;
    esac
  done <<< "$PHP_VERSIONS"

  # contadores (fuera del subshell del pipe)
  if [ "$MODE" = "apply" ]; then
    STATS_PHPRC=$(find "$HOME/.php" -name 'phprc*' ! -name '*.bak-*' 2>/dev/null | wc -l | tr -d ' ')
  elif [ "$MODE" = "verify" ]; then
    STATS_PHPRC=$(find "$HOME/.php" -name phprc -exec grep -l 'upload_progress.enabled *= *0' {} \; 2>/dev/null | wc -l | tr -d ' ')
  fi

  # reciclar procesos: DreamHost documenta kill -9 de php<XY>.cgi
  if [ "$MODE" = "apply" ] && [ "$DRY_RUN" -eq 0 ]; then
    log "== Reciclando procesos php*.cgi (pkill -9, método documentado por DreamHost) =="
    if pkill -9 -u "$USER_NAME" -f 'php[0-9]+\.cgi' 2>/dev/null; then
      ok "procesos php*.cgi reciclados"
    else
      log "   → sin workers activos (los nuevos ya nacen con la config)"
    fi
  fi
elif [ "$MODE" = "apply" ] && [ "$ENV_DETECTED" = "dreamhost" ]; then
  warn "DreamHost detectado pero sin versiones PHP identificables. Usa --php-versions 8.2,8.3"
fi

# ---------------------------------------------------------------------------
# 3. DOCROOTS
#    cPanel  → uapi DomainInfo domains_data (mapeo exacto, sin adivinar)
#    DreamHost → carpetas del home con forma de dominio (~/dominio.tld)
#    genérico  → public_html / www / htdocs
#    --domains siempre tiene prioridad
# ---------------------------------------------------------------------------
log "== Document roots =="

collect_docroots(){
  if [ -n "$FORCED_DOMAINS" ]; then
    echo "$FORCED_DOMAINS" | tr ',' '\n' | sed 's/ //g' | while IFS= read -r d; do
      [ -d "$HOME/$d" ] && echo "$HOME/$d"
    done
    return
  fi
  if [ "$ENV_DETECTED" = "cpanel" ] && command -v uapi >/dev/null 2>&1; then
    # uapi imprime YAML por defecto; --output=json da un formato estable.
    # </dev/null: bajo `bash -s` uapi no debe consumir el resto del script.
    uapi --output=json DomainInfo domains_data </dev/null 2>/dev/null \
      | grep -oE '"documentroot"[[:space:]]*:[[:space:]]*"[^"]+"' \
      | sed -e 's/^.*:[[:space:]]*"//' -e 's/"$//' -e 's#\\/#/#g' \
      | sort -u | while IFS= read -r dr; do
          [ -d "$dr" ] && echo "$dr"
        done
    return
  fi
  if [ "$ENV_DETECTED" = "dreamhost" ]; then
    find "$HOME" -mindepth 1 -maxdepth 1 -type d 2>/dev/null \
      | grep -E '/[^/]+\.[A-Za-z]{2,}$' | sort
    return
  fi
  find "$HOME" -maxdepth 3 \( -name public_html -o -name www -o -name htdocs \) -type d 2>/dev/null | sort -u
}

# temporales con mktemp (nombres impredecibles: /tmp es compartido en hosting)
DOCROOTS_FILE="$(mktemp "${TMPDIR:-/tmp}/php2shell-docroots.XXXXXX")" || { echo "ERROR: mktemp falló" >&2; exit 1; }
VERIFY_TMP="$(mktemp "${TMPDIR:-/tmp}/php2shell-verify.XXXXXX")" || { rm -f "$DOCROOTS_FILE"; echo "ERROR: mktemp falló" >&2; exit 1; }
PROBE=""   # probe HTTP en curso; el trap lo borra si el script se interrumpe
trap 'rm -f "$DOCROOTS_FILE" "$VERIFY_TMP" ${PROBE:+"$PROBE"}' EXIT
trap 'exit 130' INT TERM HUP
collect_docroots > "$DOCROOTS_FILE"
N_DR=$(wc -l < "$DOCROOTS_FILE" | tr -d ' ')

if [ "$N_DR" -eq 0 ]; then
  warn "Sin docroots detectados. Usa --domains dominio.com,dominio2.com para forzar."
else
  log "$N_DR docroot(s) en lista"
fi

# ---------------------------------------------------------------------------
# 4. .user.ini + .htaccess por docroot (while read — seguro con espacios)
# ---------------------------------------------------------------------------
ht_begin='# BEGIN php2shell protection'
ht_end='# END php2shell protection'
# FilesMatch cubre .user.ini y su respaldo .user.ini.bak-php2shell
ht_block="$ht_begin
<FilesMatch \"^\\.user\\.ini\">
  <IfModule mod_authz_core.c>
    Require all denied
  </IfModule>
  <IfModule !mod_authz_core.c>
    Order allow,deny
    Deny from all
  </IfModule>
</FilesMatch>
$ht_end"

strip_ht_block(){
  awk -v b="$ht_begin" -v e="$ht_end" \
    'index($0,b){skip=1;next} index($0,e){skip=0;next} !skip{print}' \
    "$1" > "$1.tmp" && mv "$1.tmp" "$1"
}

# BEGIN sin su END (p. ej. editado a mano) haría que strip_ht_block borre
# todo lo que sigue; en ese caso no se toca el archivo
ht_markers_ok(){
  [ "$(grep -cF "$ht_begin" "$1" 2>/dev/null || true)" = "$(grep -cF "$ht_end" "$1" 2>/dev/null || true)" ]
}
HT_UNBALANCED_MSG="marcadores BEGIN/END php2shell desbalanceados; no se modifica, revísalo a mano"

if [ "$N_DR" -gt 0 ]; then
  echo ""
  log "== B) .user.ini por document root =="
  while IFS= read -r dr; do
    [ -z "$dr" ] && continue
    case "$MODE" in
      verify)
        if [ -f "$dr/.user.ini" ] && grep -q 'session.upload_progress.enabled *= *0' "$dr/.user.ini" 2>/dev/null; then
          ok ".user.ini PRESENTE en $dr"
        else
          warn ".user.ini AUSENTE en $dr"
        fi ;;
      rollback)
        if [ -f "$dr/.user.ini.bak-php2shell" ]; then
          if [ "$DRY_RUN" -eq 1 ]; then log "(dry-run) restauraría $dr/.user.ini"
          else mv "$dr/.user.ini.bak-php2shell" "$dr/.user.ini"; chmod 644 "$dr/.user.ini" 2>/dev/null; echo "  [OK]    .user.ini restaurado en $dr"; STATS_ROLLBACK=$((STATS_ROLLBACK+1)); fi
        elif [ -f "$dr/.user.ini" ] && [ "$(cat "$dr/.user.ini" 2>/dev/null)" = "$MIT_LINES" ]; then
          if [ "$DRY_RUN" -eq 1 ]; then log "(dry-run) eliminaría $dr/.user.ini (creado por este script)"
          else rm -f "$dr/.user.ini"; echo "  [OK]    .user.ini eliminado en $dr"; STATS_ROLLBACK=$((STATS_ROLLBACK+1)); fi
        fi
        if [ -f "$dr/.htaccess" ] && grep -q "$ht_begin" "$dr/.htaccess" 2>/dev/null; then
          if ! ht_markers_ok "$dr/.htaccess"; then warn "$dr/.htaccess: $HT_UNBALANCED_MSG"
          elif [ "$DRY_RUN" -eq 1 ]; then log "(dry-run) limpiaría bloque php2shell en $dr/.htaccess"
          else
            cp "$dr/.htaccess" "$dr/.htaccess.pre-rollback-$TS"
            strip_ht_block "$dr/.htaccess"
            echo "  [OK]    .htaccess limpiado en $dr"
          fi
        fi ;;
      *)
        merge_ini "$dr/.user.ini"
        echo "  [OK]    .user.ini en $dr"
        STATS_USERINI=$((STATS_USERINI+1))
        if [ -f "$dr/.htaccess" ]; then
          # bloque actual (vacío si no hay); uno de una versión previa se reemplaza
          cur_block="$(awk -v b="$ht_begin" -v e="$ht_end" \
            'index($0,b){p=1} p{print} index($0,e){p=0}' "$dr/.htaccess" 2>/dev/null)"
          if [ -n "$cur_block" ] && ! ht_markers_ok "$dr/.htaccess"; then
            warn "$dr/.htaccess: $HT_UNBALANCED_MSG"
          elif [ "$cur_block" != "$ht_block" ]; then
            if [ "$DRY_RUN" -eq 0 ]; then
              cp "$dr/.htaccess" "$dr/.htaccess.bak-php2shell-$TS" 2>/dev/null || true
              if [ -n "$cur_block" ]; then
                # quita el bloque viejo y añade el nuevo al final, sin sumar líneas en blanco
                strip_ht_block "$dr/.htaccess"
                printf '%s\n' "$ht_block" >> "$dr/.htaccess"
              else
                printf '\n%s\n%s\n' "$ht_block" >> "$dr/.htaccess"
              fi
            fi
            if [ -n "$cur_block" ]; then
              echo "  [OK]    .htaccess: bloqueo actualizado en $dr"
            else
              echo "  [OK]    .htaccess: bloqueo añadido (Apache 2.4 con fallback 2.2) en $dr"
            fi
          fi
        else
          [ "$DRY_RUN" -eq 0 ] && printf '%s\n' "$ht_block" > "$dr/.htaccess"
          echo "  [OK]    .htaccess creado con bloqueo en $dr"
        fi ;;
    esac
  done < "$DOCROOTS_FILE"
fi

# ---------------------------------------------------------------------------
# 5. VERIFICACIÓN HTTP
#    ini_get() devuelve false SOLO si la directiva no existe; "0"/"" significa
#    que existe y vale Off. Distinguimos con === false.
#    Nota: tras escribir .user.ini hay que esperar user_ini.cache_ttl (300s).
# ---------------------------------------------------------------------------
TMPNAME="php2shellcheck-$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n').php"

# apply y verify escriben un probe por docroot y lo borran tras consultarlo
if [ "$N_DR" -gt 0 ] && [ "$DRY_RUN" -eq 0 ] && { [ "$MODE" = "verify" ] || [ "$MODE" = "apply" ]; }; then
  echo ""
  log "== C) Verificación vía HTTP =="
  [ "$MODE" = "apply" ] && warn "$USER_INI_TTL_NOTE"

  while IFS= read -r dr; do
    [ -z "$dr" ] && continue
    domain_guess="$(basename "$dr")"
    case "$domain_guess" in public_html|www|htdocs) domain_guess="$(basename "$(dirname "$dr")")";; esac

    PROBE="$dr/$TMPNAME"
    printf '<?php $v = ini_get("session.upload_progress.enabled"); echo ($v === false) ? "ABSENT" : "UPP=" . var_export((bool)$v, true) . "|STRICT=" . var_export((bool)ini_get("session.use_strict_mode"), true);' > "$PROBE" 2>/dev/null
    [ -f "$PROBE" ] || { PROBE=""; continue; }

    resp=""
    for scheme in https http; do
      resp="$(curl -m 10 -sk "$scheme://$domain_guess/$TMPNAME" </dev/null 2>/dev/null)"
      [ -n "$resp" ] && break
    done
    rm -f "$PROBE"; PROBE=""

    case "$resp" in
      "UPP=false|STRICT=true")
        ok "VERIFICADO $domain_guess → upload_progress=Off, strict_mode=On"
        echo "OK|$domain_guess" >> "$VERIFY_TMP" ;;
      "ABSENT")
        warn "$domain_guess → directiva no existe en esta build (revisar versión PHP)"
        echo "ABSENT|$domain_guess" >> "$VERIFY_TMP" ;;
      "")
        warn "$domain_guess → no alcanzable vía HTTP (guess: $domain_guess); verificar con phpinfo manual"
        echo "UNREACHABLE|$domain_guess" >> "$VERIFY_TMP" ;;
      *)
        warn "$domain_guess → valor inesperado/incompleto: $resp (¿cache de .user.ini? re-corre --verify en 5 min)"
        echo "STALE|$domain_guess" >> "$VERIFY_TMP" ;;
    esac
  done < "$DOCROOTS_FILE"

  # grep -c ya imprime 0 sin coincidencias (y sale con 1): `|| true`, no `|| echo 0`,
  # o el valor sería "0\n0" y partiría la línea SUMMARY
  STATS_VERIFIED=$(grep -c '^OK|' "$VERIFY_TMP" 2>/dev/null || true)
  STATS_FAILED=$(grep -c -v '^OK|' "$VERIFY_TMP" 2>/dev/null || true)
  VERIFY_ROWS="$(sed 's/^\([^|]*\)|\(.*\)$/| \2 | \1 |/' "$VERIFY_TMP")"
  log "→ archivos temporales de verificación eliminados"
fi

rm -f "$DOCROOTS_FILE"

# ---------------------------------------------------------------------------
# 6. REPORTE + SUMMARY (línea final parseable por el orquestador)
# ---------------------------------------------------------------------------
if [ "$MODE" != "rollback" ] && [ "$DRY_RUN" -eq 0 ]; then
  cat > "$REPORT" <<EOF
# Reporte php2shell — $(date '+%Y-%m-%d %H:%M')
- Host: \`$HOSTNAME\` | Usuario: \`$USER_NAME\` | Modo: $MODE
- Entorno: **$ENV_DETECTED**
- phprc mitigados: $STATS_PHPRC | Docroots con .user.ini: $STATS_USERINI

## Verificación por sitio
| Dominio | Estado |
|---|---|
$VERIFY_ROWS

## Pendientes del proveedor (no automatizable)
- [ ] Ticket: fecha de despliegue de PHP parcheado (8.2.35/8.3.36/8.4.27/8.5.12)
- [ ] Confirmar backport para versiones EOL en uso (5.x/7.x/8.0/8.1)
- [ ] Re-verificar post-update con phpinfo real por sitio
EOF
  ok "Reporte: $HOME/$REPORT"
fi

echo ""
echo "============================================================"
echo "SUMMARY env=$ENV_DETECTED mode=$MODE dryrun=$DRY_RUN phprc=$STATS_PHPRC userini=$STATS_USERINI verified=$STATS_VERIFIED failed=$STATS_FAILED rollback=$STATS_ROLLBACK"
echo "============================================================"
