#!/usr/bin/env bash
# ============================================================================
#  php2shell-mitigate.sh v3 — Mitigación CVE-2026-109618 / 109619
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
#    php2shell-mitigate.sh --block-multipart        # además rechaza (403) todo
#                                                   # POST multipart/form-data
#                                                   # ROMPE subidas de archivos
#    php2shell-mitigate.sh --memory-unlimited       # forzar memory_limit = -1
#    php2shell-mitigate.sh --keep-memory-limit      # no tocar memory_limit
#                                                   # (por defecto: -1 solo en
#                                                   # DreamHost/cPanel)
#    php2shell-mitigate.sh --post-max-size 8M       # post_max_size = 8M y
#                                                   # upload_max_filesize = 7M
#
#  Correr como cada usuario de hosting:
#    ssh usuario@servidor 'bash -s' < php2shell-mitigate.sh
#
#  Idempotente. Respalda todo como *.bak-php2shell. Toca solo: phprc,
#  .user.ini, .htaccess (bloques delimitados) y temporales que él borra.
#  Última línea parseable:
#  SUMMARY env=... mode=... phprc=N userini=N verified=N failed=N rollback=N
#          mpblocked=N mpopen=N mperror=N mem=0|1
# ============================================================================

set -u

MODE="apply"
DRY_RUN=0
BLOCK_MP=0
MEM_OPT="auto"      # auto | on | off
POST_MAX=""
POST_SET=0
MEM_CONFLICT=0
FORCED_VERSIONS=""
FORCED_DOMAINS=""

while [ $# -gt 0 ]; do
  case "$1" in
    --verify)          MODE="verify" ;;
    --rollback)        MODE="rollback" ;;
    --dry-run)         DRY_RUN=1 ;;
    --block-multipart) BLOCK_MP=1 ;;
    --memory-unlimited)  [ "$MEM_OPT" = off ] && MEM_CONFLICT=1; MEM_OPT="on" ;;
    --keep-memory-limit) [ "$MEM_OPT" = on ] && MEM_CONFLICT=1; MEM_OPT="off" ;;
    --post-max-size)   POST_MAX="${2:-}"; POST_SET=1; [ $# -gt 1 ] && shift ;;
    --php-versions)    FORCED_VERSIONS="${2:-}"; shift ;;
    --domains)         FORCED_DOMAINS="${2:-}"; shift ;;
    *) echo "Opción desconocida: $1" >&2; exit 1 ;;
  esac
  shift
done

# --post-max-size: un valor INI inválido genera un diagnóstico al arrancar, que
# el advisory GHSA-6wmf-4rv5-p3rp señala como parte del ataque: validar antes
[ "$MEM_CONFLICT" -eq 1 ] && { echo "--memory-unlimited y --keep-memory-limit se excluyen" >&2; exit 1; }
# solo cambian lo que se escribe: con --verify/--rollback se ignorarían en silencio
if [ "$MODE" != "apply" ] && { [ "$POST_SET" -eq 1 ] || [ "$MEM_OPT" != auto ]; }; then
  echo "--post-max-size, --memory-unlimited y --keep-memory-limit solo aplican al aplicar (no con --$MODE)" >&2; exit 1
fi

UPLOAD_MAX=""
if [ "$POST_SET" -eq 1 ]; then
  POST_MAX="$(echo "$POST_MAX" | tr 'kmg' 'KMG')"
  case "$POST_MAX" in
    ""|*[!0-9KMG]*|[KMG]*|*[KMG]*[KMG]*|*[0-9]) echo "--post-max-size inválido: '$POST_MAX' (ej. 8M, 32M, 1G)" >&2; exit 1 ;;
  esac
  n=$((10#${POST_MAX%?}))   # 10#: "08M" no es octal
  POST_MAX="$n${POST_MAX#"${POST_MAX%?}"}"
  case "$POST_MAX" in *K) kb=$n ;; *M) kb=$((n*1024)) ;; *G) kb=$((n*1048576)) ;; esac
  [ "$kb" -ge 2048 ] || { echo "--post-max-size debe ser al menos 2M" >&2; exit 1; }
  # upload_max_filesize 1M por debajo: el cuerpo multipart pesa más que el archivo
  up=$((kb-1024))
  if [ $((up % 1024)) -eq 0 ]; then UPLOAD_MAX="$((up/1024))M"; else UPLOAD_MAX="${up}K"; fi
fi

# fatal_error_backtraces solo existe en PHP 8.5 (GHSA-6wmf-4rv5-p3rp); en
# versiones previas PHP ignora la directiva desconocida sin diagnóstico
MIT_LINES='session.upload_progress.enabled = 0
session.use_strict_mode = 1
fatal_error_backtraces = 0'
# contenido exacto que creaba la v2: se trata como propio, no como original
LEGACY_MIT_LINES='session.upload_progress.enabled = 0
session.use_strict_mode = 1'
# primera línea de los archivos que crea este script: así --rollback distingue
# un archivo propio de uno del usuario aunque el contenido varíe con los flags
INI_MARK='; php2shell mitigation (php2shell-mitigate.sh)'

TS="$(date +%Y%m%d-%H%M%S)"
HOSTNAME="$(hostname 2>/dev/null || echo unknown)"
USER_NAME="$(whoami)"
REPORT="php2shell-reporte-${USER_NAME}-${TS}.md"
USER_INI_TTL_NOTE=".user.ini tarda hasta 300s en recargarse (user_ini.cache_ttl): si la verificación muestra el valor viejo, re-corre --verify 5 minutos después."

ENV_DETECTED="generico"
DH_CGI_DIR="${DH_CGI_DIR:-/dh/cgi-system}"   # binarios php<XY>.cgi de DreamHost
STATS_PHPRC=0; STATS_USERINI=0; STATS_VERIFIED=0; STATS_FAILED=0; STATS_ROLLBACK=0
STATS_MP_BLOCKED=0; STATS_MP_OPEN=0; STATS_MP_ERROR=0
VERIFY_ROWS=""

log(){  echo "  $*"; }
ok(){   echo "  [OK]    $*"; }
warn(){ echo "  [AVISO] $*"; }

# archivo creado por este script (marcador, o contenido exacto de v2/v3 previas)
is_own_ini(){
  local c
  [ "$(head -1 "$1" 2>/dev/null)" = "$INI_MARK" ] && return 0
  c="$(cat "$1" 2>/dev/null)"
  [ "$c" = "$MIT_LINES" ] || [ "$c" = "$LEGACY_MIT_LINES" ]
}

# <línea> la puso este script: archivo propio, o ausente en el respaldo del original
ours_line(){
  grep -qxF "$2" "$1" 2>/dev/null || return 1
  is_own_ini "$1" && return 0
  [ -f "$1.bak-php2shell" ] && ! grep -qxF "$2" "$1.bak-php2shell" 2>/dev/null
}

# último valor de <clave> en un ini (vacío si no está)
ini_val(){
  grep -E "^[[:space:]]*$2[[:space:]]*=" "$1" 2>/dev/null | tail -1 \
    | sed -e 's/^[^=]*=[[:space:]]*//' -e 's/[[:space:]]*$//'
}

# escribe WRITE_LINES en archivo nuevo (o merge en existente), respetando dry-run.
# Si ya tiene todas las directivas no lo toca: re-correr no debe respaldar la
# propia mitigación como si fuera el original. Solo reemplaza las claves que
# escribe en esta corrida (WRITE_KEYS_RE): un memory_limit del usuario se
# conserva salvo que se active memory_limit = -1.
merge_ini(){
  local f="$1" line missing=0
  # respaldos creados por versiones previas pudieron quedar 644: cerrarlos siempre
  [ "$DRY_RUN" -eq 0 ] && [ -f "$f.bak-php2shell" ] && chmod 600 "$f.bak-php2shell" 2>/dev/null
  if [ -f "$f" ]; then
    while IFS= read -r line; do
      grep -qxF "$line" "$f" || missing=1
    done <<< "$WRITE_LINES"
    [ "$missing" -eq 0 ] && { log "$f ya mitigado, sin cambios"; return; }
  fi
  if [ "$DRY_RUN" -eq 1 ]; then log "(dry-run) escribiría $f"; return; fi
  if [ -f "$f" ]; then
    grep -vE "^[[:space:]]*($WRITE_KEYS_RE)[[:space:]]*=" "$f" 2>/dev/null \
      | grep -vxF "$INI_MARK" > "$f.tmp2s" || true
    if is_own_ini "$f"; then
      # propio (de esta versión o de una previa): se reescribe sin respaldo
      { echo "$INI_MARK"; grep -v '^[[:space:]]*$' "$f.tmp2s"; echo "$WRITE_LINES"; } > "$f"
    else
      if [ ! -f "$f.bak-php2shell" ]; then
        cp "$f" "$f.bak-php2shell"
        chmod 600 "$f.bak-php2shell" 2>/dev/null || true   # puede quedar en un docroot
      fi
      { cat "$f.tmp2s" 2>/dev/null; echo ""; echo "$WRITE_LINES"; } > "$f"
    fi
    rm -f "$f.tmp2s"
  else
    printf '%s\n%s\n' "$INI_MARK" "$WRITE_LINES" > "$f"
  fi
  chmod 644 "$f" 2>/dev/null || true
}

echo "============================================================"
echo " php2shell mitigación v3 | $(date '+%Y-%m-%d %H:%M:%S')"
echo " host: $HOSTNAME | usuario: $USER_NAME | modo: $MODE$([ $DRY_RUN -eq 1 ] && echo ' (dry-run)')$([ $BLOCK_MP -eq 1 ] && echo ' + block-multipart')"
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

# memory_limit = -1 es la mitigación de configuración principal del OOM
# (GHSA-w8hw-w9fx-j79w). Por defecto solo en hosting compartido, donde el
# proveedor limita la memoria por cuenta; en genérico/VPS un script
# descontrolado podría agotar la RAM del servidor.
# (solo al aplicar: --verify y --rollback no escriben directivas)
MEM_ON=0
[ "$MODE" = "apply" ] && case "$MEM_OPT" in
  on)   MEM_ON=1 ;;
  auto) case "$ENV_DETECTED" in dreamhost|cpanel) MEM_ON=1 ;; esac ;;
esac

WRITE_LINES="$MIT_LINES"
WRITE_KEYS_RE='session\.(upload_progress\.enabled|use_strict_mode)|fatal_error_backtraces'
if [ "$MEM_ON" -eq 1 ]; then
  WRITE_LINES="$WRITE_LINES
memory_limit = -1"
  WRITE_KEYS_RE="$WRITE_KEYS_RE|memory_limit"
  ok "memory_limit = -1: activado ($([ "$MEM_OPT" = on ] && echo 'forzado con --memory-unlimited' || echo "por defecto en $ENV_DETECTED"))"
fi
if [ -n "$POST_MAX" ]; then
  WRITE_LINES="$WRITE_LINES
post_max_size = $POST_MAX
upload_max_filesize = $UPLOAD_MAX"
  WRITE_KEYS_RE="$WRITE_KEYS_RE|post_max_size|upload_max_filesize"
  ok "post_max_size = $POST_MAX, upload_max_filesize = $UPLOAD_MAX (subidas mayores dejan de funcionar)"
fi

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
        elif [ -f "$dir/phprc" ] && is_own_ini "$dir/phprc"; then
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

# --block-multipart: rechaza con 403 todo POST multipart/form-data antes de
# PHP (regla de github.com/syhunt/php2shell-protection). Va al INICIO del
# .htaccess: un RewriteRule [L] previo (p. ej. el de WordPress para
# index.php) terminaría la ronda antes de llegar a esta regla.
mp_begin='# BEGIN php2shell multipart block'
mp_end='# END php2shell multipart block'
mp_block="$mp_begin
<IfModule mod_rewrite.c>
  RewriteEngine On
  RewriteCond %{REQUEST_METHOD} ^POST\$ [NC]
  RewriteCond %{HTTP:Content-Type} ^[[:space:]]*multipart/form-data([;,[:space:]]|\$) [NC]
  RewriteRule ^ - [F,L]
</IfModule>
$mp_end"

# strip_ht_block <archivo> <begin> <end>
strip_ht_block(){
  awk -v b="$2" -v e="$3" \
    'index($0,b){skip=1;next} index($0,e){skip=0;next} !skip{print}' \
    "$1" > "$1.tmp" && mv "$1.tmp" "$1"
}

# bloque actual entre <begin> y <end> (vacío si no hay)
get_ht_block(){
  awk -v b="$2" -v e="$3" 'index($0,b){p=1} p{print} index($0,e){p=0}' "$1" 2>/dev/null
}

# BEGIN sin su END (p. ej. editado a mano) haría que strip_ht_block borre
# todo lo que sigue; en ese caso no se toca el archivo
# ht_markers_ok <archivo> <begin> <end>
ht_markers_ok(){
  [ "$(grep -cF "$2" "$1" 2>/dev/null || true)" = "$(grep -cF "$3" "$1" 2>/dev/null || true)" ]
}
HT_UNBALANCED_MSG="marcadores BEGIN/END php2shell desbalanceados; no se modifica, revísalo a mano"

# un solo respaldo por archivo y corrida, tomado antes del primer cambio
ht_backup_once(){
  [ -f "$1.bak-php2shell-$TS" ] || cp "$1" "$1.bak-php2shell-$TS" 2>/dev/null || true
}

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
        elif [ -f "$dr/.user.ini" ] && is_own_ini "$dr/.user.ini"; then
          if [ "$DRY_RUN" -eq 1 ]; then log "(dry-run) eliminaría $dr/.user.ini (creado por este script)"
          else rm -f "$dr/.user.ini"; echo "  [OK]    .user.ini eliminado en $dr"; STATS_ROLLBACK=$((STATS_ROLLBACK+1)); fi
        fi
        # ambos bloques (protección y multipart) se quitan con un solo respaldo
        if [ -f "$dr/.htaccess" ]; then
          pre_rb_done=0
          for pair in "$ht_begin|$ht_end|bloque php2shell|.htaccess limpiado" \
                      "$mp_begin|$mp_end|bloque multipart|.htaccess: bloqueo multipart quitado"; do
            IFS='|' read -r b e label done_msg <<< "$pair"
            grep -qF "$b" "$dr/.htaccess" 2>/dev/null || continue
            if ! ht_markers_ok "$dr/.htaccess" "$b" "$e"; then warn "$dr/.htaccess: $HT_UNBALANCED_MSG"
            elif [ "$DRY_RUN" -eq 1 ]; then log "(dry-run) limpiaría $label en $dr/.htaccess"
            else
              [ "$pre_rb_done" -eq 1 ] || cp "$dr/.htaccess" "$dr/.htaccess.pre-rollback-$TS"
              pre_rb_done=1
              strip_ht_block "$dr/.htaccess" "$b" "$e"
              echo "  [OK]    $done_msg en $dr"
            fi
          done
        fi ;;
      *)
        merge_ini "$dr/.user.ini"
        echo "  [OK]    .user.ini en $dr"
        STATS_USERINI=$((STATS_USERINI+1))
        ht_existed=0; [ -f "$dr/.htaccess" ] && ht_existed=1
        if [ -f "$dr/.htaccess" ]; then
          # bloque actual (vacío si no hay); uno de una versión previa se reemplaza
          cur_block="$(get_ht_block "$dr/.htaccess" "$ht_begin" "$ht_end")"
          if [ -n "$cur_block" ] && ! ht_markers_ok "$dr/.htaccess" "$ht_begin" "$ht_end"; then
            warn "$dr/.htaccess: $HT_UNBALANCED_MSG"
          elif [ "$cur_block" != "$ht_block" ]; then
            if [ "$DRY_RUN" -eq 0 ]; then
              ht_backup_once "$dr/.htaccess"
              if [ -n "$cur_block" ]; then
                # quita el bloque viejo y añade el nuevo al final, sin sumar líneas en blanco
                strip_ht_block "$dr/.htaccess" "$ht_begin" "$ht_end"
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
        fi
        # sin el flag no se toca un bloque multipart existente: solo --rollback lo quita
        if [ "$BLOCK_MP" -eq 1 ]; then
          cur_mp=""
          [ -f "$dr/.htaccess" ] && cur_mp="$(get_ht_block "$dr/.htaccess" "$mp_begin" "$mp_end")"
          if [ -n "$cur_mp" ] && ! ht_markers_ok "$dr/.htaccess" "$mp_begin" "$mp_end"; then
            warn "$dr/.htaccess: $HT_UNBALANCED_MSG"
          elif [ "$cur_mp" = "$mp_block" ]; then
            log ".htaccess: bloqueo multipart ya presente en $dr"
          elif [ "$DRY_RUN" -eq 1 ]; then
            log "(dry-run) añadiría bloqueo multipart al inicio de $dr/.htaccess"
          else
            # un .htaccess recién creado por este script no necesita respaldo
            [ "$ht_existed" -eq 1 ] && ht_backup_once "$dr/.htaccess"
            if [ -n "$cur_mp" ]; then
              # sin el bloque viejo (el original no se toca hasta el final);
              # la línea en blanco que lo separaba del resto se conserva
              { printf '%s\n' "$mp_block"
                awk -v b="$mp_begin" -v e="$mp_end" \
                  'index($0,b){skip=1;next} index($0,e){skip=0;next} !skip{print}' "$dr/.htaccess"
              } > "$dr/.htaccess.tmp"
            else
              { printf '%s\n\n' "$mp_block"; cat "$dr/.htaccess"; } > "$dr/.htaccess.tmp"
            fi
            # escritura en el mismo archivo (no mv): conserva permisos y symlinks,
            # y falla en vez de reemplazar un .htaccess de solo lectura
            if cat "$dr/.htaccess.tmp" > "$dr/.htaccess"; then
              warn ".htaccess: bloqueo multipart activo en $dr (las subidas de archivos dejan de funcionar)"
            else
              warn "$dr/.htaccess: no se pudo escribir el bloqueo multipart (¿solo lectura?)"
            fi
            rm -f "$dr/.htaccess.tmp"
          fi
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
    # FEB solo aparece donde la directiva existe (PHP 8.5+); ML/PMS siempre
    printf '<?php $v = ini_get("session.upload_progress.enabled"); $f = ini_get("fatal_error_backtraces"); echo ($v === false) ? "ABSENT" : "UPP=" . var_export((bool)$v, true) . "|STRICT=" . var_export((bool)ini_get("session.use_strict_mode"), true) . (($f === false) ? "" : "|FEB=" . var_export((bool)$f, true)) . "|ML=" . ini_get("memory_limit") . "|PMS=" . ini_get("post_max_size");' > "$PROBE" 2>/dev/null
    [ -f "$PROBE" ] || { PROBE=""; continue; }

    resp=""
    for scheme in https http; do
      resp="$(curl -m 10 -sk "$scheme://$domain_guess/$TMPNAME" </dev/null 2>/dev/null)"
      [ -n "$resp" ] && break
    done

    # bloqueo multipart: se prueba si se pidió o si el .htaccess ya lo tiene.
    # Un POST multipart al probe debe recibir 403 antes de llegar a PHP.
    mp="-"
    if [ -n "$resp" ] && { [ "$BLOCK_MP" -eq 1 ] || grep -qF "$mp_begin" "$dr/.htaccess" 2>/dev/null; }; then
      code="$(curl -m 10 -sk -o /dev/null -w '%{http_code}' -F 'php2shell=probe' \
        "$scheme://$domain_guess/$TMPNAME" </dev/null 2>/dev/null)"
      if [ "$code" = "403" ]; then
        mp="BLOCKED"; ok "VERIFICADO $domain_guess → POST multipart rechazado (403)"
      elif [ -z "$code" ] || [ "$code" = "000" ]; then
        # curl falló o expiró: no hay evidencia de que llegue a PHP
        mp="ERROR"; warn "$domain_guess → POST multipart sin respuesta; verificar a mano"
      else
        mp="OPEN"; warn "$domain_guess → POST multipart NO bloqueado (HTTP $code); ¿sin mod_rewrite, nginx, o .htaccess en subcarpeta?"
      fi
    fi
    rm -f "$PROBE"; PROBE=""

    # separa ML/PMS; solo se exigen si esas líneas las puso este script
    # (los valores propios del usuario no se juzgan)
    base="$resp"; ml=""; pms=""
    case "$resp" in
      *"|ML="*) base="${resp%%|ML=*}"; ext="${resp#*|ML=}"; ml="${ext%%|PMS=*}"; pms="${ext#*|PMS=}" ;;
    esac
    extra_ok=""; mismatch=""
    if ours_line "$dr/.user.ini" 'memory_limit = -1'; then
      if [ "$ml" = "-1" ]; then extra_ok=", memory_limit=-1"; else mismatch="memory_limit=$ml (esperado -1)"; fi
    fi
    exp_pms="$(grep -E '^post_max_size = [0-9]+[KMG]$' "$dr/.user.ini" 2>/dev/null | tail -1 | sed 's/^post_max_size = //')"
    exp_up="$(grep -E '^upload_max_filesize = [0-9]+[KMG]$' "$dr/.user.ini" 2>/dev/null | tail -1 | sed 's/^upload_max_filesize = //')"
    if [ -n "$exp_pms" ] && [ -n "$exp_up" ] \
       && ours_line "$dr/.user.ini" "post_max_size = $exp_pms" \
       && ours_line "$dr/.user.ini" "upload_max_filesize = $exp_up"; then
      if [ "$pms" = "$exp_pms" ]; then extra_ok="$extra_ok, post_max_size=$pms"
      else mismatch="${mismatch:+$mismatch, }post_max_size=$pms (esperado $exp_pms)"; fi
    fi
    if [ -n "$mismatch" ] && { [ "$base" = "UPP=false|STRICT=true" ] || [ "$base" = "UPP=false|STRICT=true|FEB=false" ]; }; then
      warn "$domain_guess → $mismatch: ¿cache de .user.ini (re-corre --verify en 5 min) o fijado por el hosting?"
      echo "STALE|$domain_guess|$mp" >> "$VERIFY_TMP"
      continue
    fi

    case "$base" in
      "UPP=false|STRICT=true"|"UPP=false|STRICT=true|FEB=false")
        ok "VERIFICADO $domain_guess → upload_progress=Off, strict_mode=On$([ "${base##*|}" = "FEB=false" ] && echo ', fatal_error_backtraces=Off')$extra_ok"
        echo "OK|$domain_guess|$mp" >> "$VERIFY_TMP" ;;
      "ABSENT")
        warn "$domain_guess → directiva no existe en esta build (revisar versión PHP)"
        echo "ABSENT|$domain_guess|$mp" >> "$VERIFY_TMP" ;;
      "")
        warn "$domain_guess → no alcanzable vía HTTP (guess: $domain_guess); verificar con phpinfo manual"
        echo "UNREACHABLE|$domain_guess|$mp" >> "$VERIFY_TMP" ;;
      *)
        warn "$domain_guess → valor inesperado/incompleto: $base (¿cache de .user.ini? re-corre --verify en 5 min)"
        echo "STALE|$domain_guess|$mp" >> "$VERIFY_TMP" ;;
    esac
  done < "$DOCROOTS_FILE"

  # grep -c ya imprime 0 sin coincidencias (y sale con 1): `|| true`, no `|| echo 0`,
  # o el valor sería "0\n0" y partiría la línea SUMMARY
  STATS_VERIFIED=$(grep -c '^OK|' "$VERIFY_TMP" 2>/dev/null || true)
  STATS_FAILED=$(grep -c -v '^OK|' "$VERIFY_TMP" 2>/dev/null || true)
  STATS_MP_BLOCKED=$(grep -c '|BLOCKED$' "$VERIFY_TMP" 2>/dev/null || true)
  STATS_MP_OPEN=$(grep -c '|OPEN$' "$VERIFY_TMP" 2>/dev/null || true)
  STATS_MP_ERROR=$(grep -c '|ERROR$' "$VERIFY_TMP" 2>/dev/null || true)
  VERIFY_ROWS="$(sed 's/^\([^|]*\)|\([^|]*\)|\(.*\)$/| \2 | \1 | \3 |/' "$VERIFY_TMP")"
  log "→ archivos temporales de verificación eliminados"
fi

rm -f "$DOCROOTS_FILE"

# ---------------------------------------------------------------------------
# 6. REPORTE + SUMMARY (línea final parseable por el orquestador)
# ---------------------------------------------------------------------------
if [ "$MODE" != "rollback" ] && [ "$DRY_RUN" -eq 0 ]; then
  # la línea de multipart solo aparece si algún sitio se probó
  MP_LINE=""
  grep -qE '\|(BLOCKED|OPEN|ERROR)$' "$VERIFY_TMP" 2>/dev/null && MP_LINE="
- Multipart (\`BLOCKED\` = 403, \`OPEN\` = llega a PHP, \`ERROR\` = sin respuesta, \`-\` = no probado): bloqueado $STATS_MP_BLOCKED | abierto $STATS_MP_OPEN | error $STATS_MP_ERROR"
  EXTRA_LINE=""
  [ "$MEM_ON" -eq 1 ] && EXTRA_LINE="
- memory_limit = -1 ($([ "$MEM_OPT" = on ] && echo 'forzado' || echo "por defecto en $ENV_DETECTED"))"
  [ -n "$POST_MAX" ] && EXTRA_LINE="$EXTRA_LINE
- post_max_size = $POST_MAX | upload_max_filesize = $UPLOAD_MAX"
  cat > "$REPORT" <<EOF
# Reporte php2shell — $(date '+%Y-%m-%d %H:%M')
- Host: \`$HOSTNAME\` | Usuario: \`$USER_NAME\` | Modo: $MODE
- Entorno: **$ENV_DETECTED**
- phprc mitigados: $STATS_PHPRC | Docroots con .user.ini: $STATS_USERINI$MP_LINE$EXTRA_LINE

## Verificación por sitio
| Dominio | Estado | Multipart |
|---|---|---|
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
echo "SUMMARY env=$ENV_DETECTED mode=$MODE dryrun=$DRY_RUN phprc=$STATS_PHPRC userini=$STATS_USERINI verified=$STATS_VERIFIED failed=$STATS_FAILED rollback=$STATS_ROLLBACK mpblocked=$STATS_MP_BLOCKED mpopen=$STATS_MP_OPEN mperror=$STATS_MP_ERROR mem=$MEM_ON"
echo "============================================================"
