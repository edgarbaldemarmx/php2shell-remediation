#!/usr/bin/env bash
# ============================================================================
#  php2shell-run-all.sh v3 — Orquestador paralelo de la mitigación php2shell
#  (CVE-2026-109618 / CVE-2026-109619)
#
#  Corre php2shell-mitigate.sh en paralelo contra servers.txt y consolida
#  resultados parseando la línea SUMMARY del agente (sin regex frágiles).
#
#  USO:
#    ./php2shell-run-all.sh servers.txt               # aplicar
#    ./php2shell-run-all.sh servers.txt --verify      # solo verificar
#    ./php2shell-run-all.sh servers.txt --rollback    # revertir
#    ./php2shell-run-all.sh servers.txt --dry-run     # simular
#    ./php2shell-run-all.sh servers.txt --php-versions 8.3,8.4
#    ./php2shell-run-all.sh servers.txt --domains s1.com,s2.com
#    ./php2shell-run-all.sh servers.txt --block-multipart --domains s1.com
#    ./php2shell-run-all.sh servers.txt --memory-unlimited | --keep-memory-limit
#    ./php2shell-run-all.sh servers.txt --post-max-size 8M
#
#  servers.txt — una línea por servidor:
#    usuario@host            → conexión estándar
#    usuario@host:2222       → puerto custom
#    (líneas vacías y # comentarios se ignoran)
#
#  Requisitos: SSH por llaves (BatchMode; nunca pide contraseñas).
#  Salida: results/reporte-<user>-<host>.md + php2shell-consolidado.csv
# ============================================================================

set -u

SERVERS_FILE="${1:-}"; shift || true
MODE="apply"
DRY_RUN=0
EXTRA_ARGS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --verify|--rollback) MODE="${1#--}"; EXTRA_ARGS+=("$1") ;;
    --dry-run) DRY_RUN=1; EXTRA_ARGS+=("$1") ;;
    --block-multipart|--memory-unlimited|--keep-memory-limit) EXTRA_ARGS+=("$1") ;;
    --php-versions|--domains|--post-max-size) EXTRA_ARGS+=("$1" "${2:-}"); shift ;;
    *) echo "Opción desconocida: $1" >&2; exit 1 ;;
  esac
  shift
done

# el agente reporta dry-run aparte (dryrun=1), no como modo: MODE se compara
# contra su SUMMARY y MODE_LABEL es solo para pantalla y CSV
MODE_LABEL="$MODE"
if [ "$DRY_RUN" -eq 1 ]; then
  if [ "$MODE" = "apply" ]; then MODE_LABEL="dry-run"; else MODE_LABEL="$MODE+dry-run"; fi
fi

HERE="$(cd "$(dirname "$0")" && pwd)"
AGENT="$HERE/php2shell-mitigate.sh"
OUTDIR="$HERE/results"
CSV="$HERE/php2shell-consolidado.csv"
MAX_PARALLEL=5   # conexiones ssh simultáneas (ajustar si el firewall se queja)
SSH_OPTS="-o ConnectTimeout=15 -o StrictHostKeyChecking=accept-new -o BatchMode=yes"

[ -z "$SERVERS_FILE" ] && { echo "Uso: $0 <servers.txt> [--verify|--rollback|--dry-run] [--php-versions 8.3,8.4] [--domains d1,d2] [--block-multipart] [--memory-unlimited|--keep-memory-limit] [--post-max-size 8M]"; exit 1; }
[ -f "$AGENT" ] || { echo "ERROR: falta $AGENT (debe estar junto a este script)"; exit 1; }
[ -f "$SERVERS_FILE" ] || { echo "ERROR: falta $SERVERS_FILE"; exit 1; }

mkdir -p "$OUTDIR"
echo "host,usuario,timestamp,modo,estado,phprc,userini,verified,failed,rollback,reporte,mp_blocked,mp_open,mp_error,mem" > "$CSV"

# ---------------------------------------------------------------------------
# Worker: envía el agente por stdin (sin copia en el /tmp remoto, que es
# compartido en hosting), parsea SUMMARY y consolida
# ---------------------------------------------------------------------------
run_one(){
  local entry="$1"
  local user host port
  user="${entry%%@*}"
  local rest="${entry#*@}"
  if [[ "$rest" == *:* ]]; then host="${rest%%:*}"; port="${rest##*:}"; else host="$rest"; port="22"; fi

  echo "[$(date '+%H:%M:%S')] → $user@$host:$port (modo: $MODE_LABEL)"
  local tmplog="$OUTDIR/.tmp-${user}-${host}.log"
  local estado="OK" phprc=0 userini=0 verified=0 failed=0 rollback=0 mpblocked=0 mpopen=0 mperror=0 mem=0 rep=""

  local remote_out rc
  remote_out="$(ssh -p "$port" $SSH_OPTS "$user@$host" "bash -s -- ${EXTRA_ARGS[*]:-}" < "$AGENT" 2>&1)"
  rc=$?
  echo "$remote_out" > "$tmplog"
  # 255 = falló la conexión ssh (el agente solo sale con 0 o 1)
  if [ $rc -eq 255 ]; then
    echo "[$(date '+%H:%M:%S')] ✗ ssh falló a $host (¿llaves SSH?)" >&2
    echo "$host,$user,$(date -Iseconds),$MODE_LABEL,SSH_FAIL,0,0,0,0,0,,0,0,0," >> "$CSV"
    rm -f "$tmplog"; return 1
  fi
  [ $rc -ne 0 ] && estado="AGENT_ERROR"

  # parsear la línea SUMMARY (formato estable clave=valor, sin regex frágiles)
  local summary kv pair k v
  summary="$(echo "$remote_out" | grep '^SUMMARY ' | tail -1)"
  if [ -n "$summary" ]; then
    kv="${summary#SUMMARY }"
    for pair in $kv; do
      k="${pair%%=*}"; v="${pair#*=}"
      case "$k" in
        phprc)    phprc="$v" ;;
        userini)  userini="$v" ;;
        verified) verified="$v" ;;
        failed)   failed="$v" ;;
        rollback) rollback="$v" ;;
        mpblocked) mpblocked="$v" ;;
        mpopen)   mpopen="$v" ;;
        mperror)  mperror="$v" ;;
        mem)      mem="$v" ;;
        mode)     [ "$v" != "$MODE" ] && estado="MODE_MISMATCH" ;;
      esac
    done
  else
    estado="NO_SUMMARY"
  fi

  # traer reporte (si lo generó) y limpiarlo del servidor
  rep="$OUTDIR/reporte-${user}-${host}.md"
  scp -P "$port" $SSH_OPTS -q "$user@$host:~/php2shell-reporte-*.md" "$rep" 2>/dev/null || rep=""
  ssh -p "$port" $SSH_OPTS "$user@$host" 'rm -f ~/php2shell-reporte-*.md' >/dev/null 2>&1 || true

  echo "$host,$user,$(date -Iseconds),$MODE_LABEL,$estado,$phprc,$userini,$verified,$failed,$rollback,${rep##*/},$mpblocked,$mpopen,$mperror,$mem" >> "$CSV"
  rm -f "$tmplog"
  echo "[$(date '+%H:%M:%S')] ✓ $host [$estado] phprc:$phprc userini:$userini verified:$verified failed:$failed rollback:$rollback$( [ $((mpblocked+mpopen+mperror)) -gt 0 ] && echo " mp:$mpblocked/$mpopen/$mperror")"
}

# ---------------------------------------------------------------------------
# Paralelismo controlado
# ---------------------------------------------------------------------------
echo "============================================================"
echo " php2shell run-all v3 | $(date '+%Y-%m-%d %H:%M:%S')"
echo " servidores: $(grep -cve '^\s*$' -e '^\s*#' "$SERVERS_FILE") | paralelismo: $MAX_PARALLEL | modo: $MODE_LABEL"
echo "============================================================"

while IFS= read -r line; do
  line="$(echo "$line" | sed 's/#.*//' | xargs)"
  [ -z "$line" ] && continue
  run_one "$line" &
  while [ "$(jobs -rp | wc -l)" -ge "$MAX_PARALLEL" ]; do sleep 2; done
done < "$SERVERS_FILE"
wait

# ---------------------------------------------------------------------------
# Resumen
# ---------------------------------------------------------------------------
echo ""
echo "============================================================"
echo " RESUMEN CONSOLIDADO"
echo "============================================================"
column -t -s',' "$CSV" 2>/dev/null || cat "$CSV"
echo ""
awk -F',' 'NR>1 {
  tot++
  if ($5=="SSH_FAIL") sf++
  else if ($5!="OK") other++
  ph+=$6; ui+=$7; ve+=$8; fa+=$9; ro+=$10; mb+=$12; mo+=$13; me+=$14
} END {
  printf " servidores: %d | SSH_FAIL: %d | otros estados: %d\n phprc: %d | user.ini: %d | verificados: %d | fallidos: %d | rollback: %d\n multipart bloqueado: %d | multipart abierto: %d | multipart error: %d\n", tot+0, sf+0, other+0, ph+0, ui+0, ve+0, fa+0, ro+0, mb+0, mo+0, me+0
}' "$CSV"
echo ""
echo " CSV: $CSV | Detalle: $OUTDIR/"
echo "============================================================"
