#!/usr/bin/env bash
# ============================================================================
#  privscan — Auditor de SUID, SGID y Linux capabilities
#
#  Enumera binarios con SUID/SGID y capabilities, avisa de los que NO
#  deberían tener privilegios y permite corregirlos de forma interactiva.
#  Cada cambio se guarda en un script de restauración para poder deshacerlo.
#
#  Licencia: MIT
# ============================================================================
set -u -o pipefail

readonly VERSION="1.0.0"
BACKUP_DIR="${PRIVSCAN_BACKUP_DIR:-/var/backups/privscan}"
ALLOWLIST="${PRIVSCAN_ALLOWLIST:-/etc/privscan/allowlist.txt}"

INTERACTIVE=1
SHOW_ALL=0
USE_COLOR=1
DO_UNDO=0
UNDO_FILE=""
EXTRA_EXCLUDES=()
PKG_MGR="none"
RESTORE_FILE=""
N_CRIT=0
N_WARN=0

declare -A MODE OWNER GROUP CAPS KIND SEV REASON BACKED_UP SEEN
PATHS=()

# ---------------------------------------------------------------------------
# Listas de referencia (separadas por espacios, con espacio inicial y final)
# ---------------------------------------------------------------------------

# Binarios que legítimamente suelen llevar SUID/SGID en distribuciones comunes.
BASELINE=" sudo sudoedit su passwd chsh chfn gpasswd newgrp chage expiry mount umount \
ping ping6 fusermount fusermount3 pkexec polkit-agent-helper-1 unix_chkpwd unix2_chkpwd \
ssh-keysign pam_extrausers_chkpwd ssh-agent wall write bsd-write crontab at locate mlocate plocate dotlockfile \
mutt_dotlock newuidmap newgidmap dbus-daemon-launch-helper pam_timestamp_check mount.nfs \
mount.cifs ntfs-3g Xorg.wrap snap-confine chrome-sandbox traceroute6.iputils mtr-packet \
utempter postdrop postqueue vmware-user-suid-wrapper "

# Binarios que, con SUID/SGID o capabilities, permiten escalar a root
# (basado en GTFOBins: https://gtfobins.github.io/).
GTFO=" ash bash busybox cat chmod chown cp csh tcsh ksh zsh fish dash sh curl wget cut dd diff \
docker emacs env expect find flock gawk awk mawk nawk gdb ltrace strace git head ionice \
jq ld.so less more man view vi vim vim.basic vim.tiny vimdiff ed nano pico rnano lua make mv \
nc ncat netcat socat nice nl nmap node od openssl perl php pip python rlwrap rpm yum apt \
apt-get dpkg rsync scp ruby irb run-parts sed setarch shuf sort stdbuf systemctl journalctl \
tail tar taskset tclsh tee time timeout unshare nsenter capsh unzip watch xargs xxd xz zip \
base64 date strings script screen tmux start-stop-daemon aria2c gimp tcpdump install "

# Binarios que legítimamente suelen llevar capabilities.
CAP_BASELINE=" ping ping6 mtr-packet traceroute6.iputils arping clockdiff tracepath \
gst-ptp-helper newuidmap newgidmap dumpcap "

# Capabilities que equivalen (en la práctica) a root.
DANGEROUS_CAPS_RE='cap_(setuid|setgid|setfcap|sys_admin|sys_module|sys_ptrace|sys_rawio|dac_override|dac_read_search|fowner|chown|bpf)'

# ---------------------------------------------------------------------------
# Utilidades
# ---------------------------------------------------------------------------
setup_colors() {
  if (( USE_COLOR )) && [[ -t 1 && -z ${NO_COLOR:-} ]]; then
    RED=$'\e[1;31m'; YEL=$'\e[1;33m'; GRN=$'\e[1;32m'
    DIM=$'\e[2m'; BLD=$'\e[1m'; RST=$'\e[0m'
  else
    RED=""; YEL=""; GRN=""; DIM=""; BLD=""; RST=""
  fi
}

ok()   { printf '  %s✔%s %s\n' "$GRN" "$RST" "$*"; }
warn() { printf '  %s!%s %s\n' "$YEL" "$RST" "$*" >&2; }
err()  { printf '  %s✘%s %s\n' "$RED" "$RST" "$*" >&2; }

usage() {
  cat <<USAGE
privscan $VERSION — auditor de SUID, SGID y capabilities

Uso: sudo privscan [opciones]

  -l, --list           Solo lista (sin menú interactivo). Código de salida 1
                       si hay hallazgos CRÍTICOS (útil para cron/CI).
  -a, --all            Muestra también los binarios considerados normales.
  -x, --exclude RUTA   Excluye una ruta del escaneo (se puede repetir).
      --undo [FICHERO] Deshace los cambios (último script de restauración
                       o el indicado).
      --no-color       Desactiva colores.
  -V, --version        Muestra la versión.
  -h, --help           Muestra esta ayuda.

Variables: PRIVSCAN_ALLOWLIST (por defecto $ALLOWLIST)
           PRIVSCAN_BACKUP_DIR (por defecto $BACKUP_DIR)
USAGE
}

norm_name() {  # python3.11 -> python ; fusermount3 -> fusermount
  local b=$1 n
  n=${b%"${b##*[!0-9.]}"}
  printf '%s' "${n:-$b}"
}

in_list() { [[ $1 == *" $2 "* ]]; }

is_system_dir() {
  case $1 in
    /bin/*|/sbin/*|/usr/bin/*|/usr/sbin/*|/usr/lib/*|/usr/lib64/*|/usr/libexec/*) return 0 ;;
  esac
  return 1
}

is_trusted_location() {  # ruta nombre_base
  is_system_dir "$1" && return 0
  # Electron/Chromium instalados por paquete (VS Code, Chrome, etc.)
  if [[ $2 == chrome-sandbox ]]; then
    case $1 in /usr/share/*|/opt/*) return 0 ;; esac
  fi
  return 1
}

is_risky_dir() {
  case $1 in
    /tmp/*|/var/tmp/*|/dev/shm/*|/home/*|/root/*|/var/www/*|/srv/*|/media/*|/mnt/*) return 0 ;;
  esac
  return 1
}

has_shebang() { [[ $(head -c2 -- "$1" 2>/dev/null) == '#!' ]]; }

is_allowlisted() { [[ -r $ALLOWLIST ]] && grep -Fxq -- "$1" "$ALLOWLIST"; }

detect_pkg_mgr() {
  if command -v dpkg >/dev/null 2>&1; then PKG_MGR=dpkg
  elif command -v rpm >/dev/null 2>&1; then PKG_MGR=rpm
  elif command -v pacman >/dev/null 2>&1; then PKG_MGR=pacman
  else PKG_MGR=none; fi
}

pkg_name() {  # imprime el paquete propietario del fichero (vacío si ninguno)
  local p=$1 out alt
  case $PKG_MGR in
    dpkg)
      alt=${p#/usr}   # compatibilidad con /usr merge (/bin/su vs /usr/bin/su)
      out=$(dpkg -S -- "$p" 2>/dev/null | head -n1)
      if [[ -z $out && $alt != "$p" ]]; then out=$(dpkg -S -- "$alt" 2>/dev/null | head -n1); fi
      printf '%s' "${out%%:*}" ;;
    rpm)
      if out=$(rpm -qf --qf '%{NAME}' -- "$p" 2>/dev/null); then printf '%s' "$out"; fi ;;
    pacman)
      pacman -Qoq -- "$p" 2>/dev/null | head -n1 ;;
  esac
}

confirm() {
  local a
  read -r -p "  ¿$1? [s/N] " a </dev/tty || return 1
  [[ $a =~ ^[sSyY]$ ]]
}

# ---------------------------------------------------------------------------
# Registro y clasificación de hallazgos
# ---------------------------------------------------------------------------
add_reason() {  # ruta severidad(0-2) [motivo]
  local p=$1 s=$2 r=${3:-}
  if [[ -z ${SEEN["$p"]+x} ]]; then
    SEEN["$p"]=1; PATHS+=("$p")
    SEV["$p"]=0; REASON["$p"]=""; KIND["$p"]=""; CAPS["$p"]=""
  fi
  if (( s > ${SEV["$p"]} )); then SEV["$p"]=$s; fi
  if [[ -n $r ]]; then REASON["$p"]+="${REASON["$p"]:+; }$r"; fi
}

classify_special() {  # ruta modo propietario grupo
  local p=$1 mode=$2 owner=$3 group=$4
  local base=${p##*/} norm m kind="" known=0 gtfo=0
  norm=$(norm_name "$base")
  m=$((8#$mode))
  (( m & 04000 )) && kind="SUID"
  (( m & 02000 )) && kind="${kind:+$kind+}SGID"

  add_reason "$p" 0
  MODE["$p"]=$mode; OWNER["$p"]=$owner; GROUP["$p"]=$group
  KIND["$p"]="${KIND["$p"]:+${KIND["$p"]} }$kind"

  if is_allowlisted "$p"; then add_reason "$p" 0 "en tu allowlist"; return; fi

  if in_list "$GTFO" "$base" || in_list "$GTFO" "$norm"; then
    gtfo=1
    add_reason "$p" 2 "$kind en un binario que permite obtener shell root (GTFOBins)"
  fi
  if is_risky_dir "$p"; then
    add_reason "$p" 2 "ubicación inusual donde escriben usuarios normales"
  fi
  if (( m & 0022 )); then
    add_reason "$p" 2 "fichero escribible por grupo/otros: cualquiera podría sustituirlo"
  fi
  if [[ $owner != root ]] && (( m & 04000 )); then
    add_reason "$p" 1 "SUID con propietario distinto de root ($owner)"
  fi
  if has_shebang "$p"; then
    add_reason "$p" 1 "es un script con $kind (peligroso y poco habitual)"
  fi

  # ¿Es un binario habitual, en su ubicación habitual?
  if { in_list "$BASELINE" "$base" || in_list "$BASELINE" "$norm"; } \
      && is_trusted_location "$p" "$base"; then
    known=1
  fi
  (( known )) && return

  # No es habitual: comprobar si pertenece a algún paquete del sistema
  if (( ! gtfo )) && (( ${SEV["$p"]} < 2 )); then
    local pk; pk=$(pkg_name "$p")
    if [[ $PKG_MGR != none && -z $pk ]]; then
      add_reason "$p" 2 "no pertenece a ningún paquete y no es un binario SUID/SGID habitual"
    else
      add_reason "$p" 1 "no figura en la lista de binarios SUID/SGID habituales${pk:+ (paquete: $pk)}"
    fi
  fi
}

classify_caps() {  # ruta capabilities
  local p=$1 caps=$2 base norm o g
  base=${p##*/}; norm=$(norm_name "$base")
  add_reason "$p" 0
  CAPS["$p"]=$caps
  KIND["$p"]="${KIND["$p"]:+${KIND["$p"]} }CAPS"
  if [[ -z ${MODE["$p"]:-} ]]; then
    MODE["$p"]=$(stat -c %a -- "$p" 2>/dev/null || echo 0)
    read -r o g < <(stat -c '%U %G' -- "$p" 2>/dev/null || echo "? ?")
    OWNER["$p"]=$o; GROUP["$p"]=$g
  fi

  if is_allowlisted "$p"; then add_reason "$p" 0 "en tu allowlist"; return; fi

  if in_list "$GTFO" "$base" || in_list "$GTFO" "$norm"; then
    add_reason "$p" 2 "capabilities ($caps) en un binario que permite escalar a root"; return
  fi
  if is_risky_dir "$p"; then
    add_reason "$p" 2 "capabilities ($caps) en ubicación inusual"; return
  fi
  if in_list "$CAP_BASELINE" "$base" && is_trusted_location "$p" "$base"; then return; fi
  if [[ $caps == =* || $caps =~ $DANGEROUS_CAPS_RE ]]; then
    add_reason "$p" 2 "capabilities equivalentes a root ($caps) fuera de la lista habitual"
  else
    add_reason "$p" 1 "capabilities no habituales ($caps)"
  fi
}

# ---------------------------------------------------------------------------
# Escaneo
# ---------------------------------------------------------------------------
build_prune() {
  PRUNE=( '(' -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /snap \
          -o -path /var/lib/snapd -o -path /var/lib/docker -o -path /var/lib/containers )
  local x
  for x in ${EXTRA_EXCLUDES[@]+"${EXTRA_EXCLUDES[@]}"}; do PRUNE+=( -o -path "$x" ); done
  PRUNE+=( ')' -prune -o )
}

scan_suid_sgid() {
  local mode owner group path
  while IFS='|' read -r mode owner group path; do
    [[ -n $path ]] && classify_special "$path" "$mode" "$owner" "$group"
  done < <(find / "${PRUNE[@]}" -type f \( -perm -4000 -o -perm -2000 \) \
             -printf '%m|%u|%g|%p\n' 2>/dev/null)
}

scan_caps() {
  if ! command -v getcap >/dev/null 2>&1; then
    warn "getcap no está instalado: se omiten las capabilities (apt install libcap2-bin)"
    return
  fi
  local line path caps
  while IFS= read -r line; do
    [[ -z $line ]] && continue
    if [[ $line == *" = "* ]]; then path=${line% = *}; caps=${line##* = }
    else path=${line% *}; caps=${line##* }; fi
    classify_caps "$path" "$caps"
  done < <(find / "${PRUNE[@]}" -type f -print0 2>/dev/null | xargs -0 -r getcap 2>/dev/null)
}

# ---------------------------------------------------------------------------
# Presentación
# ---------------------------------------------------------------------------
print_item() {  # ruta [etiqueta]
  local p=$1 tag=${2:-} col lab r
  local -a rs
  case ${SEV["$p"]} in
    2) col=$RED; lab="CRÍTICO" ;;
    1) col=$YEL; lab="REVISAR" ;;
    *) col=$GRN; lab="OK" ;;
  esac
  printf '\n %s[%s]%s %s%s%s %s\n' "$col" "$lab" "$RST" "$BLD" "$p" "$RST" "$tag"
  printf '     tipo: %s | permisos: %s | propietario: %s:%s\n' \
    "${KIND["$p"]}" "${MODE["$p"]}" "${OWNER["$p"]:-?}" "${GROUP["$p"]:-?}"
  if [[ -n ${CAPS["$p"]} ]]; then printf '     capabilities: %s\n' "${CAPS["$p"]}"; fi
  IFS=';' read -ra rs <<<"${REASON["$p"]}"
  for r in ${rs[@]+"${rs[@]}"}; do
    r=${r# }
    if [[ -n $r ]]; then printf '       %s•%s %s\n' "$DIM" "$RST" "$r"; fi
  done
}

print_report() {
  local p n_crit=0 n_warn=0 n_ok=0
  for p in ${PATHS[@]+"${PATHS[@]}"}; do
    case ${SEV["$p"]} in
      2) n_crit=$((n_crit+1)) ;;
      1) n_warn=$((n_warn+1)) ;;
      *) n_ok=$((n_ok+1)) ;;
    esac
  done
  for p in ${PATHS[@]+"${PATHS[@]}"}; do
    if [[ ${SEV["$p"]} -eq 2 ]]; then print_item "$p"; fi
  done
  for p in ${PATHS[@]+"${PATHS[@]}"}; do
    if [[ ${SEV["$p"]} -eq 1 ]]; then print_item "$p"; fi
  done
  if (( SHOW_ALL )); then
    printf '\n%sNormales:%s\n' "$BLD" "$RST"
    for p in ${PATHS[@]+"${PATHS[@]}"}; do
      if [[ ${SEV["$p"]} -eq 0 ]]; then
        printf '  %s✔%s %-45s %s %s\n' "$GRN" "$RST" "$p" "${KIND["$p"]}" "${CAPS["$p"]}"
      fi
    done
  fi
  printf '\n%s──────────────── Resumen ────────────────%s\n' "$BLD" "$RST"
  printf '  %sCríticos:%s %d   %sA revisar:%s %d   %sNormales:%s %d\n' \
    "$RED" "$RST" "$n_crit" "$YEL" "$RST" "$n_warn" "$GRN" "$RST" "$n_ok"
  N_CRIT=$n_crit; N_WARN=$n_warn
}

show_details() {
  local p=$1 base norm pk
  base=${p##*/}; norm=$(norm_name "$base")
  echo; ls -l -- "$p"
  if command -v file >/dev/null 2>&1; then file -- "$p"; fi
  if command -v sha256sum >/dev/null 2>&1; then sha256sum -- "$p"; fi
  pk=$(pkg_name "$p")
  echo "  Paquete: ${pk:-(ninguno)}"
  if in_list "$GTFO" "$base" || in_list "$GTFO" "$norm"; then
    echo "  Técnicas conocidas: https://gtfobins.github.io/gtfobins/$norm/"
  fi
  echo
}

# ---------------------------------------------------------------------------
# Corrección + copia para deshacer
# ---------------------------------------------------------------------------
backup_init() {
  [[ -n $RESTORE_FILE ]] && return 0
  mkdir -p "$BACKUP_DIR" && chmod 700 "$BACKUP_DIR" || return 1
  RESTORE_FILE="$BACKUP_DIR/restore-$(date +%Y%m%d-%H%M%S).sh"
  {
    echo '#!/usr/bin/env bash'
    echo "# privscan $VERSION — restaura permisos y capabilities originales"
  } >"$RESTORE_FILE" || return 1
  chmod 700 "$RESTORE_FILE"
}

backup_item() {
  local p=$1
  [[ -n ${BACKED_UP["$p"]+x} ]] && return 0
  backup_init || return 1
  printf 'chmod %s %q\n' "${MODE["$p"]}" "$p" >>"$RESTORE_FILE"
  if [[ -n ${CAPS["$p"]} ]]; then printf 'setcap %q %q\n' "${CAPS["$p"]}" "$p" >>"$RESTORE_FILE"; fi
  BACKED_UP["$p"]=1
}

fix_bit() {  # ruta u-s|g-s etiqueta
  local p=$1 op=$2 label=$3
  confirm "Quitar $label de $p" || return 0
  backup_item "$p" || { err "No se pudo crear la copia de seguridad; no se modifica nada"; return 0; }
  if chmod "$op" -- "$p"; then
    MODE["$p"]=$(stat -c %a -- "$p"); ok "$label eliminado"
  else
    err "chmod falló"
  fi
}

fix_caps() {
  local p=$1
  command -v setcap >/dev/null 2>&1 || { err "setcap no está instalado (libcap2-bin)"; return 0; }
  confirm "Quitar capabilities de $p" || return 0
  backup_item "$p" || { err "No se pudo crear la copia de seguridad; no se modifica nada"; return 0; }
  if setcap -r "$p"; then CAPS["$p"]=""; ok "capabilities eliminadas"; else err "setcap falló"; fi
}

fix_all() {
  local p=$1
  confirm "Quitar SUID, SGID y capabilities de $p" || return 0
  backup_item "$p" || { err "Sin copia de seguridad; no se modifica nada"; return 0; }
  chmod u-s,g-s -- "$p" && MODE["$p"]=$(stat -c %a -- "$p")
  if [[ -n ${CAPS["$p"]} ]] && setcap -r "$p"; then CAPS["$p"]=""; fi
  ok "Privilegios eliminados"
}

review_item() {  # ruta índice total  -> devuelve 1 si el usuario quiere salir
  local p=$1 idx=$2 total=$3 choice m
  local has_suid has_sgid has_caps
  while true; do
    m=$((8#${MODE["$p"]:-0}))
    has_suid=0; has_sgid=0; has_caps=0
    (( m & 04000 )) && has_suid=1
    (( m & 02000 )) && has_sgid=1
    [[ -n ${CAPS["$p"]} ]] && has_caps=1
    if (( has_suid + has_sgid + has_caps == 0 )); then return 0; fi
    print_item "$p" "($idx/$total)"
    echo "   Acciones:"
    (( has_suid )) && echo "     [1] Quitar SUID                 (chmod u-s)"
    (( has_sgid )) && echo "     [2] Quitar SGID                 (chmod g-s)"
    (( has_caps )) && echo "     [3] Quitar capabilities         (setcap -r)"
    (( has_suid + has_sgid + has_caps > 1 )) && echo "     [4] Quitar TODO lo anterior"
    echo "     [i] Ignorar (es legítimo: añadir a allowlist)"
    echo "     [d] Ver detalles   [s] Saltar (Enter)   [q] Salir"
    read -r -p "   > " choice </dev/tty || return 1
    case ${choice:-s} in
      1) if (( has_suid )); then fix_bit "$p" u-s SUID; fi ;;
      2) if (( has_sgid )); then fix_bit "$p" g-s SGID; fi ;;
      3) if (( has_caps )); then fix_caps "$p"; fi ;;
      4) fix_all "$p" ;;
      i|I) if mkdir -p "$(dirname "$ALLOWLIST")" && printf '%s\n' "$p" >>"$ALLOWLIST"; then
             ok "Añadido a $ALLOWLIST"; return 0
           else
             err "No se pudo escribir en $ALLOWLIST"
           fi ;;
      d|D) show_details "$p" ;;
      s|S) return 0 ;;
      q|Q) return 1 ;;
      *) warn "Opción no válida" ;;
    esac
  done
}

interactive_fix() {
  local -a queue=()
  local p i=0 total
  for p in ${PATHS[@]+"${PATHS[@]}"}; do
    if [[ ${SEV["$p"]} -eq 2 ]]; then queue+=("$p"); fi
  done
  for p in ${PATHS[@]+"${PATHS[@]}"}; do
    if [[ ${SEV["$p"]} -eq 1 ]]; then queue+=("$p"); fi
  done
  total=${#queue[@]}
  for p in "${queue[@]}"; do
    i=$((i+1))
    [[ -e $p ]] || continue
    review_item "$p" "$i" "$total" || break
  done
  if [[ -n $RESTORE_FILE ]]; then
    echo; ok "Para deshacer los cambios: sudo $0 --undo   (copia: $RESTORE_FILE)"
  fi
}

do_undo() {
  local f=$UNDO_FILE
  if [[ -z $f ]]; then
    # shellcheck disable=SC2012
    f=$(ls -1t "$BACKUP_DIR"/restore-*.sh 2>/dev/null | head -n1)
  fi
  [[ -n $f && -r $f ]] || { err "No hay copias de seguridad en $BACKUP_DIR"; return 1; }
  (( EUID == 0 )) || { err "Necesitas root (sudo) para restaurar"; return 1; }
  echo "Se restaurará desde: $f"; echo "----"; grep -v '^#' "$f"; echo "----"
  confirm "Restaurar permisos y capabilities originales" || { echo "  Cancelado."; return 0; }
  bash "$f" && ok "Restauración completada"
}

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
main() {
  while (( $# )); do
    case $1 in
      -l|--list) INTERACTIVE=0 ;;
      -a|--all) SHOW_ALL=1 ;;
      -x|--exclude)
        [[ -n ${2:-} ]] || { echo "Falta la ruta tras $1" >&2; exit 2; }
        EXTRA_EXCLUDES+=("$2"); shift ;;
      --no-color) USE_COLOR=0 ;;
      --undo)
        DO_UNDO=1
        if [[ -n ${2:-} && $2 != -* ]]; then UNDO_FILE=$2; shift; fi ;;
      -V|--version) echo "privscan $VERSION"; exit 0 ;;
      -h|--help) usage; exit 0 ;;
      *) echo "Opción desconocida: $1" >&2; usage >&2; exit 2 ;;
    esac
    shift
  done

  setup_colors
  [[ $(uname -s) == Linux ]] || { err "privscan solo funciona en Linux"; exit 2; }
  if (( DO_UNDO )); then do_undo; exit $?; fi

  detect_pkg_mgr
  build_prune

  printf '%sprivscan %s%s — %s — kernel %s\n' "$BLD" "$VERSION" "$RST" "$(hostname)" "$(uname -r)"
  if (( EUID != 0 )); then
    warn "Ejecutándose sin root: el escaneo puede ser incompleto y no se podrá corregir."
  fi
  if [[ -t 2 ]]; then printf '  Escaneando SUID/SGID…\r' >&2; fi
  scan_suid_sgid
  if [[ -t 2 ]]; then printf '  Escaneando capabilities…\r' >&2; fi
  scan_caps
  if [[ -t 2 ]]; then printf '                              \r' >&2; fi

  if (( ${#PATHS[@]} )); then
    mapfile -t PATHS < <(printf '%s\n' "${PATHS[@]}" | LC_ALL=C sort)
  fi
  print_report

  if (( INTERACTIVE )) && [[ -t 0 && -t 1 ]]; then
    if (( N_CRIT + N_WARN == 0 )); then
      echo; ok "Nada sospechoso. Sistema limpio."
    elif (( EUID != 0 )); then
      echo; warn "Vuelve a ejecutar con sudo para poder corregir los hallazgos."
    else
      echo
      if confirm "Revisar y corregir los hallazgos ahora"; then interactive_fix; fi
    fi
    exit 0
  fi
  if (( N_CRIT > 0 )); then exit 1; fi
  exit 0
}

main "$@"
