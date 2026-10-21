#!/usr/bin/env bash
# audit-extensions.sh - which PHP extensions each handler actually loads.
#
# Why: an ini file cannot patch compiled code, but a DISABLED extension is not
# loaded into the process at all. If a CVE turns out to live in a PECL/optional
# extension, commenting its ini line genuinely removes that code path. For that
# to be useful tomorrow you need to know, today, which extensions you load and
# which of them nothing uses.
#
#   sudo ./audit-extensions.sh                    # probe every handler on this box
#   ./audit-extensions.sh --from-file list.txt    # classify a saved `php -m` list
#
# READ-ONLY.

set -uo pipefail
PLESK=${PLESK_BIN:-plesk}

# Extensions that ship inside a stock PHP build. Disabling these breaks things.
BUNDLED=" core standard date pcre spl reflection session hash json filter "
BUNDLED+=" ctype tokenizer zlib simplexml dom xml xmlreader xmlwriter libxml "
BUNDLED+=" mbstring iconv fileinfo exif pdo mysqli pdo_mysql pdo_sqlite sqlite3 "
BUNDLED+=" pgsql pdo_pgsql openssl curl gd sockets posix shmop sysvmsg sysvsem "
BUNDLED+=" sysvshm wddx xmlrpc soap calendar bcmath gmp intl gettext ldap imap "
BUNDLED+=" snmp tidy ftp pcntl readline phar zip bz2 zend opcache Zend OPcache "
BUNDLED+=" Phar SPL Reflection PDO mysqlnd sodium ffi random "

# Extensions usually installed via PECL/third parties. These are the ones worth
# removing when unused - they are extra C code in the process, often with a
# history of memory-safety and deserialization bugs of their own.
declare -A NOTE=(
  [imagick]="ImageMagick bindings - heavy C surface, parser CVEs historically"
  [igbinary]="serializer - deserialization surface"
  [msgpack]="serializer - deserialization surface"
  [redis]="client lib - deserialization surface"
  [memcached]="client lib - deserialization surface"
  [mongodb]="client lib - large C surface"
  [apcu]="shared cache - fine, but unused ones are pure surface"
  [xdebug]="debugger - should never be on in production"
  [swoole]="async runtime - large surface"
  [grpc]="RPC - large surface"
  [protobuf]="serialization - parser surface"
  [ssh2]="libssh2 bindings - historically CVE-prone"
  [yaml]="libyaml bindings - parser surface"
  [gnupg]="GPG bindings"
  [oauth]="OAuth bindings"
  [uuid]="uid generation - safe but unnecessary if unused"
  [ds]="data structures - low risk"
  [event]="libevent bindings"
  [rdkafka]="Kafka client - large surface"
  [mailparse]="MIME parser - parser surface"
  [uopz]="can rewrite opcodes - dangerous, never in production"
  [pcov]="coverage - dev only"
  [excimer]="profiler - dev only"
  [decimal]="numeric - low risk"
  [zookeeper]="ZooKeeper client"
  [amqp]="AMQP client"
  [sqlsrv]="MSSQL client"
  [pdo_sqlsrv]="MSSQL client"
  [newrelic]="APM agent - vendor code in-process"
)

classify() {  # one extension name -> "bundled" | "pecl"
  local e=" $1 "
  [[ "$BUNDLED" == *" $1 "* || "$BUNDLED" == *" $1 "* ]] && { echo bundled; return; }
  case "$1" in
    [A-Z]*) echo bundled ;;   # Zend/Phar/PDO style built-ins
    *) echo pecl ;;
  esac
}

report_list() {  # $1 = label, stdin = `php -m` output
  local label="$1" mod line cls
  local pecl_count=0
  echo "  $label"
  while IFS= read -r line; do
    mod="$(printf '%s' "$line" | tr -d '[:space:]')"
    [[ -z "$mod" ]] && continue
    [[ "$mod" =~ ^\[.*\]$ ]] && continue        # [PHP Modules] / [Zend Modules]
    case "$mod" in
      "PHPModules"|"ZendModules") continue ;;
    esac
    cls=$(classify "$mod")
    if [[ "$cls" == "pecl" ]]; then
      pecl_count=$((pecl_count+1))
      if [[ -n "${NOTE[$mod]:-}" ]]; then
        printf '    %-16s  non-bundled  %s\n' "$mod" "${NOTE[$mod]}"
      else
        printf '    %-16s  non-bundled\n' "$mod"
      fi
    fi
  done
  echo "    ($pecl_count non-bundled extension(s) loaded)"
}

echo "PHP extension audit    $(date -u '+%Y-%m-%d %H:%M UTC')"

if [[ "${1:-}" == "--from-file" ]]; then
  [[ -r "${2:-}" ]] || { echo "cannot read ${2:-}"; exit 1; }
  report_list "from ${2}" < "$2"
  exit 0
fi

if [[ -n "${PLESK:-}" ]] && command -v "$PLESK" >/dev/null 2>&1; then
  echo
  echo "handlers registered with Plesk:"
  "$PLESK" bin php_handler --list 2>/dev/null | awk 'NF>3 {printf "  %-18s %s\n", $1, $4}'
fi

echo
echo "per-binary module lists:"
shopt -s nullglob
BINS=(/opt/plesk/php/*/bin/php /usr/bin/php /usr/bin/php[0-9]*)
shopt -u nullglob
if [[ ${#BINS[@]} -eq 0 ]]; then
  echo "  no php CLI found (expected /opt/plesk/php/*/bin/php)"
else
  for b in "${BINS[@]}"; do
    [[ -x "$b" ]] || continue
    ver=$("$b" -r 'echo PHP_VERSION;' 2>/dev/null || echo "?")
    report_list "$b  (PHP $ver)" < <("$b" -m 2>/dev/null)
    echo
  done
fi

cat <<'EOF'
How to disable one (reversible):
  Plesk: /opt/plesk/php/<ver>/etc/php.d/*.ini  -> comment out `extension=name.so`
         or Domain > PHP Settings > Additional configuration directives
  then: sudo systemctl restart plesk-php<ver>-fpm
  verify: <handler>/bin/php -m | grep -i name     (must be absent)

Do NOT disable bundled extensions listed in this script unless you know the
application does not need them - gd/curl/simplexml/zip break WordPress fast.
EOF