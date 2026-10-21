#!/usr/bin/env bash
# audit-plesk-php.sh - read-only PHP exposure audit for a Plesk server.
#
# Answers, in one pass:
#   * which PHP handlers exist and what version each is
#   * which domain runs which handler  (Plesk multi-PHP: one box, many builds)
#   * which domains are on an end-of-life branch that will get NO patch for
#     CVE-2026-109618/619
#   * hardening gaps that matter for an RCE: exec-family functions enabled,
#     allow_url_include, expose_php, open_basedir
#   * WordPress instances known to WP Toolkit
#
# READ-ONLY: it runs no write operations and changes nothing. Safe to run on
# production. Output is plain text; tee it to a file.
#
#   sudo ./audit-plesk-php.sh | tee plesk-php-audit-$(hostname)-$(date +%F).txt

set -uo pipefail

PLESK=${PLESK_BIN:-plesk}

have() { command -v "$1" >/dev/null 2>&1; }
hr()   { printf '%s\n' "------------------------------------------------------------"; }

echo "Plesk PHP exposure audit"
echo "host: $(hostname -f 2>/dev/null || hostname)   date: $(date -u '+%Y-%m-%d %H:%M UTC')"
have "$PLESK" || { echo "ERROR: plesk CLI not found (set PLESK_BIN=/path/to/plesk)"; exit 1; }

hr
echo "1. PHP handlers installed"
hr
HANDLERS=$("$PLESK" bin php_handler --list 2>/dev/null)
declare -A HVER=()   # handler id -> full version, used to map domains below
if [[ -z "$HANDLERS" ]]; then
  echo "  could not list handlers (are you root?)"
else
  printf '  %-18s %-10s %-14s %-10s %s\n' ID VERSION STATUS TYPE PATH
  while IFS= read -r line; do
    [[ -z "${line// }" ]] && continue
    # handler rows look like: id  display-name  full-version  path  type  [cgi-bin]
    # header row has no x.y.z version, so it falls through and is skipped
    ver=$(printf '%s\n' "$line" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    [[ -z "$ver" ]] && continue
    hid=$(printf '%s\n' "$line" | awk '{print $1}')
    path=$(printf '%s\n' "$line" | awk '{print $4}')
    type=$(printf '%s\n' "$line" | awk '{print $5}')
    case "$ver" in
      5.*|7.*|8.0.*|8.1.*) flag="EOL-NO-PATCH" ;;
      *)                   flag="supported" ;;
    esac
    HVER["$hid"]="$ver"
    printf '  %-18s %-10s %-14s %-10s %s\n' "$hid" "$ver" "$flag" "$type" "$path"
  done < <(printf '%s\n' "$HANDLERS")
fi

hr
echo "2. domain -> PHP handler  (the line that actually matters: EOL sites)"
hr
# php_handler_id lives on hosting; subdomains carry their own handler too.
DOMAINS=$("$PLESK" db -Ne \
  "SELECT d.name, IFNULL(h.php_handler_id,'inherit') \
   FROM domains d LEFT JOIN hosting h ON h.dom_id=d.id ORDER BY d.name;" 2>/dev/null)
if [[ -z "$DOMAINS" ]]; then
  echo "  could not query psa database"
else
  eol_count=0
  while IFS=$'\t' read -r dom handler; do
    [[ -z "$dom" ]] && continue
    # Plesk handler ids ("fpm-8.4", "cgi-fcgi-5.6") do not carry the patch
    # version, so resolve through the handler table from section 1.
    if [[ -n "${HVER[$handler]:-}" ]]; then
      ver="${HVER[$handler]}"
    else
      ver="unresolved($handler)"
    fi
    case "$ver" in
      5.*|7.*|8.0.*|8.1.*)
        printf '  %-40s %-10s  <== EOL, no patch coming\n' "$dom" "$ver"
        eol_count=$((eol_count+1)) ;;
      *) printf '  %-40s %s\n' "$dom" "$ver" ;;
    esac
  done <<< "$DOMAINS"
  [[ $eol_count -gt 0 ]] && \
    printf '\n  %d domain(s) on an end-of-life branch.\n' "$eol_count"
fi

hr
echo "3. hardening gaps that affect an RCE's blast radius"
hr
echo "  (exec-family disabled = attacker still gets code exec, but not a shell)"
# Read the ini files on disk rather than exec'ing a handler: php-fpm refuses
# -r, and per-handler ini paths are the only place the real values live.
# PHP_INI_GLOBS overrides the search path for non-standard layouts
# (and makes the script testable off-box).
INI_GLOB=${PHP_INI_GLOBS:-/opt/plesk/php/*/etc/php.ini /etc/php/*/fpm/php.ini /etc/php.ini}
shopt -s nullglob
INI_FILES=( $INI_GLOB )
shopt -u nullglob
if [[ ${#INI_FILES[@]} -eq 0 ]]; then
  echo "  no php.ini found in the usual Plesk/OS locations"
else
  for ini in "${INI_FILES[@]}"; do
    echo "  $ini"
    for key in disable_functions allow_url_include expose_php open_basedir; do
      val=$(grep -E "^[[:space:]]*${key}[[:space:]]*=" "$ini" 2>/dev/null \
            | tail -1 | cut -d= -f2- | sed 's/^[[:space:]]*//')
      [[ -z "$val" ]] && val="(not set)"
      case "$key" in
        disable_functions)
          if [[ "$val" == "(not set)" || -z "$val" ]]; then
            mark="  <== nothing disabled: easy shell stage"
          else
            mark=""
          fi ;;
        allow_url_include) [[ "$val" == "(not set)" ]] && val="Off (default)" ; mark="" ;;
        *) mark="" ;;
      esac
      printf '    %-20s %s%s\n' "$key" "${val:0:90}" "$mark"
    done
  done
fi
# Per-domain overrides win over the file, and are where Plesk actually stores
# the "Additional configuration directives" box.
OVR=$("$PLESK" db -Ne \
  "SELECT d.name, s.value FROM domains d \
   JOIN hosting h ON h.dom_id=d.id \
   JOIN php_settings s ON s.hosting_id=h.id \
   WHERE s.value LIKE '%disable_functions%' LIMIT 20;" 2>/dev/null)
if [[ -n "$OVR" ]]; then
  echo "  per-domain disable_functions overrides found:"
  printf '%s\n' "$OVR" | sed 's/^/    /'
fi

hr
echo "4. WordPress instances (WP Toolkit)"
hr
if have wp-toolkit; then
  wp-toolkit --list 2>/dev/null | sed 's/^/  /' | head -40
  echo
  echo "  per-site hardening state:"
  echo "    wp-toolkit --security-status      (if supported on your build)"
else
  echo "  wp-toolkit CLI not installed - check the WP Toolkit extension in the UI"
fi

hr
echo "5. what to do with this"
hr
cat <<'EOF'
  * Any domain on 5.x / 7.x / 8.0 / 8.1: there is no patch coming for it.
    Upgrade the handler, or disable the domain until it can be upgraded.
  * Handlers on 8.2-8.5: patch at 2026-10-21 14:00 UTC, then restart that
    handler's FPM service (systemctl restart plesk-phpXX-fpm) or Apache.
  * Re-run this script after patching. Every version should move.
EOF