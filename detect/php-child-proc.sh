#!/usr/bin/env bash
# php-child-proc.sh - alert when a PHP worker spawns a child process.
#
# Rationale: a PHP-core RCE (CVE-2026-109618 / CVE-2026-109619) needs the
# interpreter to execute something. Normal PHP request handling never forks a
# shell, curl, or python. A php-fpm/php-cgi/apache worker with a shell child is
# the single highest-signal indicator available before patches land.
#
# This is intentionally dependency-free (procfs only) so it runs on hosts where
# you cannot install an EDR. For fleet-wide coverage, deploy the Sigma rule in
# this directory to your SIEM instead.
#
#   sudo ./php-child-proc.sh                 # one pass, print findings
#   sudo ./php-child-proc.sh --watch 10      # poll every 10s, alert on new pids
#
# Exit: 0 = clean, 1 = findings. Intended for cron or a systemd timer.

set -uo pipefail

SUSPECT_RE='^(sh|bash|dash|zsh|ksh)$|^(curl|wget|nc|ncat|socat|telnet|rsync|scp|ssh)$|^(python[0-9.]*|perl|ruby|node)$|^(mkfifo|chmod|chown|base64|xxd)$'
PHP_RE='^(php-fpm[0-9.]*|php-cgi|php|httpd|apache2|nginx)$'

WATCH=0; INTERVAL=10
if [[ "${1:-}" == "--watch" ]]; then WATCH=1; INTERVAL="${2:-10}"; fi

declare -A SEEN=()

proc_name() {  # pid -> basename of comm
  local c
  c=$(cat "/proc/$1/comm" 2>/dev/null) || return 1
  printf '%s' "$c"
}

ppid_of() { awk '{print $4}' "/proc/$1/stat" 2>/dev/null; }

cmdline_of() {
  tr '\0' ' ' < "/proc/$1/cmdline" 2>/dev/null | sed 's/ *$//'
}

scan_once() {
  local found=0 pid name ppid pname cmd
  for d in /proc/[0-9]*; do
    pid=${d#/proc/}
    name=$(proc_name "$pid") || continue
    [[ "$name" =~ $SUSPECT_RE ]] || continue
    ppid=$(ppid_of "$pid")
    [[ -n "${ppid:-}" && "$ppid" != "0" ]] || continue
    pname=$(proc_name "$ppid") || continue
    [[ "$pname" =~ $PHP_RE ]] || continue

    [[ -n "${SEEN[$pid]:-}" ]] && continue
    SEEN[$pid]=1
    cmd=$(cmdline_of "$pid")
    printf '[ALERT] php2shell-suspect: %s (pid %s) spawned %s (pid %s): %s\n' \
      "$pname" "$ppid" "$name" "$pid" "${cmd:-<no cmdline>}"
    # reverse-shell / staging tells from the Huntress writeup
    case "$cmd" in
      */dev/tcp/*|*mkfifo*|*fsockopen*) printf '        !! reverse-shell pattern in cmdline\n' ;;
    esac
    [[ "$name" == "sh" || "$name" == "bash" ]] && \
      printf '        !! shell child - verify no web request triggered this\n'
    # ancestry, useful when triaging
    local gp; gp=$(ppid_of "$ppid")
    [[ -n "${gp:-}" ]] && printf '        ancestry: %s(%s) <- %s(%s) <- %s(%s)\n' \
      "$pname" "$ppid" "$(proc_name "$gp")" "$gp" "$(proc_name "$(ppid_of "$gp")")" "$(ppid_of "$gp")"
    found=1
  done
  return $(( found ? 1 : 0 ))
}

if [[ $WATCH -eq 0 ]]; then
  scan_once; exit $?
fi

printf 'watching for PHP children every %ss (ctrl-c to stop)\n' "$INTERVAL" >&2
rc=0
while :; do
  scan_once || rc=1
  sleep "$INTERVAL"
done
