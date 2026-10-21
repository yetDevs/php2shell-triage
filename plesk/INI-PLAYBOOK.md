# php.ini and PECL: what config can and cannot do here

## The direct answer

**No php.ini directive fixes CVE-2026-109618 or -109619.** Neither does
disabling a PECL extension *by itself*.

The reason is mechanical, not political: php.ini configures a PHP *process*. It
cannot alter compiled C code in the binary, and it cannot remove a code path
that lives in the Zend engine or in `ext/standard`. There is no
`php2shell_mitigation=1`. Anyone selling you an ini snippet as a fix is
guessing — and so would I be, because nobody knows which subsystem the bug is
in yet.

What ini *can* do, and it is worth real effort:

1. **Remove entire compiled code paths** — a disabled extension is not mapped
   into the process. If the flaw is in an optional extension, disabling it is
   an actual fix, not a mitigation.
2. **Break the exploit's follow-on stages** — the shell/webshell step.
3. **Contain the blast radius** if code execution happens anyway.

That is the honest framing. Now the useful part.

---

## Apply today: six settings, ranked by real effect

Per domain: **Plesk → Domains → <domain> → PHP Settings → Additional configuration directives**.
Server-wide: `/opt/plesk/php/<ver>/etc/php.ini`.

```ini
; 1. Real: removes the ability to load arbitrary shared objects at runtime.
enable_dl = Off

; 2. Real, and widely forgotten: FFI lets PHP call arbitrary native functions
;    from a string. Almost nothing legitimate uses it on a web host.
ffi.enable = Off

; 3. Real: kills the "upload progress" session-file trick used to get code into
;    a predictable path, a standard LFI-to-RCE helper.
session.upload_progress.enabled = Off

; 4. Real: blunts the phar:// metadata deserialization family.
phar.readonly = On
phar.require_hash = On

; 5. Real: removes the cheap shell stage (attacker still gets code execution).
disable_functions = exec,passthru,shell_exec,system,proc_open,popen,pcntl_exec,pcntl_fork

; 6. Real containment: after a successful RCE this is what stops a webshell
;    reading /etc/shadow or another subscription's files. Plesk FPM sets it
;    per domain already - verify it, don't assume.
open_basedir = /var/www/vhosts/example.com/:/tmp/
```

Also reasonable, lower value:

```ini
allow_url_include = Off      ; default off since 5.2, but some vendor builds flip it
expose_php = Off             ; cosmetic only - hides your version, does not help
zend.assertions = -1         ; production default; ensures assert() cannot eval strings
session.serialize_handler = php_serialize   ; blunts session-based gadget chains
```

**Do not** set `allow_url_fopen = Off` on a WordPress host — the WP HTTP API,
plugin updates and most payment gateways need it. The upside is small and the
breakage is immediate.

**These take effect only after the pool restarts:**

```bash
sudo systemctl restart plesk-php84-fpm     # per handler you changed
```

---

## PECL: yes, this is worth doing — with one big caveat

**Caveat first:** reports say "PHP core", which — if accurate — means disabling
extensions changes nothing about exploitability. So treat this as
attack-surface hygiene that *might* turn out to be the actual fix, not as
protection.

**Why it's still worth the hour:** a loaded extension is extra C code parsed by
the same process that handles attacker input. PECL extensions are written by
third parties, maintained unevenly, and have a long history of memory-safety
and deserialization bugs of their own. An extension nothing uses is pure
liability.

Enumerate what you actually load:

```bash
sudo ./audit-extensions.sh
```

It walks every handler on the box (`/opt/plesk/php/*/bin/php`), runs `php -m`,
and separates stock bundled extensions from non-bundled ones — flagging the
ones with a history worth caring about (`imagick`, `igbinary`, `msgpack`,
`redis`, `mongodb`, `ssh2`, `xdebug`, `uopz`).

Disable one (reversible):

```bash
# 1. find the ini line
grep -rn "extension=.*\(igbinary\|imagick\|redis\)" /opt/plesk/php/*/etc/php.d/

# 2. comment it out, then restart that handler's pool
sudo sed -i 's/^extension=igbinary.so/;extension=igbinary.so/' /opt/plesk/php/8.4/etc/php.d/40-igbinary.ini
sudo systemctl restart plesk-php84-fpm

# 3. verify it is gone from the process, not just the file
/opt/plesk/php/8.4/bin/php -m | grep -i igbinary   # expect no output
```

**Never disable** on a WordPress host: `gd` or `imagick` (thumbnails),
`curl` (updates, payments), `mbstring`, `json`, `zip`, `simplexml`/`dom` (feeds,
XML-RPC, sitemaps), `openssl`, `mysqli`/`pdo_mysql`. Verify with `php -m` after
every change and load the site before moving on.

`xdebug` and `uopz` in production are indefensible regardless of this CVE —
remove them today.

---

## After 14:00 UTC: map the root cause to a config action

This is the part worth having ready. The advisory will name the subsystem. Find
the row that matches — **only that row applies**, everything else is noise.

| Advisory says the flaw is in... | Config action that genuinely helps |
|---|---|
| An optional/PECL extension (redis, imagick, igbinary, soap, …) | Disable that extension. **Real fix** for that path. |
| A bundled extension (`exif`, `gd`, `xml`, `curl`, `intl`, `zip`, `fileinfo`) | Disable it if unused — real; otherwise patch only. |
| `phar` metadata handling | `phar.readonly=On` + `phar.require_hash=On` — real. |
| `assert()` string evaluation | `zend.assertions=-1` — real. |
| `dl()` / dynamic loading | `enable_dl=Off` — real. |
| FFI | `ffi.enable=Off` — real. |
| `mail()` / sendmail argument injection | `disable_functions=mail` if unused — real. |
| `SoapClient` / SOAP deserialization | remove `soap` ext, or `disable_classes=SoapClient`. |
| Sessions | `session.serialize_handler=php_serialize`, `session.use_strict_mode=1`. |
| Upload/multipart parsing | **nothing.** Patch. WAF upload rules only. |
| `unserialize()` internals | **nothing reliable.** WP and sessions both need it; disabling breaks everything. Weak mitigations only: phar settings above, WAF signature. |
| Zend engine, opcache/JIT, core functions (`parse_url`, `filter_var`, `http_build_query`, string/array internals) | **nothing.** Config cannot reach it. Patch, or remove PHP from the internet. |

Say the last row out loud to whoever signs off on risk: for core-engine flaws
the *only* controls are patching speed and network isolation. Every ini tweak
in this document is blast-radius reduction, not prevention.

---

## Waste of time (so you don't burn the remaining hours)

- Inventing an ini snippet that "disables the vulnerable function" — the
  function is not public yet.
- `expose_php=Off` as a mitigation. Hygiene, not defence.
- Disabling `allow_url_fopen` on WordPress hosts. Breaks updates, buys nothing.
- Turning off `file_uploads`. Media uploads stop working; nobody gains.
- Disabling `unserialize`-adjacent functions. No ini directive removes the
  language feature, and both WordPress and PHP sessions depend on it.
- Any ini change without restarting the FPM pool. You will believe you applied
  it and you will not have.
