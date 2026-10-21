# Plesk + WordPress: what to do before 14:00 UTC

Status at time of writing: **no patch exists yet**, no root cause published.
Everything below is either (a) permanent risk reduction, or (b) prep so you can
patch in minutes instead of hours. Nothing here "fixes" an unknown RCE — be
suspicious of anyone who says it does.

Priority order, highest leverage first.

---

## 1. Get domains off end-of-life handlers (permanent, one-time)

On Plesk this is the finding that actually changes your outcome. PHP 5.x, 7.x,
8.0 and 8.1 will **never** receive a fix for these CVEs. A domain on 7.4 is
permanently exposed no matter how fast you patch on the 21st.

```bash
sudo ./audit-plesk-php.sh        # section 2 lists every EOL domain
```

Then, per domain: **Plesk UI → Domains → <domain> → PHP Settings → PHP version**,
pick the newest supported handler (8.4/8.5). CLI equivalents differ between
Plesk versions — verify before scripting:

```bash
plesk bin site --help | grep -i php        # find the supported flag
```

Do this on a staging copy first if the site is old; 5.6→8.4 breaks things. If a
site genuinely cannot move, the honest options are: put it behind auth
(`Plesk → domain → Apache & nginx Settings → additional directives`, basic auth
for the whole vhost), or take it off the internet. Do not leave it publicly
reachable on 7.4 and hope.

## 2. Disable the exec family (blunts the shell stage)

This does **not** stop code execution — nothing available today does. It stops
the near-universal next step: RCE → `system("curl ... | sh")` → interactive
shell. Against an unknown RCE that is the single best cost-raiser you can apply
in ten minutes.

**Plesk UI → Domains → <domain> → PHP Settings → Additional configuration directives:**

```ini
disable_functions = exec,passthru,shell_exec,system,proc_open,popen,pcntl_exec,pcntl_fork
allow_url_include = Off
expose_php = Off
```

Server-wide equivalent: **Tools & Settings → PHP Settings**, or edit
`/opt/plesk/php/<ver>/etc/php.ini`.

**Test before you widen it.** WooCommerce PDF generation, some backup plugins,
image optimisers, and `imagick`-based thumbnailers legitimately call `exec`.
Watch `/var/www/vhosts/<domain>/logs/error_log` for
`has been disabled for security reasons` and whitelist only what breaks:

```ini
disable_functions = exec,passthru,...,pcntl_fork
; no per-function whitelist exists - if a plugin needs one, drop that one
; function for that domain only, not server-wide
```

Apply per-domain, not globally, on day one.

## 3. Keep WordPress from being the easy surface

WordPress is not the vulnerable component here — PHP core is. WP hardening
reduces follow-on damage (webshell persistence, plugin chains), not the initial
RCE. Do it anyway; it's cheap.

**WP Toolkit** (Plesk extension, already installed on most servers):

- Enable **auto-updates** for core (minor/security) and for plugins you trust
- Turn on **Smart Updates** so a bad plugin update auto-rolls back rather than
  taking the site down during your patch window
- Run its **security scan** across all instances — it flags outdated core,
  abandoned plugins, and weak admin passwords in one view

CLI: `wp-toolkit --list`, then `wp-toolkit --smart-update <id>` (check
`wp-toolkit --help` for your build's flags).

**`wp-config.php` additions** (safe, reversible):

```php
define('DISALLOW_FILE_EDIT', true);        // no plugin/theme editor = no PHP editor webshell
define('FORCE_SSL_ADMIN', true);
define('AUTOMATIC_UPDATER_DISABLED', false);
```

Do **not** set `DISALLOW_FILE_MODS` during a patch window — it blocks WP's own
updates.

**Block PHP execution in uploads.** Most WordPress compromises end with a
dropped `.php` in `wp-content/uploads`. This kills that stage regardless of how
the attacker got in.

nginx (Plesk: *Additional nginx directives*):

```nginx
location ~* ^/wp-content/uploads/.*\.(php|phtml|php[0-9]|phar)$ { deny all; }
location ~* ^/wp-content/cache/.*\.(php|phtml|phar)$          { deny all; }
```

Apache (Plesk: *Additional Apache directives*):

```apache
<Directory /var/www/vhosts/example.com/httpdocs/wp-content/uploads>
    <FilesMatch "\.(php|phtml|php[0-9]|phar)$">
        Require all denied
    </FilesMatch>
</Directory>
```

Plesk runs nginx in front by default — if nginx serves static files directly,
the Apache rule alone can be bypassed, so add both.

Also worth doing: rate-limit `wp-login.php`, block XML-RPC if unused, and put
`/wp-admin` behind an IP allowlist if your editors have stable addresses.

## 4. Virtual patching — set expectations honestly

Plesk Obsidian has **Tools & Settings → Web Application Firewall (ModSecurity)**
with an OWASP CRS mode, and per-domain toggles.

Turn it on for the WordPress hosts. But understand what it can and cannot do:
**there is no signature for this CVE yet, and no signature can exist before the
root cause is published.** Generic OWASP rules catch generic RCE patterns
(command injection in parameters, PHP object injection, LFI) — useful for the
attacker's follow-on requests, not for the initial exploit.

If you run Cloudflare in front, the practical value today is the **kill switch**:
you can block all POSTs to a host in about 30 seconds once you see something.
Set that up now so it's a click, not a research project, at 3am.

Revisit this at 14:00 UTC: once technical details drop, write the specific
request signature and deploy it to hosts you cannot patch immediately.

## 5. Detection before patch (do this now)

Exploitation attempts concentrate in the leak-to-patch window — that is *today*.

```bash
sudo ./php-child-proc.sh --watch 10          # from ../detect/
```

On Plesk, PHP workers run as `php-fpm` under per-subscription pool users, so
the parent matches. Watch for any `sh`/`bash`/`curl`/`python` child of
`php-fpm`, and for `/dev/tcp/`, `mkfifo`, `fsockopen` in command lines.

Plesk logs worth tailing during the window:

- `/var/www/vhosts/<domain>/logs/error_log` and `access_log`
- `/var/log/plesk/panel.log`
- `/var/log/httpd/` or `/var/log/apache2/` (depending on the OS)

Start log retention now — if a host is hit today, the access log from the leak
window is your only evidence.

## 6. Be ready to patch in minutes (14:00 UTC)

Pre-stage these, because the difference between a 10-minute and a 4-hour patch
window is knowing which of your PHP builds come from where.

**Snapshot first.** Plesk → Backup Manager, full server snapshot. Rollback
needs to be one click when you're patching at speed.

**Know your packaging.** Two cases on Plesk:

| Handler source | Update path |
|---|---|
| Plesk-shipped PHP (`/opt/plesk/php/*`) | Plesk Installer / *Tools & Settings → Updates* — Plesk rebuilds its own PHP, usually within hours of upstream |
| OS vendor or Remi/ondrej (`/usr/bin/php*`, `/etc/php/*`) | `dnf update 'php*'` or `apt update && apt install --only-upgrade 'php*'` |

The Plesk-shipped builds are the slow lane: if Plesk's rebuild lags upstream,
you have a gap. Mitigation is to have at least one OS-vendor handler installed
and tested so you can switch a domain to a patched build rather than waiting.

**After updating, restart the right service** — installing a package does not
reload a running FPM pool:

```bash
systemctl list-units 'plesk-php*-fpm' --no-legend   # which pools exist
sudo systemctl restart plesk-php84-fpm              # per handler you updated
sudo plesk bin php_handler --reread                 # re-register handlers
```

**Verify, don't assume** — the version in the package and the version being
served can differ:

```bash
plesk bin php_handler --list
python3 ../../php_triage.py local --root /var/www/vhosts | tee post-patch.txt
```

Every domain should read `CURRENT`. Anything still `BEHIND` is a pool you did
not restart; anything `EOL` is a migration you have not finished.

---

## What does not help (so you don't waste the nine hours)

- **Changing passwords / rotating keys.** No indication of credential theft.
- **`expose_php=Off`.** Hides your version from scanners; does nothing to the
  flaw. Fine as hygiene, not as a mitigation.
- **Scanning for "php2shell" PoCs and running them.** Repos with that name are
  stealing credentials right now. There is nothing to test against.
- **WAF-only.** Cannot virtual-patch a vector nobody has described yet.
- **Blocking `wp-login.php` and calling it done.** Reduces one attack path among
  many; the RCE is in PHP itself, reachable however your app uses it.