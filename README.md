# php2shell triage — PHP estate inventory for CVE-2026-109618 / CVE-2026-109619

Built 2026-10-21, ~10 hours before the PHP security release.

## Read this first: there is no PoC to write

You asked to POC this. As of **2026-10-21 02:40 UTC** that is not possible, and
anything claiming otherwise is fake:

| Fact | Status |
|---|---|
| CVE-2026-109618 / -109619 in cve.org | **RESERVED**, no description |
| Root cause (which PHP function/subsystem) | not published |
| Affected version ranges | not published ("PHP 5 through 8" is journalist/researcher speculation, not vendor fact) |
| Fixed versions | not published |
| PHP's own advisory | advance notice only; "full details, affected versions, and fixed versions will be published with the release" |
| Security release | **2026-10-21 14:00 UTC** (10:00 ET) |
| Public exploit code | none; Huntress explicitly says it has not built or seen one |

A PoC needs a root cause and a vulnerable code path. Neither exists publicly
yet. Anything on GitHub right now named `php2shell-poc` is either a
placeholder betting on the advisory wording or a credential stealer aimed at
people panicking — this is the standard pattern in the 24h before a
high-profile patch, and it is worth telling your team explicitly.

So this toolkit does the part that *is* actionable today and stays useful
after the patches drop: **find every PHP on your estate, classify it, and
detect exploitation attempts while you wait.**

## What's here

| File | Purpose |
|---|---|
| `php_triage.py` | inventory + fingerprint + post-patch re-check (stdlib only) |
| `plesk/audit-plesk-php.sh` | read-only Plesk audit: handlers, domain→version map, EOL domains, hardening gaps |
| `plesk/audit-extensions.sh` | which extensions each handler actually loads; flags non-bundled ones safe to drop |
| `plesk/HARDENING.md` | Plesk + WordPress pre-patch runbook |
| `plesk/INI-PLAYBOOK.md` | what php.ini can and cannot do here; post-advisory root-cause→config table |
| `detect/php-child-proc.sh` | procfs watcher: alerts when a PHP worker spawns a shell/curl/python (Linux, no deps) |
| `detect/sigma-php-child-shell.yml` | same logic as a SIEM rule (Sigma → Splunk/Elastic/Sentinel) |
| `tests/fake_php_host.py` | local mock PHP host used to test the HTTP logic |
| `tests/test_local.py` | offline test for local discovery/classification |
| `tests/stub-plesk` | fake `plesk` CLI used to test the audit script off-box |

## Scope

Defensive tooling only. This repository contains **no exploit code** — not as a
matter of policy, but because none can exist yet: both CVEs are still reserved
with no published root cause. Every check here is either a local version read
or a plain HTTP GET.

Nothing here is a substitute for patching. The inventory tells you what to
patch and in what order; the detectors tell you if someone tries before you get
there.

## The classification rule

Every PHP build is scored against php.net's live release feed
(`releases/index.php?json`), not a hardcoded table:

- **EOL** — branch 5.x / 7.x / 8.0 / 8.1. These get **no patch at all** for
  these CVEs. This is the finding that matters most for your estate.
- **BEHIND** — supported branch, but behind that branch's latest security
  release (e.g. 8.2.33 vs 8.2.34).
- **CURRENT** — on the latest release of its branch *today*. Re-run after
  14:00 UTC: "current" then means 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 or
  whatever ships, and everything below it flips to BEHIND automatically.
- **PREVIEW** — branch ahead of the support matrix (e.g. an 8.6 RC box).

## Usage

### On each server (best signal — reads the actual binaries)

```bash
python3 php_triage.py local --root /var/www --root /opt --json inv-$(hostname).json
```

Walks PATH, standard install layouts, and any `--root` you give it; runs
`php -v`; tags vendor bundles (XAMPP/WAMP/Laragon/Plesk/cPanel); spots app
roots for WordPress, Drupal, Joomla, Magento, Laravel, Symfony, Composer.

No PHP on this Windows box, so local mode was validated against a mock tree
(`tests/test_local.py`, all checks pass) — run it for real on your web hosts.

### From here, over HTTP

```bash
printf 'https://app1.example.com\nhttps://shop.example.com\n' > targets.txt
python3 php_triage.py remote targets.txt --authorized --aggressive --json inv.json
```

`--authorized` is mandatory and is not ceremony: this sends GET requests.
Only point it at systems you own or have written permission to test.

What it reads, in increasing intrusiveness:

- `X-Powered-By` / `Server` headers for `PHP/x.y.z`
- `Set-Cookie: PHPSESSID` — a PHP app answered
- PHP's logo easter-egg query string — 200 + `image/*` proves a PHP handler
- `--aggressive` adds: exposed `phpinfo()` (also a version source), publicly
  readable `composer.json` / `composer.lock`, and `/wp-login.php`'s
  `wordpress_test_cookie` (a PHP signal that survives header scrubbing)

Multi-version hosts (cPanel multi-PHP, FPM + a bundled CLI) are reported as
**every version seen, each assessed separately**, worst one first. A host
running 7.4 and 8.4 is not "an 8.4 host".

### After patching

```bash
python3 php_triage.py watch inv-prod.json
```

Re-fetches php.net and re-scores the saved inventory. This is your
verification step: run it after the patch window and expect zero EOL/BEHIND.

## Patch-day runbook

1. **Now** — `local` on every web host, `remote` against every externally
   reachable site. Save the JSON. Put the EOL list at the top of your queue.
2. **Now** — deploy `detect/php-child-proc.sh` (or the Sigma rule) on
   internet-facing PHP hosts. Exploitation attempts are more likely in the
   next 12 hours than after everyone patches.
3. **14:00 UTC** — read the advisory, get the real affected/fixed version
   list. If it names a version range my EOL/PREVIEW buckets don't cover,
   the `assess()` thresholds are the one place to change.
4. **Patch** internet-facing first, then internal, then vendor bundles (those
   need the vendor's build, not yours — that's the slow lane, start it early).
5. **EOL boxes** — upgrade, or pull them off the internet. There is no patch
   coming for 5.x/7.x/8.0/8.1. This is the part people skip and it is the
   part that will be exploited.
6. **Verify** — `watch` against the saved inventory.
7. **Post-patch** — once technical details are public, add the specific
   request signature to your WAF and re-hunt logs from the leak window
   (2026-10-20 onward) for the child-process pattern.

## Honest limitations

- **No passive HTTP check proves PHP is absent.** php.net itself returns no
  `X-Powered-By` and no logo easter egg. A CDN, WAF, or `expose_php=Off`
  strips all of it. Absence of a marker = "check the host directly", not
  "not PHP".
- **No check proves a host is vulnerable.** Vulnerability depends on the
  still-unpublished root cause. Everything here is exposure inventory.
- Version detection over HTTP depends on the operator leaking it; the
  authoritative answer is `php -v` on the box (`local` mode).
- `detect/php-child-proc.sh` is Linux-only and poll-based — it can miss a
  process that lives less than one interval. Use `--watch 5` on busy hosts,
  and prefer the Sigma rule on the SIEM for real coverage. Bash syntax is
  checked; it has not been run against a live Linux fleet from here.
- The Sigma rule needs a week of baselining on hosts running shell-out
  plugins (backups, image optimisers, mailers) or it will be noisy.

## Sources

- PHP advisory: https://www.php.net/archive/2026.php (2026-10-20 entry)
- Huntress: https://www.huntress.com/blog/php2shell-leaked-critical-php-vulnerabilities
- CVE record (still reserved): https://www.cve.org/CVERecord?id=CVE-2026-109618
- CERT-EU advisory 2026-018
