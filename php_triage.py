#!/usr/bin/env python3
"""
php_triage.py - PHP estate inventory & pre-patch exposure check.

Context: CVE-2026-109618 / CVE-2026-109619 ("php2shell"), two PHP-core RCEs.
As of 2026-10-21 02:00 UTC these are still RESERVED CVE IDs: no root cause,
no affected-version list, no fixed versions, no public PoC. PHP's security
release is scheduled for 2026-10-21 14:00 UTC.

So this tool does not "exploit" anything. It answers the only question you
can answer today, and keeps answering it after patch day:

  * where is PHP on my estate, and what version / branch is each copy?
  * which copies are end-of-life (will get NO patch at all)?
  * which are behind the latest security release of their own branch?
  * which are exposing version info / phpinfo to the internet?

Modes
  local   - discover PHP binaries + web app roots on this host
  remote  - passive HTTP fingerprinting of a list of URLs (GET only)
  watch   - re-check a saved inventory against php.net's current releases

Usage
  python3 php_triage.py local  [--root DIR]... [--json out.json]
  python3 php_triage.py remote targets.txt --authorized [--json out.json]
  python3 php_triage.py watch  inventory.json

`targets.txt` is one URL or host per line. `--authorized` is required for
remote mode: only point this at systems you own or have written permission
to test. It sends nothing but ordinary GET requests.
"""

import argparse
import concurrent.futures as futures
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.request

RELEASES_URL = "https://www.php.net/releases/index.php?json"

# PHP branches that are EOL and will never get a fix for these CVEs.
EOL_BRANCHES = {"4", "5", "6", "7", "8.0", "8.1"}

# Passive PHP fingerprints. The first two are PHP's own "easter egg" query
# strings: a PHP handler answers them with a logo GIF / credits page, which
# is a reliable, non-intrusive way to confirm PHP is in front of a URL.
EGG_LOGO = "?=PHPE9568F36-D428-11d2-A769-00AA001ACF42"
EGG_CREDITS = "?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000"

PHPINFO_PATHS = ["phpinfo.php", "info.php", "i.php", "test.php", "php_info.php"]
LEAK_PATHS = ["composer.json", "composer.lock"]

UA = "php-triage/1.0 (self-assessment; owner-authorized)"


# ---------------------------------------------------------------- helpers

def _ssl_ctx(insecure=False):
    """TLS context: prefer certifi's CA bundle, since python.org builds on
    Windows often ship a stale/absent default cafile."""
    if not insecure:
        return None
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _verified_ctx():
    import ssl
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        return None


def http_get(url, timeout=10, insecure=False, max_bytes=400_000):
    """Plain GET. Returns (status, headers_dict, body_bytes) or raises."""
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    ctx = _ssl_ctx(insecure) if url.startswith("https") else None
    if ctx is None and url.startswith("https"):
        ctx = _verified_ctx()
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
        body = r.read(max_bytes)
        return r.status, dict(r.headers), body


def norm_ver(v):
    """'8.4.26' -> (8,4,26). Tolerates '8', '8.2', '8.4.26-1ubuntu2', '7.4.33-0+deb'."""
    m = re.match(r"\s*(\d+)(?:\.(\d+))?(?:\.(\d+))?", v or "")
    if not m:
        return None
    return tuple(int(x) if x else 0 for x in m.groups())


def branch_of(v):
    t = norm_ver(v)
    if not t:
        return None
    if t[0] >= 8:
        return f"{t[0]}.{t[1]}"
    return str(t[0])


def fetch_releases(timeout=15):
    """
    Latest release per branch + list of currently supported branches.

    php.net's json endpoint returns only the newest major (key "8"), which
    carries the supported_versions array. Asking it again with
    &version=<branch> returns that branch's newest release. So: one call for
    the support matrix, then one per supported branch.
    """
    try:
        _, _, body = http_get(RELEASES_URL, timeout=timeout)
        root = json.loads(body)
        supported = []
        for info in root.values():
            if isinstance(info, dict):
                for b in info.get("supported_versions") or []:
                    if re.fullmatch(r"\d+\.\d+", str(b)) and str(b) not in supported:
                        supported.append(str(b))
        if not supported:
            raise RuntimeError("no supported_versions in release feed")

        latest = {}
        for br in sorted(supported):
            _, _, b2 = http_get(RELEASES_URL + "&version=" + br, timeout=timeout)
            info = json.loads(b2)
            if isinstance(info, dict) and info.get("version"):
                latest[br] = info["version"]
        if not latest:
            raise RuntimeError("empty per-branch release data")
        return {"latest": latest, "supported": sorted(supported), "stale": False}

    except Exception as e:  # offline / rate-limited: degrade, don't crash
        print(f"  ! could not reach php.net releases ({e}); "
              f"using built-in 2026-09 snapshot", file=sys.stderr)
        return {"latest": {"8.2": "8.2.34", "8.3": "8.3.35",
                           "8.4": "8.4.26", "8.5": "8.5.11"},
                "supported": ["8.2", "8.3", "8.4", "8.5"], "stale": True}


def assess(version, rel):
    """Classify one PHP version string against the release data."""
    t = norm_ver(version)
    if not t:
        return {"status": "unknown", "detail": "version not parsed"}
    br = branch_of(version)
    max_supported = max(rel["supported"], key=lambda b: norm_ver(b))
    if br not in rel["supported"] and norm_ver(br) > norm_ver(max_supported):
        return {"status": "PREVIEW",
                "detail": f"branch {br} is ahead of the support matrix "
                          f"(pre-release) - no stable patch stream yet"}
    if br in EOL_BRANCHES or br not in rel["supported"]:
        return {"status": "EOL",
                "detail": f"branch {br} is end-of-life - no vendor patch expected"}
    latest = rel["latest"].get(br)
    if not latest:
        return {"status": "unknown", "detail": f"no release data for {br}"}
    if t < norm_ver(latest):
        return {"status": "BEHIND",
                "detail": f"{version} < {latest} (latest security release on {br})"}
    return {"status": "CURRENT", "detail": f"{version} is the latest on {br}"}


# ------------------------------------------------------------ local mode

BIN_NAMES = ["php", "php-cgi", "php-fpm", "php.exe", "php-cgi.exe", "phpdbg"]
VENDOR_MARKERS = ["xampp", "wamp", "laragon", "plesk", "cpanel",
                  "easyphp", "uniformserver", "bitnami"]
APP_MARKERS = {
    "wordpress": "wp-config.php",
    "drupal": "sites/default/settings.php",
    "joomla": "configuration.php",
    "magento": "app/etc/env.php",
    "composer": "composer.lock",
    "laravel": "artisan",
    "symfony": "bin/console",
}


def probe_binary(path):
    """Ask a php binary for its version. Returns (version, sapi, extra)."""
    out = ""
    try:
        p = subprocess.run([path, "-v"], capture_output=True, text=True, timeout=15)
        out = (p.stdout or "") + (p.stderr or "")
    except Exception:
        try:  # php-cgi needs -v too but some builds are picky
            p = subprocess.run([path, "-i"], capture_output=True, text=True, timeout=15)
            out = (p.stdout or "") + (p.stderr or "")
        except Exception as e:
            return None, None, f"unexecutable: {e}"
    m = re.search(r"PHP\s+(\d+\.\d+\.\d+[^\s(]*)", out)
    if not m:
        return None, None, "no version string in output"
    ver = m.group(1)
    sapi = None
    s = re.search(r"Server API => (\S+)|\(cli\)|\(cgi-fcgi\)|\(fpm-fcgi\)", out)
    if s:
        sapi = s.group(0).strip("() ")
    return ver, sapi, "ok"


def scan_local(roots, max_depth=4):
    found = []

    # 1. anything answering to a php name on PATH
    for name in BIN_NAMES:
        hit = shutil.which(name)
        if hit:
            found.append({"path": hit, "how": "PATH"})

    # 2. known install layouts + shallow walk of the roots you gave me
    candidates = []
    if platform.system() == "Windows":
        for drive in "CDEF":
            for d in (f"{drive}:/xampp/php", f"{drive}:/wamp64/bin/php",
                      f"{drive}:/wamp/bin/php", f"{drive}:/laragon/bin/php",
                      f"{drive}:/Program Files/php"):
                candidates.append(d)
        candidates.append(os.path.expandvars(r"%ProgramFiles%\\PHP"))
    else:
        candidates += ["/usr/bin", "/usr/local/bin", "/usr/sbin",
                       "/opt/homebrew/bin", "/usr/local/opt"]
    for c in candidates:
        if not os.path.isdir(c):
            continue
        for name in BIN_NAMES:
            p = os.path.join(c, name)
            if os.path.isfile(p):
                found.append({"path": p, "how": "known-layout"})

    # 3. walk the roots for php binaries + app roots
    apps = []
    for root in roots or []:
        if not os.path.isdir(root):
            print(f"  ! skipping missing root: {root}", file=sys.stderr)
            continue
        base_depth = root.rstrip("/\\").count(os.sep)
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            if dirpath.count(os.sep) - base_depth >= max_depth:
                dirnames[:] = []
            dirnames[:] = [d for d in dirnames
                           if d not in {".git", "node_modules", "vendor", ".cache"}]
            for name in filenames:
                if name.lower() in BIN_NAMES:
                    found.append({"path": os.path.join(dirpath, name),
                                  "how": "filesystem-walk"})
            low = {f.lower() for f in filenames}
            for app, marker in APP_MARKERS.items():
                if marker.lower() in low:
                    apps.append({"app": app, "root": dirpath})

    # dedupe binaries by realpath
    seen, bins = set(), []
    for f in found:
        rp = os.path.realpath(f["path"])
        if rp in seen:
            continue
        seen.add(rp)
        ver, sapi, note = probe_binary(f["path"])
        vendor = next((v for v in VENDOR_MARKERS if v in rp.lower()), None)
        bins.append({**f, "realpath": rp, "version": ver, "sapi": sapi,
                     "note": note, "bundled_by": vendor})

    # dedupe on (app, root): one document root can legitimately carry several
    # markers (a WordPress site that also ships a composer.lock, for instance)
    uapps, keys = [], set()
    for a in apps:
        key = (a["app"], a["root"])
        if key in keys:
            continue
        keys.add(key)
        uapps.append(a)
    uapps.sort(key=lambda a: (a["root"], a["app"]))

    return {"binaries": bins, "apps": uapps, "releases": fetch_releases()}


# ----------------------------------------------------------- remote mode

def fingerprint(target, insecure=False, timeout=10, aggressive=False):
    """Passive GET-only fingerprint of one URL. Returns a result dict."""
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    base = target.rstrip("/")
    # A single host routinely runs several PHP builds at once (cPanel multi-PHP,
    # one SAPI per vhost, a bundled CLI next to a packaged FPM). Collect every
    # version we observe with its source instead of collapsing to the first.
    res = {"target": base, "php": False, "version": None, "observed": [],
           "evidence": [], "server": None, "x_powered_by": None,
           "risks": [], "errors": []}

    def note_version(v, source):
        if not v:
            return
        if any(o["version"] == v and o["source"] == source for o in res["observed"]):
            return
        res["observed"].append({"version": v, "source": source})
        if res["version"] is None:
            res["version"] = v

    try:
        status, headers, body = http_get(base, timeout=timeout, insecure=insecure)
    except urllib.error.HTTPError as e:
        headers = dict(e.headers or {})
        body = b""
        res["errors"].append(f"HTTP {e.code} on root")
    except Exception as e:
        res["errors"].append(f"unreachable: {type(e).__name__}: {e}")
        return res

    h = {k.lower(): v for k, v in headers.items()}
    res["server"] = h.get("server")
    res["x_powered_by"] = h.get("x-powered-by")

    # --- version from headers
    for field in ("x-powered-by", "server"):
        if h.get(field):
            m = re.search(r"PHP/(\d+\.\d+\.\d+[^\s;,]*)", h[field])
            if m:
                res["php"] = True
                note_version(m.group(1), f"{field} header")
                res["evidence"].append(f"{field}: PHP/{m.group(1)}")
                res["risks"].append(f"version disclosed in {field} header")

    # --- PHPSESSID cookie proves a PHP app is mounted
    if "phpsessid" in (h.get("set-cookie", "") or "").lower():
        res["php"] = True
        res["evidence"].append("Set-Cookie: PHPSESSID")

    # --- PHP easter-egg logo: 200 + image/* means a PHP handler answered
    try:
        st, hd, b = http_get(base + EGG_LOGO, timeout=timeout, insecure=insecure)
        ctype = {k.lower(): v for k, v in hd.items()}.get("content-type", "")
        if st == 200 and ctype.startswith("image/"):
            res["php"] = True
            res["evidence"].append("PHP logo easter-egg answered (handler confirmed)")
        elif st == 200 and b[:3] == b"GIF":
            res["php"] = True
            res["evidence"].append("PHP logo GIF returned")
    except Exception:
        pass

    # --- credits page: presence signal only.
    # Deliberately NOT a version source. Real-world pages (php.net included)
    # echo release announcements and changelogs in the same body, so a loose
    # "PHP x.y.z" scrape reports the newest *published* release as the
    # *running* one. A wrong version here is worse than no version.
    try:
        st, hd, b = http_get(base + EGG_CREDITS, timeout=timeout, insecure=insecure)
        if st == 200:
            text = b[:60000].decode("utf-8", "replace")
            if "PHP Credits" in text or "PHP Group" in text:
                res["php"] = True
                res["evidence"].append("PHP credits page served (handler confirmed)")
    except Exception:
        pass

    if aggressive:
        # exposed phpinfo = full config + exact version to any visitor
        for path in PHPINFO_PATHS:
            try:
                st, hd, b = http_get(f"{base}/{path}", timeout=timeout,
                                     insecure=insecure)
            except urllib.error.HTTPError:
                continue
            except Exception:
                continue
            text = b[:200000].decode("utf-8", "replace")
            if "phpinfo()" in text and "PHP Version" in text:
                m = re.search(r"PHP Version\s*</td><td[^>]*>\s*([\d.]+)", text) \
                    or re.search(r"PHP Version[^0-9]{0,40}([\d.]+)", text)
                res["php"] = True
                res["risks"].append(f"phpinfo() exposed at /{path}")
                if m:
                    note_version(m.group(1), f"phpinfo /{path}")
                    res["evidence"].append(f"phpinfo at /{path}: {m.group(1)}")
                break

        # WordPress sets wordpress_test_cookie from PHP on its login page:
        # a reliable PHP signal even when headers are scrubbed.
        try:
            st, hd, b = http_get(f"{base}/wp-login.php", timeout=timeout,
                                 insecure=insecure)
            hs = {k.lower(): v for k, v in hd.items()}
            if "wordpress_test_cookie" in (hs.get("set-cookie", "") or "").lower():
                res["php"] = True
                res["evidence"].append("WordPress login set wordpress_test_cookie "
                                       "(PHP confirmed)")
                m = re.search(r"PHP/(\d+\.\d+\.\d+)", hs.get("x-powered-by", ""))
                if m:
                    note_version(m.group(1), "wp-login.php header")
        except Exception:
            pass

        for path in LEAK_PATHS:
            try:
                st, hd, b = http_get(f"{base}/{path}", timeout=timeout,
                                     insecure=insecure)
                if st == 200 and b[:1] in (b"{", b"["):
                    res["risks"].append(f"/{path} publicly readable")
            except Exception:
                continue

    return res


SEVERITY = {"EOL": 4, "BEHIND": 3, "PREVIEW": 2, "unknown": 1, "CURRENT": 0}


def run_remote(targets, workers=8, insecure=False, aggressive=False):
    rel = fetch_releases()
    results = []

    def one(t):
        r = fingerprint(t, insecure=insecure, aggressive=aggressive)
        per = [{"version": o["version"], "source": o["source"],
                **assess(o["version"], rel)} for o in r["observed"]]
        r["assessments"] = per
        if per:
            worst = max(per, key=lambda a: SEVERITY[a["status"]])
            r["assessment"] = worst
            if len(per) > 1:
                r["assessment"] = {**worst,
                                   "detail": f"{len(per)} distinct PHP versions "
                                             f"seen; worst = {worst['detail']}"}
        else:
            r["assessment"] = {"status": "unknown",
                               "detail": "PHP confirmed but version not disclosed"
                                         if r["php"] else "no PHP marker seen"}
        return r

    with futures.ThreadPoolExecutor(max_workers=workers) as ex:
        for r in ex.map(one, targets):
            results.append(r)
    return {"results": results, "releases": rel}


# ------------------------------------------------------------- reporting

ICON = {"EOL": "!!", "BEHIND": "! ", "CURRENT": "ok", "unknown": "? "}


def report_local(data):
    rel = data["releases"]
    print(f"\nPHP inventory - {platform.node()} ({platform.system()} "
          f"{platform.release()})")
    print(f"reference: latest releases {json.dumps(rel['latest'])}"
          f"{'  [STALE SNAPSHOT - offline]' if rel['stale'] else ''}")
    print(f"supported branches: {', '.join(rel['supported'])}\n")

    if not data["binaries"]:
        print("  no PHP binaries found on PATH or known install layouts.")
    else:
        print(f"  {'STATUS':<9}{'VERSION':<12}{'SAPI':<12}PATH")
        print("  " + "-" * 78)
        for b in data["binaries"]:
            a = assess(b["version"], rel)
            tag = f"{ICON[a['status']]} {a['status']}"
            sapi = (b["sapi"] or "-")[:10]
            print(f"  {tag:<9}{(b['version'] or 'unknown'):<12}{sapi:<12}"
                  f"{b['realpath']}")
            if b["bundled_by"]:
                print(f"  {'':9}bundled by: {b['bundled_by']}")
            if b["note"] != "ok":
                print(f"  {'':9}note: {b['note']}")

    print(f"\n  web application roots found: {len(data['apps'])}")
    for a in data["apps"]:
        print(f"    {a['app']:<10} {a['root']}")

    eol = [b for b in data["binaries"] if assess(b["version"], rel)["status"] == "EOL"]
    if eol:
        print(f"\n  {len(eol)} end-of-life install(s) - these get NO patch "
              f"for CVE-2026-109618/619. Take them off the internet.")
    return 0


def report_remote(data):
    rel = data["releases"]
    rows = []
    print(f"\nremote fingerprint - {len(data['results'])} target(s)")
    print(f"reference: latest releases {json.dumps(rel['latest'])}"
          f"{'  [STALE SNAPSHOT - offline]' if rel['stale'] else ''}\n")
    for r in data["results"]:
        a = r["assessment"]
        print(f"  [{ICON[a['status']]}] {r['target']}")
        print(f"       php={r['php']}  version={r['version'] or 'undisclosed'}  "
              f"status={a['status']}  server={r['server']}")
        for a in r.get("assessments", []):
            print(f"       {ICON[a['status']]} {a['version']:<12} "
                  f"({a['source']}) -> {a['status']}: {a['detail']}")
        for e in r["evidence"]:
            print(f"       + {e}")
        for risk in r["risks"]:
            print(f"       * {risk}")
        for err in r["errors"]:
            print(f"       - {err}")
        print()
        rows.append((r["target"], r["version"], a["status"]))
    bad = [t for t, _, s in rows if s in ("EOL", "BEHIND")]
    unknown = [t for t, _, s in rows if s == "unknown"]
    if bad:
        print(f"  {len(bad)} target(s) need attention before/at patch time.")
    if unknown:
        print(f"  {len(unknown)} target(s) reported no PHP marker. That does NOT "
              f"prove PHP is absent:\n   a CDN, WAF, or webserver config commonly "
              f"strips X-Powered-By and the PHP eggs.\n   For those, check the "
              f"host directly (local mode on the box), not over HTTP.")
    return 0


def report_watch(path, rel=None):
    with open(path) as f:
        data = json.load(f)
    rel = rel or fetch_releases()
    print(f"\nwatch - re-checking {path} against php.net "
          f"(supported: {', '.join(rel['supported'])})")
    items = []
    for b in data.get("binaries", []):
        items.append((b.get("realpath") or b["path"], b.get("version")))
    for r in data.get("results", []):
        obs = r.get("observed") or []
        if obs:
            for o in obs:
                items.append((f"{r['target']} [{o['source']}]", o["version"]))
        else:
            items.append((r["target"], r.get("version")))
    if not items:
        print("  inventory has nothing to check")
        return 0
    change = 0
    for name, ver in items:
        a = assess(ver, rel)
        print(f"  [{ICON[a['status']]}] {name:<60} {ver or '?':<12} {a['detail']}")
        if a["status"] in ("EOL", "BEHIND"):
            change += 1
    print(f"\n  {change}/{len(items)} need patching.")
    return 0


# ------------------------------------------------------------------ cli

def main():
    ap = argparse.ArgumentParser(
        description="PHP estate inventory / php2shell pre-patch triage")
    sub = ap.add_subparsers(dest="mode", required=True)

    p1 = sub.add_parser("local", help="inventory PHP on this host")
    p1.add_argument("--root", action="append", default=[],
                    help="extra directory to walk (repeatable)")
    p1.add_argument("--json", help="save inventory to this file")

    p2 = sub.add_parser("remote", help="fingerprint URLs you own")
    p2.add_argument("targets", help="file with one URL/host per line")
    p2.add_argument("--authorized", action="store_true",
                    help="you own or have permission to test these targets")
    p2.add_argument("--aggressive", action="store_true",
                    help="also probe phpinfo/test.php/composer.json paths")
    p2.add_argument("--insecure", action="store_true", help="skip TLS verification")
    p2.add_argument("--workers", type=int, default=8)
    p2.add_argument("--json", help="save results to this file")

    p3 = sub.add_parser("watch", help="re-check a saved inventory")
    p3.add_argument("inventory")

    args = ap.parse_args()

    if args.mode == "local":
        data = scan_local(args.root)
        if args.json:
            with open(args.json, "w") as f:
                json.dump(data, f, indent=2)
            print(f"saved {args.json}")
        return report_local(data)

    if args.mode == "remote":
        if not args.authorized:
            print("remote mode requires --authorized: only scan systems you own "
                  "or have written permission to test.", file=sys.stderr)
            return 2
        with open(args.targets) as f:
            targets = [l.strip() for l in f
                       if l.strip() and not l.strip().startswith("#")]
        if not targets:
            print("no targets in file", file=sys.stderr)
            return 2
        data = run_remote(targets, workers=args.workers,
                          insecure=args.insecure, aggressive=args.aggressive)
        if args.json:
            with open(args.json, "w") as f:
                json.dump(data, f, indent=2)
            print(f"saved {args.json}")
        return report_remote(data)

    if args.mode == "watch":
        return report_watch(args.inventory)


if __name__ == "__main__":
    sys.exit(main())
