#!/usr/bin/env python3
"""
Offline test for php_triage.py local mode.

Windows will not execute a shell script named php.exe through subprocess, so
probe_binary's subprocess call is mocked to return real `php -v` output. That
still exercises discovery, dedupe, vendor tagging, version parsing, app-root
detection and assessment - everything except the OS exec itself.
"""
import os
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import php_triage as t  # noqa: E402

# directory-name -> what that "binary" reports
REAL_OUTPUT = {
    "xampp-php81": "PHP 8.1.31 (cli) (built: Nov 21 2024 00:00:00) (NTS)\n"
                   "Copyright (c) The PHP Group\nZend Engine v4.3.31\n",
    "phpcgi": "PHP 8.2.33 (cgi-fcgi) (built: Sep 25 2026 10:12:00)\n",
    "opt-php84": "PHP 8.4.26 (cli) (built: Sep 25 2026 10:12:00) (NTS)\n",
    "eol-php56": "PHP 5.6.40 (cli) (built: Jan 11 2019 16:06:00)\n"
                 "Copyright (c) 1997-2018 The PHP Group\n",
}


def fake_run(argv, capture_output=True, text=True, timeout=None):
    path = argv[0].lower()
    for key, out in REAL_OUTPUT.items():
        if key in path:
            return SimpleNamespace(stdout=out, stderr="", returncode=0)
    return SimpleNamespace(stdout="", stderr="not a php binary", returncode=1)


def main():
    root = tempfile.mkdtemp(prefix="phptriage-")
    try:
        stubs = {
            os.path.join("xampp-php81", "php.exe"): "8.1.31",
            os.path.join("phpcgi", "php-cgi.exe"): "8.2.33",
            os.path.join("opt-php84", "php.exe"): "8.4.26",
            os.path.join("eol-php56", "php.exe"): "5.6.40",
        }
        for rel in stubs:
            p = os.path.join(root, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w") as f:
                f.write("stub")

        app = os.path.join(root, "var", "www", "blog")
        os.makedirs(app)
        for marker in ("wp-config.php", "composer.lock"):
            with open(os.path.join(app, marker), "w") as f:
                f.write("stub")

        subprocess.run = fake_run  # patch the exec path
        data = t.scan_local([root], max_depth=6)

        print(f"binaries discovered: {len(data['binaries'])}")
        for b in data["binaries"]:
            a = t.assess(b["version"], data["releases"])
            print(f"  {b['version'] or '?':<10} {a['status']:<8} "
                  f"{b['realpath']}  vendor={b['bundled_by']}")
        print(f"app roots: {sorted(x['app'] for x in data['apps'])}")

        statuses = {t.assess(b["version"], data["releases"])["status"]
                    for b in data["binaries"]}
        apps = {x["app"] for x in data["apps"]}

        checks = [
            ("found all 4 binaries", len(data["binaries"]) == 4),
            ("EOL detected (5.6 + 8.1)", "EOL" in statuses),
            ("BEHIND detected (8.2.33 < 8.2.34)", "BEHIND" in statuses),
            ("CURRENT detected (8.4.26)", "CURRENT" in statuses),
            ("wordpress app root found", "wordpress" in apps),
            ("composer app root found", "composer" in apps),
            ("xampp install tagged as vendor bundle",
             any(b["bundled_by"] == "xampp" for b in data["binaries"])),
        ]
        ok = True
        for name, res in checks:
            print(f"  [{'PASS' if res else 'FAIL'}] {name}")
            ok = ok and res
        return 0 if ok else 1
    finally:
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
