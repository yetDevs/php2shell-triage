#!/usr/bin/env python3
"""
Fake PHP host for testing php_triage.py without touching anything real.

Serves:
  /                 X-Powered-By: PHP/7.4.33  (EOL, version disclosed)
  /phpinfo.php      a phpinfo() page claiming 8.2.33 (BEHIND latest 8.2.34)
  /composer.json    publicly readable manifest
  /wp-login.php     sets wordpress_test_cookie
  /?=PHPE9568F36... the PHP logo GIF

Run: python3 fake_php_host.py [port]
"""
import http.server
import socketserver
import sys

LOGO = (b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!"
        b"\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00"
        b"\x00\x02\x02D\x01\x00;")

PHPINFO = b"""<!DOCTYPE html><html><head><title>phpinfo()</title></head><body>
<h1>PHP Version 8.2.33</h1>
<table><tr><td class="e">PHP Version </td><td class="v">8.2.33</td></tr>
<tr><td class="e">System </td><td class="v">Linux web01 5.15.0</td></tr></table>
</body></html>"""

COMPOSER = b'{"name":"acme/app","require":{"php":">=8.1"},"require-dev":{}}'


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_GET(self):
        path = self.path.split("?")[0]
        body, ctype, extra = b"", "text/html", {}

        if "PHPE9568F36" in self.path:
            body, ctype = LOGO, "image/gif"
        elif path == "/phpinfo.php":
            body = PHPINFO
        elif path == "/composer.json":
            body, ctype = COMPOSER, "application/json"
        elif path == "/wp-login.php":
            body = b"<html><body>wp-login</body></html>"
            extra["Set-Cookie"] = "wordpress_test_cookie=WP%20Cookie%20check; path=/"
        elif path == "/":
            body = b"<html><body>app</body></html>"
            extra["X-Powered-By"] = "PHP/7.4.33"
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in extra.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8931
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("127.0.0.1", port), Handler) as srv:
        print(f"fake php host on http://127.0.0.1:{port}", flush=True)
        srv.serve_forever()
