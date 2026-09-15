# web/references

## The payload bibles (bookmark these — they win web challenges)

- **PayloadsAllThePings/Things** — https://github.com/swisskyrepo/PayloadsAllTheThings
  The canonical collection: SQLi, XSS, SSTI, SSRF, XXE, command injection, JWT,
  CSS injection, etc. **Clone it offline before the event.**
- **HackTricks** — https://book.hacktricks.xyz/ — methodology + payloads for
  every web bug class. Also clone/save offline.
- **OWASP Testing Guide** — https://owasp.org/www-project-web-security-testing-guide/

## CSS injection (the one that beat you last time)

- Technique write-ups:
  - https://book.hacktricks.xyz/pentesting-web/xs-search/css-injection
  - https://portswigger.net/research/blind-css-exfiltration
- The workflow: `web/scripts/collector.py --css`  +  `web/scripts/css_exfil.py`.
  1. Start the collector, expose it (ngrok/serveo) if the target is remote.
  2. Generate rules for the first char, inject, watch which URL calls home.
  3. Append the found char to `--known`, repeat.
- Single-injection variant (leak everything with one payload): recursive
  `@import` + `@font-face` unicode-range trick — see the PortSwigger article.

## Interception / tooling

- **Burp Suite (Community)** — https://portswigger.net/burp — intercept, repeat,
  decode. The **Repeater** tab is where most web solving actually happens.
- **Caido** — https://caido.io/ — lighter modern alternative to Burp.
- **ffuf** — https://github.com/ffuf/ffuf — content/parameter fuzzing.
  `ffuf -u http://host/FUZZ -w wordlist.txt`
- **feroxbuster / gobuster / dirsearch** — directory brute forcing.
- Wordlists: **SecLists** — https://github.com/danielmiessler/SecLists (clone offline).

## Specific bug classes

| Bug | Tool / reference |
|---|---|
| JWT | https://jwt.io (decode) · `jwt_tool` · check `alg=none`, weak HMAC secret (crack with `hashcat -m 16500`) |
| SQLi | `sqlmap` for blind/automatable; manual via PayloadsAllTheThings |
| SSTI | https://github.com/epinna/tplmap · the `{{7*7}}` → 49 probe |
| SSRF | `collector.py` as the OOB target; cloud metadata `169.254.169.254` |
| XXE | OOB via `collector.py` + external DTD (PayloadsAllTheThings) |
| Deserialization | `ysoserial` (Java), `phpggc` (PHP) |
| Prototype pollution | HackTricks node section |

## Client-side / recon

- **CyberChef** — decode JWTs, base64, URL, gzip in responses.
- Browser DevTools — Network tab, JS source, `debugger;` traps (deobfuscate JS
  with https://obf-io.deobfuscate.io/ or beautifier).

## Reminder

Follow the safety rules: this is for the authorized CTF environment only. Point
`collector.py` at yourself, not at third parties.
