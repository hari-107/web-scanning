# Vulnerable Test App

A deliberately-insecure Flask app for exercising **WebSec Scanner**.

> ⚠️ **Local testing only.** This app is intentionally full of security holes.
> Never deploy it or expose it beyond `127.0.0.1`.

## Run

```bash
pip install flask
python vulnapp.py
```

It listens on **http://127.0.0.1:5055/**. Start the scanner
(`python manage.py runserver` in the project root), open the dashboard, enter
`http://127.0.0.1:5055/`, tick the authorisation box, and click *Start Scan*.

## What each route triggers

| Route            | Vulnerability                              | Scanner module            |
|------------------|--------------------------------------------|---------------------------|
| `/search?q=`     | Reflected XSS                              | `vulntests.xss`           |
| `/product?id=`   | SQL Injection (error-based)                | `vulntests.sqli`          |
| `/page?file=`    | LFI / path traversal                       | `vulntests.misc.lfi`      |
| `/go?url=`       | Open redirect                              | `vulntests.misc.redirect` |
| `/ping?host=`    | OS command injection                       | `vulntests.misc.cmdi`     |
| `/greet?name=`   | Server-Side Template Injection             | `vulntests.misc.ssti`     |
| `/login`         | Login SQLi, reflected XSS, no CSRF token, no rate limit, username enumeration | `vulntests.auth.*` |
| `/api/users`     | Insecure CORS (reflected Origin + creds)   | `vulntests.misc.cors`     |
| `/admin`         | Discoverable admin panel                   | `dirsearch`               |
| `/.env`          | Exposed secrets file                       | `dirsearch`               |
| `/backup.sql`    | Exposed database backup                    | `dirsearch`               |
| `/robots.txt`    | Reveals hidden paths                       | `recon.robots`            |
| `/sitemap.xml`   | Site map for the crawler                   | `recon.sitemap`           |
| (all responses)  | Missing security headers, insecure cookie, server banner disclosure, clickjacking | `recon.*`, `vulntests.misc.clickjacking` |

You should see roughly **5 critical / 10 high / 8 medium / 3 low / 6 info**
findings and a security score near 0.
