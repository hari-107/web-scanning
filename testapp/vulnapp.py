"""Deliberately-vulnerable web app for exercising WebSec Scanner.

⚠️  FOR LOCAL TESTING ONLY. This app intentionally contains security holes
(reflected XSS, SQL-error leakage, path traversal, command-marker echo, open
redirect, SSTI, exposed secrets, missing headers, insecure cookies). NEVER
deploy it or expose it to a network you do not control.

Run:
    pip install flask
    python vulnapp.py
Then scan  http://127.0.0.1:5055/  from the WebSec Scanner dashboard.

Every route below maps to one or more detectors in the scanner so you can see
findings light up across the pipeline.
"""
from flask import Flask, Response, request

app = Flask(__name__)

# In-memory "user database" for the SQLi/login simulation.
_USERS = {"admin": "admin123", "alice": "password1"}

NAV = """
<nav style="font-family:system-ui;margin-bottom:1rem">
  <a href="/">Home</a> |
  <a href="/search?q=hello">Search (XSS)</a> |
  <a href="/product?id=1">Product (SQLi)</a> |
  <a href="/page?file=home">Page (LFI)</a> |
  <a href="/go?url=/">Redirect</a> |
  <a href="/ping?host=127.0.0.1">Ping (CMDi)</a> |
  <a href="/greet?name=guest">Greet (SSTI)</a> |
  <a href="/login">Login</a> |
  <a href="/admin">Admin</a> |
  <a href="/api/users">API</a>
</nav><hr>
"""


def page(body: str, status: int = 200) -> Response:
    html = f"""<!doctype html><html><head><title>VulnApp</title>
    <meta name="generator" content="WordPress 5.0">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <script src="/static/js/jquery-3.1.min.js"></script>
    <link rel="stylesheet" href="/static/css/bootstrap.min.css">
    </head><body style="font-family:system-ui;max-width:820px;margin:2rem auto">
    {NAV}{body}</body></html>"""
    return Response(html, status=status)


@app.after_request
def weaken(resp: Response) -> Response:
    # Intentionally omit ALL security headers and leak a server banner.
    resp.headers["Server"] = "TestServer/1.0 (Ubuntu)"
    resp.headers["X-Powered-By"] = "PHP/7.4.3"
    # Insecure cookie: no Secure / HttpOnly / SameSite.
    resp.set_cookie("session", "s3ss10n-t0k3n-abc123")
    return resp


@app.route("/")
def index():
    return page("<h1>Vulnerable Test App</h1>"
                "<p>Point WebSec Scanner at <code>http://127.0.0.1:5055/</code>.</p>"
                "<p>Each nav link maps to a different vulnerability class.</p>")


# --- Reflected XSS -----------------------------------------------------------
@app.route("/search")
def search():
    q = request.args.get("q", "")
    # VULN: reflects user input unencoded.
    return page(f"<h2>Search</h2><p>Results for: {q}</p>"
                "<form method='get'><input name='q' placeholder='search'>"
                "<button>Go</button></form>")


# --- SQL Injection (error-based) --------------------------------------------
@app.route("/product")
def product():
    pid = request.args.get("id", "")
    # VULN: single quote triggers a database-style error message.
    if "'" in pid or '"' in pid:
        return page("<h2>Product</h2><pre>You have an error in your SQL syntax; "
                    "check the manual that corresponds to your MySQL server "
                    f"version for the right syntax near '{pid}'</pre>", 500)
    return page(f"<h2>Product #{pid}</h2><p>A fine product.</p>")


# --- LFI / path traversal ----------------------------------------------------
@app.route("/page")
def page_view():
    f = request.args.get("file", "")
    # VULN: traversal to a fake /etc/passwd.
    if "etc/passwd" in f or "../" in f or "..\\" in f:
        return Response("root:x:0:0:root:/root:/bin/bash\n"
                        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                        "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin",
                        mimetype="text/plain")
    return page(f"<h2>Page: {f}</h2><p>Static content.</p>")


# --- Open redirect -----------------------------------------------------------
@app.route("/go")
def go():
    url = request.args.get("url", "/")
    # VULN: redirects to any user-supplied URL.
    return Response(status=302, headers={"Location": url})


# --- OS command injection (marker echo) -------------------------------------
@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    # VULN: simulates shell execution. Output the command RESULT (bare marker)
    # only -- do NOT reflect the raw "echo MARKER" text -- so it mimics genuine
    # execution rather than reflection (matching the scanner's cmdi guard).
    import re
    m = re.search(r"echo\s+(\w+)", host)
    if m:
        target = host.split(";")[0].split("|")[0].split("&")[0].strip()
        return page(f"<h2>Ping</h2><pre>PING {target} 56 bytes\n{m.group(1)}\n"
                    "64 bytes from 127.0.0.1: icmp_seq=1 time=0.03 ms</pre>")
    return page(f"<h2>Ping</h2><pre>Pinging {host}...</pre>")


# --- SSTI --------------------------------------------------------------------
@app.route("/greet")
def greet():
    name = request.args.get("name", "guest")
    # VULN: naive template evaluation of {{ 7*7 }} style expressions.
    import re
    def _eval(match):
        expr = match.group(1).strip()
        try:
            if re.fullmatch(r"[\d\s*+\-]+", expr):
                return str(eval(expr))  # noqa: S307 - intentional for the test
            if re.fullmatch(r"\d+\s*\*\s*'?\d'?", expr):
                a, b = re.findall(r"\d+", expr)
                return str(int(a)) * int(b)
        except Exception:
            return match.group(0)
        return match.group(0)
    rendered = re.sub(r"\{\{(.*?)\}\}", _eval, name)
    return page(f"<h2>Hello, {rendered}!</h2>")


# --- Login: SQLi + reflected XSS + no rate limit + username enum ------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = request.form.get("username", "")
        pw = request.form.get("password", "")
        # VULN: SQL error on quote in username.
        if "'" in user or '"' in user:
            return page("<pre>Warning: mysql_fetch_array(): supplied argument "
                        f"is not a valid MySQL result near '{user}'</pre>", 500)
        # VULN: username enumeration -- different message for known users.
        if user in _USERS:
            if _USERS[user] == pw:
                return page(f"<h2>Welcome back, {user}!</h2>")
            # VULN: reflected XSS in the failure message + distinct wording.
            return page(f"<h2>Login</h2><p>Incorrect password for {user}.</p>"
                        + _login_form())
        return page(f"<h2>Login</h2><p>No such user: {user}.</p>" + _login_form())
    return page("<h2>Login</h2>" + _login_form())


def _login_form() -> str:
    # VULN: no CSRF token.
    return ("<form method='post'>"
            "<input name='username' placeholder='username'><br>"
            "<input type='password' name='password' placeholder='password'><br>"
            "<button>Sign in</button></form>")


# --- Admin panel (discoverable) ---------------------------------------------
@app.route("/admin")
def admin():
    return page("<h2>Admin Panel</h2><p>Restricted area (not really).</p>")


# --- Exposed API (insecure CORS + info disclosure) --------------------------
@app.route("/api/users")
def api_users():
    resp = Response('{"users":[{"id":1,"user":"admin"},{"id":2,"user":"alice"}]}',
                    mimetype="application/json")
    # VULN: reflects arbitrary Origin with credentials allowed.
    origin = request.headers.get("Origin")
    if origin:
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Access-Control-Allow-Credentials"] = "true"
    return resp


# --- Exposed secrets / metadata ---------------------------------------------
@app.route("/.env")
def dotenv():
    return Response("DB_HOST=localhost\nDB_USER=root\n"
                    "DB_PASSWORD=SuperSecret123\nAPI_KEY=sk_live_51H8xTestKey\n"
                    "SECRET_KEY=django-insecure-testkey", mimetype="text/plain")


@app.route("/backup.sql")
def backup():
    return Response("-- MySQL dump\nINSERT INTO users VALUES "
                    "(1,'admin','admin123');", mimetype="text/plain")


@app.route("/robots.txt")
def robots():
    return Response("User-agent: *\nDisallow: /admin\nDisallow: /backup.sql\n"
                    "Disallow: /secret-panel\nSitemap: "
                    "http://127.0.0.1:5055/sitemap.xml", mimetype="text/plain")


@app.route("/sitemap.xml")
def sitemap():
    urls = ["/", "/search", "/product", "/login", "/admin", "/api/users"]
    body = ('<?xml version="1.0" encoding="UTF-8"?>'
            '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
            + "".join(f"<url><loc>http://127.0.0.1:5055{u}</loc></url>"
                      for u in urls)
            + "</urlset>")
    return Response(body, mimetype="application/xml")


if __name__ == "__main__":
    print("Vulnerable test app -> http://127.0.0.1:5055/  (Ctrl+C to stop)")
    app.run(host="127.0.0.1", port=5055, threaded=True)
