"""Authentication-related, non-destructive checks.

Focuses on *indicators* rather than active account compromise:
  * missing CSRF token on state-changing forms,
  * missing rate limiting on login (timing/behaviour based, bounded attempts),
  * username enumeration via differing responses,
  * SQLi/XSS auth-bypass payloads in login fields (detection only),
  * default-credential *indicators* (never brute forces real accounts).
"""
from __future__ import annotations

import time

from scanner.models import Form, Severity

from ..base import ScanContext
from ..payloads import SQL_ERROR_RE, XSS_MARKER
from .targets import InjectTarget, send

_LOGIN_SQLI = ["' OR '1'='1", "' OR 1=1-- ", "admin'-- ", "\" OR \"1\"=\"1"]
_MAX_LOGIN_ATTEMPTS = 6  # bounded to avoid lockouts / DoS


def run(ctx: ScanContext) -> None:
    ctx.set_phase("Authentication testing", 86, "Analysing login/registration forms")
    login_forms = list(Form.objects.filter(
        scan=ctx.scan, form_kind__in=["login", "registration"]))
    all_forms = list(Form.objects.filter(scan=ctx.scan))

    _csrf_checks(ctx, all_forms)

    if not login_forms:
        ctx.log("No login/registration forms discovered", phase="Authentication testing")
        return
    ctx.log(f"Analysing {len(login_forms)} authentication form(s)",
            phase="Authentication testing")
    for form in login_forms:
        _login_injection(ctx, form)
        _rate_limiting(ctx, form)
        _username_enum(ctx, form)


def _field_names(form: Form) -> tuple[str | None, str | None, dict]:
    """Return (username_field, password_field, baseline_data)."""
    user_field = pass_field = None
    baseline = {}
    for f in form.fields:
        name = f.get("name")
        if not name:
            continue
        ftype = (f.get("type") or "").lower()
        if ftype in ("submit", "button", "image", "reset"):
            continue
        baseline[name] = f.get("value") or "test"
        if ftype == "password" and pass_field is None:
            pass_field = name
        elif ftype in ("text", "email") and user_field is None:
            user_field = name
        elif name.lower() in ("user", "username", "email", "login") and \
                user_field is None:
            user_field = name
    return user_field, pass_field, baseline


def _post(ctx: ScanContext, form: Form, data: dict, **kw):
    method = (form.method or "POST").upper()
    if method == "GET":
        return ctx.request("GET", form.action, params=data, **kw)
    return ctx.request("POST", form.action, data=data, **kw)


def _login_injection(ctx: ScanContext, form: Form) -> None:
    user_field, pass_field, baseline = _field_names(form)
    if not (user_field and pass_field):
        return
    for payload in _LOGIN_SQLI:
        data = dict(baseline)
        data[user_field] = payload
        data[pass_field] = payload
        resp = _post(ctx, form, data)
        if resp is None:
            continue
        if SQL_ERROR_RE.search(resp.text or ""):
            ctx.add_finding(
                title="SQL Injection in login form",
                severity=Severity.CRITICAL,
                affected_url=form.action,
                http_method=form.method,
                parameter=f"{user_field}/{pass_field}",
                payload=payload,
                evidence="Database error returned when injecting into login "
                         "fields.",
                cvss_score=9.8,
                cwe="CWE-89",
                description="Login credentials are concatenated into a SQL query "
                            "without parameterisation.",
                impact="Authentication bypass and full database compromise.",
                remediation="Use parameterised queries for authentication; never "
                            "build SQL from credentials.",
                detected_by="vulntests.auth.sqli",
                confidence="Firm",
                references=[
                    "https://owasp.org/www-community/attacks/SQL_Injection"],
            )
            return
    # XSS reflection in login (e.g. echoed username on failure).
    data = dict(baseline)
    data[user_field] = f"<b>{XSS_MARKER}</b>"
    data[pass_field] = "x"
    resp = _post(ctx, form, data)
    if resp is not None and f"<b>{XSS_MARKER}</b>" in (resp.text or ""):
        ctx.add_finding(
            title="Reflected XSS in login form",
            severity=Severity.HIGH,
            affected_url=form.action,
            http_method=form.method,
            parameter=user_field,
            payload=f"<b>{XSS_MARKER}</b>",
            evidence="Username value reflected unencoded after failed login.",
            cvss_score=6.1,
            cwe="CWE-79",
            description="The login page reflects the submitted username without "
                        "encoding.",
            impact="Script execution in the victim's browser.",
            remediation="HTML-encode all user input on output.",
            detected_by="vulntests.auth.xss",
            confidence="Firm",
        )


def _rate_limiting(ctx: ScanContext, form: Form) -> None:
    user_field, pass_field, baseline = _field_names(form)
    if not (user_field and pass_field):
        return
    statuses = []
    start = time.perf_counter()
    for i in range(_MAX_LOGIN_ATTEMPTS):
        data = dict(baseline)
        data[user_field] = "websec_probe_user"
        data[pass_field] = f"wrong_pw_{i}"
        resp = _post(ctx, form, data, allow_redirects=False)
        if resp is None:
            return
        statuses.append(resp.status_code)
        # A 429 / lockout means rate limiting exists -> stop, no finding.
        if resp.status_code == 429 or "too many" in (resp.text or "").lower() \
                or "locked" in (resp.text or "").lower():
            ctx.log("Login rate limiting detected", level="success",
                    phase="Authentication testing")
            return
    elapsed = time.perf_counter() - start
    # All attempts accepted quickly with no throttling.
    if all(s not in (429,) for s in statuses):
        ctx.add_finding(
            title="Missing rate limiting on login",
            severity=Severity.MEDIUM,
            affected_url=form.action,
            http_method=form.method,
            parameter=f"{user_field}/{pass_field}",
            evidence=f"{_MAX_LOGIN_ATTEMPTS} failed logins accepted in "
                     f"{elapsed:.1f}s without throttling (statuses "
                     f"{statuses}).",
            cwe="CWE-307",
            description="The login endpoint did not throttle or lock out after "
                        "repeated failed attempts.",
            impact="Enables credential stuffing and brute-force attacks.",
            remediation="Add rate limiting, exponential backoff, account "
                        "lockout, and CAPTCHA on repeated failures.",
            detected_by="vulntests.auth.ratelimit",
            confidence="Tentative",
            references=[
                "https://owasp.org/www-community/attacks/Brute_force_attack"],
        )


def _username_enum(ctx: ScanContext, form: Form) -> None:
    user_field, pass_field, baseline = _field_names(form)
    if not (user_field and pass_field):
        return
    # Compare responses for an obviously-invalid user vs a plausible one.
    def attempt(username: str):
        data = dict(baseline)
        data[user_field] = username
        data[pass_field] = "definitely_wrong_password_123"
        return _post(ctx, form, data, allow_redirects=False)

    r_absent = attempt("no_such_user_zzq_websec")
    r_common = attempt("admin")
    if r_absent is None or r_common is None:
        return
    same_status = r_absent.status_code == r_common.status_code
    len_diff = abs(len(r_absent.text or "") - len(r_common.text or ""))
    # Distinct messaging for existing vs non-existing users.
    markers_absent = _has_marker(r_absent.text, ["no such user", "user not found",
                                                 "unknown user", "does not exist"])
    markers_common = _has_marker(r_common.text, ["incorrect password",
                                                 "wrong password", "invalid password"])
    if (markers_absent != markers_common) or (not same_status) or len_diff > 120:
        ctx.add_finding(
            title="Possible username enumeration",
            severity=Severity.LOW,
            affected_url=form.action,
            http_method=form.method,
            parameter=user_field,
            evidence=f"Differing responses for valid vs invalid usernames "
                     f"(status {r_absent.status_code} vs {r_common.status_code}, "
                     f"len diff {len_diff}).",
            cwe="CWE-203",
            description="The login response differs depending on whether a "
                        "username exists, allowing account enumeration.",
            impact="Attackers can compile valid usernames for targeted attacks.",
            remediation="Return identical responses/timing regardless of whether "
                        "the account exists.",
            detected_by="vulntests.auth.enum",
            confidence="Tentative",
            references=[
                "https://owasp.org/www-community/attacks/Testing_for_user_enumeration"],
        )


def _csrf_checks(ctx: ScanContext, forms: list[Form]) -> None:
    for form in forms:
        if (form.method or "GET").upper() != "POST":
            continue
        names = {(f.get("name") or "").lower() for f in form.fields}
        has_token = any(any(tok in n for tok in (
            "csrf", "token", "_token", "authenticity", "nonce", "__requestverification"))
            for n in names)
        if not has_token:
            # Login forms carry heavier consequence.
            sev = Severity.MEDIUM if form.form_kind in ("login", "registration",
                                                        "contact") else Severity.LOW
            ctx.add_finding(
                title="Form without anti-CSRF token",
                severity=sev,
                affected_url=form.action,
                http_method="POST",
                evidence=f"POST form ({form.form_kind or 'generic'}) on "
                         f"{form.page_url} has no CSRF token field.",
                cwe="CWE-352",
                description="A state-changing POST form lacks an anti-CSRF token.",
                impact="Attackers can forge requests on behalf of authenticated "
                       "users.",
                remediation="Include and validate a per-session anti-CSRF token; "
                            "use SameSite cookies as defence in depth.",
                detected_by="vulntests.auth.csrf",
                confidence="Tentative",
                references=[
                    "https://owasp.org/www-community/attacks/csrf"],
            )


def _has_marker(text: str | None, markers: list[str]) -> bool:
    low = (text or "").lower()
    return any(m in low for m in markers)
