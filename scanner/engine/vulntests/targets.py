"""Build the list of injectable targets from discovered params and forms.

A *target* is a normalised description of one place we can inject a value:
either a GET query parameter on a URL, or a field within a discovered form
(GET or POST). Vuln modules iterate these and mutate a single parameter at a
time while holding the others at a benign baseline.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import parse_qs, urlparse

from scanner.models import Form

from ..base import ScanContext


@dataclass
class InjectTarget:
    url: str                       # request URL (action for forms)
    method: str                    # GET / POST
    param: str                     # parameter under test
    base_params: dict = field(default_factory=dict)  # all params w/ baseline vals
    origin: str = ""               # page the form/param came from
    kind: str = ""                 # form kind or "query"

    def data_with(self, value: str) -> dict:
        d = dict(self.base_params)
        d[self.param] = value
        return d


_BENIGN = "1"


def build_targets(ctx: ScanContext, include_forms: bool = True,
                  form_kinds: set[str] | None = None) -> list[InjectTarget]:
    targets: list[InjectTarget] = []
    seen: set[tuple] = set()

    # 1) Query-string parameters gathered by the crawler.
    for url, params in ctx.params.items():
        parsed = urlparse(url)
        base = {k: (v[0] if v else "") for k, v in parse_qs(parsed.query).items()}
        clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        for p in params:
            key = ("GET", clean_url, p)
            if key in seen:
                continue
            seen.add(key)
            targets.append(InjectTarget(
                url=clean_url, method="GET", param=p,
                base_params={**base}, origin=url, kind="query"))

    # 2) Form fields (skip pure submit/hidden-csrf-only where sensible).
    if include_forms:
        for form in Form.objects.filter(scan=ctx.scan):
            if form_kinds and form.form_kind not in form_kinds:
                continue
            base = {}
            for f in form.fields:
                name = f.get("name")
                if not name:
                    continue
                ftype = (f.get("type") or "").lower()
                if ftype in ("submit", "button", "image", "reset"):
                    continue
                base[name] = f.get("value") or _BENIGN
            for f in form.fields:
                name = f.get("name")
                ftype = (f.get("type") or "").lower()
                if not name or ftype in ("submit", "button", "image", "reset",
                                          "file"):
                    continue
                key = (form.method, form.action, name)
                if key in seen:
                    continue
                seen.add(key)
                targets.append(InjectTarget(
                    url=form.action, method=form.method.upper(), param=name,
                    base_params={**base}, origin=form.page_url,
                    kind=form.form_kind))
    return targets


def send(ctx: ScanContext, t: InjectTarget, value: str, **kwargs):
    """Issue a request for target ``t`` with ``param`` set to ``value``."""
    data = t.data_with(value)
    if t.method == "POST":
        return ctx.request("POST", t.url, data=data, **kwargs)
    return ctx.request("GET", t.url, params=data, **kwargs)
