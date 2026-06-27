"""
Coda API proxy — keeps the real Coda token on Render (encrypted env var) and
exposes an authenticated pass-through. Callers present a separate, revocable
PROXY_SECRET; the proxy swaps it for the real CODA_TOKEN server-side and forwards
to Coda. The raw Coda token never leaves Render.

Env vars (set these in Render's Environment tab — never in code or git):
  CODA_TOKEN    required  the real Coda API token
  PROXY_SECRET  required  the secret callers must present (rotate to revoke access)
  ALLOWED_DOC   optional  restrict to one doc id, e.g. 4YIajnJqvo (blast-radius control)
  ALLOW_DELETE  optional  set to "1" to permit DELETE (off by default)
  EXPORT_TOKEN  optional  read-only token for the /export/* CSV links (see below).
                          Kept SEPARATE from PROXY_SECRET: it travels in a URL /
                          Coda button formula in plaintext, so leaking it must not
                          grant write access. If unset, /export/* returns 503.
"""
import os
import io
import csv
import time
import hmac
import requests
from flask import Flask, request, Response

app = Flask(__name__)

CODA_TOKEN   = os.environ["CODA_TOKEN"]
PROXY_SECRET = os.environ["PROXY_SECRET"]
ALLOWED_DOC  = os.environ.get("ALLOWED_DOC", "").strip()
ALLOW_DELETE = os.environ.get("ALLOW_DELETE", "") == "1"
EXPORT_TOKEN = os.environ.get("EXPORT_TOKEN", "").strip()

CODA_BASE = "https://coda.io/apis/v1"
ALLOWED_METHODS = {"GET", "POST", "PUT", "PATCH"} | ({"DELETE"} if ALLOW_DELETE else set())

# --- /export/rsds config --------------------------------------------------
RSDS_DOC         = "4YIajnJqvo"
RSDS_TABLE       = "grid-5p9sHmnPst"   # _Rich Skill Descriptors (RSDs)
RSDS_PROGRAM_COL = "c-6PVzDyCf6h"      # Program (lookup) — used for the ?program= filter
# (CSV header, Coda column name). The header is what shows up in the file;
# the source is the EXACT column label in the table. They differ for Category,
# whose real column is "Skill Category".
RSDS_COLUMNS = [
    ("Program",         "Program"),
    ("Category",        "Skill Category"),
    ("Canonical URL",   "Canonical URL"),
    ("Skill Title",     "Skill Title"),
    ("Skill Statement", "Skill Statement"),
]
# --------------------------------------------------------------------------


def authorized(req):
    sent = req.headers.get("X-Proxy-Key", "")
    if not sent:
        auth = req.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            sent = auth[7:]
    return bool(sent) and hmac.compare_digest(sent, PROXY_SECRET)


def cell_to_text(value):
    """Coerce a Coda cell value to plain text, mirroring .ToText()."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        # hyperlink cell -> url; relation row -> name; otherwise fall back
        return value.get("url") or value.get("name") or value.get("value") or ""
    if isinstance(value, list):
        return "; ".join(cell_to_text(v) for v in value if v is not None)
    return str(value)


def fetch_all_rows(doc_id, table_id, query=None, attempts=3):
    """Page through a table's rows, keyed by column name.

    If `query` is given (Coda rows query syntax, e.g. 'c-xxxx:"value"'), the
    filter runs server-side so a scoped export is a single page. Retries
    connection/timeout/5xx with backoff so a cold read doesn't surface as a 500;
    genuine 4xx are raised immediately.
    """
    rows = []
    url = f"{CODA_BASE}/docs/{doc_id}/tables/{table_id}/rows"
    headers = {"Authorization": f"Bearer {CODA_TOKEN}"}
    params = {"useColumnNames": "true", "valueFormat": "simpleWithArrays", "limit": 200}
    if query:
        params["query"] = query
    while True:
        body = None
        for attempt in range(attempts):
            try:
                r = requests.get(url, headers=headers, params=params, timeout=30)
                if r.status_code >= 500:
                    raise requests.HTTPError(f"{r.status_code} from Coda", response=r)
                r.raise_for_status()   # 4xx -> raise (not retried below)
                body = r.json()
                break
            except (requests.ConnectionError, requests.Timeout, requests.HTTPError) as e:
                resp = getattr(e, "response", None)
                if resp is not None and 400 <= resp.status_code < 500:
                    raise  # client error — don't retry
                if attempt == attempts - 1:
                    raise
                time.sleep(1.5 * (attempt + 1))
        rows.extend(body.get("items", []))
        token = body.get("nextPageToken")
        if not token:
            break
        params = {"pageToken": token}   # subsequent pages: token only (query is baked in)
    return rows


@app.route("/healthz")
def healthz():
    # no auth, no Coda call — just confirms the service is up
    return "ok", 200


@app.route("/export/rsds")
def export_rsds():
    # Reached by a plain browser navigation from a Coda OpenWindow() button,
    # which can't send headers — so auth is a query-string token, deliberately
    # separate from PROXY_SECRET so this read-only link can't be used to write.
    if not EXPORT_TOKEN:
        return Response("export not configured", status=503)
    key = request.args.get("key", "")
    if not (key and hmac.compare_digest(key, EXPORT_TOKEN)):
        return Response("unauthorized", status=401)

    # Optional program scope. When the button passes the current user's selected
    # program, we filter server-side (one page). Empty -> export everything.
    program = request.args.get("program", "").strip()
    query = f'{RSDS_PROGRAM_COL}:"{program}"' if program else None

    try:
        rows = fetch_all_rows(RSDS_DOC, RSDS_TABLE, query=query)
    except requests.RequestException as e:
        return Response(f"coda read failed: {e}", status=502)

    buf = io.StringIO()
    writer = csv.writer(buf, quoting=csv.QUOTE_ALL)
    writer.writerow([header for header, _ in RSDS_COLUMNS])
    for row in rows:
        values = row.get("values", {})
        writer.writerow([cell_to_text(values.get(src)) for _, src in RSDS_COLUMNS])

    # filename reflects the scope so multiple program exports don't collide
    safe = "".join(c if c.isalnum() else "_" for c in program).strip("_") or "all"
    return Response(
        buf.getvalue(),
        status=200,
        content_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="rsds_{safe}.csv"',
            "Cache-Control": "no-store",
        },
    )


@app.route("/v1/<path:subpath>", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
def proxy(subpath):
    if not authorized(request):
        return Response("unauthorized", status=401)
    if request.method not in ALLOWED_METHODS:
        return Response("method not allowed", status=405)
    if ALLOWED_DOC and not subpath.startswith(f"docs/{ALLOWED_DOC}/"):
        return Response("doc not allowed", status=403)

    resp = requests.request(
        method=request.method,
        url=f"{CODA_BASE}/{subpath}",
        params=request.args,
        data=request.get_data(),
        headers={
            "Authorization": f"Bearer {CODA_TOKEN}",
            "Content-Type": request.headers.get("Content-Type", "application/json"),
        },
        timeout=30,
    )
    return Response(
        resp.content,
        status=resp.status_code,
        content_type=resp.headers.get("Content-Type", "application/json"),
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "10000")))
