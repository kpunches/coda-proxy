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
"""
import os
import hmac
import requests
from flask import Flask, request, Response

app = Flask(__name__)

CODA_TOKEN   = os.environ["CODA_TOKEN"]
PROXY_SECRET = os.environ["PROXY_SECRET"]
ALLOWED_DOC  = os.environ.get("ALLOWED_DOC", "").strip()
ALLOW_DELETE = os.environ.get("ALLOW_DELETE", "") == "1"

CODA_BASE = "https://coda.io/apis/v1"
ALLOWED_METHODS = {"GET", "POST", "PUT", "PATCH"} | ({"DELETE"} if ALLOW_DELETE else set())


def authorized(req):
    sent = req.headers.get("X-Proxy-Key", "")
    if not sent:
        auth = req.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            sent = auth[7:]
    return bool(sent) and hmac.compare_digest(sent, PROXY_SECRET)


@app.route("/healthz")
def healthz():
    # no auth, no Coda call — just confirms the service is up
    return "ok", 200


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
