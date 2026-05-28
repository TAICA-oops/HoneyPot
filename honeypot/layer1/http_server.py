import os
import html
import json
import uuid
import time
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse
import uvicorn
from dotenv import load_dotenv
from layer1.logger import Logger
from layer2.intent_classifier import classify as _classify_intent

load_dotenv()

app = FastAPI()
_logger = Logger()

_WP_LOGIN_HTML = """\
<!DOCTYPE html><html><head><title>Log In &lsaquo; Demo Site &mdash; WordPress</title>
<style>body{font-family:Georgia,serif;background:#f1f1f1;}
#login{width:320px;margin:8% auto;background:#fff;padding:26px 24px;border:1px solid #c3c4c7;}
h1{text-align:center;font-size:16px;}input{width:100%;padding:8px;margin:4px 0 12px;box-sizing:border-box;}
.button{background:#0073aa;color:#fff;border:none;padding:10px;width:100%;cursor:pointer;}
</style></head><body>
<div id="login"><h1>Demo Site</h1>
<form method="post" action="/wp-login.php">
<label>Username<br/><input name="log" type="text" autocomplete="off"/></label>
<label>Password<br/><input name="pwd" type="password"/></label>
<input name="wp-submit" type="submit" class="button" value="Log In"/>
<input name="redirect_to" type="hidden" value="/wp-admin/"/>
</form></div></body></html>
"""

_FAKE_ENV = """\
APP_ENV=production
APP_KEY=base64:3lV7kQmN2pXwR8sT1uYvZaB4cDeF6gHi
DB_HOST=localhost
DB_DATABASE=ecommerce_db
DB_USERNAME=dbadmin
DB_PASSWORD=Sup3rS3cr3t!2019
AWS_KEY=AKIAIOSFODNN7EXAMPLE
AWS_SECRET=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
"""

_PHPMYADMIN_HTML = """\
<!DOCTYPE html><html><head><title>phpMyAdmin</title>
<style>body{font-family:sans-serif;background:#eee;}
#login{width:300px;margin:10% auto;background:#fff;padding:24px;border:1px solid #ccc;}
input{width:100%;padding:7px;margin:4px 0 10px;box-sizing:border-box;}
.btn{background:#4278a0;color:#fff;border:none;padding:8px;width:100%;cursor:pointer;}
</style></head><body>
<div id="login"><h2>phpMyAdmin</h2>
<form method="post">
<label>Username<br/><input name="pma_username" type="text"/></label>
<label>Password<br/><input name="pma_password" type="password"/></label>
<input type="submit" class="btn" value="Go"/>
</form></div></body></html>
"""

_XMLRPC = """<?xml version="1.0" encoding="UTF-8"?>
<methodResponse><params><param><value><array><data>
<value><string>blogger.deletePost</string></value>
<value><string>blogger.getPost</string></value>
<value><string>wp.getUsersBlogs</string></value>
</data></array></value></param></params></methodResponse>"""

def _make_session_id(request: Request) -> str:
    ip = request.client.host if request.client else "unknown"
    return f"http-{ip}-{uuid.uuid4().hex[:8]}"

def _log(request: Request, path: str, body: str, code: int, creds: str | None = None):
    sid = _make_session_id(request)
    _logger.session_start(sid, "http", request.client.host if request.client else "unknown")
    _logger.http_request(sid, request.method, path, body, code, creds)
    intent, conf = _classify_intent(path + " " + body)
    if intent != "unknown":
        _logger.command(sid, f"HTTP {request.method} {path}", "", intent, conf, True)
    # HTTP session 每次請求就完整記錄，立即結束
    threat = "High" if intent in ("credential_harvesting", "injection_attempt") else \
             "Medium" if intent in ("web_recon",) else "Low"
    _logger.session_end(sid, threat)

@app.get("/wp-admin", response_class=HTMLResponse)
@app.get("/wp-admin/", response_class=HTMLResponse)
@app.get("/wp-login.php", response_class=HTMLResponse)
async def wp_login_get(request: Request):
    _log(request, request.url.path, "", 200)
    return HTMLResponse(_WP_LOGIN_HTML, status_code=200)

@app.post("/wp-login.php", response_class=HTMLResponse)
async def wp_login_post(request: Request, log: str = Form(""), pwd: str = Form("")):
    creds = json.dumps({"username": log, "password": pwd})
    _log(request, "/wp-login.php", f"log={log}&pwd={pwd}", 200, creds)
    body = _WP_LOGIN_HTML.replace(
        "</form>",
        '<p style="color:red;font-size:13px;">ERROR: Invalid username or incorrect password.</p></form>'
    )
    return HTMLResponse(body, status_code=200)

@app.get("/.env")
async def dot_env(request: Request):
    _log(request, "/.env", "", 200)
    return HTMLResponse(_FAKE_ENV, media_type="text/plain")

@app.get("/phpmyadmin", response_class=HTMLResponse)
@app.get("/phpmyadmin/", response_class=HTMLResponse)
async def phpmyadmin(request: Request):
    _log(request, request.url.path, "", 200)
    return HTMLResponse(_PHPMYADMIN_HTML)

@app.post("/phpmyadmin", response_class=HTMLResponse)
@app.post("/phpmyadmin/", response_class=HTMLResponse)
async def phpmyadmin_post(
    request: Request,
    pma_username: str = Form(""),
    pma_password: str = Form(""),
):
    import json as _json
    creds = _json.dumps({"username": pma_username, "password": pma_password})
    _log(request, request.url.path,
         f"pma_username={pma_username}&pma_password={pma_password}", 200, creds)
    return HTMLResponse(_PHPMYADMIN_HTML, status_code=200)

@app.get("/xmlrpc.php")
async def xmlrpc(request: Request):
    _log(request, "/xmlrpc.php", "", 200)
    return HTMLResponse(_XMLRPC, media_type="application/xml")

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def catch_all(request: Request, path: str):
    body = (await request.body()).decode(errors="replace")
    _log(request, "/" + path, body, 404)
    return HTMLResponse(
        f'<!DOCTYPE html><html><head><title>Page not found &lsaquo; Demo Site &mdash; WordPress</title></head>'
        f'<body><h1>Not Found</h1><p>The page <code>/{html.escape(path)}</code> could not be found.</p></body></html>',
        status_code=404
    )

def run() -> None:
    port = int(os.getenv("HTTP_PORT", "8080"))
    uvicorn.run(app, host="0.0.0.0", port=port)

if __name__ == "__main__":
    run()
