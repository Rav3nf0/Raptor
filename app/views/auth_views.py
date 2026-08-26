"""Auth views — login page, login submit, logout."""
from __future__ import annotations

import os
from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app.auth import make_session_response, clear_session_response, require_auth, _RedirectToLogin

router = APIRouter(tags=["auth"])


def _render_login(error: str = "") -> str:
    err_block = f'<p class="err">{error}</p>' if error else ""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>RAPTOR — Login</title>
  <style>
    :root {{ --ground:#0B0D11; --surface:#12151B; --line:#252B36; --text:#DDE1E8;
             --dim:#8E96A4; --accent:#9E86F0; --crit:#F05552;
             --mono:"SF Mono",ui-monospace,"JetBrains Mono",Menlo,monospace;
             --sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,system-ui,sans-serif; }}
    * {{ box-sizing:border-box; }}
    body {{ margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center;
            background:var(--ground); color:var(--text); font-family:var(--sans); }}
    body::before {{ content:""; position:fixed; inset:0; pointer-events:none; opacity:.35;
      background-image:linear-gradient(#161B22 1px,transparent 1px),linear-gradient(90deg,#161B22 1px,transparent 1px);
      background-size:44px 44px; mask-image:radial-gradient(ellipse 80% 60% at 50% 0%,#000 30%,transparent 75%); }}
    .wrap {{ position:relative; width:100%; max-width:360px; padding:24px; }}
    .brand {{ text-align:center; margin-bottom:26px; }}
    .brand h1 {{ margin:0; font-family:var(--mono); font-size:26px; font-weight:650; letter-spacing:.16em; }}
    .brand h1 b {{ color:var(--accent); font-weight:650; }}
    .brand p {{ margin:6px 0 0; font-family:var(--mono); font-size:10px; letter-spacing:.14em;
                text-transform:uppercase; color:var(--dim); }}
    .card {{ background:var(--surface); border:1px solid var(--line); border-radius:10px; padding:26px 24px; }}
    label {{ display:block; font-family:var(--mono); font-size:10px; letter-spacing:.06em;
             text-transform:uppercase; color:var(--dim); margin-bottom:6px; }}
    .field {{ margin-bottom:16px; }}
    input {{ width:100%; background:var(--ground); border:1px solid var(--line); border-radius:7px;
             padding:9px 11px; font-size:13px; color:var(--text); font-family:var(--sans); }}
    input:focus {{ outline:none; border-color:var(--accent); box-shadow:0 0 0 3px rgba(158,134,240,.15); }}
    button {{ width:100%; margin-top:6px; padding:10px; border:0; border-radius:7px; cursor:pointer;
              background:var(--accent); color:#0B0D11; font-weight:650; font-size:13px; letter-spacing:.02em;
              font-family:var(--sans); transition:filter .15s; }}
    button:hover {{ filter:brightness(1.08); }}
    .err {{ color:var(--crit); font-size:12px; text-align:center; margin:0 0 12px; }}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="brand">
      <h1><b>RAP</b>TOR</h1>
      <p>Autonomous L1 Alert Triage</p>
    </div>
    <div class="card">
      <form method="POST" action="/login">
        <div class="field">
          <label>Username</label>
          <input type="text" name="username" autocomplete="username" required autofocus/>
        </div>
        <div class="field">
          <label>Password</label>
          <input type="password" name="password" autocomplete="current-password" required/>
        </div>
        {err_block}
        <button type="submit">Sign in</button>
      </form>
    </div>
  </div>
</body>
</html>"""


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    token = request.cookies.get("deepintel_session")
    if token:
        from app.auth import verify_token
        if verify_token(token):
            return RedirectResponse(url="/edr-triage", status_code=302)
    return HTMLResponse(content=_render_login())


@router.post("/login")
async def login_submit(username: str = Form(...), password: str = Form(...)):
    expected_user = os.getenv("DEEPINTEL_USERNAME", "admin")
    expected_pass = os.getenv("DEEPINTEL_PASSWORD", "")

    if not expected_pass:
        return HTMLResponse(content=_render_login("Server misconfiguration: password not set."), status_code=500)

    if username == expected_user and password == expected_pass:
        return make_session_response("/edr-triage", username)

    return HTMLResponse(content=_render_login("Invalid username or password."), status_code=401)


@router.get("/logout")
async def logout():
    return clear_session_response("/login")
