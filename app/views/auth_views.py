"""Auth views — login page, login submit, logout."""
from __future__ import annotations

import os
from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app.auth import make_session_response, clear_session_response, require_auth, _RedirectToLogin

router = APIRouter(tags=["auth"])


def _render_login(error: str = "") -> str:
    err_block = (
        f'<p class="text-red-400 text-sm text-center mt-2">{error}</p>' if error else ""
    )
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>DeepIntel — Login</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    body {{background:#0f172a;color:#e2e8f0;font-family:system-ui,sans-serif;}}
  </style>
</head>
<body class="min-h-screen flex items-center justify-center">
  <div class="w-full max-w-sm">
    <div class="text-center mb-8">
      <h1 class="text-2xl font-bold text-white tracking-tight">DeepIntel</h1>
      <p class="text-gray-400 text-sm mt-1">AI-Powered Threat Intelligence</p>
    </div>
    <div style="background:#1e293b;border:1px solid #334155;border-radius:0.75rem;" class="p-8">
      <form method="POST" action="/login">
        <div class="mb-5">
          <label class="block text-sm text-gray-400 mb-1.5">Username</label>
          <input
            type="text" name="username" autocomplete="username" required autofocus
            class="w-full bg-gray-800 border border-gray-600 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-indigo-500 transition"/>
        </div>
        <div class="mb-6">
          <label class="block text-sm text-gray-400 mb-1.5">Password</label>
          <input
            type="password" name="password" autocomplete="current-password" required
            class="w-full bg-gray-800 border border-gray-600 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-indigo-500 transition"/>
        </div>
        {err_block}
        <button type="submit"
          class="w-full bg-indigo-600 hover:bg-indigo-500 text-white text-sm font-medium py-2.5 rounded-lg transition mt-2">
          Sign in
        </button>
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
            return RedirectResponse(url="/dashboard", status_code=302)
    return HTMLResponse(content=_render_login())


@router.post("/login")
async def login_submit(username: str = Form(...), password: str = Form(...)):
    expected_user = os.getenv("DEEPINTEL_USERNAME", "admin")
    expected_pass = os.getenv("DEEPINTEL_PASSWORD", "")

    if not expected_pass:
        return HTMLResponse(content=_render_login("Server misconfiguration: password not set."), status_code=500)

    if username == expected_user and password == expected_pass:
        return make_session_response("/dashboard", username)

    return HTMLResponse(content=_render_login("Invalid username or password."), status_code=401)


@router.get("/logout")
@router.post("/logout")
async def logout():
    # 303 so a POST from the Sign out form lands on GET /login.
    resp = clear_session_response("/login")
    resp.status_code = 303
    return resp
