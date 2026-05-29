"""
Entra ID OIDC Connection Tester
A simple app to test OIDC connections with Microsoft Entra ID (Azure AD) app registrations.

Requirements:
    pip install msal requests

Usage:
    python entra_oidc_tester.py
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import json
import webbrowser
import urllib.parse
import http.server
import socketserver
import requests
import os
import base64
import hashlib
import secrets
import time

try:
    import msal
    MSAL_AVAILABLE = True
except ImportError:
    MSAL_AVAILABLE = False


# ─── Config persistence ────────────────────────────────────────────────────────

CONFIG_FILE = os.path.expanduser("~/.entra_oidc_tester.json")

def load_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE) as f:
                return json.load(f)
        except Exception:
            pass
    return {}

def save_config(data):
    try:
        with open(CONFIG_FILE, "w") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass


# ─── PKCE helpers ──────────────────────────────────────────────────────────────

def generate_pkce():
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return verifier, challenge


# ─── Local callback server ─────────────────────────────────────────────────────

class CallbackHandler(http.server.BaseHTTPRequestHandler):
    code = None
    error = None

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        if "code" in params:
            CallbackHandler.code = params["code"][0]
            body = b"<html><body><h2>Login successful!</h2><p>You may close this tab.</p></body></html>"
        elif "error" in params:
            CallbackHandler.error = params.get("error_description", params.get("error", ["Unknown error"]))[0]
            body = b"<html><body><h2>Login failed.</h2><p>You may close this tab.</p></body></html>"
        else:
            body = b"<html><body><p>Waiting...</p></body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass  # silence server logs


def wait_for_callback(port, timeout=120):
    CallbackHandler.code = None
    CallbackHandler.error = None
    with socketserver.TCPServer(("127.0.0.1", port), CallbackHandler) as httpd:
        httpd.timeout = timeout
        start = time.time()
        while CallbackHandler.code is None and CallbackHandler.error is None:
            if time.time() - start > timeout:
                return None, "Timed out waiting for callback"
            httpd.handle_request()
    return CallbackHandler.code, CallbackHandler.error


# ─── Main Application ──────────────────────────────────────────────────────────

class OIDCTesterApp(tk.Tk):
    DARK_BG      = "#0f1117"
    PANEL_BG     = "#1a1d27"
    BORDER       = "#2a2d3a"
    ACCENT       = "#3b82f6"
    ACCENT_HOVER = "#2563eb"
    SUCCESS      = "#22c55e"
    DANGER       = "#ef4444"
    TEXT_PRIMARY = "#f1f5f9"
    TEXT_MUTED   = "#64748b"
    INPUT_BG     = "#0f1117"
    FONT_MONO    = ("Courier New", 10)

    def __init__(self):
        super().__init__()
        self.title("Entra ID · OIDC Tester")
        self.configure(bg=self.DARK_BG)
        self.resizable(True, True)
        self.minsize(780, 640)

        self._token_data = None
        self._user_info  = None

        cfg = load_config()
        self._build_ui(cfg)
        self._set_status("Ready. Enter your OIDC configuration and click Login.", "muted")

    # ── UI construction ────────────────────────────────────────────────────────

    def _build_ui(self, cfg):
        # ── top bar ──
        top = tk.Frame(self, bg=self.DARK_BG)
        top.pack(fill="x", padx=0, pady=0)

        title_bar = tk.Frame(top, bg=self.DARK_BG)
        title_bar.pack(fill="x", padx=24, pady=(20, 4))

        tk.Label(
            title_bar, text="⬡  OIDC TESTER",
            bg=self.DARK_BG, fg=self.ACCENT,
            font=("Courier New", 13, "bold"), anchor="w"
        ).pack(side="left")

        tk.Label(
            title_bar, text="Microsoft Entra ID",
            bg=self.DARK_BG, fg=self.TEXT_MUTED,
            font=("Courier New", 10), anchor="e"
        ).pack(side="right")

        tk.Frame(self, bg=self.BORDER, height=1).pack(fill="x")

        # ── main body ──
        body = tk.Frame(self, bg=self.DARK_BG)
        body.pack(fill="both", expand=True, padx=24, pady=20)
        body.columnconfigure(0, weight=1)
        body.columnconfigure(1, weight=1)
        body.rowconfigure(1, weight=1)

        # Left: config panel
        self._build_config_panel(body, cfg)

        # Right: result panel
        self._build_result_panel(body)

        # Bottom: status bar
        self._build_status_bar()

    def _section_label(self, parent, text):
        tk.Label(
            parent, text=text,
            bg=self.PANEL_BG, fg=self.TEXT_MUTED,
            font=("Courier New", 9, "bold"), anchor="w"
        ).pack(fill="x", pady=(14, 4))

    def _field(self, parent, label, var, show=None):
        tk.Label(
            parent, text=label,
            bg=self.PANEL_BG, fg=self.TEXT_PRIMARY,
            font=("Courier New", 10), anchor="w"
        ).pack(fill="x")
        kwargs = dict(
            textvariable=var,
            bg=self.INPUT_BG, fg=self.TEXT_PRIMARY,
            insertbackground=self.TEXT_PRIMARY,
            relief="flat", bd=0,
            font=("Courier New", 10),
            highlightthickness=1,
            highlightbackground=self.BORDER,
            highlightcolor=self.ACCENT,
        )
        if show:
            kwargs["show"] = show
        e = tk.Entry(parent, **kwargs)
        e.pack(fill="x", ipady=6, pady=(2, 0))
        return e

    def _build_config_panel(self, parent, cfg):
        outer = tk.Frame(parent, bg=self.PANEL_BG,
                         highlightthickness=1, highlightbackground=self.BORDER)
        outer.grid(row=0, column=0, sticky="nsew", padx=(0, 10), pady=(0, 10), rowspan=2)

        canvas = tk.Canvas(outer, bg=self.PANEL_BG, bd=0,
                           highlightthickness=0)
        scroll = ttk.Scrollbar(outer, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)

        inner = tk.Frame(canvas, bg=self.PANEL_BG)
        win_id = canvas.create_window((0, 0), window=inner, anchor="nw")

        def _resize(e):
            canvas.itemconfig(win_id, width=e.width)
        canvas.bind("<Configure>", _resize)

        def _scroll_region(e):
            canvas.configure(scrollregion=canvas.bbox("all"))
        inner.bind("<Configure>", _scroll_region)

        pad = tk.Frame(inner, bg=self.PANEL_BG)
        pad.pack(fill="both", expand=True, padx=16, pady=12)

        tk.Label(
            pad, text="Configuration",
            bg=self.PANEL_BG, fg=self.TEXT_PRIMARY,
            font=("Courier New", 12, "bold"), anchor="w"
        ).pack(fill="x")

        # ── Entra ID fields ──
        self._section_label(pad, "─── Entra ID / App Registration")

        self.v_tenant    = tk.StringVar(value=cfg.get("tenant_id", ""))
        self.v_client_id = tk.StringVar(value=cfg.get("client_id", ""))
        self.v_secret    = tk.StringVar(value=cfg.get("client_secret", ""))

        self._field(pad, "Tenant ID  (or 'common' / 'organizations')", self.v_tenant)
        self._field(pad, "Client ID  (Application ID)", self.v_client_id)
        self._field(pad, "Client Secret  (leave blank for PKCE / public client)",
                    self.v_secret, show="•")

        # ── OIDC settings ──
        self._section_label(pad, "─── OIDC / OAuth2 Settings")

        self.v_redirect   = tk.StringVar(value=cfg.get("redirect_uri",  "http://localhost:8765/callback"))
        self.v_scopes     = tk.StringVar(value=cfg.get("scopes",        "openid profile email"))
        self.v_port       = tk.StringVar(value=str(cfg.get("port",      8765)))

        self._field(pad, "Redirect URI", self.v_redirect)
        self._field(pad, "Scopes  (space-separated)", self.v_scopes)
        self._field(pad, "Callback Port", self.v_port)

        # ── flow choice ──
        self._section_label(pad, "─── Auth Flow")
        self.v_flow = tk.StringVar(value=cfg.get("flow", "Authorization Code + PKCE"))
        flows = ["Authorization Code + PKCE", "Authorization Code (client secret)",
                 "Client Credentials"]
        for f in flows:
            rb = tk.Radiobutton(
                pad, text=f, variable=self.v_flow, value=f,
                bg=self.PANEL_BG, fg=self.TEXT_PRIMARY,
                selectcolor=self.INPUT_BG, activebackground=self.PANEL_BG,
                activeforeground=self.TEXT_PRIMARY,
                font=("Courier New", 10), anchor="w"
            )
            rb.pack(fill="x", pady=1)

        # ── buttons ──
        btn_frame = tk.Frame(pad, bg=self.PANEL_BG)
        btn_frame.pack(fill="x", pady=(18, 4))

        self.btn_login = self._button(btn_frame, "▶  Login", self._do_login,
                                      self.ACCENT, "#fff")
        self.btn_login.pack(fill="x", pady=(0, 8))

        self.btn_logout = self._button(btn_frame, "✕  Logout", self._do_logout,
                                       self.PANEL_BG, self.DANGER,
                                       border_color=self.DANGER)
        self.btn_logout.pack(fill="x")
        self.btn_logout.config(state="disabled")

    def _build_result_panel(self, parent):
        outer = tk.Frame(parent, bg=self.PANEL_BG,
                         highlightthickness=1, highlightbackground=self.BORDER)
        outer.grid(row=0, column=1, sticky="nsew", pady=(0, 10), rowspan=2)

        header = tk.Frame(outer, bg=self.PANEL_BG)
        header.pack(fill="x", padx=16, pady=(14, 0))

        tk.Label(
            header, text="Result",
            bg=self.PANEL_BG, fg=self.TEXT_PRIMARY,
            font=("Courier New", 12, "bold"), anchor="w"
        ).pack(side="left")

        self.lbl_status_dot = tk.Label(
            header, text="●", bg=self.PANEL_BG, fg=self.TEXT_MUTED,
            font=("Courier New", 14)
        )
        self.lbl_status_dot.pack(side="right")

        ttk.Separator(outer, orient="horizontal").pack(fill="x", padx=16, pady=8)

        # User info card
        self.user_card = tk.Frame(outer, bg=self.INPUT_BG,
                                  highlightthickness=1, highlightbackground=self.BORDER)
        self.user_card.pack(fill="x", padx=16)

        self.lbl_user_name = tk.Label(
            self.user_card, text="Not logged in",
            bg=self.INPUT_BG, fg=self.TEXT_MUTED,
            font=("Courier New", 11, "bold"), anchor="w"
        )
        self.lbl_user_name.pack(fill="x", padx=12, pady=(10, 2))

        self.lbl_user_email = tk.Label(
            self.user_card, text="",
            bg=self.INPUT_BG, fg=self.TEXT_MUTED,
            font=("Courier New", 10), anchor="w"
        )
        self.lbl_user_email.pack(fill="x", padx=12, pady=(0, 10))

        # Token tabs
        tab_bar = tk.Frame(outer, bg=self.PANEL_BG)
        tab_bar.pack(fill="x", padx=16, pady=(12, 0))

        self._active_tab = tk.StringVar(value="id_token")

        for tab_id, tab_label in [("id_token", "ID Token"),
                                  ("access_token", "Access Token"),
                                  ("userinfo", "UserInfo")]:
            btn = tk.Button(
                tab_bar, text=tab_label,
                bg=self.PANEL_BG, fg=self.TEXT_MUTED,
                relief="flat", bd=0,
                font=("Courier New", 10),
                cursor="hand2",
                command=lambda t=tab_id: self._switch_tab(t)
            )
            btn.pack(side="left", padx=(0, 4))
            # store reference
            setattr(self, f"tab_btn_{tab_id}", btn)

        self._switch_tab("id_token")  # set initial active style

        self.txt_result = scrolledtext.ScrolledText(
            outer,
            bg=self.INPUT_BG, fg=self.TEXT_PRIMARY,
            font=self.FONT_MONO,
            relief="flat", bd=0,
            insertbackground=self.TEXT_PRIMARY,
            wrap="word",
            state="disabled"
        )
        self.txt_result.pack(fill="both", expand=True, padx=16, pady=(8, 16))

        # Copy button
        copy_row = tk.Frame(outer, bg=self.PANEL_BG)
        copy_row.pack(fill="x", padx=16, pady=(0, 12))

        self._button(copy_row, "⎘  Copy", self._copy_result,
                     self.PANEL_BG, self.TEXT_MUTED, border_color=self.BORDER).pack(side="right")

    def _build_status_bar(self):
        bar = tk.Frame(self, bg=self.PANEL_BG,
                       highlightthickness=1, highlightbackground=self.BORDER)
        bar.pack(fill="x", side="bottom")

        self.lbl_statusbar = tk.Label(
            bar, text="",
            bg=self.PANEL_BG, fg=self.TEXT_MUTED,
            font=("Courier New", 9), anchor="w"
        )
        self.lbl_statusbar.pack(side="left", padx=16, pady=6)

    # ── Reusable button ────────────────────────────────────────────────────────

    def _button(self, parent, text, command, bg, fg, border_color=None):
        bc = border_color or bg
        btn = tk.Button(
            parent, text=text, command=command,
            bg=bg, fg=fg,
            activebackground=self.ACCENT_HOVER, activeforeground="#fff",
            relief="flat", bd=0,
            font=("Courier New", 10, "bold"),
            cursor="hand2",
            padx=12, pady=8,
            highlightthickness=1,
            highlightbackground=bc,
            highlightcolor=bc,
        )
        return btn

    # ── Tab switching ──────────────────────────────────────────────────────────

    def _switch_tab(self, tab_id):
        self._active_tab.set(tab_id)
        for t in ("id_token", "access_token", "userinfo"):
            btn = getattr(self, f"tab_btn_{t}", None)
            if btn:
                if t == tab_id:
                    btn.config(fg=self.ACCENT,
                               font=("Courier New", 10, "bold"))
                else:
                    btn.config(fg=self.TEXT_MUTED,
                               font=("Courier New", 10))
        self._refresh_result_tab()

    def _refresh_result_tab(self):
        if not self._token_data:
            return
        tab = self._active_tab.get()
        if tab == "id_token":
            self._show_token(self._token_data.get("id_token", "(none)"), "ID Token")
        elif tab == "access_token":
            self._show_token(self._token_data.get("access_token", "(none)"), "Access Token")
        elif tab == "userinfo":
            if self._user_info:
                self._set_result(json.dumps(self._user_info, indent=2))
            else:
                self._set_result("(UserInfo not fetched — requires openid scope and access token)")

    # ── Status helpers ─────────────────────────────────────────────────────────

    def _set_status(self, msg, kind="muted"):
        colour = {"muted": self.TEXT_MUTED,
                  "success": self.SUCCESS,
                  "error": self.DANGER,
                  "info": self.ACCENT}.get(kind, self.TEXT_MUTED)
        self.lbl_statusbar.config(text=msg, fg=colour)
        dot_colour = {"success": self.SUCCESS, "error": self.DANGER,
                      "info": self.ACCENT}.get(kind, self.TEXT_MUTED)
        self.lbl_status_dot.config(fg=dot_colour)

    def _set_result(self, text):
        self.txt_result.config(state="normal")
        self.txt_result.delete("1.0", "end")
        self.txt_result.insert("end", text)
        self.txt_result.config(state="disabled")

    def _show_token(self, token, label):
        if not token or token == "(none)":
            self._set_result(f"No {label} available.")
            return
        parts = token.split(".")
        if len(parts) == 3:
            try:
                payload_b64 = parts[1] + "=="
                payload = json.loads(base64.urlsafe_b64decode(payload_b64))
                display = (
                    f"── Raw Token ──────────────────────────────────────────\n"
                    f"{token}\n\n"
                    f"── Decoded Payload ────────────────────────────────────\n"
                    f"{json.dumps(payload, indent=2)}"
                )
                self._set_result(display)
                return
            except Exception:
                pass
        self._set_result(token)

    # ── Auth logic ─────────────────────────────────────────────────────────────

    def _collect_config(self):
        return {
            "tenant_id":     self.v_tenant.get().strip(),
            "client_id":     self.v_client_id.get().strip(),
            "client_secret": self.v_secret.get().strip(),
            "redirect_uri":  self.v_redirect.get().strip(),
            "scopes":        self.v_scopes.get().strip().split(),
            "port":          int(self.v_port.get().strip() or "8765"),
            "flow":          self.v_flow.get(),
        }

    def _do_login(self):
        cfg = self._collect_config()
        if not cfg["tenant_id"] or not cfg["client_id"]:
            messagebox.showerror("Missing config", "Tenant ID and Client ID are required.")
            return
        save_config({
            "tenant_id": cfg["tenant_id"],
            "client_id": cfg["client_id"],
            "redirect_uri": cfg["redirect_uri"],
            "scopes": " ".join(cfg["scopes"]),
            "port": cfg["port"],
            "flow": cfg["flow"],
        })
        self.btn_login.config(state="disabled", text="⏳  Logging in…")
        self._set_status("Starting authentication flow…", "info")
        threading.Thread(target=self._auth_thread, args=(cfg,), daemon=True).start()

    def _auth_thread(self, cfg):
        try:
            flow = cfg["flow"]
            if flow == "Client Credentials":
                self._flow_client_credentials(cfg)
            elif flow == "Authorization Code (client secret)":
                self._flow_auth_code(cfg, pkce=False)
            else:
                self._flow_auth_code(cfg, pkce=True)
        except Exception as ex:
            self.after(0, self._on_auth_error, str(ex))

    def _flow_auth_code(self, cfg, pkce=True):
        authority = f"https://login.microsoftonline.com/{cfg['tenant_id']}"
        auth_ep   = f"{authority}/oauth2/v2.0/authorize"
        token_ep  = f"{authority}/oauth2/v2.0/token"

        state        = secrets.token_urlsafe(16)
        verifier, challenge = generate_pkce() if pkce else (None, None)

        params = {
            "client_id":     cfg["client_id"],
            "response_type": "code",
            "redirect_uri":  cfg["redirect_uri"],
            "response_mode": "query",
            "scope":         " ".join(cfg["scopes"]),
            "state":         state,
        }
        if pkce:
            params["code_challenge"]        = challenge
            params["code_challenge_method"] = "S256"

        auth_url = auth_ep + "?" + urllib.parse.urlencode(params)
        self.after(0, self._set_status, f"Opening browser…", "info")
        webbrowser.open(auth_url)

        code, error = wait_for_callback(cfg["port"])
        if error:
            raise RuntimeError(f"Auth callback error: {error}")
        if not code:
            raise RuntimeError("No authorization code received.")

        # Exchange code for tokens
        data = {
            "client_id":    cfg["client_id"],
            "grant_type":   "authorization_code",
            "code":         code,
            "redirect_uri": cfg["redirect_uri"],
            "scope":        " ".join(cfg["scopes"]),
        }
        if pkce:
            data["code_verifier"] = verifier
        if not pkce and cfg.get("client_secret"):
            data["client_secret"] = cfg["client_secret"]

        resp = requests.post(token_ep, data=data, timeout=15)
        self._handle_token_response(resp, cfg)

    def _flow_client_credentials(self, cfg):
        authority = f"https://login.microsoftonline.com/{cfg['tenant_id']}"
        token_ep  = f"{authority}/oauth2/v2.0/token"

        scopes = [s for s in cfg["scopes"] if s not in ("openid", "profile", "email", "offline_access")]
        if not scopes:
            scopes = [f"api://{cfg['client_id']}/.default"]

        data = {
            "client_id":     cfg["client_id"],
            "client_secret": cfg["client_secret"],
            "grant_type":    "client_credentials",
            "scope":         " ".join(scopes),
        }
        resp = requests.post(token_ep, data=data, timeout=15)
        self._handle_token_response(resp, cfg)

    def _handle_token_response(self, resp, cfg):
        try:
            token_data = resp.json()
        except Exception:
            raise RuntimeError(f"Non-JSON response ({resp.status_code}): {resp.text[:300]}")

        if "error" in token_data:
            desc = token_data.get("error_description", token_data["error"])
            raise RuntimeError(f"Token error: {desc}")

        # Fetch UserInfo if we have an access token and openid scope
        user_info = None
        if "access_token" in token_data and "openid" in cfg.get("scopes", []):
            try:
                authority = f"https://login.microsoftonline.com/{cfg['tenant_id']}"
                ui_resp = requests.get(
                    f"{authority}/oidc/userinfo",
                    headers={"Authorization": f"Bearer {token_data['access_token']}"},
                    timeout=10
                )
                if ui_resp.status_code == 200:
                    user_info = ui_resp.json()
            except Exception:
                pass

        self.after(0, self._on_auth_success, token_data, user_info)

    def _on_auth_success(self, token_data, user_info):
        self._token_data = token_data
        self._user_info  = user_info

        # Extract display name / email from id_token
        name, email = "Authenticated", ""
        if user_info:
            name  = user_info.get("name", user_info.get("preferred_username", name))
            email = user_info.get("email", user_info.get("preferred_username", ""))
        elif "id_token" in token_data:
            try:
                parts   = token_data["id_token"].split(".")
                payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
                name    = payload.get("name", payload.get("preferred_username", name))
                email   = payload.get("email", payload.get("preferred_username", ""))
            except Exception:
                pass

        self.lbl_user_name.config(text=name, fg=self.SUCCESS)
        self.lbl_user_email.config(text=email, fg=self.TEXT_MUTED)
        self._set_status("Authentication successful ✓", "success")
        self.btn_login.config(state="disabled", text="▶  Login")
        self.btn_logout.config(state="normal")
        self._refresh_result_tab()

    def _on_auth_error(self, msg):
        self._set_status(f"Error: {msg}", "error")
        self._set_result(f"Authentication failed:\n\n{msg}")
        self.btn_login.config(state="normal", text="▶  Login")

    def _do_logout(self):
        self._token_data = None
        self._user_info  = None
        self.lbl_user_name.config(text="Not logged in", fg=self.TEXT_MUTED)
        self.lbl_user_email.config(text="")
        self._set_result("")
        self._set_status("Logged out.", "muted")
        self.btn_logout.config(state="disabled")
        self.btn_login.config(state="normal", text="▶  Login")

        # Open Entra logout page
        tenant = self.v_tenant.get().strip() or "common"
        webbrowser.open(
            f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/logout"
        )

    def _copy_result(self):
        content = self.txt_result.get("1.0", "end").strip()
        if content:
            self.clipboard_clear()
            self.clipboard_append(content)
            self._set_status("Copied to clipboard.", "info")


# ─── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if not MSAL_AVAILABLE:
        print("Note: 'msal' is not installed. Install it with:  pip install msal requests")

    app = OIDCTesterApp()
    app.mainloop()
