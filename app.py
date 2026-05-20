"""
API de Licenças — Wann Rodrigo
Hospedada no Render.com (free tier)

Endpoints:
  POST /validate     — App cliente valida chave + hardware
  GET  /admin        — Painel admin (lista chaves, ativa/desativa)
  POST /admin/create — Cria nova chave
  POST /admin/toggle — Ativa/desativa chave
  POST /admin/reset  — Reseta hardware (transfere chave pra outro PC)
"""

import os
import secrets
import sqlite3
import hashlib
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, render_template_string, redirect, url_for, session

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", secrets.token_hex(32))

# Senha admin (mude antes de hospedar — configure como variável de ambiente no Render)
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "Wann@2026")

DB_PATH = os.environ.get("DB_PATH", "licenses.db")


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with db() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS licenses (
            key TEXT PRIMARY KEY,
            owner TEXT NOT NULL,
            email TEXT,
            hardware_id TEXT,
            active INTEGER DEFAULT 1,
            created_at TEXT NOT NULL,
            last_check_at TEXT,
            last_ip TEXT,
            notes TEXT
        );
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT,
            hardware_id TEXT,
            ip TEXT,
            result TEXT,
            created_at TEXT NOT NULL
        );
        """)


# ─────────────────── CLIENTE ───────────────────
@app.route("/validate", methods=["POST"])
def validate():
    """O app cliente chama aqui pra validar."""
    data = request.get_json(force=True, silent=True) or {}
    key = (data.get("key") or "").strip().upper()
    hw_id = (data.get("hardware_id") or "").strip()
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "").split(",")[0].strip()

    if not key or not hw_id:
        _log(key, hw_id, ip, "missing_data")
        return jsonify({"ok": False, "reason": "missing_data"}), 400

    with db() as conn:
        row = conn.execute("SELECT * FROM licenses WHERE key = ?", (key,)).fetchone()

        if not row:
            _log(key, hw_id, ip, "invalid_key")
            return jsonify({"ok": False, "reason": "invalid_key"}), 403

        if not row["active"]:
            _log(key, hw_id, ip, "deactivated")
            return jsonify({"ok": False, "reason": "deactivated"}), 403

        # Primeira ativação: registra o hardware
        if not row["hardware_id"]:
            conn.execute(
                "UPDATE licenses SET hardware_id=?, last_check_at=?, last_ip=? WHERE key=?",
                (hw_id, datetime.utcnow().isoformat(), ip, key)
            )
            conn.commit()
            _log(key, hw_id, ip, "activated")
            return jsonify({
                "ok": True,
                "owner": row["owner"],
                "valid_until": (datetime.utcnow() + timedelta(days=1)).isoformat()
            })

        # Hardware bate?
        if row["hardware_id"] != hw_id:
            _log(key, hw_id, ip, "hardware_mismatch")
            return jsonify({"ok": False, "reason": "hardware_mismatch"}), 403

        # Tudo OK — atualiza último check
        conn.execute(
            "UPDATE licenses SET last_check_at=?, last_ip=? WHERE key=?",
            (datetime.utcnow().isoformat(), ip, key)
        )
        conn.commit()
        _log(key, hw_id, ip, "ok")
        return jsonify({
            "ok": True,
            "owner": row["owner"],
            "valid_until": (datetime.utcnow() + timedelta(days=1)).isoformat()
        })


def _log(key, hw_id, ip, result):
    try:
        with db() as conn:
            conn.execute(
                "INSERT INTO logs (key, hardware_id, ip, result, created_at) VALUES (?, ?, ?, ?, ?)",
                (key, hw_id, ip, result, datetime.utcnow().isoformat())
            )
            conn.commit()
    except: pass


# ─────────────────── PAINEL ADMIN ───────────────────
ADMIN_HTML = """
<!DOCTYPE html>
<html><head>
<meta charset="utf-8">
<title>Painel de Licenças — Wann</title>
<style>
body{font-family:-apple-system,sans-serif;max-width:1200px;margin:20px auto;padding:0 20px;background:#0f172a;color:#e2e8f0}
h1{color:#7c3aed}
table{width:100%;border-collapse:collapse;background:#1e293b;border-radius:8px;overflow:hidden}
th,td{padding:10px;text-align:left;border-bottom:1px solid #334155;font-size:13px}
th{background:#334155;color:#cbd5e1}
.active{color:#10b981;font-weight:bold}.inactive{color:#ef4444}
button,input,form{font:inherit}
button{background:#7c3aed;color:white;border:0;padding:6px 12px;border-radius:5px;cursor:pointer;margin:2px}
button.red{background:#ef4444}button.amber{background:#f59e0b}
input[type=text],input[type=email],input[type=password]{padding:8px;border:1px solid #334155;background:#0f172a;color:#e2e8f0;border-radius:5px;width:200px}
.card{background:#1e293b;padding:20px;border-radius:8px;margin:20px 0}
.log{font-size:11px;color:#94a3b8;font-family:Consolas,monospace}
</style></head><body>
<h1>🔑 Painel de Licenças</h1>

<div class="card">
<h3>➕ Criar nova chave</h3>
<form method="POST" action="/admin/create">
  <input name="owner" placeholder="Nome do usuário" required>
  <input name="email" type="email" placeholder="Email (opcional)">
  <input name="notes" placeholder="Notas (opcional)">
  <button type="submit">Gerar Chave</button>
</form>
</div>

<div class="card">
<h3>📋 Chaves ({{licenses|length}})</h3>
<table>
<tr><th>Chave</th><th>Dono</th><th>Status</th><th>Hardware</th><th>Último uso</th><th>IP</th><th>Ações</th></tr>
{% for l in licenses %}
<tr>
  <td><code>{{l.key}}</code></td>
  <td>{{l.owner}}{% if l.email %}<br><small>{{l.email}}</small>{% endif %}</td>
  <td class="{{'active' if l.active else 'inactive'}}">{{'✓ ATIVA' if l.active else '✗ INATIVA'}}</td>
  <td class="log">{{l.hardware_id[:16] + '...' if l.hardware_id else '(não usada)'}}</td>
  <td class="log">{{l.last_check_at[:16] if l.last_check_at else '-'}}</td>
  <td class="log">{{l.last_ip or '-'}}</td>
  <td>
    <form method="POST" action="/admin/toggle" style="display:inline">
      <input type="hidden" name="key" value="{{l.key}}">
      <button class="{{'red' if l.active else ''}}">{{'Desativar' if l.active else 'Ativar'}}</button>
    </form>
    {% if l.hardware_id %}
    <form method="POST" action="/admin/reset" style="display:inline" onsubmit="return confirm('Resetar hardware? Permite usar em outro PC.')">
      <input type="hidden" name="key" value="{{l.key}}">
      <button class="amber">Resetar HW</button>
    </form>
    {% endif %}
    <form method="POST" action="/admin/delete" style="display:inline" onsubmit="return confirm('DELETAR esta chave permanentemente?')">
      <input type="hidden" name="key" value="{{l.key}}">
      <button class="red">🗑</button>
    </form>
  </td>
</tr>
{% endfor %}
</table>
</div>

<div class="card">
<h3>📜 Últimos 50 acessos</h3>
<table>
<tr><th>Quando</th><th>Chave</th><th>Hardware</th><th>IP</th><th>Resultado</th></tr>
{% for log in logs %}
<tr>
  <td class="log">{{log.created_at[:19]}}</td>
  <td class="log">{{log.key or '-'}}</td>
  <td class="log">{{(log.hardware_id or '-')[:16]}}{{'...' if log.hardware_id and log.hardware_id|length > 16}}</td>
  <td class="log">{{log.ip or '-'}}</td>
  <td class="{{'active' if log.result == 'ok' or log.result == 'activated' else 'inactive'}}">{{log.result}}</td>
</tr>
{% endfor %}
</table>
</div>

<p><a href="/admin/logout" style="color:#94a3b8">Sair</a></p>
</body></html>
"""

LOGIN_HTML = """
<!DOCTYPE html><html><head><meta charset="utf-8"><title>Login</title>
<style>body{font-family:sans-serif;max-width:400px;margin:100px auto;background:#0f172a;color:#e2e8f0;padding:20px}
input{padding:10px;width:100%;margin:8px 0;border:1px solid #334155;background:#1e293b;color:#e2e8f0;border-radius:5px;box-sizing:border-box}
button{padding:10px 20px;background:#7c3aed;color:white;border:0;border-radius:5px;cursor:pointer;width:100%;font-size:14px;font-weight:bold}
</style></head><body>
<h2>🔑 Painel de Licenças</h2>
<form method="POST"><input name="password" type="password" placeholder="Senha admin" autofocus required><button>Entrar</button></form>
{% if erro %}<p style="color:#ef4444">{{erro}}</p>{% endif %}
</body></html>
"""


@app.route("/admin", methods=["GET", "POST"])
def admin_panel():
    if request.method == "POST" and not session.get("admin"):
        if request.form.get("password") == ADMIN_PASSWORD:
            session["admin"] = True
            return redirect(url_for("admin_panel"))
        return render_template_string(LOGIN_HTML, erro="Senha incorreta")

    if not session.get("admin"):
        return render_template_string(LOGIN_HTML)

    with db() as conn:
        licenses = conn.execute("SELECT * FROM licenses ORDER BY created_at DESC").fetchall()
        logs = conn.execute("SELECT * FROM logs ORDER BY id DESC LIMIT 50").fetchall()

    return render_template_string(ADMIN_HTML,
        licenses=[dict(l) for l in licenses],
        logs=[dict(l) for l in logs])


@app.route("/admin/create", methods=["POST"])
def admin_create():
    if not session.get("admin"):
        return redirect(url_for("admin_panel"))
    owner = request.form.get("owner", "").strip()
    email = request.form.get("email", "").strip()
    notes = request.form.get("notes", "").strip()
    if not owner:
        return redirect(url_for("admin_panel"))

    # Gera chave no formato WANN-2026-XXXX-YYYY
    rand1 = secrets.token_hex(2).upper()
    rand2 = secrets.token_hex(2).upper()
    year = datetime.utcnow().year
    key = f"WANN-{year}-{rand1}-{rand2}"

    with db() as conn:
        conn.execute(
            "INSERT INTO licenses (key, owner, email, notes, created_at) VALUES (?, ?, ?, ?, ?)",
            (key, owner, email, notes, datetime.utcnow().isoformat())
        )
        conn.commit()

    return redirect(url_for("admin_panel"))


@app.route("/admin/toggle", methods=["POST"])
def admin_toggle():
    if not session.get("admin"):
        return redirect(url_for("admin_panel"))
    key = request.form.get("key")
    with db() as conn:
        conn.execute("UPDATE licenses SET active = NOT active WHERE key = ?", (key,))
        conn.commit()
    return redirect(url_for("admin_panel"))


@app.route("/admin/reset", methods=["POST"])
def admin_reset():
    if not session.get("admin"):
        return redirect(url_for("admin_panel"))
    key = request.form.get("key")
    with db() as conn:
        conn.execute("UPDATE licenses SET hardware_id = NULL WHERE key = ?", (key,))
        conn.commit()
    return redirect(url_for("admin_panel"))


@app.route("/admin/delete", methods=["POST"])
def admin_delete():
    if not session.get("admin"):
        return redirect(url_for("admin_panel"))
    key = request.form.get("key")
    with db() as conn:
        conn.execute("DELETE FROM licenses WHERE key = ?", (key,))
        conn.commit()
    return redirect(url_for("admin_panel"))


@app.route("/admin/logout")
def admin_logout():
    session.pop("admin", None)
    return redirect(url_for("admin_panel"))


@app.route("/")
def index():
    return "API Wann v1.0"


if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
else:
    init_db()
