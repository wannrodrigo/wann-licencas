"""
API de Licenças — Wann Studio
Hospedada no Render.com + Postgres persistente (Neon/Supabase)

Persistência: usa Postgres via DATABASE_URL (NUNCA mais perde chave em restart).
Planos: cada chave pode ser vitalícia (sem validade) ou ter vencimento (mensal/anual).

Endpoints:
  POST /validate     — App cliente valida chave + hardware
  GET  /admin        — Painel admin (lista chaves, ativa/desativa, validade)
  POST /admin/create — Cria nova chave (com validade opcional em dias)
  POST /admin/toggle — Ativa/desativa chave
  POST /admin/reset  — Reseta hardware (transfere chave pra outro PC)
  POST /admin/extend — Estende/define validade
  POST /admin/delete — Remove chave
"""

import os
import secrets
import contextlib
from datetime import datetime, timedelta

import psycopg2
from psycopg2.extras import RealDictCursor
from flask import Flask, request, jsonify, render_template_string, redirect, url_for, session

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", secrets.token_hex(32))

ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "Wann@2026")
DATABASE_URL = os.environ.get("DATABASE_URL", "")


# ─────────────────── BANCO (Postgres) ───────────────────
@contextlib.contextmanager
def db():
    conn = psycopg2.connect(DATABASE_URL)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def q(sql, params=(), fetch=None):
    with db() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(sql, params)
            if fetch == "one":
                return cur.fetchone()
            if fetch == "all":
                return cur.fetchall()
    return None


def init_db():
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS licenses (
                    key TEXT PRIMARY KEY,
                    owner TEXT NOT NULL,
                    email TEXT,
                    hardware_id TEXT,
                    active BOOLEAN DEFAULT TRUE,
                    created_at TEXT NOT NULL,
                    last_check_at TEXT,
                    last_ip TEXT,
                    expires_at TEXT,
                    notes TEXT
                );
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS logs (
                    id SERIAL PRIMARY KEY,
                    key TEXT,
                    hardware_id TEXT,
                    ip TEXT,
                    result TEXT,
                    created_at TEXT NOT NULL
                );
            """)
            # Migração defensiva (se a tabela já existir sem a coluna)
            cur.execute("ALTER TABLE licenses ADD COLUMN IF NOT EXISTS expires_at TEXT;")


def _log(key, hw_id, ip, result):
    try:
        q("INSERT INTO logs (key, hardware_id, ip, result, created_at) VALUES (%s,%s,%s,%s,%s)",
          (key, hw_id, ip, result, datetime.utcnow().isoformat()))
    except Exception:
        pass


def _expirada(expires_at):
    if not expires_at:
        return False
    try:
        return datetime.utcnow() > datetime.fromisoformat(expires_at)
    except Exception:
        return False


# ─────────────────── CLIENTE ───────────────────
@app.route("/validate", methods=["POST"])
def validate():
    data = request.get_json(force=True, silent=True) or {}
    key = (data.get("key") or "").strip().upper()
    hw_id = (data.get("hardware_id") or "").strip()
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "").split(",")[0].strip()

    if not key or not hw_id:
        _log(key, hw_id, ip, "missing_data")
        return jsonify({"ok": False, "reason": "missing_data"}), 400

    row = q("SELECT * FROM licenses WHERE key=%s", (key,), fetch="one")

    if not row:
        _log(key, hw_id, ip, "invalid_key")
        return jsonify({"ok": False, "reason": "invalid_key"}), 403

    if not row["active"]:
        _log(key, hw_id, ip, "deactivated")
        return jsonify({"ok": False, "reason": "deactivated"}), 403

    if _expirada(row["expires_at"]):
        _log(key, hw_id, ip, "expired")
        return jsonify({"ok": False, "reason": "expired"}), 403

    now = datetime.utcnow().isoformat()

    # Primeira ativação: registra o hardware
    if not row["hardware_id"]:
        q("UPDATE licenses SET hardware_id=%s, last_check_at=%s, last_ip=%s WHERE key=%s",
          (hw_id, now, ip, key))
        _log(key, hw_id, ip, "activated")
        return jsonify({"ok": True, "owner": row["owner"],
                        "expires_at": row["expires_at"],
                        "valid_until": (datetime.utcnow() + timedelta(days=1)).isoformat()})

    # Hardware bate?
    if row["hardware_id"] != hw_id:
        _log(key, hw_id, ip, "hardware_mismatch")
        return jsonify({"ok": False, "reason": "hardware_mismatch"}), 403

    # Tudo OK
    q("UPDATE licenses SET last_check_at=%s, last_ip=%s WHERE key=%s", (now, ip, key))
    _log(key, hw_id, ip, "ok")
    return jsonify({"ok": True, "owner": row["owner"],
                    "expires_at": row["expires_at"],
                    "valid_until": (datetime.utcnow() + timedelta(days=1)).isoformat()})


# ─────────────────── PAINEL ADMIN ───────────────────
ADMIN_HTML = """
<!DOCTYPE html>
<html><head>
<meta charset="utf-8">
<title>Wann Studio — Licenças</title>
<style>
body{font-family:-apple-system,sans-serif;max-width:1280px;margin:20px auto;padding:0 20px;background:#0f172a;color:#e2e8f0}
h1{color:#7c3aed}
table{width:100%;border-collapse:collapse;background:#1e293b;border-radius:8px;overflow:hidden}
th,td{padding:10px;text-align:left;border-bottom:1px solid #334155;font-size:13px}
th{background:#334155;color:#cbd5e1}
.active{color:#10b981;font-weight:bold}.inactive{color:#ef4444}.warn{color:#f59e0b}
button,input,form,select{font:inherit}
button{background:#7c3aed;color:white;border:0;padding:6px 12px;border-radius:5px;cursor:pointer;margin:2px}
button.red{background:#ef4444}button.amber{background:#f59e0b}
input,select{padding:8px;border:1px solid #334155;background:#0f172a;color:#e2e8f0;border-radius:5px}
input[type=text],input[type=email]{width:180px}
.card{background:#1e293b;padding:20px;border-radius:8px;margin:20px 0}
.log{font-size:11px;color:#94a3b8;font-family:Consolas,monospace}
</style></head><body>
<h1>🔑 Wann Studio — Licenças</h1>

<div class="card">
<h3>➕ Criar nova chave</h3>
<form method="POST" action="/admin/create">
  <input name="owner" placeholder="Nome do usuário" required>
  <input name="email" type="email" placeholder="Email (opcional)">
  <input name="dias" type="number" min="0" placeholder="Validade (dias)" style="width:130px">
  <input name="notes" placeholder="Notas (opcional)">
  <button type="submit">Gerar Chave</button>
</form>
<small style="color:#94a3b8">Validade vazia ou 0 = vitalícia (ativa até você desativar). 30 = mensal, 365 = anual.</small>
</div>

<div class="card">
<h3>📋 Chaves ({{licenses|length}})</h3>
<table>
<tr><th>Chave</th><th>Dono</th><th>Status</th><th>Validade</th><th>Hardware</th><th>Último uso</th><th>Ações</th></tr>
{% for l in licenses %}
<tr>
  <td><code>{{l.key}}</code></td>
  <td>{{l.owner}}{% if l.email %}<br><small>{{l.email}}</small>{% endif %}</td>
  <td class="{{'active' if l.active else 'inactive'}}">{{'✓ ATIVA' if l.active else '✗ INATIVA'}}</td>
  <td class="{{l.val_cls}}">{{l.val_txt}}</td>
  <td class="log">{{l.hardware_id[:16] + '...' if l.hardware_id else '(não usada)'}}</td>
  <td class="log">{{l.last_check_at[:16] if l.last_check_at else '-'}}</td>
  <td>
    <form method="POST" action="/admin/toggle" style="display:inline">
      <input type="hidden" name="key" value="{{l.key}}">
      <button class="{{'red' if l.active else ''}}">{{'Desativar' if l.active else 'Ativar'}}</button>
    </form>
    <form method="POST" action="/admin/extend" style="display:inline">
      <input type="hidden" name="key" value="{{l.key}}">
      <input name="dias" type="number" min="0" placeholder="dias" style="width:70px">
      <button class="amber">Validade</button>
    </form>
    {% if l.hardware_id %}
    <form method="POST" action="/admin/reset" style="display:inline" onsubmit="return confirm('Resetar hardware? Permite usar em outro PC.')">
      <input type="hidden" name="key" value="{{l.key}}">
      <button class="amber">Reset HW</button>
    </form>
    {% endif %}
    <form method="POST" action="/admin/delete" style="display:inline" onsubmit="return confirm('DELETAR esta chave?')">
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
  <td class="log">{{(log.hardware_id or '-')[:16]}}</td>
  <td class="log">{{log.ip or '-'}}</td>
  <td class="{{'active' if log.result in ('ok','activated') else 'inactive'}}">{{log.result}}</td>
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
<h2>🔑 Wann Studio — Licenças</h2>
<form method="POST"><input name="password" type="password" placeholder="Senha admin" autofocus required><button>Entrar</button></form>
{% if erro %}<p style="color:#ef4444">{{erro}}</p>{% endif %}
</body></html>
"""


def _val_info(expires_at):
    """Texto + classe CSS para a coluna Validade."""
    if not expires_at:
        return "Vitalícia", ""
    try:
        dt = datetime.fromisoformat(expires_at)
    except Exception:
        return expires_at, ""
    dias = (dt - datetime.utcnow()).days
    if dias < 0:
        return f"Expirada ({dt.date()})", "inactive"
    if dias <= 7:
        return f"{dt.date()} ({dias}d)", "warn"
    return f"{dt.date()} ({dias}d)", "active"


@app.route("/admin", methods=["GET", "POST"])
def admin_panel():
    if request.method == "POST" and not session.get("admin"):
        if request.form.get("password") == ADMIN_PASSWORD:
            session["admin"] = True
            return redirect(url_for("admin_panel"))
        return render_template_string(LOGIN_HTML, erro="Senha incorreta")

    if not session.get("admin"):
        return render_template_string(LOGIN_HTML)

    licenses = q("SELECT * FROM licenses ORDER BY created_at DESC", fetch="all") or []
    logs = q("SELECT * FROM logs ORDER BY id DESC LIMIT 50", fetch="all") or []

    lic_list = []
    for l in licenses:
        d = dict(l)
        d["val_txt"], d["val_cls"] = _val_info(d.get("expires_at"))
        lic_list.append(d)

    return render_template_string(ADMIN_HTML, licenses=lic_list, logs=[dict(x) for x in logs])


def _dias_para_expires(dias_raw):
    try:
        dias = int(dias_raw)
    except (TypeError, ValueError):
        return None
    if dias <= 0:
        return None
    return (datetime.utcnow() + timedelta(days=dias)).isoformat()


@app.route("/admin/create", methods=["POST"])
def admin_create():
    if not session.get("admin"):
        return redirect(url_for("admin_panel"))
    owner = request.form.get("owner", "").strip()
    if not owner:
        return redirect(url_for("admin_panel"))
    email = request.form.get("email", "").strip()
    notes = request.form.get("notes", "").strip()
    expires_at = _dias_para_expires(request.form.get("dias"))

    key = f"WANN-{datetime.utcnow().year}-{secrets.token_hex(2).upper()}-{secrets.token_hex(2).upper()}"
    q("INSERT INTO licenses (key, owner, email, notes, expires_at, created_at) VALUES (%s,%s,%s,%s,%s,%s)",
      (key, owner, email, notes, expires_at, datetime.utcnow().isoformat()))
    return redirect(url_for("admin_panel"))


@app.route("/admin/toggle", methods=["POST"])
def admin_toggle():
    if not session.get("admin"):
        return redirect(url_for("admin_panel"))
    q("UPDATE licenses SET active = NOT active WHERE key=%s", (request.form.get("key"),))
    return redirect(url_for("admin_panel"))


@app.route("/admin/extend", methods=["POST"])
def admin_extend():
    if not session.get("admin"):
        return redirect(url_for("admin_panel"))
    expires_at = _dias_para_expires(request.form.get("dias"))  # None = vitalícia
    q("UPDATE licenses SET expires_at=%s WHERE key=%s", (expires_at, request.form.get("key")))
    return redirect(url_for("admin_panel"))


@app.route("/admin/reset", methods=["POST"])
def admin_reset():
    if not session.get("admin"):
        return redirect(url_for("admin_panel"))
    q("UPDATE licenses SET hardware_id = NULL WHERE key=%s", (request.form.get("key"),))
    return redirect(url_for("admin_panel"))


@app.route("/admin/delete", methods=["POST"])
def admin_delete():
    if not session.get("admin"):
        return redirect(url_for("admin_panel"))
    q("DELETE FROM licenses WHERE key=%s", (request.form.get("key"),))
    return redirect(url_for("admin_panel"))


@app.route("/admin/logout")
def admin_logout():
    session.pop("admin", None)
    return redirect(url_for("admin_panel"))


@app.route("/")
def index():
    return "Wann Studio API v2 (Postgres)"


# Inicializa o schema no import (Render roda via gunicorn -> não passa pelo __main__)
try:
    if DATABASE_URL:
        init_db()
except Exception as _e:
    print(f"[init_db] aviso: {_e}")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
