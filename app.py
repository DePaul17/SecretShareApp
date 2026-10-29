"""
Coffre — partage de secrets à usage unique (.env, tokens, clés API).

Principe :
  1. On colle un secret → l'app génère un LIEN + un CODE de 8 caractères.
  2. Le lien et le code s'envoient par deux canaux différents.
  3. Le destinataire ouvre le lien, saisit le code, lit le secret.
  4. Le secret est détruit après lecture (par défaut) ou à expiration.

Sécurité :
  - Le code n'est jamais stocké : il sert à dériver (scrypt) la clé de chiffrement
    AES (Fernet). La base ne contient que le texte chiffré : sans le code, même
    l'administrateur du serveur ne peut pas lire le secret.
  - 5 mauvais codes → le secret est détruit.
  - Le secret ne s'affiche qu'après un POST (les aperçus de liens Slack/Teams/
    mail ne peuvent donc pas le consommer).
"""
import os
import secrets
import sqlite3
import time

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import base64
from flask import Flask, abort, g, render_template_string, request

DB_PATH = os.environ.get("COFFRE_DB", "coffre.db")
MAX_ATTEMPTS = 5
MAX_SECRET_SIZE = 20_000  # caractères
# Alphabet sans caractères ambigus (pas de 0/O, 1/I/L) : 32 symboles
ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
TTL_CHOICES = {"1h": 3600, "24h": 86400, "7j": 7 * 86400}

app = Flask(__name__)


# ───────────────────────── Base de données ─────────────────────────
def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute(
            """CREATE TABLE IF NOT EXISTS secrets (
                id TEXT PRIMARY KEY,
                salt BLOB NOT NULL,
                token BLOB NOT NULL,
                expires_at INTEGER NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                burn INTEGER NOT NULL DEFAULT 1
            )"""
        )
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    conn = g.pop("db", None)
    if conn:
        conn.close()


@app.before_request
def purge_expired():
    db().execute("DELETE FROM secrets WHERE expires_at < ?", (int(time.time()),))
    db().commit()


@app.after_request
def security_headers(resp):
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
        "form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
    )
    return resp


# ───────────────────────── Cryptographie ─────────────────────────
def generate_code() -> str:
    return "".join(secrets.choice(ALPHABET) for _ in range(8))


def normalize_code(raw: str) -> str:
    return "".join(c for c in raw.upper() if c.isalnum())


def derive_key(code: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=2**15, r=8, p=1)
    return base64.urlsafe_b64encode(kdf.derive(code.encode()))


def encrypt(secret: str, code: str):
    salt = os.urandom(16)
    return salt, Fernet(derive_key(code, salt)).encrypt(secret.encode())


def decrypt(token: bytes, salt: bytes, code: str) -> str:
    return Fernet(derive_key(code, salt)).decrypt(token).decode()


# ───────────────────────── Interface ─────────────────────────
PAGE = """<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Coffre</title>
<style>
  :root {
    --bg: #eceae4; --surface: #fbfaf7; --ink: #1d2a2f; --muted: #5d6b70;
    --line: #cfd3cd; --accent: #1f5f5b; --accent-ink: #ffffff;
    --danger: #a3342b; --ok: #2f6b3a;
    --mono: ui-monospace, "SF Mono", "JetBrains Mono", Menlo, Consolas, monospace;
    --sans: "Inter", system-ui, -apple-system, "Segoe UI", sans-serif;
  }
  @media (prefers-color-scheme: dark) {
    :root { --bg: #14191b; --surface: #1c2326; --ink: #e8ece9; --muted: #92a0a3;
            --line: #2f3a3d; --accent: #5fb3ab; --accent-ink: #0d1516;
            --danger: #ff8a7d; --ok: #8fd19a; }
  }
  * { box-sizing: border-box; }
  body { margin: 0; background: var(--bg); color: var(--ink); font: 16px/1.55 var(--sans); }
  main { max-width: 640px; margin: 0 auto; padding: 48px 20px 80px; }
  h1 { font-size: 1.6rem; margin: 0 0 4px; letter-spacing: -0.01em; }
  p.lead { color: var(--muted); margin: 0 0 28px; }
  .card { background: var(--surface); border: 1px solid var(--line); border-radius: 10px; padding: 24px; }
  label { display: block; font-weight: 600; margin: 0 0 6px; }
  textarea, input[type=text], select {
    width: 100%; background: var(--bg); color: var(--ink); border: 1px solid var(--line);
    border-radius: 6px; padding: 10px 12px; font: inherit;
  }
  textarea { font-family: var(--mono); font-size: .9rem; min-height: 200px; resize: vertical; }
  :focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
  .row { display: flex; gap: 16px; margin-top: 18px; flex-wrap: wrap; align-items: end; }
  .row > div { flex: 1 1 160px; }
  .check { display: flex; gap: 8px; align-items: center; font-weight: 400; margin: 0; padding-bottom: 10px; }
  .check input { width: 18px; height: 18px; }
  button { font: inherit; font-weight: 600; cursor: pointer; border-radius: 6px; padding: 11px 18px;
           border: 1px solid var(--accent); background: var(--accent); color: var(--accent-ink); }
  button.ghost { background: transparent; color: var(--accent); }
  button.full { width: 100%; margin-top: 22px; }
  .out { margin-top: 22px; }
  .out + .out { margin-top: 16px; }
  .field { display: flex; gap: 8px; }
  .field input, .field .val { flex: 1; }
  .val { font-family: var(--mono); background: var(--bg); border: 1px solid var(--line);
         border-radius: 6px; padding: 10px 12px; overflow-wrap: anywhere; }
  .code { font-size: 1.6rem; letter-spacing: .18em; text-align: center; }
  pre.secret { margin: 0; font-family: var(--mono); font-size: .88rem; background: var(--bg);
               border: 1px solid var(--line); border-radius: 6px; padding: 14px; white-space: pre-wrap;
               overflow-wrap: anywhere; max-height: 420px; overflow: auto; }
  .note { color: var(--muted); font-size: .9rem; margin-top: 14px; }
  .error { color: var(--danger); font-weight: 600; margin: 0 0 14px; }
  .ok { color: var(--ok); font-weight: 600; }
  a { color: var(--accent); }
</style>
</head>
<body><main>
{% block body %}{% endblock %}
</main>
<script>
  function copyFrom(id, btn) {
    const el = document.getElementById(id);
    const text = el.value !== undefined ? el.value : el.innerText;
    navigator.clipboard.writeText(text).then(() => {
      const old = btn.textContent; btn.textContent = "Copié";
      setTimeout(() => btn.textContent = old, 1500);
    });
  }
</script>
</body></html>"""

CREATE = PAGE.replace(
    "{% block body %}{% endblock %}",
    """
<h1>Coffre</h1>
<p class="lead">Partagez un fichier .env ou une clé API avec un lien à usage unique, protégé par un code à 8 caractères.</p>
<form method="post" action="/" class="card" autocomplete="off">
  {% if error %}<p class="error">{{ error }}</p>{% endif %}
  <label for="secret">Secret à partager</label>
  <textarea id="secret" name="secret" required maxlength="{{ max_size }}" spellcheck="false"
    placeholder="DATABASE_URL=postgres://...&#10;STRIPE_KEY=sk_live_..."></textarea>
  <div class="row">
    <div>
      <label for="ttl">Expire après</label>
      <select id="ttl" name="ttl">
        {% for k in ttls %}<option value="{{ k }}" {{ 'selected' if k == '24h' }}>{{ k }}</option>{% endfor %}
      </select>
    </div>
    <div>
      <label class="check"><input type="checkbox" name="burn" checked> Détruire après lecture</label>
    </div>
  </div>
  <button class="full" type="submit">Créer le lien sécurisé</button>
</form>
<p class="note">Le code n'est jamais enregistré sur le serveur. Envoyez le lien et le code par deux canaux différents (par exemple e-mail + SMS).</p>
""",
)

CREATED = PAGE.replace(
    "{% block body %}{% endblock %}",
    """
<h1>Lien créé</h1>
<p class="lead">Ce code ne sera plus affiché. Copiez-le maintenant.</p>
<div class="card">
  <div class="out">
    <label>Lien</label>
    <div class="field">
      <div class="val" id="link">{{ link }}</div>
      <button type="button" class="ghost" onclick="copyFrom('link', this)">Copier</button>
    </div>
  </div>
  <div class="out">
    <label>Code de déverrouillage</label>
    <div class="field">
      <div class="val code" id="code">{{ code[:4] }}-{{ code[4:] }}</div>
      <button type="button" class="ghost" onclick="copyFrom('code', this)">Copier</button>
    </div>
  </div>
  <p class="note">Expire dans {{ ttl }}. {{ 'Le secret est détruit dès sa première lecture.' if burn else 'Le secret reste lisible jusqu\\'à expiration.' }}
  Après {{ max_attempts }} codes erronés, il est détruit.</p>
</div>
<p class="note"><a href="/">Partager un autre secret</a></p>
""",
)

UNLOCK = PAGE.replace(
    "{% block body %}{% endblock %}",
    """
<h1>Secret protégé</h1>
<p class="lead">Saisissez le code à 8 caractères qu'on vous a envoyé.</p>
<form method="post" class="card" autocomplete="off">
  {% if error %}<p class="error">{{ error }}</p>{% endif %}
  <label for="code">Code</label>
  <input id="code" name="code" type="text" class="code" required autofocus
         maxlength="9" placeholder="XXXX-XXXX" autocapitalize="characters" spellcheck="false">
  <button class="full" type="submit">Déverrouiller</button>
  {% if burn %}<p class="note">Attention : le secret sera détruit après affichage. Copiez-le avant de fermer la page.</p>{% endif %}
</form>
""",
)

REVEAL = PAGE.replace(
    "{% block body %}{% endblock %}",
    """
<h1>Secret déverrouillé</h1>
<p class="lead">{% if burn %}<span class="ok">Détruit sur le serveur.</span> Copiez-le maintenant, il ne sera plus accessible.
{% else %}Il reste lisible jusqu'à son expiration.{% endif %}</p>
<div class="card">
  <pre class="secret" id="secret">{{ secret }}</pre>
  <button class="full" type="button" onclick="copyFrom('secret', this)">Copier le secret</button>
</div>
""",
)

GONE = PAGE.replace(
    "{% block body %}{% endblock %}",
    """
<h1>Lien introuvable</h1>
<p class="lead">Ce secret a expiré, a déjà été lu ou a été détruit après trop d'essais. Demandez à l'expéditeur d'en créer un nouveau.</p>
""",
)


# ───────────────────────── Routes ─────────────────────────
@app.route("/", methods=["GET", "POST"])
def create():
    ctx = dict(ttls=TTL_CHOICES, max_size=MAX_SECRET_SIZE, error=None)
    if request.method == "GET":
        return render_template_string(CREATE, **ctx)

    secret = request.form.get("secret", "").strip("\r\n")
    ttl_key = request.form.get("ttl", "24h")
    burn = request.form.get("burn") is not None

    if not secret:
        ctx["error"] = "Saisissez un secret."
        return render_template_string(CREATE, **ctx), 400
    if len(secret) > MAX_SECRET_SIZE or ttl_key not in TTL_CHOICES:
        ctx["error"] = "Secret trop long ou durée invalide."
        return render_template_string(CREATE, **ctx), 400

    code = generate_code()
    salt, token = encrypt(secret, code)
    secret_id = secrets.token_urlsafe(16)

    db().execute(
        "INSERT INTO secrets (id, salt, token, expires_at, burn) VALUES (?, ?, ?, ?, ?)",
        (secret_id, salt, token, int(time.time()) + TTL_CHOICES[ttl_key], int(burn)),
    )
    db().commit()

    base = os.environ.get("COFFRE_BASE_URL", request.host_url).rstrip("/")
    return render_template_string(
        CREATED,
        link=f"{base}/s/{secret_id}",
        code=code,
        ttl=ttl_key,
        burn=burn,
        max_attempts=MAX_ATTEMPTS,
    )


@app.route("/s/<secret_id>", methods=["GET", "POST"])
def unlock(secret_id):
    row = db().execute("SELECT * FROM secrets WHERE id = ?", (secret_id,)).fetchone()
    if row is None:
        return render_template_string(GONE), 404

    # GET : simple formulaire. Rien n'est consommé (protège contre les aperçus de liens).
    if request.method == "GET":
        return render_template_string(UNLOCK, error=None, burn=bool(row["burn"]))

    code = normalize_code(request.form.get("code", ""))
    try:
        if len(code) != 8:
            raise InvalidToken
        secret = decrypt(row["token"], row["salt"], code)
    except InvalidToken:
        attempts = row["attempts"] + 1
        if attempts >= MAX_ATTEMPTS:
            db().execute("DELETE FROM secrets WHERE id = ?", (secret_id,))
            db().commit()
            return render_template_string(GONE), 403
        db().execute("UPDATE secrets SET attempts = ? WHERE id = ?", (attempts, secret_id))
        db().commit()
        left = MAX_ATTEMPTS - attempts
        return (
            render_template_string(
                UNLOCK,
                error=f"Code incorrect. {left} essai{'s' if left > 1 else ''} restant{'s' if left > 1 else ''}.",
                burn=bool(row["burn"]),
            ),
            403,
        )

    if row["burn"]:
        # DELETE atomique : si deux requêtes arrivent en même temps, une seule réussit.
        cur = db().execute("DELETE FROM secrets WHERE id = ?", (secret_id,))
        db().commit()
        if cur.rowcount == 0:
            return render_template_string(GONE), 404

    return render_template_string(REVEAL, secret=secret, burn=bool(row["burn"]))


@app.errorhandler(404)
def not_found(_e):
    return render_template_string(GONE), 404


if __name__ == "__main__":
    # En production : gunicorn derrière un proxy HTTPS (nginx, Caddy…)
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", 5000)), debug=False)
