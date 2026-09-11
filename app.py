#!/usr/bin/env python3
"""
OGIOS Key Server - Flask + SQLite
Endpoints:
  GET  /              -> web UI
  GET  /api/health    -> {status: ok}
  POST /api/generate  -> {key, expires_at} (admin auth)
  POST /api/verify    -> {valid: bool, reason}  (used by OGIOS app)
  GET  /api/keys      -> list keys (admin)
  POST /api/revoke    -> revoke key (admin)
  POST /api/login     -> admin login

DB: keys.db SQLite with table keys(key TEXT PRIMARY KEY, created_at TEXT, expires_at TEXT, revoked INT, hwid TEXT, uses INT, max_uses INT)

Admin auth: Bearer token or X-Admin-Key header. Default admin key from ADMIN_KEY env else "OGIOS-ADMIN-CHANGE-ME"

Run: pip install flask && python app.py  (listens 0.0.0.0:5000)
"""
import os, sqlite3, secrets, string, hashlib, time, json
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import Flask, request, jsonify, render_template, g, redirect, url_for, session

ADMIN_KEY = os.environ.get("ADMIN_KEY", "OGIOS-ADMIN-CHANGE-ME")
DATABASE = os.environ.get("DATABASE", "keys.db")
SECRET = os.environ.get("FLASK_SECRET", secrets.token_hex(16))

app = Flask(__name__)
app.secret_key = SECRET
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = True

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exc):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    db = sqlite3.connect(DATABASE)
    db.execute("""
    CREATE TABLE IF NOT EXISTS keys (
        key TEXT PRIMARY KEY,
        created_at TEXT NOT NULL,
        expires_at TEXT,
        revoked INTEGER DEFAULT 0,
        hwid TEXT,
        uses INTEGER DEFAULT 0,
        max_uses INTEGER DEFAULT 0,
        note TEXT
    )""")
    db.commit()
    db.close()

def now_iso():
    return datetime.now(timezone.utc).isoformat()

def is_admin_request():
    # check session
    if session.get('admin'):
        return True
    # check header
    hdr = request.headers.get('X-Admin-Key') or request.headers.get('Authorization','')
    if hdr.startswith('Bearer '):
        hdr = hdr[7:]
    return hdr == ADMIN_KEY

def require_admin(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not is_admin_request():
            # if browser and not admin, redirect to login
            if request.accept_mimetypes.best == 'text/html' and request.path.startswith('/api/') is False:
                return redirect(url_for('login'))
            return jsonify({"error":"unauthorized","hint":"Send X-Admin-Key header = ADMIN_KEY"}), 401
        return f(*args, **kwargs)
    return wrapper

def gen_key(prefix="OGIOS", length=16):
    alphabet = string.ascii_uppercase + string.digits
    # eg OGIOS-XXXX-XXXX-XXXX
    parts = []
    for _ in range(3):
        parts.append(''.join(secrets.choice(alphabet) for _ in range(4)))
    if length != 16:
        raw = ''.join(secrets.choice(alphabet) for _ in range(length))
        return f"{prefix}-{raw}"
    return f"{prefix}-{'-'.join(parts)}"

@app.route('/')
def index():
    if not session.get('admin'):
        return redirect(url_for('login'))
    return render_template('index.html', admin_key=ADMIN_KEY)

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        data = request.form if request.form else request.json or {}
        key = data.get('admin_key') or data.get('key') or ""
        if key == ADMIN_KEY:
            session['admin'] = True
            if request.is_json:
                return jsonify({"ok":True})
            return redirect(url_for('index'))
        else:
            if request.is_json:
                return jsonify({"ok":False,"error":"invalid admin key"}), 403
            return render_template('login.html', error="Invalid admin key")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/api/health')
def health():
    return jsonify({"status":"ok","time":now_iso(),"admin_configured": ADMIN_KEY != "OGIOS-ADMIN-CHANGE-ME"})

# --- OGIOS app uses this ---
@app.route('/api/verify', methods=['POST','GET'])
def verify():
    # support both JSON body and query param ?key=
    key = None
    if request.is_json:
        key = request.json.get('key') or request.json.get('license') or request.json.get('token')
    if not key:
        key = request.args.get('key') or request.form.get('key') or ""
    key = (key or "").strip()
    if not key:
        return jsonify({"valid":False,"reason":"missing key"}), 400
    db = get_db()
    row = db.execute("SELECT * FROM keys WHERE key=?", (key,)).fetchone()
    if not row:
        return jsonify({"valid":False,"reason":"invalid"}), 200
    if row['revoked']:
        return jsonify({"valid":False,"reason":"revoked"}), 200
    if row['expires_at']:
        try:
            exp = datetime.fromisoformat(row['expires_at'])
            if datetime.now(timezone.utc) > exp:
                return jsonify({"valid":False,"reason":"expired"}), 200
        except: pass
    if row['max_uses'] and row['max_uses']>0 and row['uses'] >= row['max_uses']:
        return jsonify({"valid":False,"reason":"max uses reached"}), 200
    # increment uses (optional, for tracking)
    # bind hwid if provided
    hwid = request.json.get('hwid') if request.is_json and request.json else request.args.get('hwid')
    if hwid and not row['hwid']:
        db.execute("UPDATE keys SET hwid=?, uses=uses+1 WHERE key=?", (hwid, key))
        db.commit()
    else:
        db.execute("UPDATE keys SET uses=uses+1 WHERE key=?", (key,))
        db.commit()
    return jsonify({"valid":True,"reason":"ok","expires_at": row['expires_at'], "uses": row['uses']+1}), 200

@app.route('/api/generate', methods=['POST'])
@require_admin
def generate():
    data = request.json or request.form or {}
    # params: count (default 1), prefix, length, days (expiry), max_uses, note
    try:
        count = int(data.get('count',1))
    except: count = 1
    count = max(1, min(count, 100))
    prefix = (data.get('prefix') or "OGIOS").strip().upper()[:12]
    days = data.get('days')
    try:
        days = int(days) if days not in (None,"") else 0
    except: days = 0
    expires_at = None
    if days and days>0:
        expires_at = (datetime.now(timezone.utc)+timedelta(days=days)).isoformat()
    max_uses = 0
    try:
        max_uses = int(data.get('max_uses') or 0)
    except: pass
    note = (data.get('note') or "").strip()[:200]
    keys = []
    db = get_db()
    for _ in range(count):
        k = gen_key(prefix=prefix)
        # ensure unique
        for _retry in range(5):
            if not db.execute("SELECT 1 FROM keys WHERE key=?", (k,)).fetchone():
                break
            k = gen_key(prefix=prefix)
        db.execute("INSERT INTO keys(key,created_at,expires_at,revoked,max_uses,note) VALUES(?,?,?,?,?,?)",
                   (k, now_iso(), expires_at, 0, max_uses, note))
        keys.append({"key":k,"expires_at":expires_at,"max_uses":max_uses,"note":note})
    db.commit()
    return jsonify({"generated":len(keys),"keys":keys}), 200

@app.route('/api/keys', methods=['GET'])
@require_admin
def list_keys():
    db = get_db()
    rows = db.execute("SELECT key,created_at,expires_at,revoked,uses,max_uses,note,hwid FROM keys ORDER BY created_at DESC LIMIT 500").fetchall()
    out = [dict(r) for r in rows]
    return jsonify({"count":len(out),"keys":out})

@app.route('/api/revoke', methods=['POST'])
@require_admin
def revoke():
    data = request.json or request.form or {}
    key = (data.get('key') or "").strip()
    if not key:
        return jsonify({"error":"missing key"}), 400
    db = get_db()
    cur = db.execute("UPDATE keys SET revoked=1 WHERE key=?", (key,))
    db.commit()
    if cur.rowcount==0:
        return jsonify({"error":"not found"}), 404
    return jsonify({"ok":True,"key":key}), 200

@app.route('/api/delete', methods=['POST'])
@require_admin
def delete():
    data = request.json or request.form or {}
    key = (data.get('key') or "").strip()
    if not key:
        return jsonify({"error":"missing key"}), 400
    db = get_db()
    cur = db.execute("DELETE FROM keys WHERE key=?", (key,))
    db.commit()
    return jsonify({"ok":True,"deleted":cur.rowcount}),200

# CORS for app
@app.after_request
def cors(resp):
    resp.headers['Access-Control-Allow-Origin'] = '*'
    resp.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Admin-Key'
    resp.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    return resp

# Ensure DB exists on import (needed for gunicorn on Render)
with app.app_context():
    init_db()
    try:
        db = sqlite3.connect(DATABASE)
        if not db.execute("SELECT 1 FROM keys WHERE key='OGIOS'").fetchone():
            db.execute("INSERT INTO keys(key,created_at,expires_at,revoked,max_uses,note) VALUES(?,?,?,?,?,?)",
                       ('OGIOS', now_iso(), None, 0, 0, 'legacy hardcoded key'))
            db.commit()
        db.close()
    except Exception as e:
        print(f"DB init warn: {e}")

if __name__ == '__main__':
    print(f"OGIOS Key Server running - ADMIN_KEY={ADMIN_KEY[:4]}*** database={DATABASE}")
    print("Web UI: http://0.0.0.0:5000/  API verify: POST /api/verify {\"key\":\"OGIOS\"}")
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT',5000)), debug=False)
