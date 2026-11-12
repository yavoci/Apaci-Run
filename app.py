import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import time
import urllib.request
from flask import Flask, jsonify, redirect, request, send_from_directory, session
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__, static_folder="static", static_url_path="")
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
app.config.update(
    SECRET_KEY=os.environ["SECRET_KEY"],
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("INSECURE_DEV") != "1",
    PERMANENT_SESSION_LIFETIME=60 * 60 * 24 * 365,
    MAX_CONTENT_LENGTH=32 * 1024,
)
DATABASE_URL = os.environ.get(
    "DATABASE_URL"
)  # Neon/Postgres (internette bunu kullan)
DB = os.environ.get(
    "DB_PATH", "apaci.db"
)  # DATABASE_URL yoksa yerel SQLite (sadece bilgisayarda deneme)
SCHEMA = [
    (
        "CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY, name TEXT, data"
        " TEXT, updated DOUBLE PRECISION)"
    ),
    (
        "CREATE TABLE IF NOT EXISTS codes(email TEXT PRIMARY KEY, h TEXT, exp"
        " DOUBLE PRECISION, tries INTEGER, sent DOUBLE PRECISION, hstart DOUBLE"
        " PRECISION, hcount INTEGER)"
    ),
]
_ready = False


def run(sql, args=(), one=False):
  """SQL içinde %s kullan; SQLite'ta otomatik ? yapılır."""
  global _ready
  if DATABASE_URL:
    import psycopg

    with psycopg.connect(DATABASE_URL, connect_timeout=20) as c:
      if not _ready:
        for q in SCHEMA:
          c.execute(q)
        _ready = True
      cur = c.execute(sql, args)
      return cur.fetchone() if one else None
  c = sqlite3.connect(DB)
  try:
    for q in SCHEMA:
      c.execute(q)
    cur = c.execute(sql.replace("%s", "?"), args)
    row = cur.fetchone() if one else None
    c.commit()
    return row
  finally:
    c.close()


# ---------- E-posta ile giriş (9 haneli kod) ----------
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}\.[^@\s]{2,}$")
IP_HITS = (
    {}
)  # IP başına saatlik kod isteği sayacı (tek sunucu süreci için yeterli)


def hash_code(email, code):
  return hmac.new(
      app.config["SECRET_KEY"].encode(),
      f"{email}:{code}".encode(),
      hashlib.sha256,
  ).hexdigest()


def send_mail(to, code):
  """Kodu Google Apps Script üzerinden Gmail ile gönderir."""
  url = os.environ.get("APPS_SCRIPT_URL")
  if url:
    req = urllib.request.Request(
        url,
        json.dumps({"to": to, "code": code}).encode(),
        {"Content-Type": "application/json", "User-Agent": "apaci-run/1.0"},
    )
    res = json.loads(urllib.request.urlopen(req, timeout=25).read().decode())
    if not res.get("ok") and res.get("status") != "success":
      raise RuntimeError(
          "Apps Script hatası: %s"
          % (res.get("error") or res.get("message") or res)
      )
  elif os.environ.get("INSECURE_DEV") == "1":
    print(f"[DEV] {to} için kod: {code}")
  else:
    raise RuntimeError("E-posta gönderimi ayarlanmamış")


@app.post("/api/send_code")
def send_code():
  d = request.get_json(silent=True) or {}
  email = str(d.get("email", "")).strip().lower()
  if len(email) > 254 or not EMAIL_RE.match(email):
    return jsonify(error="Geçerli bir e-posta yaz."), 400
  now, ip = time.time(), request.remote_addr
  hits = [t for t in IP_HITS.get(ip, []) if now - t < 3600]
  if len(hits) >= 20:
    return jsonify(error="Çok fazla deneme. Biraz sonra tekrar dene."), 429
  row = run(
      "SELECT sent,hstart,hcount FROM codes WHERE email=%s", (email,), one=True
  )
  sent, hstart, hcount = row if row else (0, 0, 0)
  if now - sent < 60:
    return jsonify(error="Yeni kod için %d sn bekle." % (60 - (now - sent))), 429
  if now - hstart > 3600:
    hstart, hcount = now, 0
  if hcount >= 5:
    return (
        jsonify(error="Bu e-posta için saatlik kod sınırı doldu. Sonra dene."),
        429,
    )
  code = "%09d" % secrets.randbelow(10**9)
  try:
    send_mail(email, code)
  except Exception:
    app.logger.exception("e-posta gonderilemedi")
    return jsonify(error="E-posta gönderilemedi. Biraz sonra tekrar dene."), 502
  run(
      "INSERT INTO codes(email,h,exp,tries,sent,hstart,hcount)"
      " VALUES(%s,%s,%s,0,%s,%s,%s) ON CONFLICT(email) DO UPDATE SET"
      " h=excluded.h, exp=excluded.exp, tries=0, sent=excluded.sent,"
      " hstart=excluded.hstart, hcount=excluded.hcount",
      (email, hash_code(email, code), now + 600, now, hstart, hcount + 1),
  )
  hits.append(now)
  IP_HITS[ip] = hits
  return jsonify(ok=True)


@app.post("/api/verify")
def verify():
  d = request.get_json(silent=True) or {}
  email = str(d.get("email", "")).strip().lower()
  code = re.sub(r"\D", "", str(d.get("code", "")))
  row = run("SELECT h,exp,tries FROM codes WHERE email=%s", (email,), one=True)
  if not row or time.time() > row[1] or row[2] >= 5:
    return jsonify(error="Kod geçersiz ya da süresi dolmuş. Yeni kod iste."), 400
  if not hmac.compare_digest(row[0], hash_code(email, code)):
    run("UPDATE codes SET tries=tries+1 WHERE email=%s", (email,))
    return jsonify(error="Kod yanlış."), 400
  run("UPDATE codes SET exp=0 WHERE email=%s", (email,))  # kod tek kullanımlık
  uid, name = "email:" + email, email.split("@")[0][:20]
  run(
      "INSERT INTO users(id,name,data,updated) VALUES(%s,%s,NULL,%s) ON"
      " CONFLICT(id) DO UPDATE SET name=excluded.name",
      (uid, name, time.time()),
  )
  session.clear()
  session.permanent = True
  session["uid"], session["name"] = uid, name
  return jsonify(ok=True, user=name)


# ---------- İlerleme kaydı ----------
KC = {2, 3, 4, 6, 8, 9, 10, 12}
MAXL = [
    150,
    120,
    95,
    100,
    120,
    150,
]  # oyundaki harita sırası: normal, çöl, kutup, orman, cehennem, şehir


def clean(d):
  """İstemciden gelen kaydı doğrula; geçersizse None."""
  try:
    lv = [min(max(int(x), 1), m) for x, m in zip(d["LV"], MAXL)]
    dn = [1 if x else 0 for x in d["DN"][:6]]
    hi = [min(max(int(x), 0), 10_000_000) for x in d["HI"][:6]]
    ot = [int(x) for x in d["OT"][:3]]
    ac = int(d["ac"])
  except Exception:
    return None
  if len(lv) != 6 or len(dn) != 6 or len(hi) != 6 or len(ot) != 3:
    return None
  if not set(ot) <= KC or not 0 <= ac <= 5:
    return None
  return {"LV": lv, "DN": dn, "HI": hi, "OT": ot, "ac": ac}


def merge(old, new):
  """İlerleme asla geri gitmesin: en yüksek bölüm/skor korunur."""
  if not old:
    return new
  return {
      "LV": [max(a, b) for a, b in zip(old["LV"], new["LV"])],
      "DN": [a | b for a, b in zip(old["DN"], new["DN"])],
      "HI": [max(a, b) for a, b in zip(old["HI"], new["HI"])],
      "OT": new["OT"],
      "ac": new["ac"],
  }


@app.get("/")
def index():
  return send_from_directory("static", "index.html")


@app.get("/.well-known/assetlinks.json")
def assetlinks():
  return app.response_class(
      os.environ.get("ASSETLINKS", "[]"), mimetype="application/json"
  )


@app.get("/logout")
def logout():
  session.clear()
  return redirect("/")


@app.get("/api/me")
def me():
  uid = session.get("uid")
  if not uid:
    return jsonify(user=None)
  row = run("SELECT data FROM users WHERE id=%s", (uid,), one=True)
  prog = json.loads(row[0]) if row and row[0] else None
  return jsonify(user=session.get("name"), progress=prog)


@app.post("/api/progress")
def save():
  uid = session.get("uid")
  if not uid:
    return jsonify(error="giris gerekli"), 401
  new = clean(request.get_json(silent=True))
  if new is None:
    return jsonify(error="gecersiz veri"), 400
  row = run("SELECT data FROM users WHERE id=%s", (uid,), one=True)
  old = json.loads(row[0]) if row and row[0] else None
  merged = merge(old, new)
  run(
      "INSERT INTO users(id,name,data,updated) VALUES(%s,%s,%s,%s) ON"
      " CONFLICT(id) DO UPDATE SET data=excluded.data,"
      " updated=excluded.updated",
      (uid, session.get("name", "Oyuncu"), json.dumps(merged), time.time()),
  )
  return jsonify(ok=True, progress=merged)


if __name__ == "__main__":
   app.run(debug=os.environ.get("INSECURE_DEV") == "1")
