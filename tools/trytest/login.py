#!/usr/bin/env python3
# Logs in to the trial dashboard as a browser would (the cookie jar drops
# Secure cookies over plain HTTP) and lists the open alerts of a rule.
#   login.py USERS_JSON USER PASSWORD RULE
import base64, hashlib, hmac, http.cookiejar, json, struct, sys, time, urllib.request

users, user, password, rule = sys.argv[1:5]
secret = json.load(open(users))[user]["totp_secret"]

def totp():
    key = base64.b32decode(secret.upper() + "=" * (-len(secret) % 8))
    mac = hmac.new(key, struct.pack(">Q", int(time.time()) // 30), hashlib.sha1).digest()
    o = mac[-1] & 15
    return "%06d" % ((struct.unpack(">I", mac[o:o + 4])[0] & 0x7FFFFFFF) % 1000000)

op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
csrf = ""

def call(method, path, body=None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request("http://127.0.0.1:8470" + path, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    if csrf:
        req.add_header("X-CSRF", csrf)
    with op.open(req, timeout=20) as r:
        return json.loads(r.read() or b"null")

csrf = call("POST", "/api/ui/login", {"user": user, "password": password, "code": totp()})["csrf"]
alerts = call("GET", "/api/ui/alerts?status=open")
alerts = alerts.get("alerts", alerts) if isinstance(alerts, dict) else alerts
hits = [a for a in alerts if a.get("rule") == rule]
for a in hits:
    print(a["severity"], a["title"])
sys.exit(0 if hits else 1)
