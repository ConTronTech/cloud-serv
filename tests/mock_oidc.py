#!/usr/bin/env python3
"""Tiny mock OpenID provider for tests/test_oidc.sh (plain HTTP, 127.0.0.1 only).
code format: "<scenario>.<nonce>" -> the token endpoint returns an id_token for that scenario."""
import base64, json, sys, time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

PORT = int(sys.argv[1]); ISS = f"http://127.0.0.1:{PORT}"
CID, SECRET = "test-client", "test-secret"
PEOPLE = {
    "alice": {"sub": "sub-alice", "email": "alice@sso.test", "name": "Alice", "groups": ["cloud-serv-users"]},
    "bob":   {"sub": "sub-bob",   "email": "bob@sso.test",   "name": "Bob",   "groups": ["other"]},
    "carol": {"sub": "sub-carol", "email": "local@e.cc",     "name": "Carol", "groups": ["cloud-serv-users"]},
    "dave":  {"sub": "sub-dave",  "email": "dave@sso.test",  "name": "Dave",  "groups": []},
}
def b64(d): return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def send(self, code, obj):
        b = json.dumps(obj).encode(); self.send_response(code)
        self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        if self.path == "/.well-known/openid-configuration":
            return self.send(200, {"issuer": ISS, "authorization_endpoint": ISS + "/authorize",
                                   "token_endpoint": ISS + "/token", "userinfo_endpoint": ISS + "/userinfo"})
        if self.path.startswith("/authorize?"):
            # Auto-approve as MOCK_USER (default alice): straight back to the app, like a logged-in IdP.
            import os; from urllib.parse import urlparse
            q = parse_qs(urlparse(self.path).query)
            who = os.environ.get("MOCK_USER", "alice")
            loc = q["redirect_uri"][0] + "?code=" + who + "." + q["nonce"][0] + "&state=" + q["state"][0]
            self.send_response(302); self.send_header("Location", loc); self.end_headers(); return
        if self.path == "/userinfo":
            who = (self.headers.get("Authorization") or "").replace("Bearer ", "")
            p = PEOPLE.get(who)
            return self.send(200, p) if p else self.send(401, {"error": "bad token"})
        self.send(404, {})
    def do_POST(self):
        if self.path != "/token": return self.send(404, {})
        auth = self.headers.get("Authorization", "")
        if auth != "Basic " + base64.b64encode(f"{CID}:{SECRET}".encode()).decode(): return self.send(401, {"error": "invalid_client"})
        form = parse_qs(self.rfile.read(int(self.headers.get("Content-Length", 0))).decode())
        if not form.get("code_verifier"): return self.send(400, {"error": "pkce required"})
        scen, _, nonce = form.get("code", [""])[0].partition(".")
        aud, iss = CID, ISS
        if scen.startswith("wrongaud-"): scen, aud = scen[9:], "someone-else"
        if scen.startswith("wrongiss-"): scen, iss = scen[9:], "http://evil"
        p = PEOPLE.get(scen)
        if not p: return self.send(400, {"error": "invalid_grant"})
        claims = {"iss": iss, "aud": aud, "sub": p["sub"], "nonce": nonce, "exp": int(time.time()) + 300,
                  "iat": int(time.time()), "email": p["email"], "email_verified": True, "name": p["name"]}
        idt = b64({"alg": "RS256", "typ": "JWT"}) + "." + b64(claims) + ".sig"
        self.send(200, {"access_token": scen, "token_type": "Bearer", "id_token": idt, "expires_in": 300})

HTTPServer(("127.0.0.1", PORT), H).serve_forever()
