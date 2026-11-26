"""Automated security tests:  python test_app.py"""
import os, re, tempfile, time, unittest
import app as A


class SecureLoginTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mktemp(suffix=".db")
        A.app.config.update(TESTING=True, DB_PATH=self.tmp)
        A.init_db()
        self.c = A.app.test_client()

    def tearDown(self):
        if os.path.exists(self.tmp): os.remove(self.tmp)

    def token(self, path):
        html = self.c.get(path).get_data(as_text=True)
        return re.search(r'name="_csrf" value="([^"]+)"', html).group(1)

    def register(self, u="tester", e="t@example.com", p="Str0ng!Passw0rd"):
        return self.c.post("/register", data={"_csrf": self.token("/register"), "username": u,
                                              "email": e, "password": p, "confirm": p})

    def login(self, u="tester", p="Str0ng!Passw0rd"):
        return self.c.post("/login", data={"_csrf": self.token("/login"), "username": u, "password": p})

    def test_register_and_hash_not_plaintext(self):
        self.assertEqual(self.register().status_code, 302)
        import sqlite3
        h = sqlite3.connect(self.tmp).execute("SELECT pw_hash FROM users").fetchone()[0]
        self.assertNotIn("Str0ng", h)

    def test_weak_password_rejected(self):
        self.assertEqual(self.register(p="password").status_code, 400)

    def test_login_logout_flow(self):
        self.register()
        self.assertEqual(self.login().status_code, 302)
        self.assertEqual(self.c.get("/dashboard").status_code, 200)
        self.c.post("/logout", data={"_csrf": self.token("/dashboard")})
        self.assertEqual(self.c.get("/dashboard").status_code, 302)

    def test_sql_injection_fails(self):
        self.register()
        r = self.login("admin' OR '1'='1", "x")
        self.assertEqual(r.status_code, 401)
        r = self.login("tester", "' OR '1'='1")
        self.assertEqual(r.status_code, 401)
        self.assertEqual(self.c.get("/dashboard").status_code, 302)

    def test_csrf_blocked(self):
        r = self.c.post("/login", data={"username": "a", "password": "b"})
        self.assertEqual(r.status_code, 400)

    def test_lockout_after_5_failures(self):
        self.register()
        for _ in range(5): self.login(p="wrong")
        self.assertEqual(self.login().status_code, 429)  # even correct password is locked

    def test_dashboard_requires_login(self):
        self.assertEqual(self.c.get("/dashboard").status_code, 302)

    def test_totp_known_vector(self):  # RFC 6238 test vector (SHA1, secret "12345678901234567890")
        import base64
        s = base64.b32encode(b"12345678901234567890").decode()
        self.assertEqual(A.totp_now(s, t=59, digits=8), "94287082")

    def test_2fa_flow(self):
        self.register(); self.login()
        self.c.get("/2fa/setup")
        with self.c.session_transaction() as s: secret = s["new_totp"]
        r = self.c.post("/2fa/setup", data={"_csrf": self.token("/2fa/setup"), "code": A.totp_now(secret)})
        self.assertEqual(r.status_code, 302)
        self.c.post("/logout", data={"_csrf": self.token("/dashboard")})
        self.assertEqual(self.login().headers["Location"], "/2fa/verify")
        self.assertEqual(self.c.get("/dashboard").status_code, 302)  # not logged in yet
        r = self.c.post("/2fa/verify", data={"_csrf": self.token("/2fa/verify"), "code": A.totp_now(secret)})
        self.assertEqual(r.headers["Location"], "/dashboard")


if __name__ == "__main__":
    print("bcrypt in use:", A.HAVE_BCRYPT)
    unittest.main(verbosity=2)
