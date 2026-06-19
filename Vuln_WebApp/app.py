"""
VulnHub - Deliberately Vulnerable Web Application
==================================================
Purpose : Security testing practice
Vulnerabilities:
  1. SQL Injection   → /login (username field)
  2. XSS             → /search (reflected) and /board (stored)
  3. IDOR            → /profile/<user_id>
  4. Privilege Esc.  → /update-profile (accepts role=admin in POST body)

⚠️  For LOCAL TESTING ONLY. Never expose this to the internet.
"""

import os
import sqlite3
from flask import Flask, g, redirect, render_template_string, request, session, url_for
from markupsafe import Markup

app = Flask(__name__)
app.secret_key = "vuln_secret_do_not_use_in_prod"
DB = os.path.join(os.path.dirname(__file__), "vuln.db")

# ───────────────────────────── Database ─────────────────────────────────

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(_=None):
    db = g.pop("db", None)
    if db:
        db.close()

def init_db():
    con = sqlite3.connect(DB)
    con.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email    TEXT,
            role     TEXT NOT NULL DEFAULT 'user',
            bio      TEXT,
            phone    TEXT
        );
        CREATE TABLE IF NOT EXISTS posts (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER NOT NULL,
            title      TEXT NOT NULL,
            body       TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS messages (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            author     TEXT NOT NULL,
            body       TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS orders (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER NOT NULL,
            item       TEXT NOT NULL,
            amount     REAL NOT NULL,
            secret     TEXT
        );
    """)
    # Seed only if empty
    if con.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        con.executescript("""
            INSERT INTO users (username,password,email,role,bio,phone)
            VALUES
              ('admin',  'Admin@Secret99', 'admin@vulnhub.local',  'admin',
               'Site administrator. Full access to all data.', '+1-555-000-0001'),
              ('alice',  'alice123',       'alice@vulnhub.local',  'user',
               'Alice Johnson. SSN: 123-45-6789. Salary: $92,000.', '+1-555-000-0002'),
              ('bob',    'bob456',         'bob@vulnhub.local',    'user',
               'Bob Smith. Credit card: 4111-1111-1111-1111 exp 12/26.', '+1-555-000-0003'),
              ('carol',  'carol789',       'carol@vulnhub.local',  'user',
               'Carol White. Home address: 42 Maple St, Springfield.', '+1-555-000-0004');

            INSERT INTO posts (user_id,title,body) VALUES
              (1,'Admin Announcement','Welcome to VulnHub. This server runs on Ubuntu 22.04.'),
              (2,'Alice Post','Just finished the Q3 report. Attaching next week.'),
              (3,'Bob Post','Reminder: deploy credentials in /var/secrets/deploy.key');

            INSERT INTO messages (author,body) VALUES
              ('alice','Hello everyone! Welcome to the board.'),
              ('bob','Has anyone updated the firewall rules yet?');

            INSERT INTO orders (user_id,item,amount,secret) VALUES
              (1,'Admin License',999.00,'ADMIN-TOKEN-XYZ987'),
              (2,'Pro Plan',49.99,'ALICE-RECEIPT-001'),
              (3,'Basic Plan',9.99,'BOB-RECEIPT-002'),
              (4,'Basic Plan',9.99,'CAROL-RECEIPT-003');
        """)
    con.commit()
    con.close()

# ───────────────────────────── Base template ─────────────────────────────

BASE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>VulnHub – {{ title }}</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', system-ui, sans-serif;
         background: #0f111a; color: #c9d1d9; min-height: 100vh; }
  a { color: #f05454; text-decoration: none; }
  a:hover { text-decoration: underline; }

  /* ── nav ── */
  nav { background: #161b22; border-bottom: 2px solid #f05454;
        padding: 0 32px; display: flex; align-items: center; gap: 0; height: 52px; }
  .nav-brand { font-size: 18px; font-weight: 800; color: #f05454;
               letter-spacing: .5px; margin-right: auto; }
  nav a { color: #c9d1d9; font-size: 13.5px; padding: 16px 14px;
          display: block; border-bottom: 2px solid transparent; }
  nav a:hover, nav a.active { color: #f05454;
         border-bottom-color: #f05454; text-decoration: none; }
  .badge { background:#f05454; color:#fff; font-size:10px; font-weight:700;
           padding:2px 6px; border-radius:99px; margin-left:4px;
           vertical-align: middle; }

  /* ── layout ── */
  .page { max-width: 960px; margin: 36px auto; padding: 0 20px; }

  /* ── cards ── */
  .card { background: #161b22; border: 1px solid #21262d;
          border-radius: 10px; padding: 28px; margin-bottom: 22px; }
  h1 { font-size: 24px; color: #f05454; margin-bottom: 18px; }
  h2 { font-size: 18px; color: #f05454; margin-bottom: 14px; }
  h3 { font-size: 14px; color: #8b949e; margin-bottom: 10px; font-weight: 600; }
  p  { color: #8b949e; font-size: 14px; line-height: 1.6; }

  /* ── form elements ── */
  label { display: block; font-size: 12px; color: #8b949e;
          font-weight: 600; margin-bottom: 5px; text-transform: uppercase; letter-spacing: .4px; }
  input[type=text], input[type=password], input[type=email], textarea, select {
    width: 100%; padding: 9px 13px; background: #0d1117;
    border: 1px solid #30363d; border-radius: 6px;
    color: #c9d1d9; font-size: 14px; margin-bottom: 14px; }
  input:focus, textarea:focus { outline: none; border-color: #f05454; }
  textarea { min-height: 90px; resize: vertical; font-family: inherit; }
  .form-group { margin-bottom: 4px; }

  /* ── buttons ── */
  .btn { display: inline-block; padding: 9px 20px; border-radius: 6px;
         font-size: 13.5px; font-weight: 600; cursor: pointer; border: none; }
  .btn-red   { background: #f05454; color: #fff; }
  .btn-red:hover { background: #d03c3c; }
  .btn-ghost { background: transparent; border: 1px solid #f05454; color: #f05454; }
  .btn-ghost:hover { background: #f05454; color: #fff; }
  .btn-sm { padding: 5px 12px; font-size: 12px; }

  /* ── alerts ── */
  .alert { padding: 11px 16px; border-radius: 6px; font-size: 13.5px; margin-bottom: 18px; }
  .alert-err  { background:#2d1010; border:1px solid #f05454; color:#fca5a5; }
  .alert-ok   { background:#0d2318; border:1px solid #22c55e; color:#86efac; }
  .alert-warn { background:#2d1f00; border:1px solid #f59e0b; color:#fcd34d; }
  .alert-info { background:#0d1f2d; border:1px solid #38bdf8; color:#7dd3fc; }

  /* ── table ── */
  table { width:100%; border-collapse:collapse; font-size:13.5px; }
  th { text-align:left; padding:9px 14px; background:#0d1117; color:#8b949e;
       font-weight:600; font-size:12px; text-transform:uppercase; letter-spacing:.4px; }
  td { padding:9px 14px; border-bottom:1px solid #21262d; }
  tr:last-child td { border-bottom: none; }
  tr:hover td { background:#1c2128; }

  /* ── role badges ── */
  .role { display:inline-block; padding:2px 10px; border-radius:99px;
          font-size:11px; font-weight:700; text-transform:uppercase; }
  .role-admin { background:#4a0d0d; color:#f87171; }
  .role-user  { background:#0d1f3c; color:#60a5fa; }

  /* ── vuln tag ── */
  .vuln-tag { display:inline-block; background:#2d1f00; border:1px solid #f59e0b;
              color:#fcd34d; font-size:11px; padding:2px 9px; border-radius:4px;
              font-weight:600; margin-bottom:10px; }

  /* ── avatar ── */
  .avatar { width:60px; height:60px; border-radius:50%; background:#f05454;
            display:flex; align-items:center; justify-content:center;
            font-size:26px; font-weight:800; color:#fff; margin-bottom:16px; }

  /* ── grid ── */
  .grid2 { display:grid; grid-template-columns:1fr 1fr; gap:18px; }
  @media(max-width:600px){ .grid2{ grid-template-columns:1fr; } }

  /* ── message card ── */
  .msg-card { background:#0d1117; border:1px solid #21262d; border-radius:8px;
              padding:14px 18px; margin-bottom:12px; }
  .msg-author { color:#f05454; font-weight:700; font-size:13px; }
  .msg-time   { color:#484f58; font-size:11px; margin-left:8px; }
  .msg-body   { margin-top:8px; font-size:14px; line-height:1.6; }
</style>
</head>
<body>
<nav>
  <span class="nav-brand">⚡ VulnHub</span>
  <a href="/">Home</a>
  <a href="/search">Search</a>
  <a href="/board">Board</a>
  <a href="/orders">Orders</a>
  {% if session.user_id %}
    <a href="/profile/{{ session.user_id }}">Profile</a>
    {% if session.role == 'admin' %}
      <a href="/admin">Admin<span class="badge">ADMIN</span></a>
    {% endif %}
    <a href="/logout">Logout</a>
  {% else %}
    <a href="/login">Login</a>
    <a href="/register">Register</a>
  {% endif %}
</nav>

<div class="page">
  {% if msg %}
    <div class="alert alert-{{ msg_type or 'ok' }}">{{ msg }}</div>
  {% endif %}
  {{ body }}
</div>
</body>
</html>"""

def render(title, body, msg=None, msg_type=None):
    return render_template_string(
        BASE, title=title, body=Markup(body), msg=msg, msg_type=msg_type
    )

# ──────────────────────────── Home ──────────────────────────────────────

@app.route("/")
def index():
    db = get_db()
    posts = db.execute(
        "SELECT posts.id, posts.title, posts.body, users.username "
        "FROM posts JOIN users ON posts.user_id=users.id "
        "ORDER BY posts.created_at DESC"
    ).fetchall()
    rows = "".join(
        f"<tr><td>{p['id']}</td><td>{p['title']}</td>"
        f"<td>{p['body'][:60]}…</td>"
        f"<td>{p['username']}</td></tr>"
        for p in posts
    )
    body = f"""
    <div class="card">
      <h1>Welcome to VulnHub</h1>
      <p>A deliberately vulnerable web application for local security testing.</p>
      <div class="alert alert-warn" style="margin-top:16px;">
        ⚠️ This app contains intentional vulnerabilities. Use for authorized
        local testing only. <strong>Never expose to the internet.</strong>
      </div>
      <div class="grid2" style="margin-top:20px;">
        <div style="background:#0d1117;border:1px solid #21262d;border-radius:8px;padding:16px;">
          <div class="vuln-tag">VULN #1</div>
          <h3 style="color:#f05454;margin-top:6px;">SQL Injection</h3>
          <p>Login form uses raw string concatenation.<br>
          Endpoint: <code style="color:#fcd34d;">POST /login</code></p>
        </div>
        <div style="background:#0d1117;border:1px solid #21262d;border-radius:8px;padding:16px;">
          <div class="vuln-tag">VULN #2</div>
          <h3 style="color:#f05454;margin-top:6px;">Cross-Site Scripting</h3>
          <p>Reflected on /search and stored on /board.<br>
          Endpoints: <code style="color:#fcd34d;">GET /search, POST /board</code></p>
        </div>
        <div style="background:#0d1117;border:1px solid #21262d;border-radius:8px;padding:16px;">
          <div class="vuln-tag">VULN #3</div>
          <h3 style="color:#f05454;margin-top:6px;">IDOR</h3>
          <p>No ownership check on profile or order views.<br>
          Endpoints: <code style="color:#fcd34d;">GET /profile/&lt;id&gt;, GET /orders/&lt;id&gt;</code></p>
        </div>
        <div style="background:#0d1117;border:1px solid #21262d;border-radius:8px;padding:16px;">
          <div class="vuln-tag">VULN #4</div>
          <h3 style="color:#f05454;margin-top:6px;">Privilege Escalation</h3>
          <p>Profile update accepts role from POST body.<br>
          Endpoint: <code style="color:#fcd34d;">POST /update-profile</code></p>
        </div>
      </div>
    </div>
    <div class="card">
      <h2>Recent Posts</h2>
      <table>
        <thead><tr><th>#</th><th>Title</th><th>Preview</th><th>Author</th></tr></thead>
        <tbody>{rows}</tbody>
      </table>
    </div>
    """
    return render("Home", body)

# ─────────────── VULN 1 – SQL INJECTION: Login ──────────────────────────

@app.route("/login", methods=["GET", "POST"])
def login():
    """
    VULNERABILITY: SQL Injection
    The username and password are inserted directly into the SQL query
    using string formatting — no parameterised queries.

    Bypass:  username = admin'--
             password = anything
    The resulting query becomes:
      SELECT * FROM users WHERE username='admin'--' AND password='anything'
    The '--' comments out the password check.

    Full extraction via UNION:
      username = ' UNION SELECT 1,username,password,email,role,bio,phone FROM users--
    """
    err = None
    if request.method == "POST":
        u = request.form.get("username", "")
        p = request.form.get("password", "")
        db = get_db()
        # ⚠️ INTENTIONALLY VULNERABLE — raw string interpolation
        query = f"SELECT * FROM users WHERE username='{u}' AND password='{p}'"
        try:
            user = db.execute(query).fetchone()
        except Exception as e:
            err = f"Database error: {e}"
            user = None

        if user:
            session["user_id"]  = user["id"]
            session["username"] = user["username"]
            session["role"]     = user["role"]
            return redirect(url_for("index"))
        elif not err:
            err = "Invalid username or password."

    body = f"""
    <div class="card" style="max-width:420px;margin:auto;">
      <h1>Login</h1>
      <div class="vuln-tag">VULN #1 — SQL Injection</div>
      <p style="margin-bottom:16px;">
        Try username: <code style="color:#fcd34d;">admin'--</code>
        with any password to bypass authentication.
      </p>
      {'<div class="alert alert-err">'+err+'</div>' if err else ''}
      <form method="POST">
        <div class="form-group">
          <label>Username</label>
          <input type="text" name="username" placeholder="admin'-- to bypass">
        </div>
        <div class="form-group">
          <label>Password</label>
          <input type="password" name="password" placeholder="anything">
        </div>
        <button class="btn btn-red" type="submit">Login</button>
        <a href="/register" class="btn btn-ghost" style="margin-left:10px;">Register</a>
      </form>
    </div>
    """
    return render("Login", body)


@app.route("/register", methods=["GET", "POST"])
def register():
    err = None
    if request.method == "POST":
        u = request.form.get("username", "")
        p = request.form.get("password", "")
        e = request.form.get("email", "")
        if not u or not p:
            err = "Username and password are required."
        else:
            db = get_db()
            try:
                db.execute(
                    "INSERT INTO users (username,password,email) VALUES (?,?,?)",
                    (u, p, e)
                )
                db.commit()
                return redirect(url_for("login"))
            except Exception:
                err = "Username already taken."

    body = f"""
    <div class="card" style="max-width:420px;margin:auto;">
      <h1>Register</h1>
      {'<div class="alert alert-err">'+err+'</div>' if err else ''}
      <form method="POST">
        <div class="form-group">
          <label>Username</label>
          <input type="text" name="username" placeholder="Choose a username">
        </div>
        <div class="form-group">
          <label>Password</label>
          <input type="password" name="password" placeholder="Password">
        </div>
        <div class="form-group">
          <label>Email</label>
          <input type="email" name="email" placeholder="your@email.com">
        </div>
        <button class="btn btn-red" type="submit">Create Account</button>
      </form>
    </div>
    """
    return render("Register", body)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

# ─────────────── VULN 2 – XSS: Search (Reflected) & Board (Stored) ──────

@app.route("/search")
def search():
    """
    VULNERABILITY: Reflected XSS
    The query parameter `q` is inserted directly into the HTML response
    without any HTML encoding.

    Payload: /search?q=<script>alert('XSS')</script>
    Payload: /search?q=<img src=x onerror=alert(document.cookie)>
    """
    q = request.args.get("q", "")
    db = get_db()
    results = []
    if q:
        results = db.execute(
            "SELECT posts.title, posts.body, users.username "
            "FROM posts JOIN users ON posts.user_id=users.id "
            "WHERE posts.title LIKE ? OR posts.body LIKE ?",
            (f"%{q}%", f"%{q}%")
        ).fetchall()

    result_rows = "".join(
        f"<tr><td>{r['title']}</td><td>{r['body'][:80]}</td><td>{r['username']}</td></tr>"
        for r in results
    ) if results else "<tr><td colspan='3' style='color:#484f58;'>No results.</td></tr>"

    # ⚠️ INTENTIONALLY VULNERABLE — q injected raw into HTML
    body = f"""
    <div class="card">
      <h1>Search</h1>
      <div class="vuln-tag">VULN #2 — Reflected XSS</div>
      <p style="margin-bottom:16px;">
        Try: <code style="color:#fcd34d;">&lt;script&gt;alert(1)&lt;/script&gt;</code>
        or <code style="color:#fcd34d;">&lt;img src=x onerror=alert(document.cookie)&gt;</code>
      </p>
      <form method="GET">
        <label>Search posts</label>
        <input type="text" name="q" value="{q}" placeholder="Enter search term…">
        <button class="btn btn-red" type="submit">Search</button>
      </form>
    </div>
    <div class="card">
      <h2>Results for: {q}</h2>
      <table>
        <thead><tr><th>Title</th><th>Body</th><th>Author</th></tr></thead>
        <tbody>{result_rows}</tbody>
      </table>
    </div>
    """
    # Markup() bypasses Jinja2 auto-escaping → XSS works
    return render("Search", Markup(body))


@app.route("/board", methods=["GET", "POST"])
def board():
    """
    VULNERABILITY: Stored XSS
    Message body is stored as-is in the database and rendered back
    into the page without HTML encoding.

    Payload (POST body field): <script>alert('Stored XSS')</script>
    Payload: <img src=x onerror="fetch('/api/users').then(r=>r.json()).then(d=>alert(JSON.stringify(d)))">
    """
    db = get_db()
    if request.method == "POST":
        if not session.get("user_id"):
            return redirect(url_for("login"))
        # ⚠️ INTENTIONALLY VULNERABLE — body stored without sanitisation
        body_text = request.form.get("body", "")
        db.execute(
            "INSERT INTO messages (author, body) VALUES (?,?)",
            (session["username"], body_text)
        )
        db.commit()

    msgs = db.execute(
        "SELECT * FROM messages ORDER BY created_at DESC LIMIT 30"
    ).fetchall()

    # ⚠️ INTENTIONALLY VULNERABLE — body rendered without escaping
    msg_html = "".join(
        f'<div class="msg-card">'
        f'<span class="msg-author">{m["author"]}</span>'
        f'<span class="msg-time">{m["created_at"]}</span>'
        f'<div class="msg-body">{m["body"]}</div>'
        f'</div>'
        for m in msgs
    ) or '<p style="color:#484f58;">No messages yet.</p>'

    post_form = ""
    if session.get("user_id"):
        post_form = f"""
        <div class="card">
          <h2>Post a Message</h2>
          <div class="vuln-tag">VULN #2 — Stored XSS</div>
          <p style="margin-bottom:16px;">
            HTML in the message body is stored and rendered without sanitisation.<br>
            Try: <code style="color:#fcd34d;">&lt;img src=x onerror=alert(1)&gt;</code>
          </p>
          <form method="POST">
            <label>Message</label>
            <textarea name="body" placeholder="Your message (HTML allowed)…"></textarea>
            <button class="btn btn-red" type="submit">Post</button>
          </form>
        </div>
        """

    body = f"""
    <div class="card"><h1>Message Board</h1></div>
    {post_form}
    {msg_html}
    """
    return render("Board", Markup(body))

# ─────────────── VULN 3 – IDOR: Profile & Orders ────────────────────────

@app.route("/profile/<int:uid>")
def profile(uid):
    """
    VULNERABILITY: IDOR (Insecure Direct Object Reference)
    Any logged-in user can view ANY user's profile by changing the
    numeric ID in the URL. No ownership check is performed.

    Example: Login as alice (id=2), then visit /profile/1 to see
    admin's private bio, email, and phone number.
    """
    if not session.get("user_id"):
        return redirect(url_for("login"))

    db = get_db()
    # ⚠️ INTENTIONALLY VULNERABLE — no check that uid == session["user_id"]
    user = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if not user:
        return render("Not Found", '<div class="card"><h1>User not found</h1></div>'), 404

    initial = user["username"][0].upper()
    is_own  = session["user_id"] == uid

    edit_section = ""
    if is_own:
        edit_section = f"""
        <div class="card">
          <h2>Edit Profile</h2>
          <div class="vuln-tag">VULN #4 — Privilege Escalation</div>
          <p style="margin-bottom:16px;">
            The update endpoint accepts a <code style="color:#fcd34d;">role</code> field
            in the POST body. Add <code style="color:#fcd34d;">role=admin</code> using a
            proxy or curl to escalate your privileges.
          </p>
          <form method="POST" action="/update-profile">
            <label>Bio</label>
            <textarea name="bio">{user['bio'] or ''}</textarea>
            <label>Email</label>
            <input type="email" name="email" value="{user['email'] or ''}">
            <label>Phone</label>
            <input type="text" name="phone" value="{user['phone'] or ''}">
            <!-- role field intentionally not shown but accepted by server -->
            <button class="btn btn-red" type="submit">Save</button>
          </form>
        </div>
        """

    body = f"""
    <div class="card">
      <div class="vuln-tag">VULN #3 — IDOR</div>
      <div class="avatar">{initial}</div>
      <h1>{user['username']}</h1>
      <span class="role {'role-admin' if user['role']=='admin' else 'role-user'}">
        {user['role']}
      </span>
      <p style="margin-top:4px;color:#484f58;font-size:12px;">
        Change the ID in the URL to access other users' private data.
        Try <a href="/profile/1">/profile/1</a>,
        <a href="/profile/2">/profile/2</a>,
        <a href="/profile/3">/profile/3</a>
      </p>
      <table style="margin-top:20px;">
        <tr><td style="color:#8b949e;width:120px;">Email</td><td>{user['email'] or '—'}</td></tr>
        <tr><td style="color:#8b949e;">Phone</td><td>{user['phone'] or '—'}</td></tr>
        <tr><td style="color:#8b949e;">Bio</td><td>{user['bio'] or '—'}</td></tr>
        <tr><td style="color:#8b949e;">Role</td><td>{user['role']}</td></tr>
      </table>
    </div>
    {edit_section}
    """
    return render(f"Profile – {user['username']}", body)


@app.route("/orders")
def orders_list():
    """List the current user's orders — also used as a jumping-off point for IDOR."""
    if not session.get("user_id"):
        return redirect(url_for("login"))
    db = get_db()
    rows = db.execute(
        "SELECT id, item, amount FROM orders WHERE user_id=?",
        (session["user_id"],)
    ).fetchall()
    table = "".join(
        f"<tr><td><a href='/orders/{r['id']}'>{r['id']}</a></td>"
        f"<td>{r['item']}</td><td>${r['amount']:.2f}</td></tr>"
        for r in rows
    ) or "<tr><td colspan='3' style='color:#484f58;'>No orders found.</td></tr>"

    body = f"""
    <div class="card">
      <h1>My Orders</h1>
      <div class="vuln-tag">VULN #3 — IDOR</div>
      <p style="margin-bottom:16px;">
        Click an order to view it. Then change the ID in the URL to access
        other users' orders and their secret tokens.
      </p>
      <table>
        <thead><tr><th>Order ID</th><th>Item</th><th>Amount</th></tr></thead>
        <tbody>{table}</tbody>
      </table>
    </div>
    """
    return render("My Orders", body)


@app.route("/orders/<int:oid>")
def order_detail(oid):
    """
    VULNERABILITY: IDOR
    No check that the order belongs to the current user.
    Visit /orders/1 as alice to see admin's secret token.
    """
    if not session.get("user_id"):
        return redirect(url_for("login"))
    db = get_db()
    # ⚠️ INTENTIONALLY VULNERABLE — no WHERE user_id check
    order = db.execute("SELECT * FROM orders WHERE id=?", (oid,)).fetchone()
    if not order:
        return render("Not Found", '<div class="card"><h1>Order not found</h1></div>'), 404

    owner = db.execute(
        "SELECT username FROM users WHERE id=?", (order["user_id"],)
    ).fetchone()

    body = f"""
    <div class="card">
      <div class="vuln-tag">VULN #3 — IDOR</div>
      <h1>Order #{order['id']}</h1>
      <p style="margin-bottom:16px;">
        Change the order ID in the URL to view other users' orders.
        Try <a href="/orders/1">/orders/1</a> while logged in as alice.
      </p>
      <table>
        <tr><td style="color:#8b949e;width:140px;">Order ID</td><td>{order['id']}</td></tr>
        <tr><td style="color:#8b949e;">Owner</td><td>{owner['username'] if owner else '—'}</td></tr>
        <tr><td style="color:#8b949e;">Item</td><td>{order['item']}</td></tr>
        <tr><td style="color:#8b949e;">Amount</td><td>${order['amount']:.2f}</td></tr>
        <tr><td style="color:#8b949e;">Secret Token</td>
            <td style="color:#fcd34d;font-family:monospace;">{order['secret']}</td></tr>
      </table>
      <a href="/orders" class="btn btn-ghost btn-sm" style="margin-top:16px;">← Back</a>
    </div>
    """
    return render(f"Order #{oid}", body)

# ─────────────── VULN 4 – Privilege Escalation: Update Profile ──────────

@app.route("/update-profile", methods=["POST"])
def update_profile():
    """
    VULNERABILITY: Privilege Escalation
    The 'role' field is accepted from the POST body and written
    directly to the database — no server-side validation.

    Exploit with curl:
      curl -X POST http://localhost:5001/update-profile \\
           -b "session=<your_cookie>" \\
           -d "bio=hacked&email=x@x.com&phone=0&role=admin"

    Or intercept the Save form request in a proxy and add role=admin.
    """
    if not session.get("user_id"):
        return redirect(url_for("login"))

    bio   = request.form.get("bio", "")
    email = request.form.get("email", "")
    phone = request.form.get("phone", "")
    # ⚠️ INTENTIONALLY VULNERABLE — role taken from user-supplied POST data
    role  = request.form.get("role", session.get("role", "user"))

    db = get_db()
    db.execute(
        "UPDATE users SET bio=?, email=?, phone=?, role=? WHERE id=?",
        (bio, email, phone, role, session["user_id"])
    )
    db.commit()
    session["role"] = role   # session reflects the attacker-supplied value
    return redirect(url_for("profile", uid=session["user_id"]))


# ─────────────── Admin Panel (accessible after privilege escalation) ──────

@app.route("/admin")
def admin():
    if session.get("role") != "admin":
        body = """
        <div class="card">
          <h1>403 – Access Denied</h1>
          <p>Admin role required.</p>
          <div class="alert alert-warn" style="margin-top:16px;">
            Hint: Escalate via <code>POST /update-profile</code>
            with <code>role=admin</code> in the body.
          </div>
          <a href="/" class="btn btn-ghost" style="margin-top:16px;">Go Home</a>
        </div>
        """
        return render("Access Denied", body), 403

    db = get_db()
    users  = db.execute("SELECT * FROM users").fetchall()
    orders = db.execute(
        "SELECT orders.*, users.username FROM orders "
        "JOIN users ON orders.user_id=users.id"
    ).fetchall()

    user_rows = "".join(
        f"<tr>"
        f"<td>{u['id']}</td>"
        f"<td><a href='/profile/{u['id']}'>{u['username']}</a></td>"
        f"<td>{u['email']}</td>"
        f"<td>{u['phone']}</td>"
        f"<td>{u['password']}</td>"
        f"<td><span class='role {'role-admin' if u['role']=='admin' else 'role-user'}'>{u['role']}</span></td>"
        f"</tr>"
        for u in users
    )
    order_rows = "".join(
        f"<tr><td>{o['id']}</td><td>{o['username']}</td>"
        f"<td>{o['item']}</td><td>${o['amount']:.2f}</td>"
        f"<td style='color:#fcd34d;font-family:monospace;'>{o['secret']}</td></tr>"
        for o in orders
    )
    body = f"""
    <div class="card">
      <h1>🔐 Admin Dashboard</h1>
      <p>You successfully escalated to admin. All data is now visible.</p>
    </div>
    <div class="card">
      <h2>All Users — including passwords</h2>
      <table>
        <thead><tr><th>ID</th><th>Username</th><th>Email</th>
        <th>Phone</th><th>Password</th><th>Role</th></tr></thead>
        <tbody>{user_rows}</tbody>
      </table>
    </div>
    <div class="card">
      <h2>All Orders — including secret tokens</h2>
      <table>
        <thead><tr><th>ID</th><th>User</th><th>Item</th>
        <th>Amount</th><th>Secret Token</th></tr></thead>
        <tbody>{order_rows}</tbody>
      </table>
    </div>
    """
    return render("Admin Panel", Markup(body))


# ─────────────── JSON API (bonus attack surface) ─────────────────────────

@app.route("/api/users")
def api_users():
    """No authentication — exposes all user data as JSON."""
    db = get_db()
    users = db.execute("SELECT id,username,email,role FROM users").fetchall()
    return {"users": [dict(u) for u in users]}

# ─────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    init_db()
    print("""
╔══════════════════════════════════════════════════════════╗
║              VulnHub – Vulnerable Web App               ║
║                  http://localhost:5001                  ║
╠══════════════════════════════════════════════════════════╣
║  Login credentials:                                     ║
║    admin  /  Admin@Secret99   (role: admin)             ║
║    alice  /  alice123         (role: user)              ║
║    bob    /  bob456           (role: user)              ║
║    carol  /  carol789         (role: user)              ║
╠══════════════════════════════════════════════════════════╣
║  Vulnerabilities:                                       ║
║  1. SQL Injection   → POST /login                       ║
║  2. XSS Reflected   → GET  /search?q=                   ║
║  2. XSS Stored      → POST /board                       ║
║  3. IDOR            → GET  /profile/<id>                ║
║  3. IDOR            → GET  /orders/<id>                 ║
║  4. Priv. Escalation→ POST /update-profile (role=admin) ║
╚══════════════════════════════════════════════════════════╝
""")
    app.run(debug=True, port=5001, host="127.0.0.1")
