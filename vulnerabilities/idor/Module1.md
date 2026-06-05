# IDOR Mastery — Module 01 Cheatsheet
## What is IDOR and How Does Authorization Actually Work?

> **Core principle:** IDOR is not a technical bug in a URL. It is a failure of a business rule.
> The rule: *only the right person can access the right data.*

---

## The One-Line Definition

> An application exposes a reference to an internal object and fails to verify that the requesting user is authorized to access it.

**What it is not:** "changing an ID in a URL"
**What it actually is:** a missing or misplaced authorization check

---

## The Three Questions — Ask About Every Object

| Question | What You're Looking For |
|---|---|
| **What is the object?** | Order, invoice, file, profile, message, record |
| **Who should have access?** | Owner only? Role-based? Shared recipients? Public? |
| **Where is authorization enforced?** | Server-side on every route? Frontend only? Nowhere? |

**A fourth question — always ask:**
> What assumption did the developer make that allowed unauthorized access here?

---

## Authentication vs Authorization

```
Authentication  →  "Who are you?"         →  Validates identity (JWT, session, API key)
Authorization   →  "What can you do?"     →  Validates entitlement (ownership, role, scope)
```

These are **separate systems** that can fail independently.

- ✅ Authenticated + ✅ Authorized = secure
- ✅ Authenticated + ❌ No authorization check = **IDOR**
- ❌ Not authenticated = different vulnerability class entirely

**The badge analogy:**
Scanning your badge to enter the building (authn) does not grant access to the CEO's office (authz). Those are two different controls.

---

## The Five Broken Developer Assumptions

### 1. Login ≡ Ownership
> *"If they're logged in, it must be their data"*

**Reality:** A valid session proves identity. It says nothing about what the user owns.
`requireLogin` middleware is authentication — not authorization.

### 2. Security Through Obscurity
> *"No one will find this endpoint, so it doesn't need a check"*

**Reality:** JS bundles, mobile traffic interception, and API fuzzing expose hidden routes quickly.
Obscurity is not a security control.

### 3. Unpredictability ≡ Authorization
> *"The ID is a UUID so it can't be guessed"*

**Reality:** UUIDs prevent enumeration. They do not prevent exploitation once an ID is known.
IDs leak through: email links, API responses, referrer headers, shared URLs, logs.

### 4. Client-Supplied Identity Trusted
> *"The user_id in the request came from our own UI"*

**Reality:** Anything the client sends can be modified with a proxy.
The only trusted source of identity is the **server-side session** — never the request body or headers.

### 5. List-Level Filter ≡ Record-Level Protection
> *"We filter the list endpoint so the detail endpoint is fine"*

**Reality:** `GET /orders` (filtered) ≠ `GET /orders/:id` (direct access).
Authorization must be enforced on **every route** independently, not inherited from other routes.

---

## Vulnerable vs Secure Code

### Vulnerable — IDOR present

```javascript
// Node.js / Express
app.get('/api/orders/:id', requireLogin, async (req, res) => {
  const order = await Order.findById(req.params.id);
  // ❌ No ownership check — returns any order to any logged-in user
  res.json(order);
});
```

**Broken assumption:** Authentication middleware = authorization complete.

### Secure — Authorization enforced

```javascript
app.get('/api/orders/:id', requireLogin, async (req, res) => {
  const order = await Order.findById(req.params.id);

  if (!order) return res.sendStatus(404);

  // ✅ Server-side ownership check against session identity
  if (order.userId !== req.user.id) return res.sendStatus(403);

  res.json(order);
});
```

**Key line:** `order.userId !== req.user.id`
This is the line you look for in every code review.

### Python (Django/Flask) equivalent

```python
# Vulnerable
@app.route('/api/invoices/<int:invoice_id>')
@login_required
def get_invoice(invoice_id):
    invoice = Invoice.query.get_or_404(invoice_id)
    # ❌ No ownership check
    return jsonify(invoice.to_dict())

# Secure
@app.route('/api/invoices/<int:invoice_id>')
@login_required
def get_invoice(invoice_id):
    invoice = Invoice.query.get_or_404(invoice_id)
    # ✅ Ownership enforced
    if invoice.user_id != current_user.id:
        abort(403)
    return jsonify(invoice.to_dict())
```

---

## The "List vs Lookup" Inconsistency Pattern

One of the most common real-world IDOR patterns:

```
GET /api/messages        → ✅ Returns only your messages (filtered)
GET /api/messages/884    → ❌ Returns any message by ID (no ownership check)
```

**Rule:** Authorization applied to a collection endpoint is **not** inherited by the individual resource endpoint.
Every route needs its own check.

---

## UUID ≠ Fix for IDOR

```
Numeric ID:  /orders/1042     → Enumerable, also has IDOR
UUID:        /orders/a3f9...  → Not enumerable, STILL has IDOR if no ownership check
```

UUID fixes: brute-force enumeration
UUID does NOT fix: access control

**ID leakage vectors (UUIDs still exposed via):**
- Email notifications with links
- API responses containing other users' object IDs
- Browser referrer headers
- Shared/bookmarked URLs
- Server logs accessed by other tenants
- Error messages

---

## The Four Scenario Questions — Apply to Every Target

When analyzing any endpoint or feature:

```
1. OBJECT     → What data or resource is being accessed?
2. OWNER      → Who is the legitimate owner or authorized accessor?
3. ENFORCER   → Where and how is that ownership verified?
4. ASSUMPTION → What did the developer assume would prevent unauthorized access?
```

---

## IDOR Detection Signals in Code Review

Look for these patterns — each is a potential IDOR indicator:

```javascript
// 🔴 ID comes directly from request without session cross-check
const data = await Model.findById(req.params.id);

// 🔴 user_id taken from request body (client-controlled)
const userId = req.body.user_id;

// 🔴 Authorization only on list route, not detail route
router.get('/items', auth, filterByUser);      // protected
router.get('/items/:id', auth, getById);       // ← no filter here

// 🔴 Object returned before ownership check
const obj = await fetch(id);
if (someOtherCheck) { ... }  // ownership check buried or conditional

// ✅ Correct pattern — ownership checked immediately after fetch
const obj = await fetch(id);
if (obj.ownerId !== req.user.id) return res.status(403);
```

---

## Key Vocabulary

| Term | Definition |
|---|---|
| **IDOR** | Insecure Direct Object Reference — accessing an object without proper authorization |
| **Authentication** | Verifying *who* the caller is |
| **Authorization** | Verifying *what* the caller is allowed to access |
| **Object-level authorization** | Per-record ownership check (is this record mine?) |
| **Horizontal privilege escalation** | Accessing another user's data at the same role level |
| **Vertical privilege escalation** | Accessing functionality above your role level |
| **Broken assumption** | The false belief a developer held that created the vulnerability |
| **Security through obscurity** | Relying on secrecy of endpoints/IDs as a security control — not effective |
| **List vs lookup inconsistency** | Auth on collection route but not on individual resource route |

---

## The Single Line of Defense

If you could add only one thing to a vulnerable endpoint:

```javascript
if (object.owner_id !== req.user.id) return res.status(403).end();
```

This is the check. Everything else — UUIDs, hidden endpoints, frontend hiding — is noise without this line.

---

## Coming Up — Module 02

**How Developers Create IDORs** — We go inside the developer's mental model:
- Why trust misplacement happens at scale
- How frontend vs backend responsibility confusion creates gaps
- Hidden endpoints and API versioning traps
- Real code patterns that signal "IDOR was probably created here"

---

*Module 01 — IDOR Mastery Curriculum*
*Focus: Authorization logic, broken assumptions, authentication vs authorization*