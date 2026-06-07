# IDOR Mastery — Module 02 Cheatsheet
## How Developers Create IDORs

> **Core principle:** IDOR is not a developer mistake born from ignorance.
> It is a systematic output of how software gets built — deadlines, team handoffs,
> middleware trust, and copy-paste culture all predictably produce the same authorization gaps.

---

## The Seven Root-Cause Failure Modes

### 1. Build Fast, Auth Later (Deadline Pressure)

**How it happens:** Authorization is planned but treated as non-blocking. The MVP ships without it and becomes the permanent product.

**Broken assumption:** *"We'll add the auth check before launch."*

```javascript
// VULNERABLE — auth deferred and never shipped
app.get('/api/reports/:id', async (req, res) => {
  // TODO: add authorization check
  const report = await Report.findById(req.params.id);
  res.json(report);
});

// SECURE — ownership check is non-negotiable, not deferrable
app.get('/api/reports/:id', requireLogin, async (req, res) => {
  const report = await Report.findById(req.params.id);
  if (!report) return res.sendStatus(404);
  if (report.userId !== req.user.id) return res.sendStatus(403); // ← this line
  res.json(report);
});
```

---

### 2. Frontend/Backend Trust Split (Team Boundary)

**How it happens:** Frontend hides the button or form element. Backend developer assumes the UI gatekeeps all unauthorized requests and doesn't add a server-side check.

**Broken assumption:** *"If the UI doesn't show it, users can't trigger it."*

```javascript
// VULNERABLE — backend trusts the frontend never sends unauthorized requests
app.delete('/api/posts/:id', requireLogin, async (req, res) => {
  const post = await Post.findById(req.params.id);
  // no ownership check — UI was trusted to gatekeep
  await post.delete();
  res.sendStatus(200);
});

// SECURE — backend enforces independently of what the UI does
app.delete('/api/posts/:id', requireLogin, async (req, res) => {
  const post = await Post.findById(req.params.id);
  if (!post) return res.sendStatus(404);
  if (post.authorId !== req.user.id) return res.sendStatus(403); // ← UI is irrelevant
  await post.delete();
  res.sendStatus(200);
});
```

**Rule:** The API is the security boundary. The UI is a convenience layer. These are not the same thing.

---

### 3. Auth Middleware = Done (Middleware Trust)

**How it happens:** `requireLogin` middleware is added and the developer considers authorization complete. They conflate authentication (who you are) with authorization (what you're allowed to access).

**Broken assumption:** *"I added auth middleware, so this route is protected."*

```javascript
// VULNERABLE — middleware confirms login, not ownership
app.use(requireLogin); // ← developer thinks: "auth is handled"

app.get('/api/invoices/:id', async (req, res) => {
  const inv = await Invoice.findById(req.params.id);
  // no ownership check — middleware was assumed to cover this
  res.json(inv);
});

// SECURE — authentication and authorization are separate steps
app.use(requireLogin); // confirms identity

app.get('/api/invoices/:id', async (req, res) => {
  const inv = await Invoice.findById(req.params.id);
  if (!inv) return res.sendStatus(404);
  if (inv.clientId !== req.user.id) return res.sendStatus(403); // ← ownership check
  res.json(inv);
});
```

**Rule:** `requireLogin` tells you *who* the caller is. It tells you nothing about *what they own.*

---

### 4. Forgotten Old API Routes (API Versioning)

**How it happens:** Security patches are applied to the new API version. The old version is never retired or patched and remains reachable.

**Broken assumption:** *"We fixed it in v2 so we're covered."*

```javascript
// VULNERABLE — v1 never patched, still live
app.get('/api/v2/orders/:id', requireLogin, async (req, res) => {
  const order = await Order.findById(req.params.id);
  if (order.userId !== req.user.id) return res.sendStatus(403); // ✓ patched
  res.json(order);
});

app.get('/api/v1/orders/:id', requireLogin, async (req, res) => {
  const order = await Order.findById(req.params.id);
  // patch never applied to v1 — IDOR survives here
  res.json(order);
});

// SECURE — option 1: retire v1
app.get('/api/v1/orders/:id', (req, res) => {
  res.status(410).json({ error: 'v1 API deprecated. Use /api/v2/' });
});

// SECURE — option 2: shared authorization handler across all versions
const getOrderHandler = [requireLogin, enforceOwnership, serveOrder];
app.get('/api/v1/orders/:id', ...getOrderHandler);
app.get('/api/v2/orders/:id', ...getOrderHandler);
```

**Rule:** Authorization logic belongs in shared middleware called by all versions — not duplicated per version. API versioning is a deployment concern, not a security boundary.

---

### 5. Internal Tools Without Auth (Admin Routes)

**How it happens:** An internal dashboard, admin panel, or data export endpoint is created without authentication because "only we use it internally."

**Broken assumption:** *"This endpoint is internal — no one outside will find it."*

```javascript
// VULNERABLE — assumed obscurity as security
app.get('/internal/users/:id/export', async (req, res) => {
  // no auth — "only admins would call this"
  const user = await User.findById(req.params.id);
  res.json(user.fullProfile());
});

// SECURE — internal does not mean unprotected
app.get('/internal/users/:id/export',
  requireLogin,
  requireRole('admin'),    // ← role check
  async (req, res) => {
    const user = await User.findById(req.params.id);
    res.json(user.fullProfile());
  }
);
```

**Rule:** Obscurity is not a control. JS bundles, mobile traffic interception, and endpoint fuzzing expose hidden routes quickly.

---

### 6. Trusting Client-Supplied Identity

**How it happens:** The backend reads `user_id` from the request body, query string, or a custom header — values the client controls — instead of reading identity from the server-validated session.

**Broken assumption:** *"The user_id in the request came from our own UI."*

```javascript
// VULNERABLE — user_id sourced from request body (client-controlled)
app.post('/api/messages', requireLogin, async (req, res) => {
  const { user_id, text } = req.body; // ← attacker sets this to any value
  await Message.create({ userId: user_id, text });
  res.sendStatus(201);
});

// SECURE — identity always from server-side session
app.post('/api/messages', requireLogin, async (req, res) => {
  const userId = req.user.id;  // ← from verified JWT/session, not body
  const { text } = req.body;
  await Message.create({ userId, text });
  res.sendStatus(201);
});
```

**The only trusted identity sources (server-side):**
| Source | Trusted? | Why |
|--------|----------|-----|
| `req.user.id` (set by auth middleware from JWT/session) | ✅ Yes | Server-validated |
| `req.body.user_id` | ❌ No | Client-controlled |
| `req.query.userId` | ❌ No | Client-controlled |
| `req.params.userId` | ❌ No | Client-controlled |
| `req.headers['x-user-id']` | ❌ No | Client-controlled |

---

### 7. Auth Not Copied with Code (Copy-Paste Culture)

**How it happens:** A new endpoint is created by copying an existing one. The ownership check exists in the original but is not carried over to the copy.

**Broken assumption:** *"I copied the handler, so the security came with it."*

```javascript
// ORIGINAL — has ownership check
app.get('/api/documents/:id', requireLogin, async (req, res) => {
  const doc = await Doc.findById(req.params.id);
  if (doc.ownerId !== req.user.id) return res.sendStatus(403); // ✓
  res.json(doc);
});

// COPIED for download — ownership check omitted
app.get('/api/documents/:id/download', requireLogin, async (req, res) => {
  const doc = await Doc.findById(req.params.id);
  // ownership check not carried over — IDOR on download route
  res.download(doc.filePath);
});

// SECURE — extract ownership into shared middleware (can't be forgotten)
async function ownDoc(req, res, next) {
  const doc = await Doc.findById(req.params.id);
  if (!doc) return res.sendStatus(404);
  if (doc.ownerId !== req.user.id) return res.sendStatus(403);
  req.doc = doc;    // attach for downstream handlers
  next();
}

// Both routes reuse the same ownership check — impossible to omit
app.get('/api/documents/:id',          requireLogin, ownDoc, getDocHandler);
app.get('/api/documents/:id/download', requireLogin, ownDoc, downloadHandler);
app.put('/api/documents/:id',          requireLogin, ownDoc, updateDocHandler);
app.delete('/api/documents/:id',       requireLogin, ownDoc, deleteDocHandler);
```

**Rule:** When ownership logic is centralized in middleware, it cannot be forgotten on new routes. This is the single most impactful architectural change for preventing copy-paste IDOR.

---

## The Frontend/Backend Trust Gap (Deeper)

This is a process problem, not a knowledge problem. Both developers may understand auth perfectly — individually.

```
Frontend dev:  "I only show the Delete button to the document owner."
                    ↓
Backend dev:   "If they can call this endpoint, the frontend must have authorized them."
                    ↓
Result:        IDOR — the API has no ownership check
```

**The rule that prevents this:**
> Authorization is a **backend contract**, not a shared responsibility.
> The API is the security boundary. The UI is cosmetic.

---

## The `router.use()` Ordering Trap (Express-Specific)

```javascript
// SAFE — middleware defined before routes
router.use(requireLogin);
router.get('/items/:id', handler);      // ← protected

// DANGEROUS — route added above middleware line
router.get('/items/:id/export', handler); // ← NOT protected (above middleware)
router.use(requireLogin);
router.get('/items/:id', handler);        // ← protected
```

**Rule:** In Express, `router.use()` only protects routes defined *after* it in execution order. Routes added above the middleware line bypass it silently.

---

## Code Review Signals — IDOR Indicators

Scan for these patterns in every PR review:

```javascript
// 🔴 Signal 1 — Object fetched with no ownership check after
const obj = await Model.findById(req.params.id);
res.json(obj); // nothing between these two lines

// 🔴 Signal 2 — Identity from client-controlled source
const userId = req.body.user_id;       // body
const userId = req.query.userId;       // query string
const userId = req.params.userId;      // URL param
const userId = req.headers['x-uid'];   // custom header

// 🔴 Signal 3 — Authorization only on list, not detail
router.get('/orders',     auth, filterByUser, listOrders);  // protected
router.get('/orders/:id', auth, getOrder);                   // ← no filter

// 🔴 Signal 4 — Old version route still live
app.get('/api/v1/resource/:id', auth, handler); // was this patched?

// 🔴 Signal 5 — Auth check after data is already used
const doc = await Doc.findById(id);
await doc.process();              // ← data used before check
if (doc.userId !== req.user.id) return res.status(403); // too late

// ✅ Correct pattern — check immediately after fetch, before any use
const doc = await Doc.findById(id);
if (!doc) return res.sendStatus(404);
if (doc.userId !== req.user.id) return res.sendStatus(403); // ← first thing
// ... use doc safely below
```

---

## Financial Endpoints — Three Fields to Always Audit

```javascript
// For any money-movement endpoint, audit ALL three:
POST /api/transfer {
  "from_account": "ACC-001",  // ← is this verified against session?
  "to_account":   "ACC-002",  // ← is this a valid destination?
  "amount":       500          // ← can this be negative? zero? float overflow?
}

// A negative amount can reverse the transfer direction
// from_account must be verified as owned by req.user — not just trusted from body
// Never trust any field in a financial operation from the client
```

---

## Centralized Authorization Pattern (Best Practice)

The architectural pattern that makes IDOR structurally hard to introduce:

```javascript
// 1. Ownership middleware — one place, used everywhere
async function requireOwnership(Model, ownerField = 'userId') {
  return async (req, res, next) => {
    const obj = await Model.findById(req.params.id);
    if (!obj) return res.sendStatus(404);
    if (obj[ownerField] !== req.user.id) return res.sendStatus(403);
    req.resource = obj; // attach for handlers
    next();
  };
}

// 2. Apply once — any new route for this resource is automatically covered
const ownOrder = requireOwnership(Order);

app.get('/api/orders/:id',          requireLogin, ownOrder, getOrder);
app.put('/api/orders/:id',          requireLogin, ownOrder, updateOrder);
app.delete('/api/orders/:id',       requireLogin, ownOrder, deleteOrder);
app.get('/api/orders/:id/invoice',  requireLogin, ownOrder, getInvoice);
app.get('/api/orders/:id/receipt',  requireLogin, ownOrder, getReceipt);
// New route added? Just add ownOrder — impossible to forget
```

---

## Quick Reference — What to Ask in Every Code Review

```
For every new route, ask:
  1. Where does the object ID come from?           (params, body, query)
  2. Where does the user's identity come from?     (session? body? header?)
  3. Is there a line that compares obj.owner to req.user.id?
  4. Is this route using shared ownership middleware or rolling its own?
  5. Does this route appear in multiple API versions?
  6. Was this endpoint copied from somewhere — did the auth come with it?
```

---

## Key Vocabulary Added in Module 02

| Term | Definition |
|------|------------|
| **Centralized authorization** | Ownership logic in shared middleware, applied consistently across all routes |
| **Frontend/backend trust gap** | IDOR caused by each team assuming the other handles authorization |
| **Middleware trust assumption** | Believing `requireLogin` completes authorization when it only does authentication |
| **Client-supplied identity** | Using `req.body.user_id` or `req.query.userId` instead of `req.user.id` for ownership decisions |
| **Version gap** | Old API routes that were never retired or patched alongside newer versions |
| **Copy-paste IDOR** | Ownership check present in original endpoint, absent in the copied one |
| **Authorization as a backend contract** | The principle that the API — never the UI — is responsible for enforcing access control |

---

## The One Architectural Rule That Prevents Most Module 02 IDORs

> Extract ownership checks into shared middleware.
> Apply that middleware to every route that touches a protected object.
> New routes reuse it — they cannot omit it by accident.

The copy-paste failure mode, the deadline pressure failure mode, and the versioning failure mode are all defeated by this single pattern.

---

## Coming Up — Module 03: Horizontal Privilege Escalation

We move from *how IDORs are created* to *what they enable*.
Horizontal escalation: same role, different user's data.
- E-commerce order access
- Banking account traversal
- Student portal record access
- Real bug bounty report patterns
- The methodology for finding it systematically

---

*Module 02 — IDOR Mastery Curriculum*
*Focus: Root causes, developer mental models, centralized authorization architecture*