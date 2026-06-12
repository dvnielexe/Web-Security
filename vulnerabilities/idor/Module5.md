# IDOR Mastery — Module 05 Cheatsheet
## REST API Authorization Flaws: BOLA & BFLA

> **Core principle:** REST APIs have structural conventions — resources as nouns, HTTP methods
> as verbs — that create predictable authorization blind spots. Every route, every method,
> every parameter location, and every sub-resource is an independent enforcement point.

---

## OWASP API Security Top 10 — Context

| Position | Name | Description |
|----------|------|-------------|
| **API1** | **BOLA** — Broken Object Level Authorization | Horizontal IDOR at the API level. Missing ownership check on resource IDs. |
| **API5** | **BFLA** — Broken Function Level Authorization | Vertical escalation at the API level. Missing role check on function access. |

These map directly to what you know:
```
BOLA = Horizontal IDOR (object ownership failure)
BFLA = Vertical escalation (function/role permission failure)
Both can exist on the same endpoint simultaneously
```

---

## BOLA vs BFLA — The Precise Distinction

### BOLA — resource identifier not ownership-checked

```http
GET /api/invoices/5531
Authorization: Bearer <user_A_token>
→ returns user B's invoice    ← BOLA
```

```javascript
// VULNERABLE — BOLA
app.get('/api/invoices/:id', requireLogin, async (req, res) => {
  const inv = await Invoice.findById(req.params.id);
  // ❌ No ownership check
  res.json(inv);
});

// SECURE
app.get('/api/invoices/:id', requireLogin, async (req, res) => {
  // ✅ findOne combines lookup + ownership atomically
  // Returns null for both "not found" and "not yours" → always 404
  // (never confirm existence to unauthorized callers)
  const inv = await Invoice.findOne({ id: req.params.id, userId: req.user.id });
  if (!inv) return res.sendStatus(404);
  res.json(inv);
});
```

### BFLA — function not role-checked

```http
DELETE /api/admin/users/42
Authorization: Bearer <regular_user_token>
→ 200 OK, user deleted        ← BFLA
```

```javascript
// VULNERABLE — BFLA
app.delete('/api/admin/users/:id', requireLogin, async (req, res) => {
  // ❌ Login confirmed — role never checked
  await User.delete(req.params.id);
  res.sendStatus(200);
});

// SECURE
app.delete('/api/admin/users/:id',
  requireLogin,
  requireRole('admin'),   // ✅ explicit role gate
  async (req, res) => {
    await User.delete(req.params.id);
    res.sendStatus(200);
  }
);
```

### Combined BOLA + BFLA (higher severity)

```http
PUT /api/orders/7202/status
Authorization: Bearer <user_A_token>
→ modifies user B's order AND uses an elevated status function
```

Report both. Combined findings are rated higher severity.

---

## The Authorization Coverage Matrix

The most important mental model for REST API testing:

```
Resource      GET /list   GET /:id   PUT /:id   DELETE /:id   GET /:id/sub   POST action
─────────────────────────────────────────────────────────────────────────────────────────
/orders       ✅          ✅          ❌ BOLA    ❌ BOLA        ❌ BOLA         ❌ BOLA
/users        ✅          ✅          ❌ BOLA    —              ❌ BOLA         —
/files        ✅          ✅          ❌ BOLA    ❌ BOLA         ❌ BOLA        —
/admin/users  ❌ BFLA     ❌ BFLA     ❌ BFLA    ❌ BFLA        —               ❌ BFLA
/reports      ✅          ❌ BOLA     —          —               ❌ BOLA        —
```

**Rule:** Green on GET does not protect red on DELETE.
Every cell is its own independent enforcement point.

---

## The Six REST-Specific Failure Patterns

### Pattern 1 — Query Parameter Object Reference (BOLA)

**Mechanism:** Ownership check written for path params. Query param variant of the same resource has no check.

**Broken assumption:** *"Ownership checks for path params automatically cover query param variants."*

```javascript
// VULNERABLE
// GET /api/messages?thread_id=884
app.get('/api/messages', requireLogin, async (req, res) => {
  const threadId = req.query.thread_id; // ← attacker-controlled
  // ❌ No ownership check on the thread
  const messages = await Message.findByThread(threadId);
  res.json(messages);
});

// SECURE
app.get('/api/messages', requireLogin, async (req, res) => {
  const threadId = req.query.thread_id;
  const thread = await Thread.findById(threadId);
  if (!thread) return res.sendStatus(404);
  // ✅ Ownership check applies regardless of ID location
  if (!thread.participantIds.includes(req.user.id)) return res.sendStatus(403);
  const messages = await Message.findByThread(threadId);
  res.json(messages);
});
```

**Testing tip:** For every protected path param route, also test:
- `GET /resource?id=:id`
- `GET /resource?resource_id=:id`
- `POST /resource/lookup { "id": ":id" }`

---

### Pattern 2 — Nested Resource: Parent Protected, Child Not (BOLA)

**Mechanism:** Parent route has ownership check. Child/sub-resource route forgets it. Nesting creates false sense of inherited protection.

**Broken assumption:** *"Authorization on the parent route protects all child routes."*

```javascript
// VULNERABLE
app.get('/api/projects/:id', requireLogin, async (req, res) => {
  const p = await Project.findById(req.params.id);
  if (p.ownerId !== req.user.id) return res.sendStatus(403); // ✓ protected
  res.json(p);
});

app.get('/api/projects/:id/members', requireLogin, async (req, res) => {
  // ❌ No check — lists any project's members including emails/roles
  const members = await Project.getMembers(req.params.id);
  res.json(members);
});

// SECURE — shared ownership middleware covers all routes
async function requireProjectOwner(req, res, next) {
  const project = await Project.findOne({
    id: req.params.id,
    ownerId: req.user.id
  });
  if (!project) return res.sendStatus(404); // 404 for both not-found and not-yours
  req.project = project;
  next();
}

app.get('/api/projects/:id',          requireLogin, requireProjectOwner, getProject);
app.get('/api/projects/:id/members',  requireLogin, requireProjectOwner, getMembers);
app.get('/api/projects/:id/tasks',    requireLogin, requireProjectOwner, getTasks);
app.get('/api/projects/:id/export',   requireLogin, requireProjectOwner, exportProject);
// New sub-resource? Add requireProjectOwner — impossible to forget.
```

---

### Pattern 3 — HTTP Method Switching on Same Route (BOLA + BFLA)

**Mechanism:** GET is protected. PUT/DELETE/PATCH on the same path are not. Same URL, different method, missing check.

**Broken assumption:** *"We protected the GET so the resource is protected."*

```javascript
// VULNERABLE
app.get('/api/posts/:id', requireLogin, async (req, res) => {
  const post = await Post.findById(req.params.id);
  if (post.authorId !== req.user.id) return res.sendStatus(403); // ✓
  res.json(post);
});

app.patch('/api/posts/:id', requireLogin, async (req, res) => {
  // ❌ Ownership missing — edits any post
  await Post.update(req.params.id, req.body);
  res.sendStatus(200);
});

app.delete('/api/posts/:id', requireLogin, async (req, res) => {
  // ❌ Ownership missing — deletes any post
  await Post.delete(req.params.id);
  res.sendStatus(200);
});

// SECURE — shared middleware enforces ownership on all methods
async function requirePostOwner(req, res, next) {
  const post = await Post.findOne({ id: req.params.id, authorId: req.user.id });
  if (!post) return res.sendStatus(404);
  req.post = post;
  next();
}

app.get('/api/posts/:id',    requireLogin, requirePostOwner, getPost);
app.patch('/api/posts/:id',  requireLogin, requirePostOwner, updatePost);
app.delete('/api/posts/:id', requireLogin, requirePostOwner, deletePost);
```

---

### Pattern 4 — Filter Bypass: Scope Parameter Ignored (BOLA)

**Mechanism:** API accepts a filter/scope parameter. The list is filtered — but ownership of the filter value itself is never validated.

**Broken assumption:** *"We're filtering the results so only the right data is returned."*

```javascript
// VULNERABLE
// GET /api/transactions?account_id=ACC-8821
app.get('/api/transactions', requireLogin, async (req, res) => {
  const { account_id } = req.query; // ← attacker sets to any account
  // ❌ Filter applied but account_id ownership never checked
  const txns = await Transaction.findByAccount(account_id);
  res.json(txns);
});

// SECURE — validate the filter value against the session
app.get('/api/transactions', requireLogin, async (req, res) => {
  const { account_id } = req.query;
  // ✅ Verify the requested account belongs to the caller
  const account = await Account.findById(account_id);
  if (!account || account.holderId !== req.user.id) return res.sendStatus(403);
  const txns = await Transaction.findByAccount(account_id);
  res.json(txns);
});
```

**Testing tip:** Any query parameter that scopes/filters by a foreign ID is a filter bypass candidate:
- `?account_id=`, `?user_id=`, `?workspace_id=`, `?project_id=`, `?org_id=`

---

### Pattern 5 — Batch/Bulk Operations: Partial Validation (BOLA)

**Mechanism:** Bulk endpoint accepts an array of IDs. Only some IDs (often the first) are checked. The rest are processed without ownership validation.

**Broken assumption:** *"We check the first item so the batch is authorized."*

```javascript
// VULNERABLE
// POST /api/messages/read { ids: [101, 102, 103, 9999] }
app.post('/api/messages/read', requireLogin, async (req, res) => {
  const { ids } = req.body;
  // ❌ Only checks first ID — rest processed unchecked
  const first = await Message.findById(ids[0]);
  if (first.userId !== req.user.id) return res.sendStatus(403);
  await Message.markRead(ids); // marks ALL ids including 9999
  res.sendStatus(200);
});

// SECURE — validate every ID atomically before processing any
app.post('/api/messages/read', requireLogin, async (req, res) => {
  const { ids } = req.body;
  // ✅ Step 1: fetch all objects in the batch
  const messages = await Message.findByIds(ids);
  // ✅ Step 2: validate ALL belong to the caller (not just some)
  const allOwned = messages.every(m => m.userId === req.user.id);
  if (!allOwned) return res.sendStatus(403);
  // ✅ Step 3: only process after full validation passes
  await Message.markRead(ids);
  res.sendStatus(200);
});
```

**Critical nuance:** Validate-all-first, then process-all.
Never interleave validation and processing — partial processing after partial validation creates TOCTOU risk.

**Also audit the VALUES in bulk operations:**
```javascript
// What status values is the caller allowed to set?
// status: "admin_resolved" or status: "escalated" may be privileged values
const allowedStatuses = ['open', 'closed', 'pending'];
if (!allowedStatuses.includes(status)) return res.sendStatus(403);
```

---

### Pattern 6 — Indirect Object Reference Leakage (BOLA vector)

**Mechanism:** API response includes IDs of objects the caller wasn't meant to discover. Each returned ID is a free BOLA access vector requiring no enumeration.

```json
// Response to GET /api/orders/7201
{
  "order_id": "7201",
  "customer_id": "USR-1042",      ← your ID
  "seller_id": "USR-8821",        ← pivot: GET /api/users/USR-8821
  "fulfillment_id": "FLM-0044",   ← pivot: GET /api/fulfillments/FLM-0044
  "warehouse_id": "WH-003",       ← pivot: GET /api/warehouses/WH-003
  "assigned_agent": "AGT-0091"    ← pivot: GET /api/agents/AGT-0091
}
```

**Testing methodology:**
1. Collect every API response from normal app usage
2. Extract every ID-shaped field that isn't your own user ID
3. Build a list of pivot targets: `GET /api/{resource}/{id}` for each
4. Test each with your session — no enumeration required
5. Note which return 200 vs 403 — each 200 is a BOLA finding

---

## Full Code Audit — Ticketing Platform

### Vulnerable version (all flaws annotated)

```javascript
const router = express.Router();
router.use(requireLogin);

// ✅ SECURE — correctly scoped to session user
router.get('/tickets', async (req, res) => {
  const tickets = await Ticket.findByUser(req.user.id);
  res.json(tickets);
});

// ✅ SECURE — ownership check present
router.get('/tickets/:id', async (req, res) => {
  const ticket = await Ticket.findById(req.params.id);
  if (!ticket) return res.sendStatus(404);
  if (ticket.userId !== req.user.id) return res.sendStatus(403);
  res.json(ticket);
});

// ❌ BOLA #1 — PUT with no ownership check
router.put('/tickets/:id', async (req, res) => {
  const ticket = await Ticket.findById(req.params.id);
  await ticket.update(req.body);
  res.json(ticket);
});

// ❌ BOLA #2 — close action with no ownership check
router.post('/tickets/:id/close', async (req, res) => {
  const ticket = await Ticket.findById(req.params.id);
  await ticket.close();
  res.sendStatus(200);
});

// ❌ BOLA #3 — nested sub-resource, parent protected, child not
router.get('/tickets/:id/comments', async (req, res) => {
  const comments = await Comment.findByTicket(req.params.id);
  res.json(comments);
});

// ❌ BFLA — admin endpoint with no role check
router.get('/admin/tickets', async (req, res) => {
  const tickets = await Ticket.findAll();
  res.json(tickets);
});

// ❌ BOLA + BFLA — bulk update with no per-ID ownership check
//               + no validation of privileged status values
router.post('/tickets/bulk-status', async (req, res) => {
  const { ticket_ids, status } = req.body;
  await Ticket.bulkUpdateStatus(ticket_ids, status);
  res.sendStatus(200);
});
```

### Vulnerability summary

| Route | Type | Broken Assumption |
|-------|------|-------------------|
| `PUT /tickets/:id` | BOLA | "Authenticated users only update their own tickets" |
| `POST /tickets/:id/close` | BOLA | "Authenticated users only close their own tickets" |
| `GET /tickets/:id/comments` | BOLA | "Parent route protection covers the comments sub-route" |
| `GET /admin/tickets` | BFLA | "Only admins know this admin route exists" |
| `POST /tickets/bulk-status` | BOLA + BFLA | "Users only submit their own IDs; status values are unconstrained" |

### Secure version — full rewrite

```javascript
const router = express.Router();
router.use(requireLogin);

// Shared ticket ownership middleware
// Returns 404 for both "not found" AND "not yours"
// (never confirm existence to unauthorized callers)
async function requireTicketOwner(req, res, next) {
  const ticket = await Ticket.findOne({
    id: req.params.id,
    userId: req.user.id   // ← combined lookup + ownership
  });
  if (!ticket) return res.sendStatus(404); // same response for both cases
  req.ticket = ticket;
  next();
}

// Role middleware
function requireRole(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) return res.sendStatus(403);
    next();
  };
}

// ✅ SECURE — session-scoped list
router.get('/tickets', async (req, res) => {
  const tickets = await Ticket.findByUser(req.user.id);
  res.json(tickets);
});

// ✅ SECURE — ownership via middleware
router.get('/tickets/:id',
  requireTicketOwner,
  (req, res) => res.json(req.ticket)
);

// ✅ FIXED BOLA #1 — ownership enforced on PUT
router.put('/tickets/:id',
  requireTicketOwner,
  async (req, res) => {
    await req.ticket.update(req.body);
    res.json(req.ticket);
  }
);

// ✅ FIXED BOLA #2 — ownership enforced on close action
router.post('/tickets/:id/close',
  requireTicketOwner,
  async (req, res) => {
    await req.ticket.close();
    res.sendStatus(200);
  }
);

// ✅ FIXED BOLA #3 — sub-resource uses same ownership middleware
router.get('/tickets/:id/comments',
  requireTicketOwner,
  async (req, res) => {
    const comments = await Comment.findByTicket(req.params.id);
    res.json(comments);
  }
);

// ✅ FIXED BFLA — role check added to admin route
router.get('/admin/tickets',
  requireRole('admin', 'support_lead'),
  async (req, res) => {
    const tickets = await Ticket.findAll();
    res.json(tickets);
  }
);

// ✅ FIXED BOLA + BFLA — batch ownership + status value validation
router.post('/tickets/bulk-status', async (req, res) => {
  const { ticket_ids, status } = req.body;

  // ✅ BFLA fix: validate status is an allowed value for this user's role
  const allowedStatuses = ['open', 'closed', 'pending'];
  const adminStatuses   = ['admin_resolved', 'escalated', 'flagged'];

  if (adminStatuses.includes(status) && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Insufficient role for this status value' });
  }
  if (![...allowedStatuses, ...adminStatuses].includes(status)) {
    return res.status(400).json({ error: 'Invalid status value' });
  }

  // ✅ BOLA fix: validate ALL ticket IDs belong to the caller
  const tickets = await Ticket.findByIds(ticket_ids);
  const allOwned = tickets.every(t => t.userId === req.user.id);
  if (!allOwned) return res.sendStatus(403);

  // Only process after full validation passes
  await Ticket.bulkUpdateStatus(ticket_ids, status);
  res.sendStatus(200);
});
```

---

## JWT Misuse Patterns in REST APIs

### Pattern 1 — decode() vs verify()

```javascript
// ❌ VULNERABLE — decode() never checks the signature
const payload = jwt.decode(token);
if (payload.role === 'admin') { ... }

// ✅ SECURE — verify() validates cryptographic signature
const payload = jwt.verify(token, process.env.JWT_SECRET, {
  algorithms: ['HS256']  // explicit allowlist — rejects alg:none
});
```

### Pattern 2 — Algorithm confusion / alg:none

```javascript
// Attack: attacker modifies JWT header to {"alg":"none"} and payload to {"role":"admin"}
// Vulnerable libraries honor the header's algorithm claim

// ✅ SECURE — server dictates the algorithm, ignores token's claim
jwt.verify(token, secret, { algorithms: ['HS256'] });
```

### Pattern 3 — Stale JWT claims

```javascript
// Problem: role/permissions baked into JWT at login time
// User demoted/banned in DB — JWT still says "admin" until expiry
// JWT is cryptographically valid but claims are outdated

// ✅ SECURE — cross-check critical claims against DB on sensitive ops
const payload = jwt.verify(token, secret, { algorithms: ['HS256'] });
const user = await User.findById(payload.user_id); // fresh DB lookup
if (!user || user.role !== payload.role) return res.sendStatus(401);
if (user.is_banned) return res.sendStatus(403);
```

### Pattern 4 — No expiry

```javascript
// ❌ VULNERABLE — token valid forever
jwt.sign(payload, secret);

// ✅ SECURE — short-lived with refresh pattern
jwt.sign(payload, secret, { expiresIn: '15m' });
// Pair with refresh tokens for seamless UX
```

### Pattern 5 — No logout invalidation

```javascript
// Problem: JWTs are stateless — cannot be "invalidated" server-side
// User logs out → token still valid until expiry

// ✅ SECURE — token blocklist for sensitive apps
const blocklist = new Set(); // in production: Redis

app.post('/logout', requireLogin, (req, res) => {
  blocklist.add(req.headers.authorization.split(' ')[1]);
  res.sendStatus(200);
});

// Check blocklist in auth middleware
function requireLogin(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (blocklist.has(token)) return res.sendStatus(401);
  const payload = jwt.verify(token, secret, { algorithms: ['HS256'] });
  req.user = payload;
  next();
}
```

---

## The 404 vs 403 Decision — Enumeration Prevention

```javascript
// ❌ Leaks existence — attacker learns object 7202 exists but isn't theirs
const ticket = await Ticket.findById(req.params.id);
if (!ticket) return res.sendStatus(404);
if (ticket.userId !== req.user.id) return res.sendStatus(403); // ← leaks existence

// ✅ No existence leak — attacker cannot distinguish "not found" from "not yours"
const ticket = await Ticket.findOne({ id: req.params.id, userId: req.user.id });
if (!ticket) return res.sendStatus(404); // same response for both cases
```

**Rule:** Return 404 for both "object does not exist" and "object exists but you don't own it."
This prevents ID enumeration — an attacker cannot use 403 responses to map out valid object IDs.

---

## REST API Detection Methodology

### Phase 1 — API Surface Discovery

```
Sources:
  Burp Suite proxy  → capture all API calls during normal app usage
  /api/docs         → Swagger/OpenAPI documentation
  /swagger          → Swagger UI
  /openapi.json     → raw OpenAPI spec
  JS bundles        → search for /api/, fetch(, axios.
  Mobile APK        → decompile and grep for API strings
  robots.txt        → may list /api/ paths
  Error responses   → stack traces leak route structure
  GitHub repos      → sometimes API routes in source code
```

### Phase 2 — Object Inventory

```
For each captured request, extract:
  - Resource type: orders, users, files, tickets, reports...
  - ID format: integer, UUID, slug, custom prefix (ORD-, USR-)
  - ID location: path, query, body, header
  - HTTP method used
  - Response structure: what foreign IDs appear in responses?
```

### Phase 3 — Two-Account Testing Matrix

```
Account A (attacker)   Account B (victim)
─────────────────────────────────────────
Create account         Create account
                       Create: order, file, ticket, message, report
                       Note all object IDs
Switch to A's session  ─────────────────────────────────────────
Test each ID with A's token on every route and method
```

### Phase 4 — Systematic Method Switching

```
For every endpoint that passes ownership check on GET:
  PUT    /resource/:id        → modify
  PATCH  /resource/:id        → partial modify
  DELETE /resource/:id        → delete
  POST   /resource/:id/action → trigger action (cancel, close, approve)
  GET    /resource/:id/sub    → sub-resource access
```

### Phase 5 — Parameter Location Switching

```
If path param is protected:
  GET /api/orders/7201                              → protected
  GET /api/orders?id=7201                           → test this
  GET /api/orders?order_id=7201                     → test this
  POST /api/orders/search { "id": "7201" }          → test this
  POST /api/orders/export { "order_ids": ["7201"] } → test this
```

### Phase 6 — Response Mining for Free IDs

```
Scan every API response for:
  - IDs not matching your own user_id
  - Fields ending in _id, _ids, Id, Ids
  - UUIDs in any field
  - Reference objects: { "seller": { "id": "USR-8821" } }

Build a pivot list — test each foreign ID against its resource's endpoints
No enumeration needed — the API handed you the IDs
```

---

## Bug Bounty Report Template — BOLA/BFLA

```
Title: [BOLA/BFLA] — [endpoint] allows [unauthorized action] on [resource]

CVSS: [score — BOLA typically 6.5-8.1, BFLA up to 9.1]
Severity: [High/Critical]

Summary:
[BOLA] An authenticated user can [read/modify/delete] [resource type] belonging
to other users by supplying a different [resource ID] in [location].
[BFLA] An authenticated user with role [X] can invoke [function] which requires
role [Y], by calling [endpoint] directly without UI-level gatekeeping.

Steps to Reproduce:
1. Create accounts A (attacker) and B (victim)
2. As B: create [resource] → ID: [value]
3. As A: [METHOD] [endpoint]
   Authorization: Bearer [Account A's token]
   [Request body if applicable]
4. Observe: [B's data returned / action performed / admin function invoked]

Impact:
[Specific data exposed or action performed]
[Chained impact: e.g., member list exposure → org mapping → social engineering]
[Scale: exploitable against all users at scale via automated enumeration]

Root cause:
[BOLA] The [endpoint] authenticates the caller but does not verify that
[resource].[ownerField] matches [req.user.id].
[BFLA] The [endpoint] authenticates the caller but does not verify that
[req.user.role] has permission to invoke this function.

Remediation:
[BOLA] Add server-side ownership check immediately after object retrieval.
Apply to ALL routes accessing this resource — not only this endpoint.
[BFLA] Add role check middleware: if (req.user.role !== 'admin') return 403.
Apply to all admin/privileged endpoints.
```

---

## Complete Testing Checklist — REST API

```
DISCOVERY
  □ Captured all API calls via proxy (Burp Suite / OWASP ZAP)
  □ Found and read API documentation (Swagger, OpenAPI)
  □ Searched JS bundles for API route strings
  □ Identified all resource types and ID formats
  □ Mapped all ID locations (path, query, body, header)
  □ Noted all foreign IDs in API responses

BOLA TESTING
  □ Two accounts created (A = attacker, B = victim)
  □ Resources generated in Account B
  □ Tested GET /:id with A's token against B's IDs
  □ Tested PUT /:id — method switching
  □ Tested PATCH /:id — method switching
  □ Tested DELETE /:id — method switching
  □ Tested POST /:id/action — action endpoints
  □ Tested GET /:id/sub-resource — nested routes
  □ Tested query param variants (?id=, ?resource_id=)
  □ Tested body param variants ({ "id": ":id" })
  □ Tested batch endpoints — supplied mixed owned/unowned IDs
  □ Pivoted on all foreign IDs found in responses

BFLA TESTING
  □ Mapped all admin/privileged endpoints (JS search, /api/docs)
  □ Called each admin endpoint with regular-user token
  □ Tested all HTTP methods on admin routes
  □ Tested mass assignment on every update endpoint
  □ Tested privileged status/type values in bulk operations

JWT TESTING
  □ Decoded JWT — identified all role/permission claims
  □ Verified server uses verify() not decode()
  □ Tested alg:none attack
  □ Checked for stale claims (role changed after token issued)
  □ Confirmed short expiry is enforced
  □ Checked token remains valid after logout

ENUMERATION PREVENTION
  □ Confirmed 403 on owned-but-wrong-user returns 404 (not 403)
  □ Error messages do not confirm object existence
```

---

## Key Vocabulary Added in Module 05

| Term | Definition |
|------|------------|
| **BOLA** | Broken Object Level Authorization — OWASP API #1, horizontal IDOR at API level |
| **BFLA** | Broken Function Level Authorization — OWASP API #5, vertical escalation at API level |
| **Query parameter BOLA** | Ownership check written for path params, missing for query param variant |
| **Filter bypass** | Scope/filter parameter accepted without validating caller owns the filter target |
| **Batch authorization bypass** | Bulk endpoint validates subset of IDs (often just the first) rather than all |
| **Indirect object reference leakage** | Foreign IDs in API responses used as free BOLA pivot vectors |
| **Stale JWT claims** | Token payload reflects role/permissions at login time, not current DB state |
| **Enumeration prevention** | Returning 404 for both "not found" and "not authorized" to prevent ID discovery |
| **Parameter location switching** | Testing the same resource ID via path, query, body, and header params |

---

## Coming Up — Module 06: Mobile API Authorization Flaws

REST APIs running behind mobile apps have additional attack surface:
- Traffic interception and certificate pinning bypass
- Hardcoded API endpoints in app binaries
- API versioning gaps specific to mobile release cycles
- Hidden endpoints exposed in APK/IPA decompilation
- Insecure storage of tokens on device
- Platform-specific authorization failures (iOS vs Android)

---

*Module 05 — IDOR Mastery Curriculum*
*Focus: BOLA, BFLA, REST API structural failure patterns, JWT misuse, systematic API testing*