# IDOR Mastery — Module 03 Cheatsheet
## Horizontal Privilege Escalation

> **Core principle:** Horizontal privilege escalation occurs when a user accesses data or
> performs actions belonging to another user at the **same privilege level**.
> No role elevation. No special token. Just a different object reference and a missing ownership check.

---

## The Geometry of Horizontal vs Vertical Escalation

```
VERTICAL (Module 05)
     ↑
  [Admin]          ← attacker climbs UP to higher role
     ↑
[Regular User A]

HORIZONTAL (this module)
[User A] ──────→ [User B's data]    ← attacker moves SIDEWAYS
[User B]                              same role, different ownership
[User C]
```

**Key distinction:**
- Horizontal = same role, different user's data
- Vertical = different role, higher privilege functions
- They are different failure modes with different root causes and different fixes

---

## Why Horizontal Escalation Dominates Bug Bounty Reports

Three structural reasons:

**1. Requires no privilege knowledge**
The attacker only needs to know what *they* can do — then tries doing it on someone else's data.

**2. Invisible to developers**
The data looks correct. The right type of user requests the right type of object. The ownership
mismatch is a business rule violation, not a technical error. Unit tests miss it unless written
specifically for cross-user access.

**3. Scales silently**
Valid authenticated requests returning valid data. No brute force alerts, no unusual payloads,
no error logs. One script, thousands of records.

---

## The Five-Step Detection Methodology

### Step 1 — Map All Objects
Walk the application as a legitimate user. List every resource you interact with.

```
E-commerce:    orders, invoices, addresses, payment methods, wishlists
Banking:       accounts, statements, transfers, beneficiaries
SaaS:          projects, tasks, reports, team members, API keys
Social:        posts, messages, threads, notifications, friend lists
File sharing:  files, folders, shared links, permissions, versions
```

**Rule:** Every object is a potential IDOR surface. Don't filter — map everything.

### Step 2 — Enumerate All Routes Per Object
For each object, find every endpoint that touches it.

```
Object: Order
Routes to test:
  GET    /api/orders/:id              → read
  PUT    /api/orders/:id              → update
  DELETE /api/orders/:id              → delete
  POST   /api/orders/:id/cancel       → action
  GET    /api/orders/:id/invoice      → sub-resource
  GET    /api/orders/:id/receipt      → sub-resource
  GET    /api/orders/:id/export       → export
  GET    /api/exports?order_id=:id    → query param
```

**Rule:** Each route is an *independent* enforcement point.
A check on one route is not inherited by any other route.

### Step 3 — Create Two Test Accounts
Non-negotiable. You cannot confirm horizontal IDOR with one account.

```
Account A (attacker):  your active session
Account B (victim):    generates the objects you attack

Workflow:
1. Log in as B → create an order, file, message, ticket
2. Note the object ID (from response, URL, or API)
3. Switch to A's session
4. Request B's object ID using A's token
5. If data returned → IDOR confirmed
```

**What one account cannot tell you:** Whether a 200 response is because
you're authorized or because there's no authorization check at all.

### Step 4 — Test All HTTP Methods
A protected read endpoint does not mean write/delete/action endpoints are protected.

```
For every object, test:
  GET     → read the record
  PUT     → modify the record
  PATCH   → partially modify the record
  DELETE  → delete the record
  POST    → trigger an action on the record (cancel, approve, archive)

Common pattern in the wild:
  GET  /api/tickets/:id    → 403 (protected)     ✓
  PUT  /api/tickets/:id    → 200 (no check)      ← IDOR
  POST /api/tickets/:id/close → 200 (no check)   ← IDOR
```

**Rule:** A 403 on GET is information. It tells you the developer knew about
ownership — which means they may have forgotten it elsewhere.

### Step 5 — Find ID Leakage Before Enumeration
Object IDs leak through many vectors. Find them before guessing.

```
Leakage sources:
  API responses       → other users' IDs referenced in your data
  Email notifications → links containing object IDs
  Shared URLs         → capability links with embedded IDs
  Browser history     → previously visited object URLs
  Referrer headers    → ID in URL sent to third-party analytics
  Error messages      → "Object 8821 not found" confirms existence
  WebSocket messages  → real-time events containing foreign IDs
  Exported files      → CSV/PDF exports referencing other records

Example — API response leakage:
{
  "order_id": "7201",
  "customer_id": "USR-1042",    ← your ID
  "seller_id": "USR-8821",      ← another user's ID — test this
  "assigned_to": "AGT-0044"     ← another object reference — test this
}
```

**Rule:** Every foreign ID in a response is a free access vector.
Map them all before touching enumeration.

---

## The Five Application Scenarios

### Scenario 1 — E-Commerce Order Access

**Object:** Order record (items, shipping address, payment info, status)
**Who should access:** Purchasing customer only + admin roles
**Impact:** Critical — PII exposure, purchase history

```javascript
// VULNERABLE
app.get('/api/orders/:id', requireLogin, async (req, res) => {
  const order = await Order.findById(req.params.id);
  if (!order) return res.sendStatus(404);
  // ❌ No ownership check — any customer reads any order
  res.json(order);
});

// SECURE
app.get('/api/orders/:id', requireLogin, async (req, res) => {
  const order = await Order.findById(req.params.id);
  if (!order) return res.sendStatus(404);
  if (order.customerId !== req.user.id) return res.sendStatus(403); // ✅
  res.json(order);
});
```

**Broken assumption:** "Authenticated customers only request their own orders."

---

### Scenario 2 — Banking Account Statement Access

**Object:** Bank account statements (transaction history, balances, payees)
**Who should access:** Account holder only
**Impact:** Critical — financial data, fraud enablement

```javascript
// VULNERABLE
app.get('/api/accounts/:accountId/statements', requireLogin, async (req, res) => {
  const account = await Account.findById(req.params.accountId);
  // ❌ accountId from URL — holder never verified
  const stmts = await Statement.findByAccount(account.id);
  res.json(stmts);
});

// SECURE
app.get('/api/accounts/:accountId/statements', requireLogin, async (req, res) => {
  const account = await Account.findById(req.params.accountId);
  if (!account) return res.sendStatus(404);
  if (account.holderId !== req.user.id) return res.sendStatus(403); // ✅
  const stmts = await Statement.findByAccount(account.id);
  res.json(stmts);
});
```

**Broken assumption:** "Only the real account holder would know their account ID."

---

### Scenario 3 — Student Portal Grade Access

**Object:** Academic grade records (marks, GPA, course history, standing)
**Who should access:** Student themselves + assigned advisor + admin
**Impact:** High — academic records, privacy violation

```javascript
// VULNERABLE
app.get('/api/students/:id/grades', requireLogin, async (req, res) => {
  // ❌ id from URL — not compared to session
  const grades = await Grade.findByStudent(req.params.id);
  res.json(grades);
});

// SECURE — multi-role access pattern
app.get('/api/students/:id/grades', requireLogin, async (req, res) => {
  const isOwner = req.params.id === req.user.studentId;
  const isStaff = ['advisor', 'admin'].includes(req.user.role);
  if (!isOwner && !isStaff) return res.sendStatus(403); // ✅
  const grades = await Grade.findByStudent(req.params.id);
  res.json(grades);
});
```

**Broken assumption:** "Students only request their own student IDs."
**Note:** Sequential integer IDs make enumeration trivial.

---

### Scenario 4 — Social Media DM Thread Access

**Object:** Private message thread (conversation content between participants)
**Who should access:** Thread participants only — not any authenticated user
**Impact:** High — private communications exposure

```javascript
// VULNERABLE
app.get('/api/messages/thread/:id', requireLogin, async (req, res) => {
  const thread = await Thread.findById(req.params.id);
  // ❌ No participant check — any user reads any thread
  res.json(thread.messages);
});

// SECURE — participant membership check
app.get('/api/messages/thread/:id', requireLogin, async (req, res) => {
  const thread = await Thread.findById(req.params.id);
  if (!thread) return res.sendStatus(404);
  const isParticipant = thread.participantIds.includes(req.user.id); // ✅
  if (!isParticipant) return res.sendStatus(403);
  res.json(thread.messages);
});
```

**Broken assumption:** "Thread IDs are not easily discoverable."
**Note:** Ownership model is *membership*, not *single owner* — the check pattern changes.

---

### Scenario 5 — File Sharing Private Document Download

**Object:** Private uploaded file (documents, reports, sensitive data)
**Who should access:** File owner + explicitly shared recipients
**Impact:** High — confidential data exposure

```javascript
// VULNERABLE — classic copy-paste IDOR on sub-route
app.get('/api/files/:id', requireLogin, async (req, res) => {
  const file = await File.findById(req.params.id);
  if (file.ownerId !== req.user.id) return res.sendStatus(403); // ✓ protected
  res.json(file.metadata);
});

app.get('/api/files/:id/download', requireLogin, async (req, res) => {
  const file = await File.findById(req.params.id);
  // ❌ Ownership check not carried over — IDOR on download route
  res.download(file.path);
});

// SECURE — shared ownership middleware
async function requireFileAccess(req, res, next) {
  const file = await File.findById(req.params.id);
  if (!file) return res.sendStatus(404);
  const canAccess = file.ownerId === req.user.id ||
                    file.sharedWith.includes(req.user.id); // ✅
  if (!canAccess) return res.sendStatus(403);
  req.file = file;
  next();
}

app.get('/api/files/:id',          requireLogin, requireFileAccess, serveMetadata);
app.get('/api/files/:id/download', requireLogin, requireFileAccess, serveFile);
// New file route added? requireFileAccess cannot be forgotten.
```

**Broken assumption:** "The download route is less sensitive than the view route."

---

## Hierarchical Object Ownership — The Nested IDOR Pattern

When objects belong to *parent objects* (not directly to users), the ownership
check must traverse the relationship chain.

```
User → owns → Project → contains → Task
```

**Wrong fix (flat ownership):**
```javascript
// ❌ Tasks may not have a direct ownerId field
const task = await Task.findOne({ id: req.params.id, ownerId: req.user.id });
```

**Correct fix (ownership chain):**
```javascript
// ✅ Traverse: task → project → owner
async function requireTaskAccess(req, res, next) {
  const task = await Task.findById(req.params.id);
  if (!task) return res.sendStatus(404);
  const project = await Project.findById(task.projectId);
  if (!project) return res.sendStatus(404);
  if (project.ownerId !== req.user.id) return res.sendStatus(403);
  req.task = task;
  next();
}
```

**Rule:** Always trace the full ownership chain. Checking the child object
alone is insufficient when the child doesn't directly reference a user.

---

## Full Code Audit — SaaS Project Management Tool

### Vulnerable version (all flaws annotated)

```javascript
const router = express.Router();
router.use(requireLogin); // ✓ authentication present everywhere

// ✅ SECURE — ownership check present
router.get('/projects/:id', async (req, res) => {
  const project = await Project.findById(req.params.id);
  if (!project) return res.sendStatus(404);
  if (project.ownerId !== req.user.id) return res.sendStatus(403);
  res.json(project);
});

// ❌ IDOR #1 — project tasks accessible without ownership check
router.get('/projects/:id/tasks', async (req, res) => {
  const tasks = await Task.findByProject(req.params.id);
  res.json(tasks);
});

// ❌ IDOR #2 — any user can modify any task
router.put('/tasks/:id', async (req, res) => {
  const task = await Task.findById(req.params.id);
  if (!task) return res.sendStatus(404);
  await task.update(req.body);
  res.json(task);
});

// ❌ IDOR #3 — any user can delete any task
router.delete('/tasks/:id', async (req, res) => {
  const task = await Task.findById(req.params.id);
  await task.delete();
  res.sendStatus(200);
});

// ❌ IDOR #4 — project export bypasses the ownership check on /projects/:id
router.get('/projects/:id/export', async (req, res) => {
  const project = await Project.findById(req.params.id);
  const csv = await project.exportCSV();
  res.attachment('project.csv').send(csv);
});
```

### Broken assumptions per vulnerability

| Route | Broken Assumption |
|-------|------------------|
| `GET /projects/:id/tasks` | "The project/:id check protects all sub-routes" |
| `PUT /tasks/:id` | "Authenticated users only modify their own tasks" |
| `DELETE /tasks/:id` | "Authenticated users only delete their own tasks" |
| `GET /projects/:id/export` | "The project/:id route's check protects /export too" |

### Secure version — centralized middleware

```javascript
const router = express.Router();
router.use(requireLogin);

// Shared project ownership middleware
async function requireProjectOwner(req, res, next) {
  const project = await Project.findById(req.params.id || req.params.projectId);
  if (!project) return res.sendStatus(404);
  if (project.ownerId !== req.user.id) return res.sendStatus(403); // ✅
  req.project = project;
  next();
}

// Shared task ownership middleware (traverses project chain)
async function requireTaskOwner(req, res, next) {
  const task = await Task.findById(req.params.id);
  if (!task) return res.sendStatus(404);
  const project = await Project.findById(task.projectId);
  if (!project) return res.sendStatus(404);
  if (project.ownerId !== req.user.id) return res.sendStatus(403); // ✅
  req.task = task;
  next();
}

// All project routes — ownership enforced via middleware
router.get('/projects/:id',        requireProjectOwner, getProject);
router.get('/projects/:id/tasks',  requireProjectOwner, getProjectTasks);
router.get('/projects/:id/export', requireProjectOwner, exportProject);

// All task routes — ownership traverses to parent project
router.put('/tasks/:id',    requireTaskOwner, updateTask);
router.delete('/tasks/:id', requireTaskOwner, deleteTask);
```

---

## Subtle Edge Cases

### 1. Nested object IDOR — inherited protection illusion
```
GET /api/orders/:id          → ✅ ownership checked
GET /api/orders/:id/items/:itemId  → ❌ item check missing
```
The parent check does not protect the child route. Every nested route
needs its own enforcement.

### 2. Action IDOR — write without read
```
GET  /api/orders/:id         → 403 (protected)
POST /api/orders/:id/cancel  → 200 (no check) ← cancels another user's order
```
No data is exposed. But a user's order is cancelled without consent.
Action IDOR is often rated Critical due to direct business impact.

### 3. Wildcard route bypass
```javascript
router.get('/api/orders/:id', requireLogin, checkOwner, handler); // protected
router.get('/api/orders/*',   requireLogin, wildcardHandler);     // no owner check
// GET /api/orders/7202/anything hits the wildcard — bypasses protection
```

### 4. Parameter pollution
```
GET /api/orders?id=7201&id=7202
```
Some frameworks process the second parameter; auth checks the first.
Result: auth validates 7201, data returned is 7202.

### 5. HTTP method override
```
POST /api/orders/7202
X-HTTP-Method-Override: DELETE
```
Some frameworks honor this header. If DELETE has no check but is
reachable via method override, IDOR exists.

---

## ID Exposure vs Authorization Enforcement

```
UUID randomness prevents:   enumeration / brute force
UUID randomness does NOT:   prevent IDOR once the ID is known

ID leakage vectors (UUIDs still exposed via):
  - API responses with foreign ID references
  - Email notification links
  - Shared capability URLs
  - Browser network tab
  - Exported files referencing other records
  - WebSocket real-time event payloads
  - Referrer headers to analytics
  - Error message body: "Record abc-123 not found"
```

**The test:** If you received a UUID in *any* API response or email,
the "unguessable" defense is already defeated.

---

## Trusted vs Untrusted Identity Sources

| Source | Trust | Reason |
|--------|-------|--------|
| `req.user.id` (from auth middleware) | ✅ Trusted | Server-validated session/JWT |
| `req.params.id` | ❌ Untrusted | Attacker-controlled URL segment |
| `req.body.user_id` | ❌ Untrusted | Attacker-controlled request body |
| `req.query.userId` | ❌ Untrusted | Attacker-controlled query string |
| `req.headers['x-user-id']` | ❌ Untrusted | Attacker-controlled header |

**The rule:** `req.user` is the only identity source that matters for ownership decisions.

---

## Ownership Model Patterns

Different objects have different ownership structures. The check changes accordingly.

```javascript
// Single owner (most common)
if (object.ownerId !== req.user.id) return res.sendStatus(403);

// Multi-participant (message threads, shared docs)
if (!object.participantIds.includes(req.user.id)) return res.sendStatus(403);

// Role-based with ownership (student records)
const isOwner = object.studentId === req.user.studentId;
const isStaff = ['advisor', 'admin'].includes(req.user.role);
if (!isOwner && !isStaff) return res.sendStatus(403);

// Hierarchical (task owned via project)
const project = await Project.findById(object.projectId);
if (project.ownerId !== req.user.id) return res.sendStatus(403);

// Explicit share grants (file sharing)
const canAccess = object.ownerId === req.user.id ||
                  object.sharedWith.includes(req.user.id);
if (!canAccess) return res.sendStatus(403);
```

---

## Bug Bounty Report Template — Horizontal IDOR

```
Title: Horizontal IDOR on [endpoint] allows access to other users' [object]

Severity: [High/Critical]

Summary:
An authenticated user can access [object type] belonging to other users
by supplying a different [ID type] in [location]. No authorization check
verifies that the requesting user owns the referenced object.

Steps to Reproduce:
1. Create Account A and Account B on [target]
2. As Account B, create a [object] → note ID: [value]
3. Log in as Account A
4. Send: [HTTP METHOD] [endpoint with B's ID]
   Authorization: Bearer [Account A's token]
5. Observe: [B's data returned / action performed]

Root Cause:
The [endpoint] endpoint authenticates the caller but does not verify
that [object].[ownerField] matches the authenticated user's ID.

Impact:
[Specific data exposed or action performed]. Affects all [object type]
records. Exploitable at scale by automated enumeration.

Remediation:
Add server-side ownership check immediately after object retrieval:
  if (object.ownerId !== req.user.id) return res.status(403).end();
Apply to all routes that access this object type, not only [endpoint].
```

---

## Quick Reference — Detection Checklist

```
For each target application:

MAPPING
  □ Listed all object types (orders, files, messages, accounts...)
  □ Listed all routes per object (GET, PUT, DELETE, export, sub-resources)
  □ Checked for nested objects (parent protected, child not)

SETUP
  □ Created two test accounts (A = attacker, B = victim)
  □ Generated objects in Account B
  □ Noted all object IDs from B's session

TESTING
  □ Tested GET (read) with A's token on B's object IDs
  □ Tested PUT/PATCH (update) with A's token
  □ Tested DELETE with A's token
  □ Tested POST actions (cancel, approve, archive) with A's token
  □ Tested all sub-resource routes (/invoice, /receipt, /export, /download)
  □ Tested query parameter ID variants (?id=, ?order_id=, ?user_id=)

ID LEAKAGE
  □ Inspected all API responses for foreign ID references
  □ Checked email notifications for object ID links
  □ Reviewed exported files for cross-user references
  □ Checked error messages for ID confirmation

EDGE CASES
  □ Tested HTTP method override (X-HTTP-Method-Override)
  □ Checked for duplicate parameter handling
  □ Looked for wildcard routes that bypass specific route checks
  □ Tested old API versions (/v1/ vs /v2/)
```

---

## Key Vocabulary Added in Module 03

| Term | Definition |
|------|------------|
| **Horizontal privilege escalation** | Accessing another user's data at the same privilege level |
| **Action IDOR** | Performing an action on another user's object (cancel, delete) without data exposure |
| **Nested object IDOR** | Child resource accessible without inheriting parent's ownership check |
| **Hierarchical ownership** | Object owned via a parent object — check must traverse the chain |
| **Participant-based ownership** | Access controlled by membership in a set (thread participants, team members) |
| **ID leakage** | Object identifiers exposed in responses, emails, or URLs without authorization |
| **Wildcard route bypass** | A catch-all route that intercepts requests before specific route ownership checks |
| **Parameter pollution** | Sending duplicate parameters to exploit inconsistent handling |
| **Two-account testing** | Required methodology — Account A attacks objects owned by Account B |

---

## Coming Up — Module 04: Vertical Privilege Escalation

We leave the horizontal plane and move upward.
- Accessing admin functions as a regular user
- Function-level authorization failures
- Role-based access control gaps
- Mass assignment vulnerabilities
- Privilege escalation via API parameter manipulation

---

*Module 03 — IDOR Mastery Curriculum*
*Focus: Horizontal escalation, detection methodology, five application scenarios, hierarchical ownership*