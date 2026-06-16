# IDOR Mastery — Module 08 Cheatsheet
## Multi-Tenant Application Access Control

> **Core principle:** In multi-tenant systems, the only isolation between organizations
> is software-enforced. A single missing `tenantId` filter exposes an entire
> organization's data. Every query requires two independent checks:
> tenant isolation AND user-level authorization.

---

## What Multi-Tenancy Actually Means

```
Multiple organizations (tenants) share:
  - The same application servers
  - The same codebase
  - The same database (usually — one table, tenant_id column separates rows)
  - The same API endpoints

The isolation between tenants is ENTIRELY software-enforced.
No physical walls. No separate servers. No separate schemas.
Just WHERE tenant_id = ? in every query.

One missing clause = one organization's entire data exposed.
```

**Blast radius comparison:**
```
Regular BOLA:         One user's data exposed
Intra-tenant BOLA:    One organization's internal user data exposed
Cross-tenant BOLA:    Another organization's entire dataset exposed
Platform-level BFLA:  All tenants' data exposed via admin endpoint
```

---

## The Two-Layer Authorization Model

**The most important mental model in this module.**

Every protected resource in a multi-tenant system requires two independent checks:

```
Layer 1 — Tenant isolation:   Does this object belong to the caller's TENANT?
Layer 2 — User authorization:  Does this USER own or have access to this object?

Both must pass. Either alone is insufficient.
```

```javascript
// The complete pattern — both layers in every query
async function requireAccess(req, objectId, Model) {
  const obj = await Model.findOne({
    id:       objectId,
    tenantId: req.user.tenantId,  // ✅ Layer 1: tenant isolation
    ownerId:  req.user.id         // ✅ Layer 2: user ownership
  });
  // null for: wrong tenant + wrong user + not found — leaks nothing
  return obj;
}
```

**Why both are required:**
```
Tenant scope only:  Any Company A employee reads any colleague's private data
User scope only:    Employees cross company boundaries into other orgs' data
Both enforced:      Correct — isolated per org AND per user within org
```

**Severity distinction:**
```
Intra-tenant BOLA:   Same org, different user's data   → High
Cross-tenant BOLA:   Different org's data              → Critical
Platform BFLA:       All tenants via admin endpoint    → Critical
```

---

## How Tenant Context Gets Established — Three Approaches

### Approach 1 — Subdomain-Based Resolution

```javascript
// Tenant resolved from subdomain — server-controlled routing
app.use(async (req, res, next) => {
  const subdomain = req.hostname.split('.')[0]; // 'company-a'
  req.resolvedTenant = await Tenant.findBySubdomain(subdomain);
  next();
});

// VULNERABLE — subdomain resolved but never cross-checked with session
app.get('/api/users/:id', requireLogin, async (req, res) => {
  const user = await User.findById(req.params.id);
  // ❌ User fetched without tenant scope
  res.json(user);
});

// SECURE — subdomain tenant cross-checked with session tenant
app.get('/api/users/:id', requireLogin, async (req, res) => {
  // ✅ Verify subdomain tenant matches authenticated user's tenant
  if (req.resolvedTenant.id !== req.user.tenantId) {
    return res.sendStatus(403);
  }
  const user = await User.findOne({
    id: req.params.id,
    tenantId: req.user.tenantId  // ✅ scoped
  });
  if (!user) return res.sendStatus(404);
  res.json(user);
});
```

### Approach 2 — Header-Based Resolution (Most Dangerous)

```javascript
// VULNERABLE — tenant from client header, attacker-controlled
app.use((req, res, next) => {
  req.tenantId = req.headers['x-tenant-id']; // ← set to any value
  next();
});
// Attacker sends: X-Tenant-ID: competitor_tenant_id
// Server now operates entirely in competitor's context

// SECURE — tenant ALWAYS from verified session/JWT
app.use(requireLogin, (req, res, next) => {
  req.tenantId = req.user.tenantId; // ← from verified JWT, never header
  next();
});
```

**Rule:** Any header that establishes tenant context is attacker-controlled.
`X-Tenant-ID`, `X-Org-ID`, `X-Workspace-ID` — all client-controlled unless signed.
Tenant context must come from the server-validated session.

### Approach 3 — JWT-Embedded Tenant Context

```javascript
// At login — tenant embedded in JWT at authentication time
const token = jwt.sign({
  userId:   user.id,
  tenantId: user.tenantId,  // ← locked at login, cryptographically bound
  role:     user.role
}, secret, { expiresIn: '15m', algorithm: 'HS256' });

// On every request — tenant from verified token
app.use((req, res, next) => {
  const payload = jwt.verify(token, secret, { algorithms: ['HS256'] });
  req.user = {
    id:       payload.userId,
    tenantId: payload.tenantId,  // ✅ cryptographically bound
    role:     payload.role
  };
  next();
});

// VULNERABLE even with correct JWT — tenantId extracted but never used
app.get('/api/projects/:id', requireLogin, async (req, res) => {
  const project = await Project.findById(req.params.id);
  // ❌ tenantId in session but never applied to query
  res.json(project);
});

// SECURE — tenantId applied in every query
app.get('/api/projects/:id', requireLogin, async (req, res) => {
  const project = await Project.findOne({
    id:       req.params.id,
    tenantId: req.user.tenantId  // ✅ session tenantId always used
  });
  if (!project) return res.sendStatus(404);
  res.json(project);
});
```

**The most common real-world failure:**
Context established correctly in JWT → tenantId never applied in query.
The developer has the right information and doesn't use it.

---

## The Five Multi-Tenant Failure Patterns

### Pattern 1 — Tenant Scope Missing from Query

**Broken assumption:** *"Authentication establishes who the user is — that's enough."*

```javascript
// VULNERABLE — tenant context unused in query
app.get('/api/invoices/:id', requireLogin, async (req, res) => {
  const invoice = await Invoice.findById(req.params.id);
  // ❌ Tenant A user reads Tenant B's invoice
  res.json(invoice);
});

// SECURE — tenant scope enforced in query
app.get('/api/invoices/:id', requireLogin, async (req, res) => {
  const invoice = await Invoice.findOne({
    id:       req.params.id,
    tenantId: req.user.tenantId  // ✅ cross-tenant access impossible
  });
  if (!invoice) return res.sendStatus(404);
  res.json(invoice);
});
```

---

### Pattern 2 — Client-Supplied Tenant ID Trusted

**Broken assumption:** *"The tenant ID in the request came from our own application."*

```javascript
// VULNERABLE — tenant ID from query string
app.get('/api/reports', requireLogin, async (req, res) => {
  const tenantId = req.query.tenant_id; // ← attacker sets to any value
  const reports = await Report.findByTenant(tenantId);
  res.json(reports);
});

// SECURE — tenant always from verified session
app.get('/api/reports', requireLogin, async (req, res) => {
  const tenantId = req.user.tenantId; // ← from verified JWT
  const reports = await Report.findByTenant(tenantId);
  res.json(reports);
});
```

**Trusted vs untrusted tenant sources:**
```
✅ req.user.tenantId   — from verified JWT/session
❌ req.query.tenant_id  — attacker-controlled
❌ req.body.tenant_id   — attacker-controlled
❌ req.params.tenantId  — attacker-controlled (must validate vs session)
❌ req.headers['x-tenant-id'] — attacker-controlled
```

---

### Pattern 3 — Tenant Admin Privileges Not Scoped

**Broken assumption:** *"Admin role = authorized to act on anything called as admin."*

```javascript
// VULNERABLE — role checked, tenant scope missing
app.delete('/api/users/:id', requireLogin, async (req, res) => {
  if (req.user.role !== 'admin') return res.sendStatus(403); // ✓ role
  await User.delete(req.params.id); // ❌ no tenant scope — deletes any user
  res.sendStatus(200);
});

// SECURE — role AND tenant both enforced
app.delete('/api/users/:id', requireLogin, async (req, res) => {
  if (req.user.role !== 'admin') return res.sendStatus(403); // ✅ role
  const user = await User.findOne({
    id:       req.params.id,
    tenantId: req.user.tenantId  // ✅ admin of THIS tenant only
  });
  if (!user) return res.sendStatus(404);
  await user.delete();
  res.sendStatus(200);
});
```

**Rule:** Tenant admin ≠ platform superadmin.
Admin role scoped to a tenant must never operate across tenant boundaries.

---

### Pattern 4 — Tenant Scoped but User Not Scoped (Intra-Tenant BOLA)

**Broken assumption:** *"Tenant isolation is sufficient — members share access within the org."*

```javascript
// VULNERABLE — tenant scoped, user not scoped
// Any Company A employee reads any colleague's private documents
app.get('/api/documents/:id', requireLogin, async (req, res) => {
  const doc = await Document.findOne({
    id:       req.params.id,
    tenantId: req.user.tenantId  // ✓ tenant scoped
    // ❌ no user-level ownership check within tenant
  });
  res.json(doc);
});

// SECURE — both layers enforced
app.get('/api/documents/:id', requireLogin, async (req, res) => {
  const doc = await Document.findOne({
    id:       req.params.id,
    tenantId: req.user.tenantId,  // ✅ tenant isolation
    ownerId:  req.user.id         // ✅ user-level ownership
  });
  if (!doc) return res.sendStatus(404);
  res.json(doc);
});
```

---

### Pattern 5 — Tenant ID in URL Path Not Validated Against Session

**Broken assumption:** *"The tenantId in the URL determines which tenant to serve."*

```javascript
// VULNERABLE — tenant from URL, never compared to session
app.get('/api/tenants/:tenantId/users', requireLogin, async (req, res) => {
  const { tenantId } = req.params; // ← attacker supplies any tenant ID
  const users = await User.findByTenant(tenantId);
  res.json(users);
});

// SECURE — URL tenant ID validated against session's tenant
app.get('/api/tenants/:tenantId/users', requireLogin, async (req, res) => {
  if (req.params.tenantId !== req.user.tenantId) {
    return res.sendStatus(403); // ✅ URL must match session
  }
  const users = await User.findByTenant(req.user.tenantId);
  res.json(users);
});
```

---

## Platform-Level vs Tenant-Level Roles

A critical architectural distinction in multi-tenant SaaS:

```
Tenant Admin:    Admin within one organization
                 Can manage users/settings within their tenant
                 Cannot see other tenants
                 Cannot list all tenants on the platform

Platform Superadmin: Anthropic/vendor staff role
                     Can see all tenants for support/ops purposes
                     Must be a completely separate role
                     Should require additional authentication (MFA, IP restriction)
```

```javascript
// VULNERABLE — tenant admin can list all platform tenants
app.get('/admin/tenants', async (req, res) => {
  if (req.user.role !== 'admin') return res.sendStatus(403);
  // ❌ tenant admin can now see all orgs on the platform
  const tenants = await Tenant.findAll();
  res.json(tenants);
});

// SECURE — platform superadmin role distinct from tenant admin
function requirePlatformSuperAdmin(req, res, next) {
  if (req.user.role !== 'platform_superadmin') return res.sendStatus(403);
  // Optional: IP allowlist, MFA verification
  next();
}

app.get('/admin/tenants',
  requireLogin,
  requirePlatformSuperAdmin,  // ✅ separate role entirely
  async (req, res) => {
    const tenants = await Tenant.findAll();
    res.json(tenants);
  }
);
```

---

## Bulk Operations in Multi-Tenant Context

Multi-tenant systems make batch authorization failures more severe:

```javascript
// VULNERABLE — three failures in one endpoint
app.post('/api/invoices/bulk-send', requireLogin, async (req, res) => {
  const { invoice_ids } = req.body;
  const invoices = await Invoice.findByIds(invoice_ids);
  // ❌ Failure 1: No tenant filter — may return other tenants' invoices
  // ❌ Failure 2: No per-invoice ownership check within tenant
  // ❌ Failure 3: No function-level auth — any user can bulk-send
  await Email.sendAll(invoices);
  res.sendStatus(200);
});

// SECURE — all three failures fixed
app.post('/api/invoices/bulk-send',
  requireLogin,
  requireRole('admin', 'billing_manager'),  // ✅ Fix 3: function auth
  async (req, res) => {
    const { invoice_ids } = req.body;

    // ✅ Fix 1 + 2: fetch with BOTH tenant AND ownership filters
    const invoices = await Invoice.findAll({
      id:       { $in: invoice_ids },
      tenantId: req.user.tenantId,   // ✅ tenant isolation
      ownerId:  req.user.id          // ✅ user ownership (if applicable)
    });

    // ✅ Validate ALL requested IDs were found and authorized
    if (invoices.length !== invoice_ids.length) {
      return res.status(403).json({
        error: 'One or more invoices not found or not authorized'
      });
    }

    await Email.sendAll(invoices);
    res.sendStatus(200);
  }
);
```

---

## Full Code Audit — Multi-Tenant CRM Platform

### Vulnerability summary

| Route | Vulnerability | Missing Layer |
|-------|--------------|---------------|
| `GET /contacts` | Cross-tenant BOLA | Tenant isolation — returns all tenants' contacts |
| `PUT /contacts/:id` | Cross-tenant BOLA + mass assignment | Tenant isolation + field allowlist |
| `DELETE /contacts/:id` | Cross-tenant admin BOLA | Tenant scope on admin operation |
| `GET /contacts/export` | Tenant parameter tampering | Client-supplied tenantId trusted |
| `GET /admin/tenants` | Platform-level BFLA | Tenant admin ≠ platform superadmin |
| `GET /contacts/:id` | ✅ Secure | Both tenant scope present |

### Secure version

```javascript
const router = express.Router();
router.use(requireLogin);
// req.user: { id, tenantId, role }

// Platform superadmin middleware
function requirePlatformSuperAdmin(req, res, next) {
  if (req.user.role !== 'platform_superadmin') return res.sendStatus(403);
  next();
}

// Role middleware
function requireRole(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) return res.sendStatus(403);
    next();
  };
}

// ✅ FIXED — List contacts: scoped to caller's tenant only
router.get('/contacts', async (req, res) => {
  const contacts = await Contact.findByTenant(req.user.tenantId); // ✅
  res.json(contacts);
});

// ✅ ALREADY SECURE — Get single contact (tenant scope present)
// Optionally add user ownership if contacts are private per-user
router.get('/contacts/:id', async (req, res) => {
  const contact = await Contact.findOne({
    id:       req.params.id,
    tenantId: req.user.tenantId  // ✅ tenant scoped
  });
  if (!contact) return res.sendStatus(404);
  res.json(contact);
});

// ✅ FIXED — Update contact: tenant isolation + mass assignment fix
router.put('/contacts/:id', async (req, res) => {
  const contact = await Contact.findOne({
    id:       req.params.id,
    tenantId: req.user.tenantId  // ✅ tenant isolation
  });
  if (!contact) return res.sendStatus(404);
  // ✅ Field allowlist — prevent mass assignment
  const { name, email, phone, company } = req.body;
  await contact.update({ name, email, phone, company });
  res.json(contact);
});

// ✅ FIXED — Delete contact: role + tenant scope both enforced
router.delete('/contacts/:id', async (req, res) => {
  if (req.user.role !== 'admin') return res.sendStatus(403); // ✅ role
  const contact = await Contact.findOne({
    id:       req.params.id,
    tenantId: req.user.tenantId  // ✅ tenant scope — admin of THIS org only
  });
  if (!contact) return res.sendStatus(404);
  await contact.delete();
  res.sendStatus(200);
});

// ✅ FIXED — Export: tenant from session, never from query param
router.get('/contacts/export', async (req, res) => {
  // ✅ tenantId from verified session — never from req.query
  const contacts = await Contact.findByTenant(req.user.tenantId);
  const csv = Contact.toCSV(contacts);
  res.attachment('contacts.csv').send(csv);
});

// ✅ FIXED — Admin tenant list: platform superadmin only
router.get('/admin/tenants',
  requirePlatformSuperAdmin,  // ✅ separate role from tenant admin
  async (req, res) => {
    const tenants = await Tenant.findAll();
    res.json(tenants);
  }
);
```

---

## Detection Methodology — Multi-Tenant Testing

### Setup

```
Create two complete test organizations:
  Org A (attacker): your primary testing account
  Org B (victim):   populated with data you'll attempt to access

Within each org, create users at different roles:
  Org A: regular user, admin user
  Org B: regular user, admin user

You need four accounts total to test all cross-tenant and intra-tenant combinations.
```

### Test Matrix

```
Test 1: Org A regular user → Org B's objects (cross-tenant BOLA)
Test 2: Org A admin       → Org B's objects (cross-tenant admin BOLA)
Test 3: Org A regular user → Org A admin objects (intra-tenant vertical)
Test 4: Org A regular user → Org A other user's objects (intra-tenant horizontal)
```

### What to Test

```
TENANT CONTEXT SOURCES
  □ Modify JWT tenantId — does the server use it directly or verify it?
  □ Add X-Tenant-ID header — does it override session tenantId?
  □ Add tenant_id query param — does it override session tenantId?
  □ Add tenant_id body field — does it override session tenantId?
  □ Modify Host header — does subdomain override session tenant?

CROSS-TENANT OBJECT ACCESS
  □ Request Org B's object IDs with Org A's token on every endpoint
  □ Test all HTTP methods (GET, PUT, DELETE, PATCH, POST)
  □ Test all sub-resources and nested routes
  □ Test export/bulk endpoints with cross-tenant IDs

INTRA-TENANT ACCESS
  □ Within Org A, test regular user accessing admin user's private objects
  □ Within Org A, test accessing colleague's salary/private data
  □ Confirm both tenant AND user scope are enforced, not just tenant

ADMIN SCOPE TESTING
  □ As Org A admin, attempt admin operations on Org B's objects
  □ As Org A admin, attempt to list all platform tenants
  □ As Org A admin, attempt to access platform-level admin endpoints
```

---

## Quick Reference — Authorization Checklist per Endpoint

```javascript
// For every endpoint that returns or modifies tenant data:

// ✅ 1. Is tenantId from session (never from request)?
const tenantId = req.user.tenantId; // not req.query, body, params, or header

// ✅ 2. Is every query scoped to that tenantId?
Model.findOne({ id, tenantId: req.user.tenantId });

// ✅ 3. Is user-level ownership also checked where needed?
Model.findOne({ id, tenantId: req.user.tenantId, ownerId: req.user.id });

// ✅ 4. Are admin operations scoped to the admin's own tenant?
if (req.user.role !== 'admin') return res.sendStatus(403);
Model.findOne({ id, tenantId: req.user.tenantId }); // admin of THIS org

// ✅ 5. Are platform-level operations behind a separate superadmin role?
if (req.user.role !== 'platform_superadmin') return res.sendStatus(403);

// ✅ 6. Are URL tenant IDs validated against session tenant?
if (req.params.tenantId !== req.user.tenantId) return res.sendStatus(403);

// ✅ 7. In bulk operations, are ALL IDs validated (not just first)?
const allBelongToTenant = items.every(i => i.tenantId === req.user.tenantId);
if (!allBelongToTenant) return res.sendStatus(403);

// ✅ 8. On update endpoints, is field allowlisting applied?
const { name, email } = req.body; // not spread or direct pass of req.body
```

---

## Key Vocabulary Added in Module 08

| Term | Definition |
|------|------------|
| **Multi-tenancy** | Single shared infrastructure serving multiple organizations (tenants) |
| **Tenant isolation** | Software-enforced boundary preventing cross-organization data access |
| **Cross-tenant BOLA** | Accessing another organization's objects — Critical severity |
| **Intra-tenant BOLA** | Accessing a colleague's private data within the same org — High severity |
| **Tenant context** | How the server knows which tenant a request belongs to (JWT, subdomain, header) |
| **Two-layer authorization** | Tenant isolation (Layer 1) AND user ownership (Layer 2) — both required |
| **Tenant admin** | Admin role scoped to one organization — cannot operate across tenants |
| **Platform superadmin** | Vendor-level role with cross-tenant visibility — separate from tenant admin |
| **Tenant parameter tampering** | Attacker modifies a client-supplied tenantId to access another org's data |
| **Context established, context unused** | tenantId correctly in JWT but never applied to database queries |

---

## Coming Up — Module 09: Business Logic Abuse & Chained IDOR

The final advanced module before defense:
- Indirect IDOR — reaching protected data through seemingly unrelated endpoints
- Authorization state manipulation — exploiting workflow assumptions
- Chained escalation — combining horizontal + vertical + tenant failures
- Race conditions in authorization checks
- Real bug bounty case studies with multi-vulnerability chains

---

*Module 08 — IDOR Mastery Curriculum*
*Focus: Multi-tenant isolation, two-layer authorization, tenant context establishment, platform vs tenant roles*