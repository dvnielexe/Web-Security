# IDOR Mastery — Module 10 Cheatsheet
## Secure Authorization Design

> **Core principle:** The goal is not to remember to add authorization checks.
> The goal is to design systems where forgetting is structurally difficult —
> where the secure path is the default path, and the insecure path requires
> deliberate effort to take.

---

## The Shift: Reactive → Proactive Security

```
REACTIVE (finding and patching):
  Developer writes endpoint → tester finds missing check → developer adds it
  Risk: gap exists between write and patch; some gaps are never found

PROACTIVE (structurally prevented):
  Authorization centralized → new endpoint must call authz → silence = denied
  Risk: gap structurally cannot exist without deliberate bypass
```

---

## The Three Authorization Models

### RBAC — Role-Based Access Control
**Question answered:** "What role does this user have, and what can that role do?"

```javascript
// Access determined by role
if (req.user.role !== 'admin') return res.sendStatus(403);

// RBAC covers: vertical escalation (function-level)
// RBAC does NOT cover: horizontal IDOR (object-level ownership)
// Adding more roles never fixes horizontal IDOR
```

**Use when:** Clear tier separation — guest, user, moderator, admin.
**Limitation:** Says nothing about *which objects* within a role a user can access.

---

### ABAC — Attribute-Based Access Control
**Question answered:** "Do this user's attributes match this resource's policy in this context?"

```javascript
// Access determined by attributes of user, resource, and environment
const allow =
  user.department === resource.department &&
  user.clearanceLevel >= resource.sensitivityLevel &&
  isBusinessHours(new Date()) &&
  user.location === 'office';
```

**Use when:** Complex enterprise rules — time-based access, department-scoping, clearance levels.
**Examples:** AWS IAM policies, Open Policy Agent (OPA).
**Limitation:** High complexity; policy maintenance overhead.

---

### ReBAC — Relationship-Based Access Control
**Question answered:** "Is this user related to this resource in the right way?"

```javascript
// Access determined by the graph of relationships
const allow = await graph.hasEdge(user.id, 'owns', documentId) ||
              await graph.hasEdge(user.id, 'member_of', document.teamId);
```

**Use when:** Social/collaborative apps — shared documents, team membership, org hierarchies.
**Examples:** Google Zanzibar, SpiceDB, Ory Keto.
**Strength:** Naturally models complex sharing and delegation without role explosion.

---

### Model comparison

| Criterion | RBAC | ABAC | ReBAC |
|-----------|------|------|-------|
| Complexity | Low | High | Medium |
| IDOR prevention | Partial (role only) | Strong (policy-driven) | Strong (graph-enforced) |
| Horizontal IDOR | ❌ Not addressed | ✅ Via resource attributes | ✅ Via ownership graph |
| Best for | Simple tier separation | Enterprise compliance | SaaS, social, collaborative |

**Critical rule:** Most applications need RBAC AND object-level ownership checks (ABAC/ReBAC).
RBAC alone is never sufficient for IDOR prevention.

---

## The Centralized Authorization Service Pattern

The most impactful architectural change for preventing IDOR:

```javascript
// authz.js — ALL authorization rules in ONE place
class AuthorizationService {

  // Deny by default — no rule = ForbiddenError (never accidentally permitted)
  async can(user, action, resource) {
    const key = `${action}:${resource.type}`;
    const rule = this.rules[key];

    // Unknown action on unknown resource = denied, never silently permitted
    if (!rule) throw new ForbiddenError(`No rule defined for ${key}`);

    const allowed = await rule(user, resource);

    // ✅ Always 404 — never leak object existence via 403
    if (!allowed) throw new NotFoundError();
  }

  rules = {
    // Object-level ownership rules
    'read:order': (user, order) =>
      order.userId === user.id || user.role === 'admin',

    'update:order': (user, order) =>
      order.userId === user.id,

    'delete:order': (user, order) =>
      order.userId === user.id && order.status === 'pending',  // + state check

    'refund:order': (user, order) =>
      order.userId === user.id &&
      ['delivered', 'partially_delivered'].includes(order.status),

    // Sub-resources get independent rules
    'download:report': (user, report) =>
      report.userId === user.id || report.sharedWith.includes(user.id),

    // Function-level rules
    'read:admin_users': (user) => user.role === 'admin',
    'read:all_tenants': (user) => user.role === 'platform_superadmin',

    // Multi-tenant rules (both layers)
    'read:document': (user, doc) =>
      doc.tenantId === user.tenantId &&    // tenant isolation
      doc.ownerId === user.id,            // user ownership
  };
}

const authz = new AuthorizationService();
```

**Why this works:**
- All rules in one file — auditable in one PR, changeable in one place
- `authz.can()` throws — silence is never a valid outcome
- Deny by default — missing rule = denied, never accidentally permitted
- Rules are independently testable without HTTP layer

---

## Thin Controllers, Fat Authorization

```javascript
// ❌ SCATTERED — authorization mixed with business logic everywhere
app.get('/api/orders/:id', async (req, res) => {
  const order = await Order.findById(req.params.id);
  if (!order) return res.sendStatus(404);
  if (order.userId !== req.user.id) return res.sendStatus(403); // scattered
  res.json(order);
});

app.get('/api/orders/:id/invoice', async (req, res) => {
  const order = await Order.findById(req.params.id);
  // ← forgot check — IDOR exists
  res.json(await Invoice.findByOrder(order.id));
});

// ✅ CENTRALIZED — controllers are thin, authorization is explicit
app.get('/api/orders/:id', requireLogin, async (req, res) => {
  const order = await orderRepo.findById(req.params.id, req.user); // scoped
  if (!order) return res.sendStatus(404);
  await authz.can(req.user, 'read', { ...order, type: 'order' }); // throws if denied
  res.json(order);
});

app.get('/api/orders/:id/invoice', requireLogin, async (req, res) => {
  const order = await orderRepo.findById(req.params.id, req.user); // scoped
  if (!order) return res.sendStatus(404);
  await authz.can(req.user, 'read', { ...order, type: 'invoice' }); // own rule
  res.json(await Invoice.findByOrder(order.id));
});
```

---

## Scoped Data Access Layer

Make it structurally impossible to fetch data without providing authorization context:

```javascript
class OrderRepository {
  // Standard access — requires user context, enforces both layers
  async findById(orderId, userContext) {
    return Order.findOne({
      id:       orderId,
      userId:   userContext.userId,    // ✅ user ownership
      tenantId: userContext.tenantId   // ✅ tenant isolation
    });
    // Returns null for: wrong user, wrong tenant, not found
    // Caller always returns 404 on null — no existence leak
  }

  // Admin access — explicitly named, intentionally separate
  async findByIdAsAdmin(orderId, adminContext) {
    if (adminContext.role !== 'admin') throw new ForbiddenError();
    return Order.findOne({
      id:       orderId,
      tenantId: adminContext.tenantId  // ✅ still tenant-scoped even as admin
    });
  }
}
```

**The key principle:** The method signature itself requires context. You cannot call
`findById(id)` without providing `userContext` — the omission is a compile-time/runtime
error, not a silent security gap.

---

## Open Policy Agent (OPA) — Externalized Authorization

For larger systems, authorization logic lives outside the application entirely:

```rego
# orders.rego — Rego policy language
package authz.orders

import future.keywords.if

# Owner can read their own order
allow if {
  input.action == "read"
  input.resource.type == "order"
  input.user.id == input.resource.owner_id
}

# Admin can read any order in their tenant
allow if {
  input.action == "read"
  input.resource.type == "order"
  input.user.role == "admin"
  input.user.tenant_id == input.resource.tenant_id
}

# Refund requires delivered status (state precondition in policy)
allow if {
  input.action == "refund"
  input.resource.type == "order"
  input.user.id == input.resource.owner_id
  input.resource.status == "delivered"
}
```

```javascript
// Application — thin wrapper around OPA
async function authorize(user, action, resource) {
  const response = await fetch('http://opa:8181/v1/data/authz/orders', {
    method: 'POST',
    body: JSON.stringify({ input: { user, action, resource } })
  });
  const { result } = await response.json();
  // ✅ Deny by default — allow must be explicitly true
  if (!result?.allow) throw new ForbiddenError();
}

// CRITICAL: OPA only evaluates what it receives
// The application MUST verify JWT before sending claims to OPA
// Never pass req.body or client-supplied fields as user identity
const payload = jwt.verify(token, secret, { algorithms: ['HS256'] });
await authorize(payload, 'read', resource); // ✅ verified claims only
```

**OPA benefits:**
- Authorization rules testable independently of the application
- Auditable as code — version controlled, reviewed in PRs
- Changeable without deploying new application code
- Consistent across multiple services in a microservices architecture

---

## Authorization Test Matrix

Every resource type requires this test coverage in CI:

```javascript
describe('[Resource] authorization', () => {

  // 1. Cross-user read blocked (horizontal IDOR)
  it('returns 404 for another user\'s resource', async () => {
    const [a, b] = await createTwoUsers();
    const resource = await createResource({ userId: b.id });
    const res = await api.get(`/resource/${resource.id}`).auth(a.token);
    expect(res.status).toBe(404); // 404, NOT 403 — no existence leak
  });

  // 2. Cross-user write blocked (horizontal IDOR on mutation)
  it('prevents update of another user\'s resource', async () => {
    const [a, b] = await createTwoUsers();
    const resource = await createResource({ userId: b.id });
    const res = await api.put(`/resource/${resource.id}`).auth(a.token).send({});
    expect(res.status).toBe(404);
    // Verify resource unchanged
  });

  // 3. Cross-user delete blocked
  it('prevents deletion of another user\'s resource', async () => {
    const [a, b] = await createTwoUsers();
    const resource = await createResource({ userId: b.id });
    const res = await api.delete(`/resource/${resource.id}`).auth(a.token);
    expect(res.status).toBe(404);
    expect(await Resource.findById(resource.id)).not.toBeNull();
  });

  // 4. Sub-resources tested independently (not inherited from parent)
  it('blocks cross-user sub-resource access', async () => {
    const [a, b] = await createTwoUsers();
    const resource = await createResource({ userId: b.id });
    const res = await api.get(`/resource/${resource.id}/download`).auth(a.token);
    expect(res.status).toBe(404);
  });

  // 5. Unauthenticated access blocked
  it('rejects unauthenticated request', async () => {
    const resource = await createResource();
    const res = await api.get(`/resource/${resource.id}`);
    expect(res.status).toBe(401);
  });

  // 6. Admin vertical escalation blocked (if endpoint is non-admin)
  it('blocks non-admin from admin endpoint', async () => {
    const user = await createUser({ role: 'user' });
    const res = await api.get('/admin/resources').auth(user.token);
    expect(res.status).toBe(403);
  });

  // 7. State preconditions enforced server-side
  it('blocks action on resource in wrong state', async () => {
    const user = await createUser();
    const resource = await createResource({ userId: user.id, status: 'pending' });
    const res = await api.post(`/resource/${resource.id}/finalize`).auth(user.token);
    expect(res.status).toBe(409); // or 404 depending on your error strategy
  });

  // 8. Cross-tenant access blocked (multi-tenant apps)
  it('blocks cross-tenant resource access', async () => {
    const [tenantA_user, tenantB_user] = await createUsersInDifferentTenants();
    const resource = await createResource({ tenantId: tenantB_user.tenantId });
    const res = await api.get(`/resource/${resource.id}`).auth(tenantA_user.token);
    expect(res.status).toBe(404);
  });

  // 9. Owner can access their own resource
  it('allows owner to read their resource', async () => {
    const user = await createUser();
    const resource = await createResource({ userId: user.id });
    const res = await api.get(`/resource/${resource.id}`).auth(user.token);
    expect(res.status).toBe(200);
  });
});
```

---

## The Seven Secure-by-Default Patterns

```javascript
// Pattern 1 — DENY BY DEFAULT
// Unknown action = denied, never accidentally permitted
async can(user, action, resource) {
  const rule = this.rules[`${action}:${resource.type}`];
  if (!rule) throw new ForbiddenError('No rule defined');
  if (!await rule(user, resource)) throw new NotFoundError();
}

// Pattern 2 — RETURN 404 FOR BOTH not-found AND unauthorized
// Prevents ID enumeration — attacker cannot distinguish the two cases
const obj = await Model.findOne({ id, userId: req.user.id });
if (!obj) return res.sendStatus(404); // same for both

// Pattern 3 — SCOPED REPOSITORY METHODS
// Method signature requires context — omission is an error, not a gap
async findById(id, userContext) {
  return Model.findOne({ id, userId: userContext.userId, tenantId: userContext.tenantId });
}

// Pattern 4 — THROWING AUTHORIZATION, NOT BOOLEAN HELPERS
// await authz.can() throws if denied — silence = permitted becomes impossible
// Contrast: if (!isOwner(req, obj)) return 403; // easily forgotten/ignored

// Pattern 5 — THIN CONTROLLERS
// Controllers: parse input, call service, return response — nothing else
// Services: enforce authorization as part of the business operation

// Pattern 6 — ALL HTTP METHODS COVERED
// Shared middleware covers GET, PUT, DELETE, PATCH for the same resource
const ownOrder = requireOwnership(Order);
app.get('/orders/:id',    requireLogin, ownOrder, getOrder);
app.put('/orders/:id',    requireLogin, ownOrder, updateOrder);
app.delete('/orders/:id', requireLogin, ownOrder, deleteOrder);

// Pattern 7 — STATE PRECONDITIONS IN AUTHORIZATION LAYER
// Not in the UI — in the authz rule itself
'refund:order': (user, order) =>
  order.userId === user.id &&
  ['delivered', 'partially_delivered'].includes(order.status)
```

---

## The Design Review — Weakness Map

| Weakness | Risk | Fix |
|----------|------|-----|
| Inline role checks | Scattered, forgettable, inconsistent | Centralized `AuthorizationService` |
| Boolean `isOwner()` helper | Silent failure if ignored or forgotten | Throwing `authz.can()` — silence = denied |
| No per-endpoint tests | Gaps ship undetected | Mandatory test matrix per resource in CI |
| Inconsistent 403 vs 404 | Existence oracle enables enumeration | Uniform 404 via centralized authz layer |
| No centralized authz service | Rules distributed, no single audit point | `AuthorizationService` class, all rules in one file |
| Frontend-only state checks | Bypassed by direct API call | State preconditions in authz rules |
| JWT claims passed to OPA unverified | Attacker modifies claims, OPA trusts them | `jwt.verify()` with algorithm allowlist before OPA call |

---

## JWT Verification — Non-Negotiable Before Any Authorization Decision

```javascript
// ❌ VULNERABLE — decode() never checks signature
const payload = jwt.decode(token);
await authorize(payload, action, resource); // ← payload is attacker-controlled

// ❌ VULNERABLE — no algorithm restriction (alg:none attack)
const payload = jwt.verify(token, secret);
await authorize(payload, action, resource);

// ✅ SECURE — verify with explicit algorithm allowlist
const payload = jwt.verify(token, process.env.JWT_SECRET, {
  algorithms: ['HS256']  // rejects alg:none and all other algorithms
});
// Only now is payload safe to use for authorization decisions
await authorize(payload, action, resource);
```

**OPA-specific rule:** OPA evaluates what it receives. If you pass unverified claims,
OPA's decision is only as trustworthy as your input. The application is responsible
for verifying identity before any authorization query.

---

## The Complete Authorization Stack

```
Request arrives
      ↓
[Authentication middleware]    → jwt.verify() with algorithm allowlist
      ↓                          Sets req.user from verified token only
[Rate limiting]                → Counts resolver invocations, not just requests
      ↓
[Input validation]             → Sanitize, type-check, reject malformed input
      ↓
[Route handler]                → Thin: parse params, call service
      ↓
[Authorization service]        → authz.can(user, action, resource)
      ↓                          Throws ForbiddenError or NotFoundError if denied
[Data access layer]            → Scoped repository: always requires userContext
      ↓                          Enforces tenantId + userId in every query
[Business logic]               → State validation, sequence checks
      ↓
[Response]                     → Minimal fields, no sensitive data in response
```

---

## Quick Reference — Authorization Design Checklist

```
ARCHITECTURE
  □ Centralized AuthorizationService — all rules in one place
  □ Deny by default — no rule = ForbiddenError, never accidentally permitted
  □ Controllers are thin — authorization in service/authz layer only
  □ Data access layer requires userContext — omission is an error

OBJECT-LEVEL AUTHORIZATION
  □ Every database query includes userId and tenantId where applicable
  □ findById() takes userContext — impossible to call without scope
  □ Separate admin methods explicitly named (findByIdAsAdmin)
  □ Returns null for both not-found and unauthorized

RESPONSE SECURITY
  □ 404 returned for both not-found and not-authorized
  □ 403 never returned on resource requests (existence confirmed)
  □ Response body contains only required fields (no tokens, hashes, credentials)
  □ Sensitive fields not on shared types (no passwordHash on User type)

TESTING (MANDATORY PER RESOURCE)
  □ Cross-user read → 404
  □ Cross-user write/delete → 404 + verify unchanged
  □ Sub-resource cross-user → 404 (tested independently)
  □ Unauthenticated → 401
  □ Wrong role → 403
  □ Wrong state → 409 or 404
  □ Cross-tenant → 404
  □ Owner access → 200 (positive test)

JWT
  □ jwt.verify() used everywhere, never jwt.decode() for auth decisions
  □ algorithms: ['HS256'] (or RS256) — never empty, never alg:none
  □ Short expiry (15m access token)
  □ Claims cross-checked against DB for sensitive operations (stale claims)

OPA (if used)
  □ Only verified JWT claims passed to OPA as input
  □ No client-supplied fields in OPA input
  □ Policies version-controlled and tested independently
  □ Default deny in Rego (explicit allow only)
```

---

## Key Vocabulary Added in Module 10

| Term | Definition |
|------|------------|
| **RBAC** | Role-Based Access Control — access by role; addresses vertical escalation, not horizontal IDOR |
| **ABAC** | Attribute-Based Access Control — access by policy over user/resource/context attributes |
| **ReBAC** | Relationship-Based Access Control — access by graph relationship between user and resource |
| **Centralized authorization** | All authorization rules in one service; called consistently from every handler |
| **Deny by default** | Unknown action on unknown resource produces ForbiddenError — silence is never permitted |
| **Scoped repository** | Data access layer that requires user/tenant context in its method signatures |
| **Thin controller** | Handler that only parses input and calls service — no authorization logic mixed in |
| **OPA** | Open Policy Agent — external policy engine; evaluates Rego policies against input |
| **Authorization test matrix** | Mandatory per-resource CI test suite covering all HTTP methods, roles, states, and cross-user access |
| **State precondition** | Required object state enforced server-side in authorization layer, not in UI |

---

*Module 10 — IDOR Mastery Curriculum*
*Focus: Authorization models (RBAC/ABAC/ReBAC), centralized authorization service,
OPA, deny-by-default, scoped data access, authorization test matrix*