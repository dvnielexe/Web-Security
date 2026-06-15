# IDOR Mastery — Module 07 Cheatsheet
## GraphQL Authorization Issues

> **Core principle:** GraphQL has one endpoint. Authorization cannot live at the route level.
> Every resolver is an independent authorization point — authentication at the root grants
> nothing at the object level, and object ownership grants nothing at the field level.

---

## How GraphQL Breaks REST Authorization Assumptions

```
REST model:                          GraphQL model:
────────────────────────────────     ────────────────────────────────────
Many endpoints, one operation each   One endpoint, all operations
Route = unit of authorization        Resolver = unit of authorization
Middleware per route                 Context object per request
Fixed response shape                 Client-defined response shape
Authorization: did you call          Authorization: what did you ask for,
the right route?                     on which object, requesting which fields?
```

**The authorization question changes completely:**

REST: *"Is this user allowed to call `GET /orders/7201`?"*
GraphQL: *"Is this user allowed to query the `order` field, requesting `id: 7201`, and are they allowed to see the `customer.email` nested field on that order?"*

Three different authorization checks for one query.

---

## The Resolver Chain — Three Independent Authorization Points

```
POST /graphql (single endpoint)
        ↓
[Root resolver]          ← Check 1: Is caller authenticated? Role?
        ↓
[Object resolver]        ← Check 2: Does caller own this object?
        ↓
[Field resolvers]        ← Check 3: Is caller allowed to see this field?

Rule: Passing Check 1 grants nothing at Check 2.
      Passing Check 2 grants nothing at Check 3.
      Each resolver enforces independently.
```

---

## The `context` Object — GraphQL's Session Equivalent

In REST, `req.user` is set by middleware. In GraphQL, there is no per-route middleware.
The `context` object is built once per request and passed to every resolver.

```javascript
// Apollo Server — context built at request time
const server = new ApolloServer({
  typeDefs,
  resolvers,
  context: async ({ req }) => {
    const token = req.headers.authorization?.split('Bearer ')[1];
    if (!token) return { user: null };
    try {
      const user = jwt.verify(token, process.env.JWT_SECRET, {
        algorithms: ['HS256']
      });
      return { user }; // ← available in every resolver as context.user
    } catch {
      return { user: null };
    }
  }
});

// Every resolver receives context as its third argument
const resolvers = {
  Query: {
    order: async (parent, args, context) => {
      // context.user is the authenticated caller
      if (!context.user) throw new AuthenticationError('Login required');
      // ...
    }
  }
};
```

**Critical:** If a resolver doesn't check `context.user`, it is **publicly accessible** —
not just unauthorized, but completely unauthenticated. There is no fallback middleware.

---

## The Five GraphQL-Specific Failure Patterns

### Pattern 1 — Introspection Leaks the Entire Schema

**What it is:** GraphQL introspection returns every type, field, mutation, and argument.
Enabled in production, it hands attackers a complete API map — including admin types,
sensitive fields, and mutations that don't appear in the UI.

**Broken assumption:** *"Our internal types and admin mutations aren't discoverable."*

```graphql
# Attacker sends this — gets the complete schema
{
  __schema {
    types {
      name
      fields { name type { name } args { name } }
    }
  }
}

# Response reveals everything:
# type AdminPanel { deleteUser(id: ID!): Boolean }
# type User { salary: Float, ssn: String, apiToken: String }
# mutation promoteToAdmin(userId: ID!): User
```

```javascript
// SECURE — disable introspection in production
const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: process.env.NODE_ENV !== 'production',
});

// Also block __schema/__type queries at middleware level
app.use('/graphql', (req, res, next) => {
  const query = req.body?.query || '';
  if (query.includes('__schema') || query.includes('__type')) {
    return res.status(403).json({ error: 'Introspection disabled' });
  }
  next();
});
```

**Important:** Introspection is typically rated Informational to Low on its own.
It's a *recon enabler* — the real finding is what you discover through it (BOLA, BFLA).
Report both as separate findings; note introspection enabled the others.

---

### Pattern 2 — Object Resolver Without Ownership Check (BOLA)

**What it is:** Resolver fetches an object by ID from query arguments.
No check verifies the requesting user owns or is entitled to that object.
Direct GraphQL equivalent of REST BOLA.

**Broken assumption:** *"Authenticated users only request objects they own."*

```javascript
// VULNERABLE
const resolvers = {
  Query: {
    order: async (_, { id }) => {
      return Order.findById(id); // ❌ No ownership check
    }
  }
};

// SECURE
const resolvers = {
  Query: {
    order: async (_, { id }, context) => {
      if (!context.user) throw new AuthenticationError('Login required');
      const order = await Order.findById(id);
      // ✅ Ownership check — returns null for both not-found and not-yours
      if (!order || order.customerId !== context.user.id) return null;
      return order;
    }
  }
};
```

---

### Pattern 3 — Nested Resolver: Child Escapes Parent Auth (BOLA)

**What it is:** The top-level resolver correctly checks ownership.
A nested field resolver resolves a related object without re-checking authorization.
The parent check doesn't protect child resolvers.

**Broken assumption:** *"The parent's ownership check protects all nested fields."*

```graphql
# User owns order 7201 — passes ownership check
# But seller nested resolver has no auth check
{
  order(id: "7201") {
    seller {
      email              # other user's PII
      bankAccountDetails # sensitive financial data
      internalNotes      # admin-only field
    }
  }
}
```

```javascript
// VULNERABLE — nested resolver returns full object
const resolvers = {
  Order: {
    seller: async (order) => {
      return User.findById(order.sellerId); // ❌ full user returned
    }
  }
};

// SECURE — nested resolver scopes what it returns
const resolvers = {
  Order: {
    seller: async (order, _, context) => {
      const seller = await User.findById(order.sellerId);
      // ✅ Return only public fields appropriate for a buyer to see
      return {
        id: seller.id,
        displayName: seller.displayName,
        rating: seller.rating,
        // bankAccountDetails, email, internalNotes not included
      };
    }
  }
};
```

**Better approach — separate types for different access levels:**

```graphql
# Schema-level fix: two user types
type PublicUser {
  id: ID!
  displayName: String!
  rating: Float
  # Sensitive fields never defined here
}

type User {
  id: ID!
  email: String!
  role: String!
  # Full fields — only returned to the user themselves
}

type Order {
  seller: PublicUser!  # ✅ Returns public projection only
}
```

---

### Pattern 4 — Mutation Without Role Check (BFLA)

**What it is:** A mutation performs a privileged action but the resolver only checks
authentication, not the caller's role or permission scope.

**Broken assumption:** *"Authentication confirms identity; that identity authorizes any mutation."*

```graphql
# Regular user calls admin mutation
mutation {
  deleteUser(id: "USR-1001") { success }
  promoteToAdmin(userId: "USR-1042") { role }
  updateUserRole(userId: "USR-99", role: "admin") { role }
}
```

```javascript
// VULNERABLE
const resolvers = {
  Mutation: {
    deleteUser: async (_, { id }, context) => {
      // ❌ context.user exists but role never checked
      await User.delete(id);
      return { success: true };
    }
  }
};

// SECURE
const resolvers = {
  Mutation: {
    deleteUser: async (_, { id }, context) => {
      if (!context.user) throw new AuthenticationError('Login required');
      if (context.user.role !== 'admin')              // ✅ role check
        throw new ForbiddenError('Admin only');
      if (context.user.id === id)                     // ✅ edge case
        throw new ForbiddenError('Cannot delete yourself');
      await User.delete(id);
      return { success: true };
    }
  }
};
```

---

### Pattern 5 — Alias Batching: Rate Limit Bypass + Enumeration

**What it is:** GraphQL aliases allow the same field to be queried multiple times in one
request. Attackers enumerate IDs or bypass rate limiting — one HTTP request, N resolver calls.

**Broken assumption:** *"Rate limiting per HTTP request prevents enumeration."*

```graphql
# One request — tests 5 order IDs
# Rate limiting sees 1 request. Server executes 5 resolver calls.
{
  o1: order(id: "7200") { id customerId shippingAddress }
  o2: order(id: "7201") { id customerId shippingAddress }
  o3: order(id: "7202") { id customerId shippingAddress }
  o4: order(id: "7203") { id customerId shippingAddress }
  o5: order(id: "7204") { id customerId shippingAddress }
}

# Scale to 100+ aliases — one HTTP request = 100 resolver calls
# Even with ownership checks, ForbiddenError vs null is an enumeration oracle
```

```javascript
// DEFENSE 1 — Query complexity limiting (Apollo)
const server = new ApolloServer({
  validationRules: [
    depthLimit(5),
    createComplexityRule({
      maximumComplexity: 1000,
      estimators: [fieldExtensionsEstimator()]
    })
  ]
});

// DEFENSE 2 — Alias count limiting
function limitAliases(document) {
  const aliases = (document.definitions[0]
    .selectionSet.selections || [])
    .filter(s => s.alias).length;
  if (aliases > 10) throw new Error('Too many aliases in query');
}

// DEFENSE 3 — Per-resolver rate limiting (count invocations, not requests)
// Each alias invocation counts separately against the resolver's rate limit

// DEFENSE 4 — Return null (not ForbiddenError) for unauthorized/nonexistent
// If null === not found === not yours, aliases leak nothing about ID existence
```

---

## Schema-Level Vulnerabilities

Authorization failures aren't only in resolvers. The schema itself can expose sensitive data.

### Never expose sensitive fields on shared types

```graphql
# VULNERABLE schema — sensitive fields on User type
type User {
  id: ID!
  email: String!
  role: String!
  passwordHash: String!      # ❌ Any resolver returning User exposes this
  stripeCustomerId: String!  # ❌ Financial identifier exposed
  apiToken: String!          # ❌ Credential in schema
}

type Project {
  id: ID!
  name: String!
  apiKey: String!            # ❌ Credential on general-purpose type
}

# SECURE — split types by access level
type PublicUser {
  id: ID!
  displayName: String!       # Public fields only
}

type User {
  id: ID!
  email: String!
  role: String!
  # passwordHash — removed entirely, never in schema
  # stripeCustomerId — served via dedicated billing endpoint
}

type Project {
  id: ID!
  name: String!
  owner: PublicUser!         # ✅ Returns public projection
  # apiKey — served via separate authenticated query only
}

type Query {
  project(id: ID!): Project
  myProjects: [Project]      # ✅ Name signals scope (only yours)
  user(id: ID!): PublicUser  # ✅ Public type for general queries
  me: User                   # ✅ Full type for own profile only
  projectApiKey(id: ID!): String  # ✅ Dedicated, separately authorized
}
```

---

## Reusable Authorization Middleware Pattern

```javascript
// auth.js — centralized authorization helpers for GraphQL
const { AuthenticationError, ForbiddenError, UserInputError } = require('apollo-server');

// Confirms caller is authenticated — returns user or throws
function requireAuth(context) {
  if (!context.user) throw new AuthenticationError('Login required');
  return context.user;
}

// Confirms caller has a specific role
function requireRole(context, ...roles) {
  const user = requireAuth(context);
  if (!roles.includes(user.role))
    throw new ForbiddenError(`Requires role: ${roles.join(' or ')}`);
  return user;
}

// Confirms caller owns the project
async function requireProjectOwner(context, projectId) {
  const user = requireAuth(context);
  const project = await Project.findById(projectId);
  if (!project) throw new UserInputError('Project not found');
  if (project.ownerId !== user.id)
    throw new ForbiddenError('Project access denied');
  return { user, project };
}

// Confirms caller is a member of the project (owner or member)
async function requireProjectMember(context, projectId) {
  const user = requireAuth(context);
  const project = await Project.findById(projectId);
  if (!project) throw new UserInputError('Project not found');
  const isMember = project.memberIds.includes(user.id) ||
                   project.ownerId === user.id;
  if (!isMember) throw new ForbiddenError('Project access denied');
  return { user, project };
}

module.exports = { requireAuth, requireRole, requireProjectOwner, requireProjectMember };
```

---

## Full Code Audit — Project Management SaaS

### Vulnerability summary

| Resolver | Type | Broken Assumption |
|----------|------|-------------------|
| `Query.project` | BOLA | "Anyone who knows a project ID may view it" |
| `Query.allProjects` | BOLA | "Every authenticated user can view every project" |
| `Query.user` | BOLA | "Users may receive arbitrary user records" |
| `Mutation.deleteProject` | BOLA | "Authentication implies project ownership" |
| `Mutation.updateUserRole` | BFLA | "Any authenticated user may assign roles" |
| `Mutation.createInvite` | BOLA | "Any logged-in user may invite others to any project" |
| Schema `User` type | Schema leak | "Resolvers are responsible for hiding sensitive fields" |
| Schema `Project.apiKey` | Schema leak | "Sensitive credentials are safe on general-purpose types" |

### Secure resolver implementation

```javascript
const resolvers = {
  Query: {

    // FIXED — BOLA: ownership check required
    project: async (_, { id }, context) => {
      const user = requireAuth(context);
      const project = await Project.findById(id);
      const canAccess = project &&
        (project.ownerId === user.id ||
         project.memberIds.includes(user.id));
      if (!canAccess) return null; // null for both not-found and not-yours
      return project;
    },

    // FIXED — BOLA: scope to caller's projects only (renamed myProjects)
    myProjects: async (_, __, context) => {
      const user = requireAuth(context);
      return Project.findByMemberOrOwner(user.id); // ✅ session-scoped
    },

    // FIXED — BOLA: return public projection, not full User object
    user: async (_, { id }, context) => {
      requireAuth(context);
      const user = await User.findById(id);
      if (!user) return null;
      return { id: user.id, displayName: user.displayName };
      // email, role, passwordHash, stripeCustomerId excluded
    },

    // Own profile — always session-scoped
    me: async (_, __, context) => {
      const user = requireAuth(context);
      return User.findById(user.id); // ✅ always their own
    },

    // Dedicated API key endpoint — separately authorized
    projectApiKey: async (_, { id }, context) => {
      const { project } = await requireProjectOwner(context, id);
      return project.apiKey; // ✅ owner only, not on general Project type
    },
  },

  Mutation: {

    // FIXED — BOLA: ownership required before delete
    deleteProject: async (_, { id }, context) => {
      await requireProjectOwner(context, id); // ✅ checks auth + ownership
      await Project.delete(id);
      return true;
    },

    // FIXED — BFLA: admin role required + value validation
    updateUserRole: async (_, { userId, role }, context) => {
      requireRole(context, 'admin');             // ✅ admin only
      const allowedRoles = ['user', 'moderator', 'admin'];
      if (!allowedRoles.includes(role))
        throw new UserInputError(`Invalid role: ${role}`);
      if (userId === context.user.id)
        throw new ForbiddenError('Cannot change your own role');
      return User.updateRole(userId, role);
    },

    // FIXED — BOLA: must own project to invite; validate not already member
    createInvite: async (_, { projectId, email }, context) => {
      const { project } = await requireProjectOwner(context, projectId);
      const existingUser = await User.findByEmail(email);
      if (existingUser && project.memberIds.includes(existingUser.id))
        throw new UserInputError('User is already a project member');
      return Invite.create(project.id, email, context.user.id);
    },
  },
};
```

---

## GraphQL-Specific Detection Methodology

### Phase 1 — Schema Discovery

```
1. Send introspection query (if enabled in production → first finding)
   { __schema { types { name fields { name type { name } } } } }

2. If introspection disabled, try field suggestion brute force:
   { nonExistentField }
   → "Did you mean 'order'?" suggestions leak field names

3. Check common GraphQL endpoints:
   /graphql, /api/graphql, /v1/graphql, /query, /gql

4. Check Playground/Voyager UIs (sometimes left open):
   /graphql/playground, /voyager, /graphiql
```

### Phase 2 — Object Authorization Testing (BOLA)

```
1. Two accounts (A = attacker, B = victim)
2. Query every object type with B's IDs using A's context
3. For each object type, test nested fields independently:
   { order(id: "B's order") { id } }           → passes?
   { order(id: "B's order") { customer { email } } } → check nested
4. Test allX queries without filters — do they return other users' data?
5. Test aliases for batch enumeration
```

### Phase 3 — Function Authorization Testing (BFLA)

```
1. Discover all mutations from introspection or field suggestions
2. Call every mutation with regular user token
3. Look for: delete*, promote*, update*Role, admin*, issue*, refund*
4. Test with partial role — e.g., moderator calling admin-only mutation
```

### Phase 4 — Field-Level Probing

```
1. Request every field on every type using your own objects first
2. Note which fields are returned, which return null, which throw
3. Then request same fields on other users' objects via nested resolvers
4. Pay attention to: email, phone, address, role, salary,
   apiToken, stripeCustomerId, passwordHash, internalNotes
```

---

## null vs Error — Enumeration Prevention

```javascript
// ❌ VULNERABLE — ForbiddenError reveals object existence
const order = await Order.findById(id);
if (!order) return null;                          // "not found"
if (order.customerId !== context.user.id)
  throw new ForbiddenError('Access denied');      // "exists but not yours"
// Attacker: null = fake ID, ForbiddenError = real ID → enumeration oracle

// ✅ SECURE — null for both cases, no existence signal
const order = await Order.findOne({
  id: args.id,
  customerId: context.user.id
});
return order || null; // null for both not-found and not-yours
```

---

## Quick Reference — Testing Checklist

```
SCHEMA ANALYSIS
  □ Sent introspection query — schema exposed in production?
  □ Identified sensitive fields on shared types (passwordHash, tokens, SSN)
  □ Found all mutations — especially admin/privileged ones
  □ Found all query aliases — does allX return all objects?

BOLA TESTING
  □ Two accounts created
  □ Every query tested with other user's object IDs
  □ Every nested field resolver tested independently
  □ allX queries tested for cross-user data return
  □ Alias batching tested for ownership bypass

BFLA TESTING
  □ Every mutation called with regular user token
  □ Role values tested for mass assignment (updateUserRole)
  □ Admin mutations tested without admin token

ALIAS / RATE LIMIT TESTING
  □ Sent 10+ aliases for same field — were they all resolved?
  □ Error responses tested: ForbiddenError vs null (enumeration oracle?)
  □ Query depth tested — deep nesting accepted?
  □ Query complexity tested — expensive queries accepted?

SCHEMA HARDENING
  □ PublicUser type exists for cross-user queries
  □ Sensitive fields not on shared types
  □ Credentials served via dedicated authorized queries only
  □ Introspection disabled in production
```

---

## Key Vocabulary Added in Module 07

| Term | Definition |
|------|------------|
| **Resolver** | Function that handles fetching data for a specific GraphQL field — each is an independent auth point |
| **Context object** | Request-scoped object passed to every resolver — equivalent to `req.user` in REST |
| **Introspection** | Built-in GraphQL feature returning the full schema — a recon vector when enabled in production |
| **Alias batching** | Using GraphQL aliases to query the same field multiple times in one request — bypasses per-request rate limits |
| **Nested resolver escape** | Child field resolver accessing data without inheriting or re-checking the parent's authorization |
| **Field-level authorization** | Per-field access control — restricting which fields a caller can read on an object they own |
| **Schema-level vulnerability** | Sensitive fields exposed in the type schema itself, before any resolver logic runs |
| **PublicUser / type projection** | Separate type containing only fields safe for public consumption — fixes nested resolver leakage |
| **Enumeration oracle** | Different error responses for "not found" vs "not yours" that allow attackers to discover valid object IDs |

---

## Coming Up — Module 08: Multi-Tenant Application Access Control

We move from single-application authorization to tenant isolation failures:
- Tenant context injection and cross-tenant data access
- Shared infrastructure where tenant boundaries are software-only
- SaaS platform IDOR across organizational boundaries
- subdomain-based vs header-based tenant resolution
- Privilege escalation within a tenant vs across tenants

---

*Module 07 — IDOR Mastery Curriculum*
*Focus: GraphQL resolver chain authorization, introspection leakage, alias batching, schema-level vulnerabilities*