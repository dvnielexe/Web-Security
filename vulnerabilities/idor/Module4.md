# IDOR Mastery — Module 04 Cheatsheet
## Vertical Privilege Escalation

> **Core principle:** Vertical privilege escalation occurs when a user accesses functionality
> or data that requires a **higher privilege level than they possess**.
> The failure is at the function level — the role or permission check — not the ownership check.

---

## Horizontal vs Vertical — The Critical Distinction

```
HORIZONTAL (Module 03)               VERTICAL (this module)
─────────────────────────────────    ─────────────────────────────────
Same role, different user's data     Different role, elevated functions
Ownership check fails                Role/permission check fails
Object-level authorization           Function-level authorization
"I accessed data I don't own"        "I accessed functions I can't use"
Fix: obj.ownerId !== req.user.id     Fix: req.user.role !== 'admin'
```

**Combined chain (real critical reports):**
```
Step 1: Vertical escalation   → elevate role (mass assignment, JWT tampering)
Step 2: Horizontal escalation → access all objects at the new role level
Result: Regular user reads every user's private data in the system
```
When you find vertical escalation, immediately ask:
*"What does this new role unlock, and is that data properly scoped?"*

---

## The Three Core Failure Modes

### Failure Mode 1 — Missing Function-Level Role Check

**How it happens:** Endpoint authenticates the caller but never checks their role.
Any logged-in user can invoke admin functionality.

**Broken assumption:** *"Only admins would know about or call this endpoint."*
Path prefix `/admin/` enforces nothing — it is cosmetic, not a security control.

```javascript
// VULNERABLE — login confirmed, role never checked
app.delete('/api/admin/users/:id', requireLogin, async (req, res) => {
  // ❌ Any authenticated user deletes any account
  await User.delete(req.params.id);
  res.sendStatus(200);
});

// SECURE — role check is a separate, explicit gate
app.delete('/api/admin/users/:id', requireLogin, async (req, res) => {
  if (req.user.role !== 'admin') return res.sendStatus(403); // ✅
  await User.delete(req.params.id);
  res.sendStatus(200);
});

// BETTER — reusable role middleware (centralized, can't be forgotten)
function requireRole(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) return res.sendStatus(403);
    next();
  };
}

app.delete('/api/admin/users/:id',
  requireLogin,
  requireRole('admin'),        // ✅ explicit, reusable
  deleteUserHandler
);
```

**Attacker request:**
```
DELETE /api/admin/users/1001
Authorization: Bearer <regular_user_token>
→ 200 OK — victim account deleted
```

---

### Failure Mode 2 — UI-Only Role Enforcement

**How it happens:** Admin controls are hidden in the frontend for regular users.
The backend API route has no role check — it only validates the session.

**Broken assumption:** *"Regular users can't see the button so they can't make the request."*

```javascript
// Frontend (React) — cosmetic, not a security control
{ user.role === 'admin' && <button onClick={promoteUser}>Promote</button> }

// VULNERABLE backend — trusts frontend gatekeeping
app.post('/api/users/:id/promote', requireLogin, async (req, res) => {
  // ❌ Button was hidden — backend assumed that was sufficient
  await User.setRole(req.params.id, 'admin');
  res.sendStatus(200);
});

// SECURE backend — enforces independently of UI state
app.post('/api/users/:id/promote', requireLogin, async (req, res) => {
  if (req.user.role !== 'admin') return res.sendStatus(403); // ✅
  await User.setRole(req.params.id, 'admin');
  res.sendStatus(200);
});
```

**Attacker bypasses UI entirely:**
```
POST /api/users/self/promote
Authorization: Bearer <regular_user_token>
→ 200 OK — attacker is now admin
```

**Rule:** The API is the security boundary. The UI is cosmetic.
Hiding a button provides zero protection against direct API calls.

---

### Failure Mode 3 — Client-Supplied Role Trusted

**How it happens:** The server reads the user's role from a client-controlled source —
request body, query string, cookie, or custom header — instead of from the
server-validated session or JWT claims.

**Broken assumption:** *"The role field in the request came from our own system."*

```javascript
// VULNERABLE — role from request body
app.post('/api/settings', requireLogin, async (req, res) => {
  const { settings, role } = req.body; // ❌ attacker sends role: "admin"
  if (role === 'admin') {
    await Settings.saveAdminConfig(settings);
  }
  res.sendStatus(200);
});

// VULNERABLE — role from unsigned cookie
const role = req.cookies.role; // ❌ easily modified in DevTools
if (role === 'admin') { ... }

// SECURE — role always from verified server-side session
app.post('/api/settings', requireLogin, async (req, res) => {
  const role = req.user.role; // ✅ from verified JWT/session, never body
  if (role === 'admin') {
    await Settings.saveAdminConfig(req.body.settings);
  }
  res.sendStatus(200);
});
```

**Trusted vs untrusted role sources:**
```
✅ req.user.role           — set by auth middleware from verified JWT/session
❌ req.body.role           — attacker-controlled
❌ req.query.role          — attacker-controlled
❌ req.params.role         — attacker-controlled
❌ req.cookies.role        — attacker-controlled (unless signed + verified)
❌ req.headers['x-role']   — attacker-controlled
```

---

## Mass Assignment — The Invisible Vertical Escalation

**What it is:** The application automatically binds all request body parameters to
model properties without filtering. The developer intends to update name/email.
The attacker includes `"role": "admin"` — the framework sets it.

**Why it's dangerous:** No special endpoint knowledge required. The exploit
happens through a normal, innocent-looking update request.

### Attack payload — looks like a profile update
```http
PATCH /api/users/profile
Authorization: Bearer <regular_user_token>
Content-Type: application/json

{
  "name": "Beejay",
  "email": "beejay@example.com",
  "role": "admin",
  "is_verified": true,
  "is_admin": true,
  "credit_balance": 99999,
  "subscription_tier": "enterprise",
  "permissions": ["admin", "billing:write", "users:delete"]
}
```

### Node.js / Express — No built-in protection

```javascript
// VULNERABLE — entire body bound to model
app.patch('/api/users/profile', requireLogin, async (req, res) => {
  await User.findByIdAndUpdate(req.user.id, req.body); // ❌ every field set
  res.sendStatus(200);
});

// SECURE — Option 1: explicit field destructuring
app.patch('/api/users/profile', requireLogin, async (req, res) => {
  const { name, email } = req.body; // ✅ only permitted fields extracted
  await User.findByIdAndUpdate(req.user.id, { name, email });
  res.sendStatus(200);
});

// SECURE — Option 2: lodash pick allowlist
const allowed = _.pick(req.body, ['name', 'email']);
await User.findByIdAndUpdate(req.user.id, allowed);

// SECURE — Option 3: schema validation (zod)
const schema = z.object({
  name: z.string(),
  email: z.string().email()
  // role not listed → stripped at validation layer
});
const data = schema.parse(req.body); // throws if unexpected fields
await User.findByIdAndUpdate(req.user.id, data);
```

### Django (Python) — Strong built-in protection

```python
# ModelForm — only listed fields accepted
class ProfileForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ['name', 'email']  # ✅ role excluded = cannot be set

# DRF Serializer — same principle
class ProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['name', 'email']  # role not listed → cannot be updated
```

### Ruby on Rails — Strong Params required

```ruby
# VULNERABLE — no filtering
@user.update(params[:user])

# SECURE — strong params allowlist
@user.update(user_params)

def user_params
  params.require(:user).permit(:name, :email)
  # role is not permitted → silently dropped
end
```

### Fields to always test in mass assignment attacks
```
role, is_admin, is_superuser, admin, is_verified, verified,
subscription_tier, plan, permissions, credits, credit_balance,
balance, discount, is_staff, is_moderator, account_type,
email_verified, phone_verified, kyc_status, trust_level
```

---

## The `alg: none` JWT Attack

### What it is
JWT signature verification is skipped when the library reads `"alg": "none"`
from the token header and honors it — allowing the attacker to forge any payload.

### Anatomy

```
Normal JWT:
  Header:    { "alg": "HS256", "typ": "JWT" }
  Payload:   { "user_id": 42, "role": "user" }
  Signature: HMACSHA256(header + payload, secret)

Attacker's JWT:
  Header:    { "alg": "none", "typ": "JWT" }   ← modified
  Payload:   { "user_id": 42, "role": "admin" } ← modified
  Signature: [empty]                             ← no secret needed
```

### Vulnerable vs secure implementation

```javascript
// VULNERABLE — decode without verify (no signature check)
const payload = jwt.decode(token);  // ❌ anyone can decode — no verification
if (payload.role === 'admin') { ... }

// VULNERABLE — alg: none accepted
jwt.verify(token, secret, {});      // ❌ algorithms not restricted

// SECURE — verify with explicit algorithm whitelist
jwt.verify(token, process.env.JWT_SECRET, {
  algorithms: ['HS256']  // ✅ rejects alg: none, RS256, and any other
});

// SECURE — always use verify(), never decode() for authorization decisions
```

### The two things the server must do
1. **Validate the cryptographic signature** — confirms the token wasn't tampered with
2. **Enforce the algorithm** — server decides the algorithm, ignores what the token claims

---

## Financial Endpoint Authorization — Special Rules

Every financial or billing endpoint requires additional scrutiny beyond role checks:

```javascript
// VULNERABLE — discount code trusted from client
router.post('/billing/upgrade', async (req, res) => {
  const { plan, discount_code } = req.body;
  // ❌ Is this user allowed to use this discount_code?
  // Staff-only codes? Expired codes? Single-use codes?
  await Billing.upgrade(req.user.id, plan, discount_code);
});

// SECURE — validate discount against user's entitlement server-side
router.post('/billing/upgrade', requireLogin, async (req, res) => {
  const { plan, discount_code } = req.body;
  if (discount_code) {
    const discount = await Discount.findByCode(discount_code);
    // ✅ Validate the discount exists, is active, and user is eligible
    if (!discount || !discount.isEligible(req.user)) {
      return res.status(403).json({ error: 'Invalid or unauthorized discount' });
    }
  }
  await Billing.upgrade(req.user.id, plan, discount_code);
  res.sendStatus(200);
});
```

**Fields to always audit in financial endpoints:**
```
discount_code, coupon, promo_code, override_price, amount,
credit_adjustment, refund_amount, fee_waiver, plan, tier
```

---

## API Key Generation — Permission Scope Validation

```javascript
// VULNERABLE — two separate flaws
router.post('/api-keys/generate', requireLogin, async (req, res) => {
  const { user_id, permissions } = req.body;
  // ❌ Flaw 1: user_id from body — can generate keys for other users
  // ❌ Flaw 2: permissions from body — can request admin-level permissions
  const key = await ApiKey.create(user_id, permissions);
  res.json({ key });
});

// SECURE — both flaws fixed
router.post('/api-keys/generate', requireLogin, async (req, res) => {
  const { permissions } = req.body;

  // ✅ Fix 1: user_id always from session
  const userId = req.user.id;

  // ✅ Fix 2: permissions validated against caller's own scope
  const userPermissions = await Permission.getForUser(userId);
  const invalidPerms = permissions.filter(p => !userPermissions.includes(p));
  if (invalidPerms.length > 0) {
    return res.status(403).json({
      error: `Cannot grant permissions beyond your own scope: ${invalidPerms}`
    });
  }

  const key = await ApiKey.create(userId, permissions);
  res.json({ key });
});
```

**Rule:** A user can never grant an API key more permissions than they themselves possess.
This principle is called **permission inheritance** — delegation cannot exceed delegation source.

---

## Full Code Audit — SaaS Billing Platform

### Vulnerable version (all flaws annotated)

```javascript
const router = express.Router();
router.use(requireLogin);

// ❌ FLAW 1 — Financial parameter trust (discount_code unvalidated)
router.post('/billing/upgrade', async (req, res) => {
  const { plan, discount_code } = req.body;
  await Billing.upgrade(req.user.id, plan, discount_code);
  res.sendStatus(200);
});

// ❌ FLAW 2 — Mass assignment (req.body passed directly)
router.patch('/users/me', async (req, res) => {
  await User.findByIdAndUpdate(req.user.id, req.body);
  res.sendStatus(200);
});

// ❌ FLAW 3 — Missing role check on admin endpoint
router.get('/admin/transactions', async (req, res) => {
  const txns = await Transaction.findAll();
  res.json(txns);
});

// ❌ FLAW 4 — Missing role check on admin refund action
router.post('/admin/refund', async (req, res) => {
  const { transaction_id, amount } = req.body;
  await Payment.refund(transaction_id, amount);
  res.sendStatus(200);
});

// ❌ FLAW 5 — Client-supplied user_id + unconstrained permissions
router.post('/api-keys/generate', async (req, res) => {
  const { user_id, permissions } = req.body;
  const key = await ApiKey.create(user_id, permissions);
  res.json({ key });
});
```

### Broken assumptions per vulnerability

| Route | Failure Mode | Broken Assumption |
|-------|-------------|-------------------|
| `POST /billing/upgrade` | Parameter trust | "Discount codes are validated by the client" |
| `PATCH /users/me` | Mass assignment | "Users only send the fields the form shows" |
| `GET /admin/transactions` | Missing role check | "Only admins know this route exists" |
| `POST /admin/refund` | Missing role check | "Only admins would trigger a refund" |
| `POST /api-keys/generate` | Client identity + permission scope | "Users only request their own keys with their own permissions" |

### Secure version

```javascript
const router = express.Router();
router.use(requireLogin);

// Role middleware — reusable across all admin routes
function requireRole(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) return res.sendStatus(403);
    next();
  };
}

// ✅ FIXED 1 — Validate discount server-side
router.post('/billing/upgrade', async (req, res) => {
  const { plan, discount_code } = req.body;
  if (discount_code) {
    const discount = await Discount.findByCode(discount_code);
    if (!discount || !discount.isEligible(req.user)) {
      return res.status(403).json({ error: 'Invalid or unauthorized discount' });
    }
  }
  await Billing.upgrade(req.user.id, plan, discount_code);
  res.sendStatus(200);
});

// ✅ FIXED 2 — Explicit field allowlist
router.patch('/users/me', async (req, res) => {
  const { name, email } = req.body; // only permitted fields
  await User.findByIdAndUpdate(req.user.id, { name, email });
  res.sendStatus(200);
});

// ✅ FIXED 3 — Role check on admin transaction list
router.get('/admin/transactions',
  requireRole('admin'),
  async (req, res) => {
    const txns = await Transaction.findAll();
    res.json(txns);
  }
);

// ✅ FIXED 4 — Role check on admin refund
router.post('/admin/refund',
  requireRole('admin'),
  async (req, res) => {
    const { transaction_id, amount } = req.body;
    await Payment.refund(transaction_id, amount);
    res.sendStatus(200);
  }
);

// ✅ FIXED 5 — Session identity + permission scope validation
router.post('/api-keys/generate', async (req, res) => {
  const { permissions } = req.body;
  const userId = req.user.id; // from session, never body

  const userPermissions = await Permission.getForUser(userId);
  const invalid = permissions.filter(p => !userPermissions.includes(p));
  if (invalid.length > 0) {
    return res.status(403).json({
      error: `Cannot grant permissions beyond your scope: ${invalid}`
    });
  }

  const key = await ApiKey.create(userId, permissions);
  res.json({ key });
});
```

---

## Detection Methodology — Finding Vertical Escalation

### Step 1 — Map all privilege tiers
```
Walk the app as a regular user. Document what you CANNOT do:
  - Pages that redirect away
  - Buttons that are disabled or hidden
  - API calls that return 403
  - Features behind upgrade prompts

These are your targets — the boundary between your tier and above.
```

### Step 2 — Discover hidden administrative routes
```
Sources to check:
  JavaScript bundles    → search for /admin /internal /manage /staff /superuser
  Mobile app APK        → decompile, search API strings
  API documentation     → Swagger/OpenAPI often exposes all routes
  robots.txt            → sometimes lists admin paths to "disallow"
  Web archive           → old versions of JS may expose deprecated routes
  Error messages        → stack traces leak internal route structure

Tools: LinkFinder, JSParser, ffuf (directory fuzzing)
```

### Step 3 — Replay elevated-function requests with lower-privilege token
```
1. Create an admin account (or find documented admin endpoints)
2. Capture the admin API request
3. Replace the admin token with your regular-user token
4. If response is 200 → vertical IDOR confirmed

Example:
  Admin makes:  GET /api/admin/users   → 200
  You replay:   GET /api/admin/users   Authorization: Bearer <your_token>
                                       → should 403, but returns 200?  → IDOR
```

### Step 4 — Test mass assignment on every update endpoint
```
For every PUT, PATCH, POST that updates a model, add to the body:

{
  "role": "admin",
  "is_admin": true,
  "is_verified": true,
  "subscription_tier": "enterprise",
  "permissions": ["admin", "billing:write"],
  "credit_balance": 99999,
  "discount": 100
}

Then check:
  - Did your role change? (GET /api/users/me)
  - Did your plan change?
  - Did your balance change?
  - Did your permissions change?
```

### Step 5 — Inspect JWT for tampering opportunities
```
1. Copy your JWT from Authorization header
2. Decode payload: base64 decode the middle segment
3. Look for: role, is_admin, permissions, tier, plan, scope
4. Test alg: none attack:
   - Modify header to {"alg":"none"}
   - Modify payload to {"role":"admin"}
   - Encode both, append empty signature
   - Submit: header.payload.
5. If accepted → server not enforcing algorithm or verifying signature

Tools: jwt.io (manual), jwt_tool (automated attacks)
```

---

## Vertical Escalation in Combined Attack Chains

Real critical reports rarely involve one vulnerability type alone.

### Chain Pattern 1: Mass Assignment → Horizontal IDOR
```
1. PATCH /api/users/me { "role": "moderator" }  → role elevated
2. GET /api/moderation/reports/:id              → reads all user reports
   (check only existed for "user" role, not "moderator")
```

### Chain Pattern 2: Vertical → Full Data Dump
```
1. Exploit missing role check on admin endpoint
2. GET /api/admin/users → all user records, emails, phone numbers
3. Enumerate all IDs found → access all individual records
```

### Chain Pattern 3: JWT Tampering → Admin Panel Access
```
1. Decode JWT: {"role": "free"}
2. Modify: {"role": "admin"}, alg: none
3. Access /api/admin/* → full administrative control
```

---

## Quick Reference — Vertical Escalation Testing Checklist

```
FUNCTION DISCOVERY
  □ Mapped all privilege tiers and boundaries
  □ Searched JS bundles for /admin /internal /staff /manage
  □ Checked robots.txt, API docs, Swagger UI
  □ Noted all 403 responses (active restrictions = active targets)

ROLE CHECK TESTING
  □ Called every admin endpoint with regular-user token
  □ Called every moderator endpoint with regular-user token
  □ Tested all HTTP methods on admin routes (GET, POST, PUT, DELETE)

MASS ASSIGNMENT TESTING
  □ Added role/is_admin fields to every profile update endpoint
  □ Added permission/tier fields to every update endpoint
  □ Checked account state after each attempt (GET /api/users/me)
  □ Tested registration endpoint for privilege fields

JWT TESTING
  □ Decoded JWT payload — identified all role/permission claims
  □ Tested alg: none attack
  □ Tested algorithm confusion (RS256 → HS256 with public key as secret)
  □ Checked if role is read from body/cookie instead of JWT claims

FINANCIAL ENDPOINTS
  □ Tested all discount/coupon/promo fields with unauthorized codes
  □ Tested negative amounts on all financial operations
  □ Checked API key generation for permission scope enforcement

API KEYS
  □ Tested user_id field — can you generate keys for other users?
  □ Tested permissions field — can you request admin permissions?
```

---

## Key Vocabulary Added in Module 04

| Term | Definition |
|------|------------|
| **Vertical privilege escalation** | Accessing functions or data requiring a higher role than possessed |
| **Function-level authorization (FLAB)** | The check that a caller's role permits a specific function — distinct from ownership |
| **Mass assignment** | Framework auto-binding of request body to model fields without allowlist filtering |
| **Client-supplied role** | Reading role/permission from attacker-controlled input instead of server-validated session |
| **`alg: none` attack** | JWT attack where attacker removes signature requirement by claiming no algorithm |
| **Permission inheritance** | Principle that delegated permissions cannot exceed the delegator's own permissions |
| **UI-only enforcement** | Access control implemented only in the frontend — bypassed by direct API calls |
| **Privilege chain** | Combining vertical escalation (role elevation) with horizontal escalation (cross-user access) |
| **Algorithm confusion** | JWT attack exploiting libraries that accept multiple signing algorithms |

---

## Coming Up — Module 05: REST API Authorization Flaws (BOLA & BFLA)

We move from application-level to API-design-level failures.
- Broken Object Level Authorization (BOLA) — OWASP API #1
- Broken Function Level Authorization (BFLA) — OWASP API #5
- Real REST API patterns and where authorization consistently breaks
- JWT misuse patterns in API authentication
- Route-level vs middleware-level enforcement gaps
- API versioning and authorization inheritance

---

*Module 04 — IDOR Mastery Curriculum*
*Focus: Vertical escalation, mass assignment, JWT attacks, function-level authorization*