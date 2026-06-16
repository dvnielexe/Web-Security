# IDOR Mastery — Module 09 Cheatsheet
## Business Logic Abuse & Chained IDOR

> **Core principle:** Real high-severity findings are chains, not isolated endpoints.
> A low-severity information disclosure that leaks an ID, combined with a medium-severity
> BOLA, combined with a missing state check, becomes a Critical account takeover.
> Think in chains. Ask "what does this unlock?" before filing any report.

---

## What Business Logic Abuse Means

Business logic is the set of rules governing how an application *should* work.
Business logic abuse exploits assumptions about *how users behave*, not just *who they are*.

```
Previous modules:  "Only authorized users access this object."
                   → Fixed by ownership/role checks

This module:       "Users will follow the intended workflow in the intended order."
                   → Almost never enforced in code — only enforced in the UI
```

**The broken assumption factory:**
```
Developer builds:  UI flow A → B → C → D
Developer tests:   happy path only
Developer assumes: users will always follow A → B → C → D

Attacker does:     calls D directly, skipping A, B, and C entirely
```

---

## The Authorization State Machine

Every protected operation has implicit preconditions — states that must be true before
the operation is allowed. Most applications only enforce ownership, not state or sequence.

```
Intended flow:
  [Authenticated] → [Order placed] → [Shipped] → [Delivered] → [Refund issued]
      ↑ precondition: each state must exist before the next is allowed

What usually gets enforced:
  ✅ ownership check     (order.userId === req.user.id)
  ❌ state check         (order.status === 'delivered')   ← usually missing
  ❌ sequence check      (all prior states completed)     ← almost never present

What attackers do:
  [Authenticated] ──────────────────────────────→ [Refund issued]
                  skips all intermediate states
```

**The three enforcements every state-changing operation needs:**

```javascript
// 1. Ownership — does this object belong to this user?
if (order.userId !== req.user.id) return res.sendStatus(403);

// 2. State — is the object in the required state for this operation?
if (!['delivered', 'partially_delivered'].includes(order.status))
  return res.status(409).json({ error: 'Order not eligible for refund' });

// 3. Sequence — have all prior required steps completed?
if (!order.payment_confirmed || !order.fulfillment_id)
  return res.status(409).json({ error: 'Required prior steps incomplete' });
```

---

## The Five Business Logic + Chaining Patterns

### Pattern 1 — Workflow Bypass (State Preconditions Not Enforced)

**Mechanism:** Attacker calls the final step directly without completing prior steps.
UI enforces the sequence. Server does not.

**Broken assumption:** *"Users always reach this endpoint through the intended flow."*

```javascript
// VULNERABLE — ownership checked, state not checked
app.post('/api/orders/:id/refund', requireLogin, async (req, res) => {
  const order = await Order.findById(req.params.id);
  if (order.userId !== req.user.id) return res.sendStatus(403); // ✓ ownership
  // ❌ No state check — refund issued even if order never shipped
  await Refund.issue(order.id);
  res.sendStatus(200);
});

// SECURE — ownership + state both enforced
app.post('/api/orders/:id/refund', requireLogin, async (req, res) => {
  const order = await Order.findById(req.params.id);
  if (!order || order.userId !== req.user.id) return res.sendStatus(404);
  // ✅ State precondition enforced server-side
  const refundableStates = ['delivered', 'partially_delivered'];
  if (!refundableStates.includes(order.status))
    return res.status(409).json({ error: 'Order not eligible for refund' });
  await Refund.issue(order.id);
  res.sendStatus(200);
});
```

**Common workflow bypass targets:**
```
POST /orders/:id/refund         → requires: delivered
POST /orders/:id/cancel         → requires: pending (not shipped)
POST /invoices/:id/paid         → requires: sent
POST /documents/:id/publish     → requires: reviewed + approved
POST /subscriptions/:id/renew   → requires: active, not cancelled
POST /accounts/:id/close        → requires: zero balance
```

---

### Pattern 2 — Indirect IDOR (Reaching Protected Data Through a Related Endpoint)

**Mechanism:** Object A is accessible. Object B is protected. A relationship between
them allows B's data to leak via A's response — without ever directly requesting B.

**Broken assumption:** *"We protect the sensitive endpoint — the related endpoint is fine."*

```javascript
// Direct access — correctly blocked
GET /api/salary-records/SR-991  → 403

// Indirect access via related endpoint — no check
GET /api/expense-reports/ER-4421
// Response:
{
  "id": "ER-4421",
  "salary_record": {
    "id": "SR-991",
    "annual_salary": 95000,    // ← leaked via indirect reference
    "bonus_target": 15000,     // ← leaked
    "grade_level": "L6"        // ← leaked
  }
}

// SECURE — nested objects return only permitted projection
const report = await ExpenseReport.findById(id);
return {
  ...report,
  salary_record: { id: report.salary_record.id }
  // sensitive fields stripped — only reference returned
};
```

**Where to look for indirect IDOR:**
```
Notification objects    → may contain the triggering object's data
Audit logs              → contain actions, tokens, emails of other users
Comment/feed endpoints  → may expose parent object metadata
Export endpoints        → often include related object data without auth
Webhook payloads        → may expose cross-user event data
Search results          → may return fields that direct fetch would block
```

---

### Pattern 3 — Horizontal → Vertical Chain (Low + Medium → Critical)

**Mechanism:** A low-severity information disclosure leaks an identifier that enables
a BOLA that enables a privilege escalation. Three individually unremarkable findings
chain into a Critical.

**The canonical chain:**

```
Step 1 [Low — Info disclosure]:
  GET /api/profile
  Response includes: { ..., "admin_invite_token": "tok_abc123" }
  Severity alone: Low (information exposure, no direct harm)
        ↓
Step 2 [Medium — BOLA]:
  GET /api/invites/tok_abc123
  Response: { "role": "admin", "team_id": "TEAM-001" }
  Severity alone: Medium (unauthorized data access)
        ↓
Step 3 [Critical — BFLA]:
  POST /api/invites/tok_abc123/accept
  Result: attacker now has admin role in TEAM-001
  Severity alone: High (privilege escalation)
        ↓
Combined chain severity: CRITICAL
Business impact: Full administrative access via three steps,
                 each of which seemed innocuous in isolation
```

**Reporting structure for chains:**
```
Finding 1: [Low]    Information disclosure in GET /api/profile
Finding 2: [Medium] BOLA on GET /api/invites/:token
Finding 3: [High]   BFLA on POST /api/invites/:token/accept
Finding 4: [Critical] Attack chain: Finding 1 + 2 + 3 = admin account takeover

File all four. The chain is a separate submission referencing the others.
```

---

### Pattern 4 — Race Condition (TOCTOU — Time of Check to Time of Use)

**Mechanism:** The authorization check passes at T1. Between T1 and T2, concurrent
requests exploit the gap. The action executes multiple times under one authorization decision.

**Broken assumption:** *"We check the state before acting — that's sufficient."*

```javascript
// VULNERABLE — check and act are separate (non-atomic)
app.post('/api/orders/:id/cancel', requireLogin, async (req, res) => {
  const order = await Order.findById(req.params.id);
  if (order.userId !== req.user.id) return res.sendStatus(403);
  if (order.status !== 'pending') return res.status(409); // ← T1: check
  // ← 50 concurrent requests all pass the check above simultaneously
  await Bank.credit(req.user.id, order.amount);           // ← T2: act (50 times)
  await order.update({ status: 'cancelled' });
  res.sendStatus(200);
});

// SECURE — atomic check-and-update in one DB operation (TOCTOU fix)
app.post('/api/orders/:id/cancel', requireLogin, async (req, res) => {
  // UPDATE orders SET status='cancelled'
  // WHERE id=? AND userId=? AND status='pending'
  // Returns affected rows — 0 if already processed
  const updated = await Order.atomicCancel({
    id: req.params.id,
    userId: req.user.id,
    requiredStatus: 'pending'
  });
  // ✅ Only one concurrent request can win — all others get 0 rows
  if (!updated) return res.status(409).json({ error: 'Already processed' });
  await Bank.credit(req.user.id, updated.amount);
  res.sendStatus(200);
});
```

**TOCTOU testing technique:**
```bash
# Send N concurrent requests to the same state-changing endpoint
# Use Burp Suite Turbo Intruder or:
for i in {1..20}; do
  curl -s -X POST https://target.com/api/orders/7201/cancel \
    -H "Authorization: Bearer $TOKEN" &
done
wait

# Check: was the action performed more than once?
# Check: was the balance credited multiple times?
```

**Where TOCTOU is most impactful:**
```
Financial: cancel/refund endpoints that credit accounts
Voucher/coupon: single-use codes that can be redeemed multiple times
Inventory: purchase endpoints that can oversell
Rate limits: free-tier limits bypassed via concurrent requests
Email verification: tokens that should be single-use
```

---

### Pattern 5 — Cross-Module IDOR (Authorization Enforced in One Module, Not Another)

**Mechanism:** Two features of the application share object IDs. Authorization is
correctly enforced in Module A. Module B references the same objects without its own check.

**Broken assumption:** *"The document viewer protects documents — the comment system can trust that."*

```javascript
// Module A: document viewer — correctly protected
GET /api/documents/DOC-881  → 403 (ownership checked)

// Module B: comment system — shares document IDs, no auth of its own
GET /api/comments?document_id=DOC-881
// Response exposes:
{
  "document": {
    "id": "DOC-881",
    "title": "Q3 Confidential Financials",  // ← leaked
    "owner_email": "cfo@company.com"        // ← leaked
  },
  "comments": []
}

// SECURE — each module enforces authorization independently
const comments = async (req, res) => {
  // Comments module verifies document access independently
  const doc = await Document.findOne({
    id: req.query.document_id,
    ownerId: req.user.id              // ✅ own check, not inherited
  });
  if (!doc) return res.sendStatus(404);
  const comments = await Comment.findByDocument(doc.id);
  res.json(comments);
};
```

**Rule:** Every module that references a protected object must enforce authorization
independently. Authorization is never inherited between modules.

---

## The Chain-Finding Methodology

```
Step 1 — Find any information disclosure
         Look for: leaked IDs, tokens, emails, references in API responses
               ↓
Step 2 — Ask: what endpoints accept this leaked value as input?
         Search all routes for parameters matching the leaked value type
               ↓
Step 3 — Test those endpoints without owning the referenced object
         Does the leaked ID bypass any access control?
               ↓
Step 4 — Ask: what does this unauthorized access enable?
         Can you modify state? Trigger actions? Escalate privilege?
               ↓
Step 5 — Ask: what does that state change or privilege unlock?
         Can you access more objects? Affect other users? Cross tenant boundaries?
               ↓
Report: each finding individually + the chain as a separate higher-severity finding
```

---

## Full Chain Analysis — SaaS Invoicing Platform

### Individual vulnerabilities

```javascript
// VULN 1 — GET /users/me returns sensitive fields
// api_key and invited_by_token should never be in a profile response
{ id, email, role, api_key, team_id, invited_by_token }  // ❌

// VULN 2 — POST /invites/:token/accept — no token ownership validation
// Any user can accept any invite, not just the intended recipient

// VULN 3 — POST /invoices/:id/send — no ownership check
const invoice = await Invoice.findById(req.params.id);  // ❌ no userId check
await Email.send(invoice.recipient_email, invoice);

// VULN 4 — POST /invoices/:id/paid — state check present, but reachable via VULN 3
// Attacker sends invoice first (VULN 3), then marks as paid

// VULN 5 — DELETE /invoices/:id — no ownership check at all
const invoice = await Invoice.findById(req.params.id);  // ❌
await invoice.delete();
```

### Chain 1 — Invite Token Disclosure → Unauthorized Team Access (Critical)

```
Step 1 [Low — Info disclosure]:
  GET /api/users/me
  Response leaks: { "invited_by_token": "inv_tok_abc123" }
  Severity alone: Low

Step 2 [Critical — Cross-tenant privilege escalation]:
  POST /api/invites/inv_tok_abc123/accept
  Result: attacker joins another organization's team
  Severity alone: High

Combined severity: CRITICAL
Business impact:  Full unauthorized access to victim organization's
                  invoices, client data, financial records, and team operations
                  (cross-tenant BOLA via stolen invite token)
```

### Chain 2 — Send IDOR → Workflow Bypass → False Payment Confirmation

```
Step 1 [Medium — Action IDOR]:
  POST /api/invoices/INV-8821/send   (no ownership check)
  Result: triggers email to victim's client saying invoice is due
  Severity alone: Medium

Step 2 [Medium — Workflow bypass + BOLA]:
  POST /api/invoices/INV-8821/paid   (status is now 'sent' from Step 1)
  Result: marks another user's invoice as paid without actual payment
  Severity alone: Medium

Combined severity: HIGH
Business impact:  Attacker marks victim's invoices as paid,
                  disrupting payment tracking and potentially hiding
                  fraud from the victim's accounting records
```

### Chain 3 — Invoice ID Enumeration → Mass Deletion (Critical)

```
Step 1 [Medium — BOLA]:
  GET /api/invoices/:id  (correctly protected — returns 404 for others)
  But: DELETE /api/invoices/:id has no ownership check
  Finding: attacker can delete any invoice by ID
  Severity alone: High

Step 2 [Amplifier — Enumeration]:
  Invoice IDs are sequential (INV-001, INV-002...)
  Combined: attacker scripts deletion of all invoices on the platform
  Severity: CRITICAL

Combined severity: CRITICAL
Business impact:  Complete destruction of all invoice records across
                  all users on the platform — irreversible data loss
                  if no backups exist
```

### Chain 4 — Full Attack Scenario (All Chains Combined)

```
1. GET /users/me → extract invited_by_token         [Low]
2. POST /invites/{token}/accept → join victim's team [Critical]
3. As team member: access all team invoices          [High]
4. POST /invoices/{id}/send → trigger emails         [Medium]
5. POST /invoices/{id}/paid → falsify payment status [Medium]
6. DELETE /invoices/{id} → destroy financial records [Critical]

Final combined severity: CRITICAL
Report as: "Multi-step attack chain: information disclosure to
            complete organizational data destruction and fraud enablement"
```

---

## Secure Fixes — Full Rewrite

```javascript
const router = express.Router();
router.use(requireLogin);

// FIXED — profile: exclude sensitive fields
router.get('/users/me', async (req, res) => {
  const user = await User.findById(req.user.id);
  // ✅ Allowlist returned fields — never expose api_key or invite tokens
  const { id, email, role, team_id } = user;
  res.json({ id, email, role, team_id });
});

// FIXED — invoice read: ownership already correct
router.get('/invoices/:id', requireLogin, async (req, res) => {
  const invoice = await Invoice.findOne({
    id: req.params.id,
    userId: req.user.id   // ✅ ownership enforced
  });
  if (!invoice) return res.sendStatus(404);
  res.json(invoice);
});

// FIXED — accept invite: validate token was issued to this user
router.post('/invites/:token/accept', requireLogin, async (req, res) => {
  const invite = await Invite.findByToken(req.params.token);
  if (!invite) return res.sendStatus(404);
  // ✅ Verify invite was issued to this user's email
  if (invite.recipient_email !== req.user.email)
    return res.sendStatus(403);
  // ✅ Mark token as used — prevent replay
  if (invite.used_at) return res.status(409).json({ error: 'Invite already used' });
  await invite.update({ used_at: new Date() });
  await User.joinTeam(req.user.id, invite.team_id, invite.role);
  res.sendStatus(200);
});

// FIXED — send invoice: ownership check added
router.post('/invoices/:id/send', requireLogin, async (req, res) => {
  const invoice = await Invoice.findOne({
    id: req.params.id,
    userId: req.user.id   // ✅ ownership enforced
  });
  if (!invoice) return res.sendStatus(404);
  // ✅ State check: can only send a draft invoice
  if (invoice.status !== 'draft')
    return res.status(409).json({ error: 'Invoice already sent' });
  await Email.send(invoice.recipient_email, invoice);
  await invoice.update({ status: 'sent' });
  res.sendStatus(200);
});

// FIXED — mark paid: ownership + state already present (no change needed here)
// But now status:'sent' is harder to fake since SEND endpoint is protected
router.post('/invoices/:id/paid', requireLogin, async (req, res) => {
  const invoice = await Invoice.findOne({
    id: req.params.id,
    userId: req.user.id   // ✅ ownership
  });
  if (!invoice) return res.sendStatus(404);
  if (invoice.status !== 'sent')  // ✅ state check
    return res.status(409).json({ error: 'Invoice must be sent before marking paid' });
  await invoice.update({ status: 'paid' });
  res.sendStatus(200);
});

// FIXED — delete: ownership check added
router.delete('/invoices/:id', requireLogin, async (req, res) => {
  const invoice = await Invoice.findOne({
    id: req.params.id,
    userId: req.user.id   // ✅ ownership enforced
  });
  if (!invoice) return res.sendStatus(404);
  // ✅ State check: cannot delete a paid invoice (financial record)
  if (invoice.status === 'paid')
    return res.status(409).json({ error: 'Cannot delete a paid invoice' });
  await invoice.delete();
  res.sendStatus(200);
});
```

---

## Bug Bounty Chain Report Template

```
Title: [Attack chain] Information disclosure → unauthorized team access →
       complete invoice record destruction

Severity: Critical

Individual findings:
  Finding A [Low]:    GET /api/users/me exposes invite token in response
  Finding B [High]:   POST /api/invites/:token/accept — no recipient validation
  Finding C [High]:   DELETE /api/invoices/:id — no ownership check
  Finding D [Medium]: POST /api/invoices/:id/send — no ownership check

Attack chain:
  Step 1: Attacker calls GET /api/users/me → extracts invited_by_token
  Step 2: Attacker calls POST /api/invites/{token}/accept → joins victim's team
  Step 3: Attacker enumerates invoice IDs (sequential)
  Step 4: Attacker calls DELETE /api/invoices/{id} for all discovered IDs
  Result: Complete destruction of victim organization's financial records

Business impact:
  - Unauthorized access to all invoices, clients, and financial data
  - Ability to destroy all invoice records across the platform
  - Potential financial fraud via false payment status manipulation
  - No authentication or special knowledge required beyond a valid account

Remediation:
  1. Remove api_key and invited_by_token from GET /api/users/me response
  2. Validate invite token recipient against req.user.email before accepting
  3. Add ownership check (userId === req.user.id) to DELETE /api/invoices/:id
  4. Add ownership check to POST /api/invoices/:id/send
  5. Add state preconditions to all workflow transition endpoints
```

---

## Quick Reference — Business Logic Testing Checklist

```
WORKFLOW BYPASS
  □ Identified all multi-step workflows (checkout, approval, refund, publish)
  □ Called the final step directly without completing prior steps
  □ Tested all state transition endpoints for state precondition checks
  □ Tested whether prior-state requirements are enforced server-side

INDIRECT IDOR
  □ Inspected all API responses for nested related objects
  □ Checked whether nested objects expose sensitive fields
  □ Tested comment/notification/feed endpoints for parent object leakage
  □ Checked export endpoints for cross-reference data exposure

CHAIN ANALYSIS
  □ For every info disclosure: asked "what endpoints accept this value?"
  □ For every BOLA: asked "what actions can I perform on this object?"
  □ For every action IDOR: asked "what state change does this enable?"
  □ For every state change: asked "what does this new state unlock?"
  □ Filed: individual findings + the chain as a separate higher-severity report

RACE CONDITIONS (TOCTOU)
  □ Identified state-changing endpoints with financial or count implications
  □ Sent 10-50 concurrent requests to the same endpoint
  □ Checked: was the action performed more than once?
  □ Verified atomic DB operations on all critical state transitions

CROSS-MODULE IDOR
  □ Mapped all features that reference the same object types by ID
  □ Tested each feature independently for authorization on shared objects
  □ Verified each module enforces its own authorization, not inherited

SENSITIVE FIELD EXPOSURE
  □ Audited all API responses for: tokens, api_keys, internal IDs, credentials
  □ Verified profile/user endpoints return only necessary fields (allowlist)
  □ Checked that nested object responses are projected, not returned in full
```

---

## Severity Escalation Reference

| Individual findings | Combined chain severity |
|--------------------|------------------------|
| Info disclosure (Low) + BOLA (Medium) | High |
| Info disclosure (Low) + BOLA (Medium) + BFLA (High) | Critical |
| Action IDOR (Medium) + workflow bypass (Medium) | High |
| Info disclosure (Low) + invite BOLA (High) + cross-tenant access | Critical |
| BOLA (Medium) + TOCTOU (High) on financial endpoint | Critical |
| Any chain with: account takeover, financial fraud, mass data destruction | Critical |

---

## Key Vocabulary Added in Module 09

| Term | Definition |
|------|------------|
| **Business logic abuse** | Exploiting assumptions about user behavior rather than authentication failures |
| **Workflow bypass** | Calling a late-stage operation without completing required prior steps |
| **State precondition** | Required object state that must be true before an operation is permitted |
| **Indirect IDOR** | Reaching protected data through a related, less-protected endpoint |
| **Attack chain** | Multiple individually low-severity findings that combine into a critical exploit |
| **TOCTOU** | Time of Check to Time of Use — race condition between authorization check and action |
| **Atomic operation** | Database check-and-update in a single operation — prevents TOCTOU |
| **Cross-module IDOR** | Same object accessible via multiple features; auth present in one, absent in another |
| **Chain severity** | The combined severity of a multi-step exploit, always higher than any individual step |
| **Enabler finding** | A low-severity disclosure that makes a higher-severity exploit possible |

---

## Coming Up — Module 10: Secure Authorization Design

The final modules shift to defense and code review:
- Designing authorization from scratch — RBAC vs ABAC vs ReBAC
- Centralized authorization services and policy engines
- Authorization testing in CI/CD pipelines
- Secure-by-default patterns that prevent IDOR structurally
- Code review methodology for authorization flaws

---

*Module 09 — IDOR Mastery Curriculum*
*Focus: Business logic abuse, chained IDOR, workflow bypass, TOCTOU race conditions, attack chain reporting*