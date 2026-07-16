# Module 10: OAuth, OIDC & API Authentication - Cheatsheet

## Core Theme
OAuth lets a third-party app act on your behalf with a different app, without ever handing over your password. It is an authorization delegation protocol, NOT a login mechanism. OIDC is the identity layer built on top of it that actually makes "Sign in with X" a valid authentication method. Confusing the two is the source of a real, recurring vulnerability class.

## Mental Model
Hotel key-card system: you (resource owner) never give the valet (third-party app) your house keys (password). You go to the front desk (authorization server), authorize a scoped key card (access token) - opens exactly one thing, for a limited time. The valet hands the card to the garage (resource server), which checks it's legitimate and releases only what was authorized.

## Why the Redirect-to-Real-Authority Design Exists
Replaces the old "password anti-pattern" (user types real password directly into third-party app). A breached/malicious third-party app under the old pattern gets the MASTER credential (full account access), not scoped access. Under OAuth, the third-party app never touches the actual password - only a scoped, revocable, time-limited token. Also preserves MFA fully, since the user authenticates directly with the real provider (no need to relay MFA codes to a third party, avoiding Module 4's real-time-relay problem).

## Authorization Code Flow
```
1. User clicks "Login with Provider" on ThirdPartyApp
2. Browser redirected DIRECTLY to Provider's auth endpoint (ThirdPartyApp never sees credentials)
3. User authenticates with Provider directly (password + MFA, on Provider's domain)
4. Consent screen shown and approved
5. Provider redirects browser back with a short-lived, single-use AUTHORIZATION CODE (not the token yet)
6. ThirdPartyApp's SERVER exchanges the code for an access token, server-to-server, using a separate CLIENT SECRET (never touches the browser)
7. ThirdPartyApp uses the access token to call the API on the user's behalf
```

## Why "Code, Then Exchange" Instead of Handing Back the Token Directly
The authorization code travels through the browser (redirect, history, Referer, logs - Module 5's exposure vectors all apply). The client secret NEVER travels through the browser at all - lives only on the app's server. **Split the sensitive exchange across two channels with different exposure profiles**, so compromising the browser-visible piece (the code) alone is insufficient - the code is structurally useless without the secret, which an attacker positioned to intercept browser traffic can never obtain. Same principle as MFA's two independent factor categories (Module 4), applied to a different problem.

## PKCE - For Public Clients (Mobile Apps / SPAs)
A client secret embedded in a mobile app binary or SPA JS is **not a fixable misconfiguration** - it's an architectural impossibility, since the secret ships to the same untrusted device/browser that would need to be kept out. Decompilation or traffic interception always extracts it.

**PKCE fix:** generate a random, high-entropy, CSPRNG "code verifier" fresh per attempt; send a hashed "code challenge" upfront; present the original unhashed verifier at exchange time. Achieves "prove same entity that initiated the request" without a permanent embedded secret.

**Critical:** PKCE only works if the verifier has full reset-token-grade entropy (Module 5). A weak/reused/predictable verifier collapses PKCE entirely - hashing a weak value doesn't add strength (same lesson as Module 3: the hash function's properties don't compensate for insufficient input entropy). PKCE is the SUBSTITUTE for a client secret in public clients, not a bonus layer added on top of one - never embed a secret AND rely on PKCE, thinking that's extra-safe; the secret adds nothing and false confidence.

## OAuth Access Token vs. OIDC ID Token - The Confused Deputy Vulnerability

**The gap:** a bare OAuth access token is a bearer credential for an API - it does NOT inherently carry a verifiable statement of who the user is or what application it was issued for.

**The attack:** an app implements "Sign in with Provider" by just checking "did we get back *any* valid access token, call /userinfo, log in as whatever email comes back." Attacker gets a victim to authorize a completely unrelated, low-stakes third-party app (e.g., "read your Drive files"). That legitimately-issued token - never meant for login - is then fed directly to VictimApp, which naively accepts it, calls /userinfo, and logs the ATTACKER in as the victim. No forgery, just wrong-audience token reuse.

**The fix - OIDC ID Token:** a JWT with explicit, audience-bound claims:
```json
{"iss": "https://accounts.google.com", "sub": "...", "aud": "your-app-client-id", "exp": ..., "email": "..."}
```
Must independently validate: **signature** (authenticity) AND **`iss`** (trusted provider) AND **`aud`** (issued specifically for THIS app) AND **`exp`**. Signature validity alone only proves the token is genuinely from the provider - it says nothing about which application it was intended for. Skipping the `aud` check is structurally identical to Module 9's algorithm-pinning lesson: verifying crypto correctness is necessary but never sufficient; every claim relevant to the trust decision must be checked independently.

## redirect_uri Validation
If the authorization server doesn't strictly match `redirect_uri` against a pre-registered exact allowlist (loose/domain-only matching is insufficient): attacker crafts a malicious authorization link with a substituted `redirect_uri`, gets a victim to click it, victim authenticates/consents normally (sees the real app's legitimate consent screen), but the resulting authorization code is silently delivered to the attacker's server instead of the real callback endpoint. "OAuth turns into a code exfiltration channel."

**Compounding factor:** for a confidential client (has a client secret), attacker is still stuck at the exchange step. For a public client (PKCE, no secret) with ANY PKCE weakness, the attacker can complete the entire exchange with nothing but the exfiltrated code alone - full account takeover. redirect_uri validation and PKCE strength are independent controls that compound; a weakness in one is far more exploitable if the other is also weak.

## SSO Ecosystem-Wide Risk (Weakest Relying Party)
A shared identity provider's tokens are cryptographically valid everywhere by design - only per-application `aud` validation is what scopes that validity correctly. If ANY relying party in the ecosystem (even a "low priority internal wiki") skips the `aud` check, it becomes a universal token acceptor: any validly-signed token from the shared provider, issued for ANY other app, gets accepted there too. **The security of the entire SSO ecosystem is only as strong as the least rigorous validator anywhere in it** - a correctly-implemented high-value app (payroll) does not protect the organization if a low-value app shares the same identity provider and implements validation poorly. Security reviews must cover every relying party, not just the "important" ones.

## Common Developer Mistakes
- Using raw OAuth access tokens as login instead of OIDC ID tokens with full claim validation
- Not validating `aud` on ID tokens (confused deputy)
- Not validating `iss` (accepting tokens from unexpected providers)
- Embedding a client secret in a mobile app/SPA instead of using PKCE
- Weak/predictable PKCE code_verifier generation
- Overly broad scope requests (violates least privilege, increases leak blast radius)
- Loose/missing `redirect_uri` validation (code exfiltration - Module 5's open-redirect lesson reapplied)
- Missing/unvalidated `state` parameter (enables OAuth CSRF / account-binding attacks - binds the flow to the initiating session)
- API auth relying solely on a permanent, unscoped, unrotated API key

## Detection Methodology
- Attempt `redirect_uri` substitution to attacker-controlled/unregistered destination
- Check if the app treats a bare access token as sufficient login proof vs. properly validating ID token signature/iss/aud/exp
- For mobile/SPA: decompile/intercept traffic for embedded secrets; confirm PKCE is enforced
- Check PKCE verifier entropy/predictability if source available
- Review requested scopes against actual app functionality (least privilege check)
- Test authorization code single-use enforcement (replay the same code twice)
- Test if a token issued for one scope/audience works against an unrelated API/endpoint that skips audience validation
- Check `state` parameter presence and validation

## Secure Design Principles
- Never use bare OAuth access tokens for login - always OIDC ID tokens with full claim validation
- Validate iss, aud, exp, and signature on every ID token, no exceptions for "low priority" apps
- Public clients: PKCE with CSPRNG-generated, single-use, high-entropy verifier - never a static embedded secret
- Strict exact-match redirect_uri allowlist validation
- Authorization codes: single-use, short-lived
- Request minimum necessary scopes
- Treat every relying party in an SSO ecosystem as security-relevant regardless of its own data sensitivity

## Common Misconceptions
- "OAuth is a login system" - it's authorization delegation; OIDC is the actual auth layer
- "A valid access token proves who the user is" - proves what the bearer can DO, not a verified identity
- "If the signature is valid, the token can be trusted for our purpose" - signature = authenticity only; audience/purpose must be checked separately
- "PKCE + embedded secret is extra safe" - the secret can't be kept safe in a public client; PKCE is the substitute, not a bonus
- "This internal app is low-priority so its OAuth quality doesn't matter" - it affects the whole SSO ecosystem's trust boundary

## Variations & Edge Cases
- **Client Credentials flow** - machine-to-machine, no human user, client itself is the resource owner
- **Implicit flow (deprecated)** - returned access token directly in the URL fragment, skipping code exchange; deprecated precisely because of browser-exposure risk (industry learning this module's exact lesson)
- **Token introspection endpoints** - resource server calls back to the authorization server per-request instead of validating JWTs locally; trades JWT's lookup-free benefit for real-time revocation - a live production example of Module 9's "reintroduce statefulness where it matters" tradeoff

## Reporting Reference
- **Missing/loose redirect_uri validation**
  - CWE-601 (URL Redirection to Untrusted Site), also enables authorization code exfiltration
- **Missing aud/iss validation on ID tokens (confused deputy)**
  - CWE-287 (Improper Authentication), CWE-346 (Origin Validation Error)
- **Client secret embedded in public client**
  - CWE-798 (Use of Hard-coded Credentials)
- **Weak/predictable PKCE verifier**
  - CWE-330 (Insufficiently Random Values)
- **Missing/unvalidated state parameter**
  - CWE-352 (CSRF) - OAuth-flow-specific variant
- **Overly broad scope grants**
  - CWE-269 (Improper Privilege Management)

## Key Test to Remember
For any "Sign in with X" implementation: is the app validating a proper OIDC ID token (signature + iss + aud + exp), or just checking "did we get back a valid-looking access token"? The second pattern is the confused-deputy vulnerability waiting to happen.