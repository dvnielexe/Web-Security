# IDOR Mastery — Module 06 Cheatsheet
## Mobile API Authorization Flaws

> **Core principle:** Mobile apps ship compiled binaries containing API endpoint strings,
> authentication logic, and version information. An attacker completes full reconnaissance
> *before making a single network request*. Authorization must live server-side regardless
> of what the binary reveals or conceals.

---

## Why Mobile Changes the Threat Model

```
Web application                    Mobile application
────────────────────────────────   ────────────────────────────────────────
Server delivers JS fresh           APK/IPA installed on device — persistent
No persistent client artifact      Fully reversible binary — offline recon
Endpoints visible during use       All endpoints in binary, including unused
Limited offline inspection         Full offline analysis before first request
Token in browser storage           Token in device filesystem or keychain
```

**The strategic implication:**
An attacker downloads your APK, decompiles it offline, extracts every API route,
then builds a complete test plan — before your servers log a single request.
Hiding routes in the binary is not security. Server-side enforcement is security.

---

## The Four Mobile-Specific Attack Surfaces

### Surface 1 — APK / IPA Decompilation

**What attackers extract:**
- All API endpoint paths (including admin, debug, internal, legacy)
- API base URLs and environment constants
- Hardcoded API keys, tokens, or secrets
- Version strings identifying which routes old app versions call
- Authentication flow logic (where tokens are sent, how they're formatted)

**Broken assumption:** *"Our internal endpoints are secret — they're not documented."*

```java
// Decompiled Android Java — all strings are plaintext
public class ApiClient {
    // ❌ Everything below is readable by anyone with jadx
    private static final String BASE_URL     = "https://api.example.com";
    private static final String ADMIN_PANEL  = "/api/v1/admin/users";
    private static final String DEBUG_LOGS   = "/api/internal/debug/logs";
    private static final String API_KEY      = "sk_prod_a8f2c..."; // hardcoded!
}

// React Native — JS bundle ships with app, fully readable
const API = {
  base:            'https://api.example.com',
  adminDashboard:  '/api/admin/dashboard',     // discoverable
  internalMetrics: '/api/internal/metrics',    // discoverable
  secret:          'Bearer sk_live_9x2k...'   // fully exposed
};
```

**Secure approach:**
```java
// Base URL only — no sensitive route paths hardcoded
public class ApiClient {
    private static final String BASE_URL = "https://api.example.com";
    // API keys fetched at runtime after authentication — never in binary
}

// The real fix is NOT hiding routes in the binary.
// The real fix is server-side authorization on every route.
// Knowing /api/admin/users exists is harmless IF the server enforces roles.
```

**Testing commands:**
```bash
# Extract APK from device
adb pull /data/app/com.target.package/base.apk ./target.apk

# Decompile with jadx
jadx -d ./output/ ./target.apk

# Search for API patterns
grep -rE '(/api|/v[0-9]|/admin|/internal|/debug)' ./output/
grep -rE '(Bearer|api_key|secret|token)' ./output/
grep -rE 'https?://' ./output/ | grep -v 'google\|android'

# iOS IPA
unzip app.ipa
strings Payload/App.app/App | grep -E '(/api|/v[0-9])'
```

---

### Surface 2 — Certificate Pinning Bypass

**What it is:** Apps implement certificate pinning to prevent traffic interception.
When bypassed, all API traffic is visible in a proxy — identical to web app testing.

**Broken assumption:** *"We use certificate pinning so our API is safe from interception."*

```kotlin
// Android — OkHttp pinning (correctly implemented)
val client = OkHttpClient.Builder()
    .certificatePinner(
        CertificatePinner.Builder()
            .add("api.example.com", "sha256/AAAA...")
            .build()
    ).build()
```

**Certificate pinning protects against:**
- Casual network interception (public Wi-Fi MITM)
- Proxy attempts without bypass tools

**Certificate pinning does NOT protect against:**
```
Frida runtime bypass        → hooks the pinning check and nullifies it
apk-mitm                    → patches binary to trust user certificates
Objection framework         → one-command automated bypass
SSL Kill Switch (iOS)        → Cydia tweak disables pinning system-wide
Reverse-engineered certs     → extracted from app memory at runtime
```

**Critical mental model:**
```
Pinning raises the bar for interception.
It does not make authorization irrelevant.
Assume all API traffic is eventually interceptable.
Authorization must live server-side regardless.
```

**Bypass toolkit:**
```bash
# Android — apk-mitm (no root required, patches binary)
apk-mitm target.apk
# Installs patched APK, route traffic through Burp Suite

# Android/iOS — Objection (Frida-based, one command)
objection -g com.target.package explore
# Then: android sslpinning disable
# Or:   ios sslpinning disable

# iOS — SSL Kill Switch 2 (Cydia, jailbroken device)
# Install from Cydia, enable in Settings, proxy through Burp
```

---

### Surface 3 — Insecure Token Storage

**What it is:** Authentication tokens persisted insecurely on the device filesystem.
Accessible via adb backup, root access, device compromise, or adjacent vulnerabilities.

**Broken assumption:** *"The token is on the device — only our app can read it."*

```kotlin
// VULNERABLE — Android SharedPreferences (plaintext)
val prefs = getSharedPreferences("auth", MODE_PRIVATE)
prefs.edit().putString("token", authToken).apply()
// Readable: adb backup, root shell, backup exploits

// VULNERABLE — iOS NSUserDefaults (unencrypted)
UserDefaults.standard.set(authToken, forKey: "auth_token")
// Readable: device backup, jailbroken device, MDM

// VULNERABLE — React Native AsyncStorage (plaintext SQLite)
await AsyncStorage.setItem('token', authToken);
// Stored at: /data/data/com.app/databases/RCTAsyncLocalStorage
```

```kotlin
// SECURE — Android Keystore (hardware-backed encryption)
val encryptedPrefs = EncryptedSharedPreferences.create(
    "auth", masterKey, context,
    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
)

// SECURE — iOS Keychain (hardware-backed, app-sandboxed)
KeychainSwift().set(authToken, forKey: "auth_token")

// SECURE — React Native (delegates to platform Keychain/Keystore)
await Keychain.setGenericPassword('user', authToken);
```

**Additional hardening:**
```
Short token expiry (15m access token)    → stolen token expires quickly
Refresh token rotation                   → each use issues a new refresh token
Biometric re-auth for sensitive ops      → re-verify user before high-value actions
Token binding to device fingerprint      → token unusable on different device
```

**Testing commands:**
```bash
# Pull app data (Android)
adb backup -noapk com.target.package

# Direct file access (rooted or run-as)
adb shell run-as com.target.package ls /data/data/com.target.package/
adb shell run-as com.target.package cat /data/data/com.target.package/shared_prefs/auth.xml

# Check AsyncStorage SQLite
adb shell run-as com.target.package \
  sqlite3 /data/data/com.target.package/databases/RCTAsyncLocalStorage_V1 \
  "SELECT * FROM catalystLocalStorage;"
```

---

### Surface 4 — API Versioning Gaps (Mobile-Specific)

**What it is:** Backend deploys security patches to the current API version. Old app
versions in the field continue calling legacy routes that were never patched.
Unlike web apps, you cannot force all users to update immediately.

**Broken assumption:** *"We patched the API so the vulnerability is fixed."*

```
Timeline:
  v1.8 app in field → calls /api/v1/orders/:id (no ownership check)
  Security patch deployed → /api/v2/orders/:id gets ownership check
  v2.0 app released → calls /api/v2/ correctly
  
  Problem: /api/v1/ still live and unpatched
  App store update rate: ~60% in first week
  Old route may remain exploitable for months
  Attacker doesn't need the old app — they just call /api/v1/ directly
```

```javascript
// VULNERABLE — v1 unpatched, v2 patched
app.get('/api/v2/orders/:id', requireLogin, async (req, res) => {
  const order = await Order.findById(req.params.id);
  if (order.userId !== req.user.id) return res.sendStatus(403); // ✓ patched
  res.json(order);
});

app.get('/api/v1/orders/:id', requireLogin, async (req, res) => {
  const order = await Order.findById(req.params.id);
  // ❌ Never patched — BOLA still present here
  res.json(order);
});
```

```javascript
// SECURE — Option 1: Shared authorization handler across ALL versions
const getOrderHandler = [requireLogin, requireOrderOwner, serveOrder];
app.get('/api/v1/orders/:id', ...getOrderHandler); // ✅
app.get('/api/v2/orders/:id', ...getOrderHandler); // ✅
// Authorization logic in ONE place — patch it once, covered everywhere

// SECURE — Option 2: Hard deprecate old version
app.get('/api/v1/orders/:id', (req, res) => {
  res.status(410).json({
    error: 'v1 API deprecated',
    migration: '/api/v2/orders/:id'
  }); // ✅ 410 Gone — forces client to update
});

// SECURE — Option 3: Minimum version enforcement
app.use((req, res, next) => {
  const appVersion = req.headers['x-app-version'];
  if (semver.lt(appVersion, '2.0.0')) {
    return res.status(426).json({ error: 'App update required' });
  }
  next(); // ✅ 426 Upgrade Required
});
```

**Testing technique:**
```
1. Check binary for version strings → know exactly which routes old versions call
2. After finding a protected v2 endpoint, test v1 equivalent
3. Variants to try: /api/v1/, /v1/, /api/v1.0/, /api/legacy/, /api/old/
4. Test deprecated routes that return 200 on any method
```

---

## Mobile-Specific BOLA Patterns

### Pattern A — Client-Supplied Device ID (Header-Based BOLA)

**Mechanism:** Device identifier comes from an attacker-controlled header.
Server uses it to scope data without verifying the device belongs to the session user.

**Why it's missed:** `X-Device-ID` looks like a routing hint to developers, not an authorization decision. The ownership check gets forgotten.

```javascript
// VULNERABLE — device ID from header, never ownership-checked
app.get('/api/device/settings', requireLogin, async (req, res) => {
  const deviceId = req.headers['x-device-id']; // ← attacker-controlled
  const settings = await Device.findById(deviceId);
  // ❌ No check: does this device belong to req.user?
  res.json(settings);
});

// SECURE — device must be owned by the authenticated user
app.get('/api/device/settings', requireLogin, async (req, res) => {
  const deviceId = req.headers['x-device-id'];
  const device = await Device.findById(deviceId);
  if (!device || device.userId !== req.user.id) return res.sendStatus(403); // ✅
  res.json(device.settings);
});
```

**Rule:** Any identifier in any request location (header, query, body, path) that scopes the response is an object reference and requires an ownership check.

---

### Pattern B — Push Notification Token IDOR

**Mechanism:** App registers device push token with a `user_id` from the body.
Attacker registers their device against another user's account — receiving their notifications.

```javascript
// VULNERABLE — user_id from body, attacker-controlled
app.post('/api/devices/register', requireLogin, async (req, res) => {
  const { user_id, device_token, platform } = req.body;
  // ❌ Attacker sends user_id of victim — receives their push notifications
  await Device.register(user_id, device_token, platform);
  res.sendStatus(201);
});

// SECURE — identity always from session
app.post('/api/devices/register', requireLogin, async (req, res) => {
  const { device_token, platform } = req.body;
  // ✅ user_id from verified session — never from body
  await Device.register(req.user.id, device_token, platform);
  res.sendStatus(201);
});
```

---

### Pattern C — Debug Endpoints in Production

**Mechanism:** Debug routes exist in server code for all builds, not just debug builds.
Binary analysis reveals their paths.

```javascript
// VULNERABLE — debug route accessible in production
app.get('/api/debug/user/:id', async (req, res) => {
  // ❌ No auth, no role check — raw user data dump
  const user = await User.findById(req.params.id);
  res.json(user); // includes password hash, tokens, PII
});

// SECURE — debug routes fully removed or gated
// Option 1: Remove from production build entirely
if (process.env.NODE_ENV === 'development') {
  app.get('/api/debug/user/:id', requireLogin, requireRole('admin'), debugHandler);
}

// Option 2: Return 404 in production
app.get('/api/debug/*', (req, res) => res.sendStatus(404));
```

---

## Full Code Audit — Mobile Banking API

### Vulnerable version (all flaws annotated)

```javascript
const router = express.Router();
router.use(requireLogin);

// ❌ BOLA #1 — account balance, no ownership check
router.get('/accounts/:id/balance', async (req, res) => {
  const account = await Account.findById(req.params.id);
  res.json({ balance: account.balance });
});

// ❌ BOLA #2 — transfer, from_account from body + amount unvalidated
router.post('/transfer', async (req, res) => {
  const { from_account, to_account, amount } = req.body;
  await Bank.transfer(from_account, to_account, amount);
  res.sendStatus(200);
});

// ❌ Mobile-specific BOLA — device ID from header, no ownership check
router.get('/alerts', async (req, res) => {
  const deviceId = req.headers['x-device-id']; // client-controlled
  const alerts = await Alert.findByDevice(deviceId);
  res.json(alerts);
});

// ❌ BFLA — admin endpoint, no role check
router.get('/admin/accounts', async (req, res) => {
  const accounts = await Account.findAll();
  res.json(accounts);
});

// ❌ BOLA + Legacy route — v1 unpatched, no ownership check
router.get('/v1/accounts/:id', async (req, res) => {
  const account = await Account.findById(req.params.id);
  res.json(account);
});

// ❌ BOLA — user_id from body, attacker registers token to victim's account
router.post('/devices/register', async (req, res) => {
  const { user_id, device_token, platform } = req.body;
  await Device.register(user_id, device_token, platform);
  res.sendStatus(201);
});
```

### Vulnerability summary

| Route | Type | Broken Assumption |
|-------|------|-------------------|
| `GET /accounts/:id/balance` | BOLA | "Any requested account belongs to the caller" |
| `POST /transfer` | BOLA + financial param trust | "Client truthfully sends their own account; amount is valid" |
| `GET /alerts` | Mobile-specific BOLA | "`X-Device-ID` header is trustworthy and device belongs to caller" |
| `GET /admin/accounts` | BFLA | "Only admins will call `/admin/*`" |
| `GET /v1/accounts/:id` | BOLA + legacy gap | "Patching v2 covers v1" |
| `POST /devices/register` | BOLA | "Client truthfully sends their own user_id" |

### Secure version — full rewrite

```javascript
const router = express.Router();
router.use(requireLogin);

// Role middleware
function requireRole(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) return res.sendStatus(403);
    next();
  };
}

// ✅ FIXED #1 — ownership check on balance (findOne = lookup + auth atomically)
// Returns 404 for both "not found" and "not yours" — prevents ID enumeration
router.get('/accounts/:id/balance', async (req, res) => {
  const account = await Account.findOne({
    id: req.params.id,
    ownerId: req.user.id  // ✅ combined lookup + ownership
  });
  if (!account) return res.sendStatus(404); // same response for both cases
  res.json({ balance: account.balance });
});

// ✅ FIXED #2 — transfer: three separate fixes
router.post('/transfer', async (req, res) => {
  const { to_account, amount } = req.body;

  // Fix 1: Verify from_account belongs to the session user
  const fromAccount = await Account.findOne({
    ownerId: req.user.id  // ✅ from session, not body
  });
  if (!fromAccount) return res.sendStatus(403);

  // Fix 2: Validate amount is positive and within limits
  if (amount <= 0 || amount > fromAccount.balance) {
    return res.status(400).json({ error: 'Invalid transfer amount' });
  }

  // Fix 3: Verify destination is a real account
  const toAccount = await Account.findById(to_account);
  if (!toAccount) return res.status(400).json({ error: 'Invalid destination' });

  await Bank.transfer(fromAccount.id, toAccount.id, amount);
  res.sendStatus(200);
});

// ✅ FIXED #3 — device ID ownership check (header-based BOLA)
router.get('/alerts', async (req, res) => {
  const deviceId = req.headers['x-device-id'];
  // ✅ Verify the device belongs to the authenticated user
  const device = await Device.findById(deviceId);
  if (!device || device.userId !== req.user.id) return res.sendStatus(403);
  const alerts = await Alert.findByDevice(deviceId);
  res.json(alerts);
});

// ✅ FIXED #4 — role check on admin route
router.get('/admin/accounts',
  requireRole('admin'),    // ✅ role gate before handler
  async (req, res) => {
    const accounts = await Account.findAll();
    res.json(accounts);
  }
);

// ✅ FIXED #5 — v1 legacy route: share handler OR hard deprecate
// Option A: Shared handler (same ownership check as current version)
router.get('/v1/accounts/:id', async (req, res) => {
  const account = await Account.findOne({
    id: req.params.id,
    ownerId: req.user.id  // ✅ same ownership check applied to v1
  });
  if (!account) return res.sendStatus(404);
  res.json(account);
});
// Option B: Hard deprecate
// router.get('/v1/accounts/:id', (req, res) =>
//   res.status(410).json({ error: 'v1 deprecated', use: '/accounts/:id' })
// );

// ✅ FIXED #6 — push token registration: user_id from session
router.post('/devices/register', async (req, res) => {
  const { device_token, platform } = req.body;
  // ✅ user_id from verified session — never from body
  await Device.register(req.user.id, device_token, platform);
  res.sendStatus(201);
});
```

---

## Mobile API Testing Workflow

### Phase 1 — Binary Analysis (Offline, Before Any Requests)

```bash
# Extract and decompile APK
adb pull /data/app/com.target.package/base.apk .
jadx -d ./decompiled/ ./target.apk

# Hunt for API surface
grep -rE '(/api|/v[0-9]|/admin|/internal|/debug)' ./decompiled/
grep -rE '(Bearer|api_key|secret|token|password)' ./decompiled/
grep -rE 'x-[a-z]+-[a-z]+' ./decompiled/  # custom headers

# Build test list from findings:
# - All API endpoint paths
# - Legacy/versioned routes
# - Admin and internal paths
# - Debug endpoints
# - Custom headers the app sends
```

### Phase 2 — Certificate Pinning Bypass

```bash
# Method 1: apk-mitm (no root, patches binary)
apk-mitm target.apk
adb install target-patched.apk

# Method 2: Objection (Frida, requires USB debugging)
frida-server &  # on device
objection -g com.target.package explore
# android sslpinning disable

# Verify bypass: route device through Burp Suite proxy
# Settings → WiFi → Proxy → Burp IP:8080
```

### Phase 3 — Traffic Analysis

```
Capture all API calls during normal app use:
  - Log in, browse features, create resources
  - Note: authentication header format (Bearer, Basic, custom)
  - Note: custom headers (X-Device-ID, X-App-Version, X-Platform)
  - Note: request body structure for all write operations
  - Note: ID formats in responses (integer, UUID, custom prefix)
```

### Phase 4 — Authorization Testing

```
Apply full REST API methodology (Module 05) PLUS:
  □ Test all routes found in binary not triggered by normal use
  □ Test all legacy/versioned routes found in binary
  □ Test debug/internal endpoints found in binary
  □ Test every custom header as a potential BOLA vector
  □ Test push notification registration with foreign user_id
  □ Test all device-scoped endpoints with foreign device IDs
  □ Test version enforcement (remove/modify X-App-Version header)
```

---

## 404 vs 403 — Enumeration Prevention (Critical Pattern)

```javascript
// ❌ LEAKS EXISTENCE — 403 tells attacker "object exists, not yours"
const account = await Account.findById(req.params.id);
if (!account) return res.sendStatus(404);
if (account.ownerId !== req.user.id) return res.sendStatus(403); // ← leaks

// ✅ NO EXISTENCE LEAK — same 404 for both "not found" and "not yours"
const account = await Account.findOne({
  id: req.params.id,
  ownerId: req.user.id  // combined lookup + ownership
});
if (!account) return res.sendStatus(404); // attacker learns nothing
```

This pattern is especially important in mobile banking where account ID enumeration has direct financial risk.

---

## Complete Testing Checklist — Mobile API

```
BINARY ANALYSIS
  □ Extracted APK with adb pull
  □ Decompiled with jadx
  □ Searched for all API endpoint strings
  □ Found all version prefixes (/v1/, /v2/, /legacy/)
  □ Found all admin/internal/debug paths
  □ Identified all custom headers the app sends
  □ Checked for hardcoded secrets, API keys, tokens

PINNING BYPASS
  □ Attempted apk-mitm (no-root method)
  □ Fallback: Objection/Frida bypass
  □ Verified traffic visible in Burp Suite

TRAFFIC ANALYSIS
  □ Captured all API calls during normal use
  □ Identified all resource types and ID formats
  □ Noted all custom headers in requests
  □ Identified authentication token format

MOBILE-SPECIFIC BOLA TESTING
  □ Tested all custom headers as BOLA vectors (X-Device-ID, etc.)
  □ Tested push notification registration with foreign user_id
  □ Tested device-scoped endpoints with foreign device IDs
  □ Tested all routes found in binary not triggered by normal use

VERSION GAP TESTING
  □ Tested v1 equivalent of every v2 endpoint
  □ Tested /legacy/, /old/, /v1.0/ variants
  □ Modified X-App-Version header to old version strings
  □ Verified 410/426 responses on deprecated routes

STANDARD REST TESTING (from Module 05)
  □ Two-account ownership testing across all routes
  □ HTTP method switching (GET → PUT/DELETE/PATCH)
  □ Parameter location switching (path → query → body)
  □ Batch endpoint partial validation testing
  □ Admin endpoint BFLA testing
  □ Response mining for foreign IDs

TOKEN STORAGE VERIFICATION
  □ Checked SharedPreferences / NSUserDefaults for plaintext tokens
  □ Verified Keychain/Keystore usage for sensitive credentials
  □ Checked AsyncStorage / SQLite for token exposure
```

---

## Key Vocabulary Added in Module 06

| Term | Definition |
|------|------------|
| **APK decompilation** | Extracting readable code and strings from Android app binary using jadx |
| **Certificate pinning** | App-level TLS validation that rejects non-app certificates — bypassable with Frida/apk-mitm |
| **Certificate pinning bypass** | Patching or hooking the app to trust a proxy certificate for traffic interception |
| **Header-based BOLA** | BOLA where the object reference comes from an HTTP header (X-Device-ID) rather than a path or body parameter |
| **Push token IDOR** | Registering a device push token to another user's account to receive their notifications |
| **Mobile versioning gap** | Security patch applied to current API version; legacy routes called by old app versions remain unpatched |
| **Debug endpoint exposure** | Internal/debug API routes included in production binary and accessible without authorization |
| **apk-mitm** | Tool that patches an APK to trust user-installed certificates, enabling traffic interception without root |
| **Objection** | Frida-based mobile exploration framework used for certificate pinning bypass and runtime analysis |
| **Enumeration prevention** | Returning 404 for both "not found" and "unauthorized" to prevent object ID enumeration |

---

## Coming Up — Module 07: GraphQL Authorization Issues

GraphQL introduces an entirely different authorization surface:
- Single endpoint, multiple operations — authorization per-field, not per-route
- Introspection leaks the entire schema
- Nested resolver chains where each level needs its own check
- Batching abuse (aliases) to bypass rate limiting
- Fragment injection and query complexity attacks
- Authorization at the resolver level vs the schema level

---

*Module 06 — IDOR Mastery Curriculum*
*Focus: Mobile APK analysis, certificate pinning bypass, token storage, versioning gaps, mobile-specific BOLA patterns*