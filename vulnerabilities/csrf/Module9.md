# CSRF Module 09 — Framework-Level Mitigations
> **Curriculum:** CSRF Mastery for Ethical Hacking & Bug Bounty  
> **Module:** 09 of 12  
> **Topic:** Django, Rails, Spring Security, Express, DRF, Laravel — CSRF implementation, misconfiguration patterns, audit checklists  
> **Level:** Advanced — framework-specific CSRF behavior, escape hatches, and silent disablement patterns

---

## Table of Contents
- [CSRF Module 09 — Framework-Level Mitigations](#csrf-module-09--framework-level-mitigations)
  - [Table of Contents](#table-of-contents)
  - [1. The Framework CSRF Model — Opt-Out vs Opt-In](#1-the-framework-csrf-model--opt-out-vs-opt-in)
  - [2. Django — Complete CSRF Implementation](#2-django--complete-csrf-implementation)
    - [How Django's CSRF Middleware Works](#how-djangos-csrf-middleware-works)
    - [Middleware Execution Order](#middleware-execution-order)
    - [Django CSRF Decorators Reference](#django-csrf-decorators-reference)
    - [Django + React SPA Integration (Correct Pattern)](#django--react-spa-integration-correct-pattern)
  - [3. Django — Common Mistakes and Misconfigurations](#3-django--common-mistakes-and-misconfigurations)
  - [4. Django REST Framework — Special CSRF Behavior](#4-django-rest-framework--special-csrf-behavior)
    - [DRF Common Mistake](#drf-common-mistake)
  - [5. Ruby on Rails — Complete CSRF Implementation](#5-ruby-on-rails--complete-csrf-implementation)
    - [Default Protection](#default-protection)
    - [Rails CSRF Token Locations](#rails-csrf-token-locations)
    - [protect\_from\_forgery Options Compared](#protect_from_forgery-options-compared)
    - [Rails API Mode — No CSRF](#rails-api-mode--no-csrf)
  - [6. Rails — Common Mistakes and Misconfigurations](#6-rails--common-mistakes-and-misconfigurations)
  - [7. Spring Security (Java) — Complete CSRF Implementation](#7-spring-security-java--complete-csrf-implementation)
    - [Default Configuration](#default-configuration)
    - [CSRF Token Storage Options](#csrf-token-storage-options)
    - [Spring CSRF Token Header Names](#spring-csrf-token-header-names)
    - [Disabling for Specific Paths](#disabling-for-specific-paths)
  - [8. Spring Security — Common Mistakes and Misconfigurations](#8-spring-security--common-mistakes-and-misconfigurations)
  - [9. Express.js (Node.js) — No Built-In CSRF Protection](#9-expressjs-nodejs--no-built-in-csrf-protection)
    - [The Problem](#the-problem)
    - [Modern Express CSRF Solution](#modern-express-csrf-solution)
    - [Express Middleware Order — Critical](#express-middleware-order--critical)
  - [10. Laravel (PHP) — CSRF Implementation](#10-laravel-php--csrf-implementation)
    - [Laravel Mistakes](#laravel-mistakes)
  - [11. ASP.NET Core — CSRF Implementation](#11-aspnet-core--csrf-implementation)
  - [12. Framework CSRF Comparison Table](#12-framework-csrf-comparison-table)
  - [13. The Webhook Exemption Pattern](#13-the-webhook-exemption-pattern)
    - [Why Webhooks Don't Need CSRF](#why-webhooks-dont-need-csrf)
    - [Correct Webhook Implementation (Django)](#correct-webhook-implementation-django)
    - [Security Consequence Without Signature Verification](#security-consequence-without-signature-verification)
  - [14. Mobile API Authentication — The Correct Pattern](#14-mobile-api-authentication--the-correct-pattern)
    - [The Wrong Approach](#the-wrong-approach)
    - [The Correct Approach — Split Authentication](#the-correct-approach--split-authentication)
    - [Mobile Token Flow](#mobile-token-flow)
  - [15. The Remember-Me Cookie Trap](#15-the-remember-me-cookie-trap)
  - [16. Middleware Order — Why It Matters](#16-middleware-order--why-it-matters)
  - [17. Framework Audit Checklist](#17-framework-audit-checklist)
    - [Django Audit](#django-audit)
    - [Rails Audit](#rails-audit)
    - [Spring Security Audit](#spring-security-audit)
    - [Express Audit](#express-audit)
    - [All Frameworks](#all-frameworks)
  - [18. Key Terminology Reference](#18-key-terminology-reference)
  - [19. Common Misconceptions](#19-common-misconceptions)
    - [❌ "CsrfViewMiddleware being present means all views are protected"](#-csrfviewmiddleware-being-present-means-all-views-are-protected)
    - [❌ "Rails API mode has the same CSRF protection as Base mode"](#-rails-api-mode-has-the-same-csrf-protection-as-base-mode)
    - [❌ ".csrf().disable() is safe for REST APIs"](#-csrfdisable-is-safe-for-rest-apis)
    - [❌ "Express has CSRF protection by default"](#-express-has-csrf-protection-by-default)
    - [❌ "@csrf\_exempt is necessary for mobile API support"](#-csrf_exempt-is-necessary-for-mobile-api-support)
    - [❌ "protect\_from\_forgery with: :null\_session is safe"](#-protect_from_forgery-with-null_session-is-safe)
    - [❌ "Adding CSRF middleware anywhere in the stack is sufficient"](#-adding-csrf-middleware-anywhere-in-the-stack-is-sufficient)
    - [❌ "The csrftoken cookie being HttpOnly improves security"](#-the-csrftoken-cookie-being-httponly-improves-security)
  - [20. Bug Bounty Reference](#20-bug-bounty-reference)
    - [Code Review Targets](#code-review-targets)
    - [Framework-Specific Severity Notes](#framework-specific-severity-notes)
  - [21. Module 9 Summary — What You Must Know Cold](#21-module-9-summary--what-you-must-know-cold)

---

## 1. The Framework CSRF Model — Opt-Out vs Opt-In

```
OPT-OUT MODEL (safer default):
  CSRF protection enabled globally for all views
  Developers must explicitly exempt views that don't need it
  Frameworks: Django, Rails (Base), Spring Security, Laravel, ASP.NET Core

  Risk pattern:
    @csrf_exempt / skip_before_action / .csrf().disable()
    applied too broadly — disables protection silently
    New views are protected by default ✓

OPT-IN MODEL (dangerous default):
  CSRF protection disabled by default
  Developers must explicitly enable per view or route
  Frameworks: Express.js (no built-in), Rails API mode

  Risk pattern:
    Developers forget to add protection
    New views are unprotected by default ✗
    Protection only exists where developer remembered to add it

THE CORE DANGER IN OPT-OUT MODELS:
  Developers who don't understand CSRF exempt endpoints
  to make something work (mobile API, webhook, cross-origin call)
  without realizing the security consequence
  
  One @csrf_exempt or one commented-out middleware line
  can silently remove protection from critical endpoints
```

---

## 2. Django — Complete CSRF Implementation

### How Django's CSRF Middleware Works

```
STEP 1: On first request or session creation
  Django sets cookie:
  Set-Cookie: csrftoken=xK9mP2qL...; SameSite=Lax; Path=/
  
  IMPORTANT: This cookie is NOT HttpOnly by default
  JavaScript must be able to read it (for SPA integration)
  CSRF_COOKIE_HTTPONLY = True breaks SPA integration

STEP 2: Template rendering
  {% csrf_token %} embeds hidden field:
  <input type="hidden" name="csrfmiddlewaretoken" value="xK9mP2qL...">

STEP 3: On state-changing request (POST/PUT/PATCH/DELETE)
  CsrfViewMiddleware checks TWO locations for token:
  
  Location 1 — Request body:
    request.POST.get('csrfmiddlewaretoken')
    Only works for form-encoded bodies (application/x-www-form-urlencoded)
    DOES NOT work for JSON bodies
  
  Location 2 — Request header:
    request.META.get('HTTP_X_CSRFTOKEN')
    X-CSRFToken header (Django internal naming: HTTP_ prefix + uppercase)
    Works for AJAX and SPA fetch() calls
  
  Compares submitted value against csrftoken cookie value
  Match → proceed
  No match / missing → 403 Forbidden

STEP 4: Safe methods are exempt
  Django does NOT check CSRF for:
  GET, HEAD, OPTIONS, TRACE
  Assumes these are read-only (state-changing GETs bypass protection)
```

### Middleware Execution Order

```python
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',            # 1
    'django.contrib.sessions.middleware.SessionMiddleware',     # 2
    'django.middleware.common.CommonMiddleware',                # 3
    'django.middleware.csrf.CsrfViewMiddleware',               # 4 ← CSRF
    'django.contrib.auth.middleware.AuthenticationMiddleware', # 5 ← Auth
    'django.contrib.messages.middleware.MessageMiddleware',    # 6
]

Execution order on incoming request:
  1 → 2 → 3 → 4 (CSRF validated) → 5 (user identified) → View → @login_required

CSRF is validated BEFORE the server knows who the user is.
Invalid CSRF token = 403 before authentication check.
```

### Django CSRF Decorators Reference

```python
from django.views.decorators.csrf import (
    csrf_exempt,          # disables CSRF for this view
    csrf_protect,         # enforces CSRF even if middleware disabled
    requires_csrf_token,  # adds token to context but doesn't enforce
    ensure_csrf_cookie,   # forces csrftoken cookie to be set in response
)

# csrf_exempt — removes protection
@csrf_exempt
@login_required
def transfer(request):
    pass  # NO CSRF protection regardless of middleware

# csrf_protect — adds protection even without middleware
@csrf_protect
def sensitive_view(request):
    pass  # protected even if CsrfViewMiddleware commented out

# ensure_csrf_cookie — for SPA first load
@ensure_csrf_cookie
def spa_home(request):
    return render(request, 'index.html')
    # React app reads csrftoken cookie after this response
```

### Django + React SPA Integration (Correct Pattern)

```javascript
// React reads Django's csrftoken cookie (NOT HttpOnly — by design)
function getCookie(name) {
  const value = `; ${document.cookie}`;
  const parts = value.split(`; ${name}=`);
  if (parts.length === 2) return parts.pop().split(';').shift();
  return null;
}

// Every state-changing API call
async function apiPost(url, data) {
  return fetch(url, {
    method: 'POST',
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRFToken': getCookie('csrftoken')  // ← REQUIRED
    },
    body: JSON.stringify(data)
  });
}

// WHY X-CSRFToken header, not JSON body field:
// Django's CSRF middleware reads request.POST (form-encoded only)
// JSON body is NOT parsed into request.POST
// Token in JSON body: {"csrfmiddlewaretoken": "..."} → INVISIBLE to middleware
// Token must be in X-CSRFToken header for JSON requests
```

---

## 3. Django — Common Mistakes and Misconfigurations

```python
# MISTAKE 1: Commenting out middleware (global disable)
MIDDLEWARE = [
    # 'django.middleware.csrf.CsrfViewMiddleware',  ← disabled
]
# ALL views lose CSRF protection silently
# Blast radius: every view without @csrf_exempt (they were protected)
# Views with @csrf_exempt: no change (were already unprotected)

# MISTAKE 2: CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_HTTPONLY = True
# JavaScript cannot read the csrftoken cookie
# SPA fetch() cannot obtain token to send in X-CSRFToken header
# All SPA POST requests return 403
# Developers then comment out middleware to "fix" → global disable

# MISTAKE 3: @csrf_exempt for mobile support
@csrf_exempt
@login_required
def transfer_funds(request):
    pass
# Correct fix: use token auth for mobile (see Section 14)

# MISTAKE 4: Blanket @csrf_exempt on API base class
@csrf_exempt
class BaseAPIView(View):
    pass
# All subclasses inherit exemption — potentially dozens of views

# MISTAKE 5: Token in JSON body (invisible to Django)
# React sends: {"amount": 100, "csrfmiddlewaretoken": "xK9mP2..."}
# Django sees: request.POST = {} (empty — not form-encoded)
# Result: 403 Forbidden on all POST requests
# Fix: send token in X-CSRFToken header

# MISTAKE 6: State-changing GET endpoints
def delete_user(request):
    if request.method == 'GET':
        user_id = request.GET.get('id')
        User.objects.filter(id=user_id).delete()
        return HttpResponse('deleted')
# Django exempts GET from CSRF — this endpoint is fully unprotected
# SameSite=Lax navigation exception makes it exploitable

# MISTAKE 7: Token not invalidated on logout
# Django handles this correctly by default via session rotation
# Custom logout views that don't call request.session.flush() may not
```

---

## 4. Django REST Framework — Special CSRF Behavior

DRF's CSRF behavior depends on which authentication class is used.

```python
from rest_framework.views import APIView
from rest_framework.authentication import (
    SessionAuthentication,
    TokenAuthentication,
    BasicAuthentication,
)

# CASE 1: SessionAuthentication → CSRF ENFORCED
class MyView(APIView):
    authentication_classes = [SessionAuthentication]
    # DRF's SessionAuthentication explicitly calls self.enforce_csrf(request)
    # CSRF IS enforced even though it's a DRF view

# CASE 2: TokenAuthentication → CSRF NOT ENFORCED
class MyView(APIView):
    authentication_classes = [TokenAuthentication]
    # Token in Authorization header = explicit attachment
    # No cookies = no CSRF risk
    # CSRF NOT enforced (correctly)

# CASE 3: No authentication_classes → CSRF NOT ENFORCED
class MyView(APIView):
    authentication_classes = []
    permission_classes = []
    # Completely open endpoint
    # No CSRF, no auth

# CASE 4: Mixed → depends on which auth succeeds
class MyView(APIView):
    authentication_classes = [SessionAuthentication, TokenAuthentication]
    # If request has valid session → SessionAuthentication runs → CSRF enforced
    # If request has valid token → TokenAuthentication runs → no CSRF needed
    # DRF uses first successful authentication class

# DRF SessionAuthentication internals:
class SessionAuthentication(BaseAuthentication):
    def authenticate(self, request):
        # validate session...
        self.enforce_csrf(request)  # ← explicit CSRF enforcement
        return (user, None)
    
    def enforce_csrf(self, request):
        check = CSRFCheck(request)
        check.process_request(request)
        reason = check.process_view(request, None, (), {})
        if reason:
            raise exceptions.PermissionDenied('CSRF Failed: %s' % reason)
```

### DRF Common Mistake

```python
# DANGEROUS: switching to TokenAuthentication while session cookies still set
# Before change:
class MyView(APIView):
    authentication_classes = [SessionAuthentication]  # CSRF enforced

# Developer "upgrades" to token auth:
class MyView(APIView):
    authentication_classes = [TokenAuthentication]  # CSRF not enforced

# But: session middleware still sets session cookies on login
# Browser still sends session cookie on every request (ambient authority)
# TokenAuthentication ignores the cookie → no CSRF check
# But the session cookie is still being sent!
# If attacker forges request: session cookie sent, TokenAuthentication
# doesn't use it but session data may still be accessible
# Subtle: depends on whether session middleware processes the cookie

# Clean fix: if using token auth, also disable session middleware
# or use CSRF tokens on all endpoints using session cookies
```

---

## 5. Ruby on Rails — Complete CSRF Implementation

### Default Protection

```ruby
# ApplicationController — enabled by default for ActionController::Base
class ApplicationController < ActionController::Base
  protect_from_forgery with: :exception
  # :exception  → raises ActionController::InvalidAuthenticityToken → 422
  # :reset_session → clears session, request continues with empty session
  # :null_session → provides empty session for request (DANGEROUS — see below)
end

# Token stored in session:
# session[:_csrf_token] = SecureRandom.base64(32)

# Embedded in forms via helpers:
# <%= form_tag do %>  → automatically includes hidden field
# <%= hidden_field_tag :authenticity_token, form_authenticity_token %>

# Meta tag for AJAX:
# <%= csrf_meta_tags %>
# → <meta name="csrf-param" content="authenticity_token">
#   <meta name="csrf-token" content="xK9mP2qL...">
```

### Rails CSRF Token Locations

```ruby
# Rails checks for token in:
# 1. params[:authenticity_token] (form body)
# 2. X-CSRF-Token header (for AJAX/SPA)

# JavaScript reads from meta tag:
const token = document.querySelector('meta[name="csrf-token"]').content;

fetch('/transfer', {
  method: 'POST',
  headers: {
    'X-CSRF-Token': token,
    'Content-Type': 'application/json'
  },
  credentials: 'include',
  body: JSON.stringify({ amount: 100, to: 'bob' })
});
```

### protect_from_forgery Options Compared

```
:exception (RECOMMENDED)
  → Raises ActionController::InvalidAuthenticityToken
  → Request HALTED — action does NOT execute
  → Returns 422 Unprocessable Entity
  → Error logged → alerting possible

:reset_session
  → Clears session data
  → Request CONTINUES with empty session
  → Action executes but user appears logged out
  → May cause partial execution of action
  → Useful for APIs where session clearing is acceptable

:null_session (DANGEROUS)
  → Provides empty session object for duration of request
  → Request CONTINUES with null session
  → Action executes — potentially doing work without session context
  → No error raised — monitoring blind spot
  → Appears to fail (no session) but action may partially execute
  → Developers think they're protected because "nothing happens"
```

### Rails API Mode — No CSRF

```ruby
# rails new myapp --api creates:
class ApplicationController < ActionController::API
  # ActionController::API does NOT include:
  # - protect_from_forgery
  # - CSRF protection of any kind
  # - Cookie handling (reduced middleware stack)
end

# vs standard Rails:
class ApplicationController < ActionController::Base
  protect_from_forgery with: :exception  # ← included automatically
end

# DANGER PATTERN:
# Start with --api mode (no CSRF)
# Add session-based authentication later (Devise, etc.)
# Session cookie is now set
# But CSRF was never enabled
# All endpoints are CSRF-vulnerable
```

---

## 6. Rails — Common Mistakes and Misconfigurations

```ruby
# MISTAKE 1: Using ActionController::API with session auth
class ApplicationController < ActionController::API
  # No CSRF protection
  before_action :authenticate_user!  # Devise — sets session cookie
  # All endpoints: session cookie sent automatically, no CSRF check

# MISTAKE 2: Blanket skip
class ApplicationController < ActionController::Base
  skip_before_action :verify_authenticity_token  # ALL controllers, ALL actions
  # Equivalent to disabling middleware globally

# MISTAKE 3: protect_from_forgery with: :null_session
class ApplicationController < ActionController::Base
  protect_from_forgery with: :null_session
  # Silently provides empty session instead of rejecting
  # Action may execute with no session context
  # No error raised — no visibility

# MISTAKE 4: Skip on parent class affecting all children
class ApiController < ApplicationController
  skip_before_action :verify_authenticity_token
  # All controllers inheriting ApiController are unprotected

# MISTAKE 5: Skipping for "API routes" without checking auth mechanism
namespace :api do
  # skip_before_action in api controllers
  # If these use session auth: CSRF vulnerable
  # Fix: use token auth for API namespace

# CORRECT webhook exemption:
class WebhooksController < ApplicationController
  skip_before_action :verify_authenticity_token, only: [:stripe]
  
  def stripe
    payload = request.body.read
    sig = request.env['HTTP_STRIPE_SIGNATURE']
    begin
      Stripe::Webhook.construct_event(payload, sig, ENV['STRIPE_SECRET'])
    rescue Stripe::SignatureVerificationError
      return head :bad_request
    end
    head :ok
  end
end
```

---

## 7. Spring Security (Java) — Complete CSRF Implementation

### Default Configuration

```java
// Spring Security enables CSRF by default
// No configuration needed to enable it

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            // CSRF enabled by default — .csrf() not needed
            .authorizeRequests()
                .anyRequest().authenticated()
                .and()
            .formLogin();
    }
}
```

### CSRF Token Storage Options

```java
// Option 1: HttpSessionCsrfTokenRepository (DEFAULT)
// Token stored in server-side HttpSession
// Embedded in forms via Thymeleaf:
// <input type="hidden" th:name="${_csrf.parameterName}" th:value="${_csrf.token}"/>
// OR Spring Security form tag handles it automatically

// Option 2: CookieCsrfTokenRepository (for SPAs)
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .csrf()
                .csrfTokenRepository(
                    CookieCsrfTokenRepository.withHttpOnlyFalse()
                    // withHttpOnlyFalse() → Angular/React can read cookie
                    // Default is HttpOnly=true → JS cannot read → SPA breaks
                )
    }
}

// Angular reads XSRF-TOKEN cookie automatically (built-in HttpClient)
// React must manually read cookie and send in X-XSRF-TOKEN header
```

### Spring CSRF Token Header Names

```
Default parameter name: _csrf
Default header name:    X-CSRF-TOKEN
Cookie name (CookieRepo): XSRF-TOKEN
Cookie header name:     X-XSRF-TOKEN

Angular HttpClient automatically:
  Reads XSRF-TOKEN cookie
  Sends X-XSRF-TOKEN header
  → Works with CookieCsrfTokenRepository out of the box

React must manually:
  Read document.cookie for XSRF-TOKEN
  Set X-XSRF-TOKEN header on each request
```

### Disabling for Specific Paths

```java
@Override
protected void configure(HttpSecurity http) throws Exception {
    http
        .csrf()
            .ignoringAntMatchers("/api/webhooks/**")  // exempt webhooks
            .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
        .and()
        .authorizeRequests()
            .antMatchers("/api/webhooks/**").permitAll()
            .anyRequest().authenticated();
}
```

---

## 8. Spring Security — Common Mistakes and Misconfigurations

```java
// MISTAKE 1: .csrf().disable() from REST tutorial copypasta
// Every Spring Boot REST tutorial shows this
// Appropriate ONLY for fully stateless JWT (no cookies anywhere)
// DANGEROUS when session cookies or remember-me are in use
@Override
protected void configure(HttpSecurity http) throws Exception {
    http
        .csrf().disable()  // ← dangerous if any cookie auth exists
        .sessionManagement()
        .sessionCreationPolicy(SessionCreationPolicy.STATELESS);
}

// MISTAKE 2: .csrf().disable() + remember-me
http
    .csrf().disable()       // disabled
    .rememberMe()           // sets persistent cookie → ambient auth
    .rememberMeParameter("remember-me")
    .tokenValiditySeconds(2592000);
// All endpoints authenticatable via remember-me cookie
// No CSRF protection → all vulnerable

// MISTAKE 3: CookieCsrfTokenRepository without withHttpOnlyFalse()
.csrfTokenRepository(new CookieCsrfTokenRepository())
// XSRF-TOKEN cookie is HttpOnly
// Angular/React cannot read it
// All POST requests fail with 403
// Developer "fixes" by disabling CSRF

// MISTAKE 4: Overly broad ignoringAntMatchers
.csrf()
    .ignoringAntMatchers("/api/**")
// All /api endpoints lose CSRF protection
// If /api endpoints use session auth → all vulnerable

// MISTAKE 5: Method security without CSRF
// @PreAuthorize on methods doesn't add CSRF protection
// CSRF must be at the HTTP security config level
@PreAuthorize("hasRole('USER')")
public void transferFunds(String to, BigDecimal amount) {
    // method secured but HTTP endpoint may not have CSRF
}

// CORRECT: Stateless JWT — safe to disable CSRF
http
    .csrf().disable()
    .sessionManagement()
        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
    .and()
    .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
// No cookies = no ambient authority = no CSRF risk
// .csrf().disable() is CORRECT here
```

---

## 9. Express.js (Node.js) — No Built-In CSRF Protection

Express provides no CSRF protection by default. Every Express app must explicitly add it.

### The Problem

```javascript
// Default Express setup with Passport session auth:
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({ secret: process.env.SESSION_SECRET }));
app.use(passport.initialize());
app.use(passport.session());

// State-changing route — NO CSRF PROTECTION:
app.post('/transfer', isAuthenticated, (req, res) => {
  processTransfer(req.user, req.body.to, req.body.amount);
  res.json({ status: 'success' });
});
// Session cookie sent automatically, no token required → CSRF vulnerable
```

### Modern Express CSRF Solution

```javascript
// csrf-csrf package (replacement for deprecated csurf)
const { doubleCsrf } = require('csrf-csrf');

const {
  invalidCsrfTokenError,
  generateToken,
  validateRequest,
  doubleCsrfProtection,
} = doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET,
  cookieName: '__Host-psifi.x-csrf-token',
  cookieOptions: {
    sameSite: 'lax',
    secure: true,
    httpOnly: true,
  },
  size: 64,
  getTokenFromRequest: (req) =>
    req.headers['x-csrf-token'] || req.body?._csrf,
});

// Apply globally BEFORE routes:
app.use(doubleCsrfProtection);

// Endpoint to get CSRF token (SPA first load):
app.get('/api/csrf-token', (req, res) => {
  const token = generateToken(res, req);
  res.json({ csrfToken: token });
});

// Error handler for CSRF failures:
app.use((err, req, res, next) => {
  if (err === invalidCsrfTokenError) {
    return res.status(403).json({ error: 'Invalid CSRF token' });
  }
  next(err);
});
```

### Express Middleware Order — Critical

```javascript
// WRONG — middleware after routes never runs for those routes:
app.post('/transfer', handler);    // route registered first
app.use(csrfMiddleware);           // middleware after — never runs for /transfer

// CORRECT — middleware before all routes:
app.use(sessionMiddleware);
app.use(csrfMiddleware);           // CSRF before routes
app.post('/transfer', handler);    // now protected
app.get('/transfer', readHandler); // GET — CSRF typically not checked

// ALSO WRONG — CSRF before session (can't validate without session):
app.use(csrfMiddleware);  // needs session to store/read token
app.use(sessionMiddleware);
// Fix: session → CSRF → routes
```

---

## 10. Laravel (PHP) — CSRF Implementation

```php
// Laravel includes VerifyCsrfToken middleware by default
// app/Http/Middleware/VerifyCsrfToken.php

class VerifyCsrfToken extends Middleware
{
    // Routes exempted from CSRF verification
    protected $except = [
        'stripe/*',           // webhook endpoints
        'api/*',              // API routes (if using token auth)
    ];
}

// Laravel generates token: csrf_token() helper
// Blade template: @csrf or {{ csrf_field() }}
// → <input type="hidden" name="_token" value="xK9mP2...">

// AJAX: X-CSRF-TOKEN header OR _token in body
// Laravel reads: X-CSRF-TOKEN header or _token field
// Also accepts: XSRF-TOKEN cookie (for Angular)
```

### Laravel Mistakes

```php
// MISTAKE 1: Blanket API exemption with session auth
protected $except = [
    'api/*',  // ALL API routes exempt
];
// If API uses session cookies → all API endpoints CSRF-vulnerable

// MISTAKE 2: Disabling middleware globally
// Removing VerifyCsrfToken from $middlewareGroups['web']
// All web routes lose protection

// CORRECT: Separate web (CSRF) and API (token auth)
// routes/web.php   → session auth + CSRF (VerifyCsrfToken active)
// routes/api.php   → Sanctum/Passport token auth (no CSRF needed)
```

---

## 11. ASP.NET Core — CSRF Implementation

```csharp
// ASP.NET Core uses Antiforgery middleware
// Enabled by default for Razor Pages
// Must be explicitly added for MVC

// Startup.cs / Program.cs
builder.Services.AddAntiforgery(options => {
    options.HeaderName = "X-CSRF-TOKEN";   // custom header name
    options.Cookie.Name = "XSRF-TOKEN";    // cookie name
    options.Cookie.HttpOnly = false;       // allow JS to read (for SPA)
});

// Controller attribute options:
[AutoValidateAntiforgeryToken]  // validates on all unsafe methods
[ValidateAntiForgeryToken]      // validates on specific action
[IgnoreAntiforgeryToken]        // exempts the action

// API Controllers:
[ApiController]
// ApiController attribute disables antiforgery by default
// If session auth used: must re-enable explicitly

// Razor Pages — automatic:
// All POST handlers automatically validated
// @Html.AntiForgeryToken() in forms
```

---

## 12. Framework CSRF Comparison Table

```
┌──────────────┬───────────────┬────────────────────┬──────────────────────────┐
│ Framework    │ Default State │ Token Locations     │ Common Disable Pattern   │
├──────────────┼───────────────┼────────────────────┼──────────────────────────┤
│ Django       │ ENABLED       │ Cookie (readable)  │ @csrf_exempt decorator   │
│              │ via middleware│ Body: csrfmiddleware│ Commenting out middleware│
│              │               │ Header: X-CSRFToken │                          │
├──────────────┼───────────────┼────────────────────┼──────────────────────────┤
│ Rails        │ ENABLED       │ Session store      │ skip_before_action       │
│ (Base)       │ protect_from  │ Body: authenticity_│ Using API mode           │
│              │ _forgery      │ token              │ protect_from_forgery     │
│              │               │ Header: X-CSRF-Token│ with: :null_session     │
├──────────────┼───────────────┼────────────────────┼──────────────────────────┤
│ Rails        │ DISABLED      │ N/A                │ N/A (never enabled)      │
│ (API mode)   │               │                    │                          │
├──────────────┼───────────────┼────────────────────┼──────────────────────────┤
│ Spring       │ ENABLED       │ Session or Cookie  │ .csrf().disable()        │
│ Security     │               │ Header: X-CSRF-TOKEN│ common in tutorials     │
│              │               │ Cookie: XSRF-TOKEN  │                          │
├──────────────┼───────────────┼────────────────────┼──────────────────────────┤
│ Express.js   │ DISABLED      │ N/A (must add      │ N/A (never added)        │
│              │ (no built-in) │ manually)           │                          │
├──────────────┼───────────────┼────────────────────┼──────────────────────────┤
│ Laravel      │ ENABLED       │ Session            │ $except array in         │
│              │               │ Body: _token        │ VerifyCsrfToken          │
│              │               │ Header: X-CSRF-TOKEN│                          │
├──────────────┼───────────────┼────────────────────┼──────────────────────────┤
│ ASP.NET Core │ ENABLED       │ Cookie + header    │ [IgnoreAntiforgeryToken] │
│              │ (Razor Pages) │ X-CSRF-TOKEN        │ [ApiController] disables │
│              │ Manual (MVC)  │                    │                          │
└──────────────┴───────────────┴────────────────────┴──────────────────────────┘
```

---

## 13. The Webhook Exemption Pattern

Webhooks legitimately require CSRF exemption. But exemption must be paired with authentication.

### Why Webhooks Don't Need CSRF

```
CSRF protects against: browser-based ambient credential attacks
Webhooks come from:    payment provider servers (not browsers)

Payment provider servers:
  Do NOT have session cookies
  Do NOT carry ambient browser credentials
  Are server-to-server HTTP calls
  → Traditional CSRF model does not apply

What webhooks DO need protection against:
  Fake webhook payloads from attackers
  Replay attacks
  Payload tampering

CSRF exemption: CORRECT for webhooks
Replacement control: Webhook signature verification (REQUIRED)
```

### Correct Webhook Implementation (Django)

```python
import hmac
import hashlib
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

@csrf_exempt
@require_POST
def stripe_webhook(request):
    payload = request.body
    sig = request.headers.get('Stripe-Signature', '')
    
    expected = 'sha256=' + hmac.new(
        settings.STRIPE_WEBHOOK_SECRET.encode(),
        payload,
        hashlib.sha256
    ).hexdigest()
    
    if not hmac.compare_digest(expected, sig):
        return HttpResponse(status=403)  # Signature invalid
    
    # Process verified webhook payload
    import json
    event = json.loads(payload)
    handle_event(event)
    return JsonResponse({'status': 'received'})
```

### Security Consequence Without Signature Verification

```
@csrf_exempt + no auth on webhook endpoint:
  Any attacker can POST fake payment events
  Attacker can fake "payment successful" → get goods without paying
  Attacker can fake "subscription upgraded" → get premium access
  Attacker can replay legitimate events → double-process payments

@csrf_exempt + signature verification:
  Only the payment provider (with the shared secret) can send valid events
  Replay attacks require valid signature → time-limited via timestamp check
```

---

## 14. Mobile API Authentication — The Correct Pattern

The correct solution when developers reach for `@csrf_exempt` to support mobile apps.

### The Wrong Approach

```python
# WRONG: @csrf_exempt to support mobile
@csrf_exempt
@login_required  # session-cookie based
def transfer(request):
    pass
# Web users: CSRF vulnerable
# Mobile users: use session cookies (also vulnerable)
```

### The Correct Approach — Split Authentication

```python
# CORRECT: Token auth for mobile, session auth for web

# Mobile API views — use token authentication
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView

class TransferAPIView(APIView):
    authentication_classes = [TokenAuthentication]  # explicit, not ambient
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        # No @csrf_exempt needed — token auth has no ambient authority
        amount = request.data.get('amount')
        to = request.data.get('to')
        process_transfer(request.user, to, amount)
        return Response({'status': 'success'})

# Web views — use session authentication with CSRF
@login_required
def web_transfer(request):
    if request.method == 'POST':
        # Protected by CsrfViewMiddleware
        amount = request.POST.get('amount')
        to = request.POST.get('to')
        process_transfer(request.user, to, amount)
        return JsonResponse({'status': 'success'})
```

### Mobile Token Flow

```
Mobile app authentication:
  1. Mobile sends credentials: POST /api/auth/login {username, password}
  2. Server returns token: {"token": "9944b09199c62bcf..."}
  3. Mobile stores token securely (Keychain/Keystore)
  4. Every API request:
     Authorization: Bearer 9944b09199c62bcf...
  5. Browser does NOT automatically attach Authorization header
  6. Forged requests (form, img, meta) cannot include the token
  → No CSRF risk

Why this eliminates CSRF:
  No ambient authority (token not automatically sent)
  Token requires explicit application code to attach
  HTML forms and image tags cannot set Authorization header
```

---

## 15. The Remember-Me Cookie Trap

Adding remember-me cookie authentication to an application introduces CSRF risk even if CSRF was previously unnecessary.

```
SCENARIO:
  Application uses JWT in Authorization header (CSRF safe)
  Developer adds "remember me" feature:
    Set-Cookie: remember=xyz; Max-Age=2592000; HttpOnly; Secure

  API endpoint logic:
    if valid_jwt_in_header OR valid_remember_cookie:
        authenticate_request()

CSRF RISK INTRODUCED:
  Before: no cookies → no ambient authority → CSRF safe
  After:  remember cookie → browser attaches automatically
          Any endpoint accepting remember cookie = CSRF vulnerable

SPECIFIC SPRING SECURITY EXAMPLE:
  http.csrf().disable()        // disabled (was safe with JWT-only)
  http.rememberMe()...         // adds remember-me cookie
  
  All authenticated endpoints now accept the remember-me cookie
  All those endpoints are now CSRF-vulnerable
  .csrf().disable() + .rememberMe() = critical misconfiguration

FIX:
  Option 1: Add CSRF protection when adding cookie-based auth
  Option 2: Ensure remember-me endpoints always require re-auth
  Option 3: Use refresh tokens instead of remember-me cookies
```

---

## 16. Middleware Order — Why It Matters

Framework middleware runs in a specific order. Getting it wrong silently breaks security.

```
DJANGO — correct order:
  SessionMiddleware     (must come before CSRF)
  CsrfViewMiddleware   (needs session to validate token)
  AuthMiddleware       (runs after CSRF — user identified after token check)

If CSRF before Session:
  CsrfViewMiddleware cannot read session → cannot validate token → error

EXPRESS — correct order:
  session()      (create session)
  csrfMiddleware (needs session for token storage)
  routes         (protected by CSRF middleware above)

If routes before CSRF middleware:
  Those routes are never protected by CSRF middleware

RAILS — correct order (automatic):
  Rails handles middleware order internally
  before_action callbacks run in declaration order within controller
  skip_before_action with only: affects specific actions only

SPRING SECURITY — filter chain order:
  SecurityContextPersistenceFilter  (loads security context)
  CsrfFilter                        (validates CSRF token)
  UsernamePasswordAuthenticationFilter (authenticates user)
  
  Configured via HttpSecurity — Spring Security manages order automatically
```

---

## 17. Framework Audit Checklist

### Django Audit

```
□ Is CsrfViewMiddleware in MIDDLEWARE and NOT commented out?
□ Search for: grep -r "csrf_exempt" . — audit every occurrence
□ For each @csrf_exempt: is there alternative auth (token/signature)?
□ Is CSRF_COOKIE_HTTPONLY = True anywhere? (breaks SPA)
□ Does SPA send X-CSRFToken header (not JSON body field)?
□ Are state-changing GET endpoints present?
□ Are DRF views using SessionAuthentication? (CSRF enforced)
□ Are webhook views protected by HMAC signature verification?
□ Is session cookie set with explicit SameSite attribute?
```

### Rails Audit

```
□ Is protect_from_forgery in ApplicationController?
□ Is :null_session used? (silent bypass risk)
□ Search for: grep -r "skip_before_action.*verify_authenticity" .
□ Is the app using ActionController::API? (no CSRF)
□ For API controllers: is alternative auth in place?
□ Are webhook controllers using signature verification?
□ Does SPA send X-CSRF-Token header?
□ Are API routes using session cookies? (should use token auth)
```

### Spring Security Audit

```
□ Search for: .csrf().disable() — is it justified?
□ If disabled: confirm ONLY stateless JWT used (no cookies anywhere)
□ Is remember-me enabled? (requires CSRF even with JWT)
□ Is CookieCsrfTokenRepository.withHttpOnlyFalse() used for SPAs?
□ Check .ignoringAntMatchers() — are those paths truly safe?
□ Are Angular/React clients reading and sending CSRF token/cookie?
□ Is session creation policy STATELESS for JWT endpoints?
```

### Express Audit

```
□ Is any CSRF middleware in the dependency list?
□ Is csurf used? (deprecated — flag for replacement)
□ Is CSRF middleware applied BEFORE route definitions?
□ Is session middleware applied BEFORE CSRF middleware?
□ Are session-authenticated endpoints explicitly protected?
□ Are JWT-only endpoints identified as CSRF-safe?
□ Does error handler catch CSRF failures specifically?
```

### All Frameworks

```
□ Are state-changing GET endpoints present? (bypass all CSRF)
□ Are session cookies set with explicit SameSite=Lax or Strict?
□ Is CORS policy correctly configured? (no origin reflection)
□ Are webhook/callback endpoints using signature verification?
□ Is mobile API using token auth (not session cookies)?
□ Are remember-me / persistent cookies paired with CSRF protection?
□ Is CSRF token invalidated on logout?
```

---

## 18. Key Terminology Reference

| Term | Definition |
|------|------------|
| **Opt-out CSRF model** | CSRF enabled globally; developers explicitly exempt views; safer default |
| **Opt-in CSRF model** | CSRF disabled by default; developers must enable; dangerous default |
| **@csrf_exempt** | Django decorator that removes CSRF protection from a specific view |
| **csrf_protect** | Django decorator that adds CSRF protection even if middleware disabled |
| **ensure_csrf_cookie** | Django decorator that forces csrftoken cookie to be set in response |
| **protect_from_forgery** | Rails method enabling CSRF protection in ApplicationController |
| **:null_session** | Rails CSRF failure option that silently provides empty session (dangerous) |
| **:exception** | Rails CSRF failure option that raises exception and halts request (correct) |
| **skip_before_action** | Rails method to exempt specific actions from before_action callbacks |
| **ActionController::API** | Rails API-mode base class — no CSRF protection included |
| **.csrf().disable()** | Spring Security method disabling all CSRF protection (common mistake) |
| **CookieCsrfTokenRepository** | Spring Security CSRF token storage in cookie (for SPAs) |
| **withHttpOnlyFalse()** | Spring Security option making CSRF cookie JS-readable (required for SPA) |
| **VerifyCsrfToken** | Laravel middleware handling CSRF validation |
| **$except** | Laravel array of routes exempted from CSRF verification |
| **[IgnoreAntiforgeryToken]** | ASP.NET Core attribute exempting action from antiforgery validation |
| **Webhook signature** | HMAC-based authentication for server-to-server webhook payloads |
| **csurf** | Deprecated Node.js CSRF middleware — should not be used in new projects |
| **csrf-csrf** | Modern replacement for csurf in Express.js applications |
| **DRF** | Django REST Framework — CSRF behavior depends on authentication class used |

---

## 19. Common Misconceptions

### ❌ "CsrfViewMiddleware being present means all views are protected"
**Wrong.** `@csrf_exempt` on individual views or an entire base class silently removes protection. Presence of middleware in `MIDDLEWARE` list is necessary but not sufficient — all views must avoid `@csrf_exempt`.

### ❌ "Rails API mode has the same CSRF protection as Base mode"
**Wrong.** `ActionController::API` does not include `protect_from_forgery`. Applications using API mode with session-based authentication have no CSRF protection and must add it explicitly.

### ❌ ".csrf().disable() is safe for REST APIs"
**Conditionally true.** It is safe ONLY when authentication is purely stateless (JWT in Authorization header, no cookies of any kind). It is dangerous when session cookies, remember-me cookies, or any cookie-based auth is present.

### ❌ "Express has CSRF protection by default"
**Wrong.** Express has no built-in CSRF protection. Every Express application with session-based authentication must explicitly add CSRF middleware before route definitions.

### ❌ "@csrf_exempt is necessary for mobile API support"
**Wrong.** The correct solution is switching mobile clients to token-based authentication (Authorization: Bearer header). This eliminates ambient authority and makes CSRF tokens unnecessary without exempting the endpoint.

### ❌ "protect_from_forgery with: :null_session is safe"
**Wrong.** `:null_session` silently provides an empty session and allows the action to execute. No error is raised, no alert triggered. `:exception` is the correct option — it halts execution and raises a loggable error.

### ❌ "Adding CSRF middleware anywhere in the stack is sufficient"
**Wrong.** Middleware order matters. In Express, middleware defined after routes never runs for those routes. In Django, `CsrfViewMiddleware` must come after `SessionMiddleware` to have access to session data.

### ❌ "The csrftoken cookie being HttpOnly improves security"
**Wrong in most contexts.** `CSRF_COOKIE_HTTPONLY = True` prevents JavaScript from reading the cookie. Since SPAs need to read this cookie to include the token in requests, HttpOnly breaks SPA integration. The `csrftoken` cookie being readable by JavaScript is intentional Django design — the security comes from the server-side validation, not from keeping the cookie secret.

---

## 20. Bug Bounty Reference

### Code Review Targets

```
HIGHEST PRIORITY (search these patterns):

Django:
  grep -rn "csrf_exempt" .
  grep -rn "CsrfViewMiddleware" settings.py  # check if commented
  grep -rn "CSRF_COOKIE_HTTPONLY" .

Rails:
  grep -rn "skip_before_action.*verify_authenticity" .
  grep -rn "ActionController::API" .
  grep -rn "null_session" .

Spring:
  grep -rn "csrf().disable()" .
  grep -rn "rememberMe()" .
  grep -rn "ignoringAntMatchers" .

Express:
  grep -rn "csrf" package.json  # is any CSRF package present?
  grep -rn "app.use.*csrf" .    # is middleware applied?

All:
  Search for webhook/callback endpoints without auth
  Search for state-changing GET routes
```

### Framework-Specific Severity Notes

```
Django @csrf_exempt on financial endpoint:
  Severity: Critical (if session auth in place)
  Note: Exempt decorator + session cookie = CSRF vulnerable

Rails API mode + session auth:
  Severity: Critical (all endpoints affected)
  Note: No CSRF on any endpoint — scope is entire application

Spring .csrf().disable() + rememberMe:
  Severity: Critical (all endpoints)
  Note: remember-me cookie = ambient auth = full CSRF surface

Express with no CSRF middleware:
  Severity: Critical (all session-auth endpoints)
  Note: No middleware = no protection on any route
```

---

## 21. Module 9 Summary — What You Must Know Cold

```
MODEL TYPES:
✓ Opt-out (Django/Rails/Spring/Laravel): enabled by default, exemptions disable
✓ Opt-in (Express, Rails API): disabled by default, must add explicitly
✓ Opt-out is safer; opt-in requires vigilance on every new endpoint

DJANGO:
✓ CsrfViewMiddleware runs BEFORE AuthenticationMiddleware
✓ Token locations: X-CSRFToken header OR csrfmiddlewaretoken in body
✓ JSON body token: INVISIBLE to Django — must use X-CSRFToken header
✓ CSRF_COOKIE_HTTPONLY = True breaks SPA integration
✓ DRF: SessionAuthentication enforces CSRF; TokenAuthentication does not
✓ @csrf_exempt = no protection; must pair with alternative auth

RAILS:
✓ ActionController::API = no CSRF protection
✓ :null_session = action executes with empty session, no error raised
✓ :exception = correct; halts request, raises exception
✓ skip_before_action too broadly = global disable

SPRING SECURITY:
✓ .csrf().disable() = safe ONLY with fully stateless JWT (no cookies)
✓ .csrf().disable() + .rememberMe() = critical misconfiguration
✓ CookieCsrfTokenRepository.withHttpOnlyFalse() required for SPA
✓ Common tutorial pattern (.csrf().disable()) is dangerous with cookies

EXPRESS:
✓ No built-in CSRF protection
✓ csurf is deprecated — use csrf-csrf or equivalent
✓ Middleware must be defined BEFORE route definitions
✓ Session → CSRF → routes is the correct order

WEBHOOKS:
✓ @csrf_exempt is CORRECT for webhooks (server-to-server, no browser cookies)
✓ Replacement control: HMAC webhook signature verification
✓ Without signature verification: any attacker can fake webhook events

MOBILE API:
✓ @csrf_exempt is WRONG solution for mobile support
✓ Correct: switch mobile to token auth (Authorization: Bearer)
✓ Token in header = explicit attachment = no ambient authority = no CSRF
✓ Web: session + CSRF token | Mobile: Bearer token, no CSRF needed

REMEMBER-ME:
✓ Any cookie-based auth path introduces CSRF risk
✓ .csrf().disable() + cookie auth = critical vulnerability
✓ Adding remember-me to JWT app reintroduces CSRF surface
```

---

*Next: Module 10 — Real CVEs & Case Studies*  
*Selected real-world CSRF disclosures, what developers assumed,*
*what researchers found, how severity was scoped,*
*and what defense failures enabled each exploit*