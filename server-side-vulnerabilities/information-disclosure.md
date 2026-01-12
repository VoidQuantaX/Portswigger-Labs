
# Lab-1 ❌ Information Disclosure – Verbose Error Messages  
## Third-Party Vulnerable Framework Disclosure

---

## 1️⃣ Overview

Information disclosure via verbose error messages occurs when an application reveals internal technical details during error handling.

Instead of failing safely, the application exposes implementation details that attackers can leverage for targeted attacks.

This vulnerability is especially dangerous when *third-party frameworks and exact versions* are disclosed, as it enables precise vulnerability research and exploitation.

---

## 2️⃣ What Is This Topic?

This topic focuses on *error-based information disclosure*, where attackers intentionally trigger application errors to extract sensitive backend information.

*Core security failure:*

> The application explains why it failed instead of failing silently.

Typical leaked information includes:

- Web server type  
- Backend framework name  
- Third-party library versions  
- Programming language details  
- Deployment configuration clues  

---

## 3️⃣ Lab Walkthrough

### 🎯 Goal  
Identify a vulnerable third-party framework disclosed through a verbose error message.

---

### Step 1️⃣ Normal Application Behavior

User accesses a valid product page.

Request:
- GET /product?productId=1

Server processes request successfully.  
Product details are rendered correctly.

---

### Step 2️⃣ Triggering an Error

Attacker modifies expected input type.

Request changed to:
- GET /product?productId=abc

A string is supplied where an integer is expected.

---

### Step 3️⃣ Improper Error Handling

Backend attempts to process invalid input.

Input validation is weak or missing.

An internal exception is thrown.

---

### Step 4️⃣ Information Disclosure

Server responds with a *verbose error message*.

The error reveals:

- Third-party framework name  
- Underlying web server (Apache x.x.y.y)  
- Exact framework/server version  

This version corresponds to a *known vulnerable release*.

---

### Step 5️⃣ Lab Completion

Disclosed vulnerable framework version is submitted.

✅ Lab solved.

---

## 📸 Evidence - Screnshot of verbose error message revealing third party framework

![verbose error message revealing third party framework
](../images/verbose-error-info-disclosure.png)

---

## 4️⃣ Real-World Scenarios (Methodology)

### Attacker Methodology

1. Identify user-controlled input parameters  
   - IDs  
   - Numeric fields  
   - Query parameters  

2. Break input expectations  
   - Numbers → strings  
   - Missing parameters  
   - Malformed values  

3. Observe error responses carefully  
   - Response body  
   - HTTP headers  
   - Stack traces  
   - Server banners  

4. Extract disclosed technical details  

5. Correlate with known CVEs and exploits  

---

### Real-World Impact Example

- Verbose error discloses Apache framework version  
- Attacker searches vulnerability databases  
- Public CVE found for disclosed version  
- Exploit used as entry point for deeper compromise  

---

## 5️⃣ High-Value Endpoints

Endpoints where verbose errors are most useful:
```
- /product?id=  
- /view?item=  
- /api/*  
- /search?q=  
- /login  
- /checkout  
- /upload  
- /admin/*  
```
🔴 These endpoints frequently trigger backend logic and exceptions.

---

## 6️⃣ Multi-Chain Attacks

### Example Attack Chain

1️⃣ Verbose error → framework + version disclosed  
2️⃣ Version fingerprinting → vulnerable release identified  
3️⃣ CVE research → public exploit available  
4️⃣ Exploitation → RCE / file disclosure / auth bypass  
5️⃣ Privilege escalation → full system compromise  

➡️ Information disclosure acts as a *force multiplier*, not a standalone exploit.

---

## 7️⃣ Remediation

### Correct Defensive Measures

- Disable debug mode in production  
- Use generic user-facing error messages  
- Log detailed errors server-side only  
- Enforce strict input validation  
- Suppress stack traces and server banners  

---

### What Developers Must Avoid

- Returning raw exception messages  
- Exposing framework or server versions  
- Assuming attackers won’t inspect errors  

---

# Lab-2 🐞 Information Disclosure – Debug Pages & Debugging Data
*(HTML Comment → Debug Endpoint → Secret Key Disclosure)*

---

## 🔍 Overview

Debug-related information disclosure occurs when an application exposes debug pages,
diagnostic scripts, or development data to end users.

These disclosures often reveal critical secrets such as:

- Environment variables
- Application secret keys
- Internal file paths
- Backend framework versions (Apache, PHP, etc.)

Unlike minor leaks, debug disclosures frequently lead to immediate full compromise
of the application.

This vulnerability is extremely common in real-world breaches,
especially in misconfigured production servers.

---

## 📌 What Is This Topic?

This is an **Information Disclosure** vulnerability caused by development or debugging
features left enabled in production.

Core mistake:

> Debug functionality is accessible outside the trusted developer environment.

Attackers do not guess passwords — they read what the server tells them.

---

## 🧪 Lab Walkthrough

### 🎯 Goal

Extract a secret key exposed through a debug endpoint.

### Steps

1. Load the application homepage  
2. View page source (HTML)

3. Identify a developer HTML comment revealing a hidden endpoint:

<!-- Debug endpoint: /cgi-bin/phpinfo.php -->

4. Manually access the endpoint:

GET /cgi-bin/phpinfo.php

5. Server responds with a phpinfo() debug page

6. Debug page reveals:
- Server software (Apache x.x.x)
- PHP version
- Loaded modules
- Environment variables

7. Search within the response
8. Extract sensitive value:

SECRET_KEY=xxxxxxxx

9. Submit the extracted key  
✅ Lab solved

## 📸 Evidence (SS)

### 🖼️ SS‑1: HTML Comment Disclosure

- Developer HTML comment discovered in page source
- Comment revealed a hidden internal endpoint

[HTML comment exposing hidden endpoint](../images/html-comment-info-leak.png)

---

### 🖼️ SS‑2: Manual Access to Hidden Debug Endpoint

- Hidden endpoint accessed directly via browser
- Debug page loaded successfully
- Sensitive information disclosed in response

[Debug endpoint revealing secret key](../images/debug-endpoint-info-leak.png)

---

## 🌍 Real-World Scenarios (100% COMPLETE)

### 1️⃣ Debug Pages Left in Production (MOST COMMON)

Examples:
- phpinfo.php
- debug.php
- test.php
- info.php

Impact:
- Secret keys leaked
- Session forging
- Authentication bypass

---

### 2️⃣ HTML Comments Leaking Internal Paths

Examples:
<!-- TODO: remove /internal/debug -->
<!-- Debug endpoint: /admin-test -->

Impact:
- Hidden admin/debug endpoints discovered
- Attack surface expanded instantly

---

### 3️⃣ Environment Variable Disclosure

Leaked via:
- phpinfo()
- debug dumps
- error pages

Impact:
- SECRET_KEY exposure
- JWT signing key leakage
- OAuth token compromise

---

### 4️⃣ Framework & Server Version Disclosure

Examples:
- Apache x.x.x
- PHP x.x.x
- Laravel / Django versions

Impact:
- Public CVEs identified
- Exploit selection becomes trivial

---

### 5️⃣ Debug APIs in Modern Applications

Examples:
- /debug/vars
- /status
- /metrics
- /actuator/env (Spring)

Impact:
- Cloud secrets exposed
- Internal service mapping

---

### 6️⃣ CI/CD & Development Artifacts Exposed

Examples:
- .env
- .git/
- Backup files
- Test scripts

Impact:
- Full source disclosure
- Credential reuse attacks

---

### 7️⃣ Cloud & Container Debug Endpoints

Examples:
- Kubernetes metrics
- Docker diagnostics

Impact:
- Infrastructure compromise
- Lateral movement

---

## 🎯 High-Value Endpoints to Always Test

### Debug & Diagnostic Paths
```
/cgi-bin/phpinfo.php  
/phpinfo.php  
/info.php  
/debug  
/debug.php  
/debug/vars  
/status  
/metrics  
/health  
/test  
/dev  
```
---

### Files & Configurations
```
/.env  
/.git/  
/config  
/settings  
/internal  
```
🔴 Any public access = **critical severity**

---

## 🔗 Multi-Chain Attacks (Real Hacker Paths)

### Chain 1 (Classic & Guaranteed)

HTML comment  
→ Debug endpoint  
→ SECRET_KEY leak  
→ Session forging  
→ Admin access  
→ Full takeover

---

### Chain 2 (Version → Exploit)

Debug page  
→ Apache x.x.x disclosed  
→ Public CVE identified  
→ RCE exploit  
→ Server compromise

---

### Chain 3 (Secrets → Auth Bypass)

Environment variables  
→ JWT secret leaked  
→ Token forging  
→ Authentication bypass  
→ Account takeover

---

### Chain 4 (Debug → IDOR → Data Dump)

Debug reveals internal APIs  
→ IDOR discovered  
→ User data extraction  
→ Privacy breach

---

## 🛡️ Remediation (Developer Fix)

✅ Remove all debug pages from production  
✅ Disable phpinfo and CGI scripts  
✅ Strip HTML comments before deployment  
✅ Protect environment variables  
✅ Use deny-by-default access controls  
✅ Restrict diagnostics to localhost only  

❌ NEVER:
- Leave debug endpoints accessible
- Assume “hidden” equals secure
- Trust users not to view source
- Expose secrets via diagnostics

---
