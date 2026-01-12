
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
