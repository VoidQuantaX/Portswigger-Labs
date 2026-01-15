# Lab-1 💰 Business Logic Vulnerability – Price Manipulation

(Complete & Real-World Notes)

---

## 🔹 Overview

Price manipulation is a business logic vulnerability where an application allows users to control or influence the price of a product during the purchase workflow.

The application does not have a technical flaw — it behaves exactly as designed — but the design itself is insecure.

This vulnerability often results in:

- Free or discounted purchases
- Financial loss
- Refund abuse
- Unlimited balance creation

Price manipulation is one of the most common real-world causes of business loss in e-commerce systems.

---

## 🔹 What Is This Topic?

This is a **Business Logic / Insecure Design** vulnerability where:

> Critical business values are accepted from the client instead of being enforced server-side.

The server trusts:

- Client-supplied prices
- Cart values
- Order totals

Attackers simply change values — no exploitation skills required.

---

## 🔹 Lab Walkthrough (Simple & Clear)

### 1️⃣ Login as Normal User

```
Username: wiener
Password: peter
```

Check account balance:

```
Balance: $100.00
```

📌 Product price is higher than available balance.

---

### 2️⃣ View Expensive Product

- Product price shown: `$1300`
- Add product to cart
- Attempt checkout → **fails due to low balance**

---

### 3️⃣ Identify Vulnerable Flow

Cart update request:

```
POST /cart HTTP/2
```

Intercept request using Burp Suite.

---

### 4️⃣ Observe Client-Controlled Parameters

Example parameters in request:

```
productId=1
quantity=1
price=1300
```

📌 **`price` is fully client-controlled**

---

### 5️⃣ Modify the Price Parameter

Change:

```
price=1300
```

to:

```
price=1
```

---

### 6️⃣ Forward the Request

- Server accepts modified value
- No validation or recalculation performed

---

### 7️⃣ Verify Cart

- Product price now shows as `$1`
- Cart total updated accordingly

---

### 8️⃣ Complete Checkout

```
POST /cart/checkout HTTP/2
```

- Purchase succeeds
- Balance reduced by `$1`

✅ Lab solved

---

## 🔹 Evidence

### 🖼️ Screenshot

- ![Price parameter modified in POST /cart request](../images/price-manipulation-cart.png)

---

## 🔹 Real-World Scenarios (100% COMPLETE – NO GAPS)

### 1️⃣ Client-Side Price Control (Most Common)

Prices sent via:

- `POST /cart`
- `POST /checkout`

📌 Impact:

- Free purchases
- Discount abuse
- Revenue loss

---

### 2️⃣ Mobile App API Abuse

Mobile APIs often send:

- price
- total
- discount

📌 Impact:

- API tampering
- Scalable abuse
- No UI limitations

---

### 3️⃣ Currency Manipulation

Example:

```
price=100
currency=USD → change to weaker currency
```

📌 Impact:

- Pay far less than intended
- Accounting inconsistencies

---

### 4️⃣ Quantity × Price Logic Flaws

Example:

```
quantity=999
price recalculated incorrectly
```

📌 Impact:

- Bulk items for free
- Inventory abuse

---

### 5️⃣ Coupon + Price Chain Abuse

- Price lowered manually
- Coupon applied afterward

📌 Impact:

- Negative totals
- Store credit generation

---

### 6️⃣ Refund Abuse After Price Manipulation

- Buy item cheaply
- Refund at original price

📌 Impact:

- Unlimited money creation

---

### 7️⃣ Third-Party Payment Integration Issues

Mismatch between:

- Application price
- Payment gateway price

📌 Impact:

- Partial payments
- Payment bypass

---

## 🔹 High-Value Parameters to Always Test

Critical parameters:

- price
- total
- amount
- subtotal
- discount
- coupon
- currency
- quantity
- shipping_cost
- tax

🔴 If any are client-controlled → **critical severity**

---

## 🔹 Multi-Chain Attacks (Real Hacker Paths)

### Chain 1 – Direct Loss

```
Price manipulation
→ Free purchase
→ Financial loss
```

---

### Chain 2 – Infinite Money

```
Price manipulation
→ Purchase
→ Refund
→ Balance increases
→ Repeat
```

---

### Chain 3 – Coupon + Price Abuse

```
Lower price
→ Apply coupon
→ Negative checkout total
→ Credit issued
```

---

### Chain 4 – Logic → Account Takeover

```
Free premium upgrade
→ Premium access
→ Sensitive data exposure
```

---

## 🔹 Why This Is Hard to Detect

- No errors
- No crashes
- Valid workflows
- Looks normal

Automated scanners ❌  
Manual logic testing ✅

---

## 🔹 Remediation (Developer Fix)

### ✅ Correct Fixes

- Calculate prices server-side only
- Ignore client-supplied price values
- Recalculate cart during checkout
- Validate totals against database
- Enforce strict business rules

---

### ❌ Never

- Trust frontend prices
- Accept POSTed totals
- Assume users follow UI flow
- Rely on JavaScript validation

---

## 🔹 Extra Notes / Pentest Gold

🧠 **Golden Rule**

> If the client controls money, the attacker controls the business.

🔥 **Red Flags**

- `price` parameter in requests
- `total` sent from frontend
- No server-side recalculation
- UI/backend mismatch

📌 Classification:

- OWASP A04 – Insecure Design
- Severity: High → Critical

---

## 🧠 One-Line Memory Hook

> Business logic bugs don’t break code — they break companies.

---

# Lab-2 🛡️ Business Logic Vulnerability – Flawed 2FA Logic
## (Complete & Real-World)

---

## 🔹 Overview

Flawed 2FA logic vulnerabilities occur when an application implements multi-factor authentication but fails to correctly bind the OTP to the **right user, session, or authentication flow**.

Instead of attacking cryptography, attackers exploit **logic assumptions** made by the application.

**Impact includes:**
- Account takeover
- Authentication bypass
- Privilege escalation

This vulnerability is **extremely common** in custom-built authentication systems.

---

## 🔹 What Is This Topic?

This is a **Business Logic / Insecure Design** vulnerability.

**Core mistake:**

> The application trusts client-controlled identity parameters during 2FA.

In flawed 2FA implementations:
- OTP is generated
- OTP is verified
- ❌ OTP is NOT securely bound to:
  - The correct user
  - The correct session
  - The correct authentication step

⚠️ If identity can be controlled by the client, **2FA provides zero security**.

---

## 🔹 Lab Walkthrough (Clear & Exact)

### 🎯 Objective

Authenticate as **carlos** without knowing his password by abusing flawed 2FA logic.

---

### 1️⃣ Observe Normal Authentication Flow

- Login using valid credentials:

  - **Username:** wiener  
  - **Password:** peter

- Server flow:
  - `POST /login`
  - Redirect → `/login2`

- Observe parameters used during 2FA:
  - `verify`
  - `mfa-code`

📌 Purpose: understand how OTP generation and verification works.

---

### 2️⃣ Generate OTP for Victim User

- Log out from the application
- Manually access:

  `GET /login2?verify=carlos`

**Result:**
- Server generates an OTP for **carlos**
- No authentication required ❌

📌 Critical flaw: OTP generation depends solely on a client-controlled parameter.

---

### 3️⃣ Start Legitimate Login as Attacker

- Login again as:

  - **Username:** wiener  
  - **Password:** peter

- Reach the OTP verification step
- Submit any random OTP
- Intercept the request:

  `POST /login2`

---

### 4️⃣ Brute-Force OTP for Victim

- Send the intercepted request to Intruder
- Configure payloads:

  - `verify=carlos` (fixed)
  - `mfa-code=§000000§`

- Payload range:
  - `000000` → `999999`

- Start attack

---

### 5️⃣ Identify Successful Authentication

Success indicators:
- HTTP 302 redirect
- Different response length
- Access to victim account

Open successful request → authenticated as **carlos**.

---

### 6️⃣ Complete the Lab

- Access **My Account**
- Confirm victim login

✅ **Lab solved**

---

## 🔹 Evidence (SS)

### Screenshot-1
- ![OTP generated for victim via verify parameter](../images/otp-generation-carlos.png)

  ### Screenshot-2
- ![OTP brute force authentication as victim](../images/otp-bruteforce-success.png)

---

## 🔹 Real-World Scenarios (NO SKIPS)

### 1️⃣ OTP User Binding Failure
- OTP tied to `verify=username`
- Attacker modifies parameter

**Impact:** account takeover

---

### 2️⃣ OTP Brute Force (No Rate Limiting)
- Unlimited OTP attempts

**Impact:** full authentication bypass

---

### 3️⃣ OTP Reuse
- OTP remains valid after use

**Impact:** replay attacks

---

### 4️⃣ OTP Session Confusion
- OTP generated in one session
- Used in another

**Impact:** cross-session takeover

---

### 5️⃣ Password Reset OTP Misbinding
- OTP not bound to email/user

**Impact:** reset victim password

---

### 6️⃣ Debug / Test OTPs
- Static OTPs like `000000`

**Impact:** universal bypass

---

### 7️⃣ Frontend-Only OTP Validation
- Backend never validates OTP

**Impact:** direct API bypass

---

### 8️⃣ OAuth / SSO 2FA Bypass
- 2FA enforced at IdP only

**Impact:** login without second factor

---

## 🔹 High-Value Endpoints to Test

- `/login`
- `/login2`
- `/verify`
- `/otp`
- `/mfa`
- `/2fa`
- `/reset`

🔴 Any **user-controlled identity parameter** = critical risk.

---

## 🔹 Multi-Chain Attacks

### Chain 1
- OTP misbinding  
→ OTP brute force  
→ Account takeover

---

### Chain 2
- OTP bypass  
→ Password reset  
→ Permanent takeover

---

### Chain 3
- XSS  
→ OTP/session theft  
→ Privilege escalation

---

## 🔹 Remediation (Correct Fix Only)

### ✅ Proper Fixes
- Bind OTP to **user + session + step**
- Enforce strict rate limiting
- Single-use OTPs
- Regenerate session after auth
- Enforce 2FA on sensitive actions

---

### ❌ Never
- Trust `verify` parameters
- Separate OTP generation & verification
- Allow OTP reuse
- Rely on frontend validation

---

## 🔹 Extra Notes (Exam + Pentest)

**Golden Rule:**

> OTP without binding is not authentication.

**Red Flags:**
- `verify=username`
- Public OTP endpoints
- No rate limiting
- Same OTP works twice

**Severity:**
- OWASP A04 – Insecure Design
- High → Critical

---

## 🧠 One-Line Memory Hook

> 2FA fails not when OTP is weak — but when logic is weak.
