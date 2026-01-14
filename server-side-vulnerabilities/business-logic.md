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
