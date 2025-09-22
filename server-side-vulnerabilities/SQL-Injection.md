# SQL Injection — Lab 1: Retrieving Hidden Data

---

## 🔹 One-line summary
Injected SQL via the category parameter to bypass released = 1 and display unreleased products (proof attached).

---

## 🔹 Overview
SQL Injection (SQLi) lets attackers manipulate database queries by injecting crafted input.  
In this lab the category filter is concatenated into SQL; by altering the parameter we force the WHERE clause to return unreleased products.

---

## 🔹 Methodology

- Capture the category filter request (e.g. GET /filter?category=...) in Burp Proxy.  
- Send to Repeater and modify the category value to comment out or bypass the released = 1 check:CorporateGifts'-- // or CorporateGifts' OR 1=1--
- Forward the modified request and inspect the response for unreleased products.

---

## 🔹 Proof (evidence)

![SQLi payload injected in request (category modified)](../images/sqli-lab1-injected.png)  
(Screenshot 1: modified request showing payload CorporateGifts' OR 1=1-- in the URL/params.)

![Lab solved — unreleased products displayed after injection](../images/sqli-lab1-solved.png)  
(Screenshot 2: page showing unreleased products / PoC that the injection returned additional items.)

---

## 🔹 Impact
- Data disclosure: hidden/unreleased product data exposed.  
- Potential escalation: with additional queries an attacker can read sensitive tables, extract credentials, or modify data.

---

## 🔹 Remediation (short)
- Use *parameterized queries / prepared statements* (no string concatenation into SQL).  
- Whitelist allowed category values (e.g., only allow known categories).  
- Apply least privilege to DB user accounts and monitor for anomalous query patterns.

---
