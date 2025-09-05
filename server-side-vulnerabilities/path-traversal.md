# 🖥️ Server-Side Vulnerabilities

This section contains write-ups for *server-side vulnerabilities* from PortSwigger Web Security Academy.  
Each subtopic (Path Traversal, SQL Injection, OS Command Injection, etc.) has its own section here.

---

## 🔹 Path Traversal

### 🔍 Overview
Path Traversal (Directory Traversal) lets attackers read files outside the web root folder by manipulating file paths (e.g., ../../../etc/passwd).

### 🛠️ Lab Write-up
*Lab:* File path traversal, simple case  
*Steps Taken:*
1. Intercepted the request in Burp Suite.  
2. Modified the file path parameter with ../../../etc/passwd.  
3. Retrieved the /etc/passwd file successfully.  

### 📸 Screenshots
![Path Traversal Screenshot](./images/path-traversal-1.png)

### ✅ Mitigation
- Validate and sanitize file path inputs.  
- Use safe file APIs that block ../.  
- Enforce least privilege on server file access.  

---

(Next sections will be added as I complete more labs: SQL Injection, OS Command Injection, etc.)
