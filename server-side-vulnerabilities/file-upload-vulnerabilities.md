# File Upload Vulnerabilities – Lab: Web Shell / File Execution

---

## 🔹 Overview
This lab demonstrates a *file upload* vulnerability where the application accepts user files and serves them from a path that executes server-side code.  
By uploading a crafted file (web shell or file reader), an attacker can execute commands or read sensitive files on the server.

---

## 🔹 Why this matters
- Executing an uploaded script (PHP/JSP/ASP/Python) can lead to *full server compromise*.  
- Even if direct execution fails, uploaded files can expose sensitive files (config, credentials) or be used to pivot to other systems.  
- Many real engagements rely on the reliable two-step method: *upload benign → discover path → upload shell → execute*.

---

## 🔹 Methodology / Lab Walkthrough

*Goal:* discover the storage URL for uploads, upload an exploit file (web shell or file reader), request the stored file and obtain secret / command output.

1. *Discover upload path*
   - Upload a benign image (avatar) via the upload form.  
   - Open the account page and inspect the network request for the image GET to find the canonical stored path and any random prefix.

2. *Prepare exploit*
   - Create a small web shell or file reader, e.g.:  
     php
     <?php echo file_get_contents('/home/carlos/secret'); ?>
     
   - Name it with a plausible extension (exploit.php, exploit.phtml, or exploit.php.jpg depending on the target checks).

3. *Upload exploit*
   - Intercept the upload POST in Burp. Replace the file part with your exploit content (keep CSRF/form fields unchanged).  
   - If the site expects image Content-Type, try setting Content-Type: image/jpeg or use GIF stub trick.

4. *Request the uploaded file*
   - Use the exact GET from step 1 (same Host and session cookie) to request the stored file URL:  
     GET /files/avatars/exploit.php  
   - If the file executes, you will see the secret or command output.

5. *If execution fails*
   - Try alternate extensions, double-extension tricks, .phtml, .php5, or GIF-stub.  
   - If only source is returned (no execution), you still gain intelligence (read code) — try other upload endpoints or storage paths.

---

## 🔹 Proof of Exploit
![File upload exploit proof — web shell output / secret read](../images/file-upload-lab1.png)  
(Screenshot showing the uploaded exploit.php being executed and returning sensitive data / command output — strongest single proof.)

---

## 🔹 Security Impact
- Remote code execution → full server takeover.  
- Exposure of DB credentials, config files, SSH keys → long-term compromise.  
- Ability to pivot to internal services or maintain persistence via backdoors.

---

## 🔹 Remediation
- Validate uploads *server-side*: allowlist extensions and MIME types.  
- Validate file contents (magic bytes), but do not rely solely on it.  
- Store uploads *outside webroot* or serve them from a non-executable domain/subdomain.  
- Rename uploaded files to safe, non-executable names; never use user-supplied filenames.  
- Apply size limits, scanning, and strict ACLs for uploaded content.

---

# File Upload – Lab 2: Web-shell Upload via Content-Type Restriction Bypass

---

## 🔹 Overview
This lab demonstrates an upload restriction bypass where the application attempts to block non-image uploads by checking the multipart file-part *Content-Type* (and possibly filename).  
Because Content-Type and filename are client-controllable, an attacker can spoof these values, upload a PHP web shell, execute it, and read sensitive files (e.g., /home/carlos/secret).

---

## 🔹 Why this matters
- Relying only on client-supplied headers or filename checks is insecure.  
- Upload + execution → *remote code execution (RCE)*, data exfiltration, persistence, and full server compromise.  
- This technique is common in labs and real applications and is often straightforward to exploit.

---

## 🔹 Lab goal (concise)
Bypass upload restrictions, upload a PHP web shell, GET the uploaded file, retrieve /home/carlos/secret, and submit the secret.

---

## 🔹 Methodology / Exact steps

1. *Baseline — discover stored path*
   - Log in (e.g., wiener:peter) with Burp Proxy ON.  
   - Upload a benign image (avatar) and forward the POST.  
   - Open the account page and check Burp → Proxy → HTTP history → filter by Images to find the GET the browser made for the stored image.  
   - Copy the exact stored path (canonical URL) — you will use this later.

2. *Prepare web shell*
   - Create exploit.php locally with a simple payload:
     php
     <?php echo file_get_contents('/home/carlos/secret'); ?>
     

3. *Intercept a fresh upload POST*
   - On the upload UI choose exploit.php and click Upload while Burp intercepts.  
   - Right-click the captured request → *Send to Repeater* (safe place to edit).

4. *Bypass Content-Type / extension checks (edit only the file-part)*
   Try these techniques in order — stop when one works:

   *A — Change the file-part Content-Type*
   Content-Disposition: form-data; name="avatar"; filename="exploit.php" Content-Type: image/jpeg

   <?php echo file_get_contents('/home/carlos/secret'); ?>- Keep CSRF and other form fields
   - Keep CSRF and other form fields unchanged. Forward the request.

*B — Double-extension*
Content-Disposition: form-data; name="avatar"; filename="exploit.php.jpg" Content-Type: image/jpeg 
- Forward and check if uploaded as .php.jpg but executed.
*C — GIF-stub (if magic-bytes checked)*
?php echo file_get_contents('/home/carlos/secret'); ?>
*D — Alternate extensions*
- Try exploit.phtml, exploit.php5, exploit.phar, etc.

5. *Confirm upload & request the shell*
- If the upload response returns a filename, use it. Otherwise re-open the account page and capture the avatar GET — that reveals the final path including any prefix or renaming.  
- Send a clean GET to the stored file URL using the same Host and Cookie: session=... headers:
  
  GET /files/avatars/exploit.php HTTP/1.1
  Host: <lab-host>
  Cookie: session=<session>
  Accept: */*
  Connection: close
  
- The response should include the secret — copy & submit.

6. *If execution fails*
- Try different extensions or double-extensions.  
- If source is returned (no execution), you still gain intelligence; try other upload endpoints or modify the path.  
- If upload blocked due to CSRF, refresh for a new token and re-capture the POST.

---

## 🔹 Proof of Exploit
![File Upload Bypass — web shell executed and secret returned](../images/file-upload-lab2-solved.png)  
(Screenshot shows the GET to the uploaded shell and the returned /home/carlos/secret output — this single image is the clearest proof of successful exploitation.)

---

## 🔹 Troubleshooting quick checks
- *404 Not Found* → wrong path/prefix or file renamed; use the exact GET captured after benign upload.  
- *Source returned (no exec)* → server doesn’t execute .php in that directory — try .phtml, double-ext, or GIF stub.  
- *Upload blocked / CSRF* → refresh the upload page and capture a fresh POST (new token).  
- *Client-side blocking* → always edit the captured POST in Repeater/Proxy to bypass browser JS checks.

---

## 🔹 Security Impact
- Remote code execution → full server takeover.  
- Exposure of DB credentials, config files, SSH keys → persistent compromise and lateral movement.  
- Web shell access enables data exfiltration and privilege escalation.

---

## 🔹 Remediation & best practices
- Enforce *server-side* validation with an allowlist of safe extensions and MIME types.  
- Validate file contents (magic bytes) in addition to filename checks.  
- Store uploaded files *outside* webroot or serve from a separate non-executable domain/subdomain.  
- Rename uploaded files to safe, non-executable names and remove execute permissions.  
- Implement AV scanning, size limits, and strict ACLs on uploaded content.

---
