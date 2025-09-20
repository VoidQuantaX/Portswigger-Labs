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
