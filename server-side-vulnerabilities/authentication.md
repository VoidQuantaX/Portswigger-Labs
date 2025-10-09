# Authentication Lab-1 — Username enumeration & Password brute-force

---

## 🔹 One-line summary
Identified username enumeration via subtle response differences, then used password brute-force against the discovered account to gain access (PoC attached).

---

## 🔹 Overview
Authentication verifies identity (username/password/MFA). Username enumeration leaks whether an account exists and drastically lowers attacker effort. Once a valid username is known, automated password guessing (brute-force / credential-stuffing) can lead to account takeover and further escalation.

---

## 🔹 Methodology / Lab walkthrough (concise flow)
- *Capture login flow* — with Burp Proxy ON, submit a normal login to capture POST /login (or equivalent).  
- *Manual enumeration check* — in Repeater, replace username with a candidate and use a known-wrong password; observe response differences (status, content-length, headers).  
- *Automated enumeration* — send the captured POST to Intruder with payloads on the username field (wordlist). Sort results by length/status to find the username that produces a different response (valid user).  
- *Password brute-force* — send the login POST to Intruder with payloads on the password field (username fixed to discovered user). Use Sniper or appropriate attack type; detect success by different status/length/redirect/Set-Cookie.  
- *Verify & document* — log in with the found credentials in the browser or Repeater, capture the successful response and screenshot the logged-in page. Save the raw request/response and screenshots as PoC.

---

## 🔹 Repeater / Intruder PoC templates
*Captured login POST (example)*
POST /login HTTP/1.1 Host: <LAB_HOST> Content-Type: application/x-www-form-urlencoded Cookie: session=<SESSION>

username=<CANDIDATE>&password=wrongpassword
*Intruder — username payload position*  
Place §username§ at the username value and load wordlist of candidate usernames.

*Intruder — password payload position*  
Fix username to discovered account, place §password§ at password value and load password list.

---

## 🔹 Proof (evidence)
1. *Username enumeration — differing response*  
   ![Username enumeration — different status/length indicates valid user](../images/auth-lab-username-enum.png)  
   (Screenshot: Intruder/Repeater results showing the username entry with a different status/content-length.)

2. *Password brute-force — discovered correct password*  
   ![Password brute-force — different response indicates correct password](../images/auth-lab-password-found.png)  
   (Screenshot: Intruder/Repeater hit showing the request/response that indicates a successful login attempt for the discovered username.)

3. *Lab solved — logged-in view / success page*  
   ![Lab solved — logged-in dashboard / admin panel showing successful login](../images/auth-lab-solved.png)  
   (Screenshot: browser showing the logged-in page or lab success confirmation.)

---

## 🔹 Impact
- Fast account discovery → targeted attacks and credential stuffing.  
- Account takeover leads to data theft, abuse of user privileges, and potential vertical escalation (admin takeover).  
- Attackers can use valid accounts to bypass protections, access private features, or pivot.

---

## 🔹 Remediation (short)
- Return uniform error messages & HTTP status codes for authentication failures.  
- Normalize response lengths and avoid side-channel leaks (timing, headers, redirects).  
- Rate-limit and throttle login attempts by IP and account; enforce progressive delays and account lockouts.  
- Enforce MFA for high-value accounts and strong password policies.  
- Monitor/alert on enumeration/brute-force patterns and apply CAPTCHAs when abusive activity is detected.

---

## 🔹 Pentest checklist
- [x] Capture login requests and identify username param.  
- [x] Try manual enumeration in Repeater (wrong password).  
- [x] Automate enumeration with Intruder; sort by length/status.  
- [x] Brute-force password for confirmed username with Intruder (Sniper).  
- [x] Verify successful login, save raw request/response and screenshots.  
- [x] Recommend mitigation steps and re-test after fixes.

---
