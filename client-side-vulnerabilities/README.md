# 🧠 Client-Side Vulnerabilities — Reference Index

## Cross-Site Scripting (XSS)
- Stored XSS
- Reflected XSS
- DOM-based XSS
- Sink & source analysis
- Context-aware payloads
- CSP bypass scenarios

---

## DOM-Based Vulnerabilities
- Client-side trust issues
- DOM sinks (innerHTML, document.write, eval)
- DOM sources (location, document.referrer, postMessage)
- DOM clobbering
- Framework-specific DOM issues

---

## Cross-Site Request Forgery (CSRF)
- Same-site cookie abuse
- Token-based protections bypass
- GET vs POST CSRF
- CSRF + XSS chaining
- CSRF on JSON / API endpoints

---

## Cross-Origin Resource Sharing (CORS)
- Misconfigured Access-Control-Allow-Origin
- Credentialed requests abuse
- Wildcard origin issues
- Null origin exploitation
- CORS + token theft chains

---

## Clickjacking
- UI redressing attacks
- Frame overlay abuse
- Missing X-Frame-Options
- CSP frame-ancestors bypass
- Clickjacking + CSRF chaining

---

## WebSockets
- Insecure WebSocket authentication
- Token reuse in WS connections
- Missing origin validation
- WS + XSS message injection
- State desync vulnerabilities
