# Server-Side Request Forgery (SSRF) — Comprehensive Reference Guide

Server-Side Request Forgery (SSRF) is a critical web security vulnerability that arises when a server-side application is induced to make HTTP or other protocol requests to an unintended location. These requests typically target internal-only services within the organization's infrastructure or arbitrary external systems, bypassing security controls by leveraging the trusted network position of the vulnerable server [2].

---

## 1. Core Mechanics & Threat Vectors

In an SSRF attack, the attacker manipulates an input parameter (such as a URL, hostname, or IP address) that the server-side application uses to fetch remote resources. The application acts as a proxy, executing requests on behalf of the attacker.

### Vulnerability Contexts
*   **Front-End URL Inputs:** Parameters explicitly designed to receive URLs (e.g., `stockApi=http://stock.weliketoshop.net:8080/product/stock/check`) [2].
*   **Partial Path Injection:** Parameters where the user controls only a hostname, port, or path segment, which the application then prepends or appends to a hardcoded URL string [6].
*   **Implicit Headers:** HTTP headers processed by backend systems, such as the `Referer` header utilized by analytics software [7].
*   **Nested Data Formats:** Structured data formats like XML or SVG that support external entity references or remote resource fetching [6, 7].

---

## 2. Common SSRF Attack Types

SSRF attacks are broadly categorized by their target systems and whether the response is visible to the attacker.

### A. SSRF Attacks Against the Server Itself (Localhost)
In this scenario, an attacker forces the application to make an HTTP request back to the hosting server via its loopback network interface [2].

*   **Target Identifiers:** `127.0.0.1` or `localhost` [2].
*   **Bypassing Access Controls:** Many applications trust requests originating from the local machine (`localhost`). This loopback access often bypasses administrative login screens or edge-layer authorization checks, granting access to administrative interfaces like `/admin` [2].
*   **Why Loopback Trust Exists:**
    1.  **Distributed Access Checks:** Access control mechanisms might be implemented in a front-end reverse proxy or API gateway. When a connection is established directly back to the backend application server via loopback, it bypasses the front-end proxy entirely [2].
    2.  **Disaster Recovery:** Applications may expose diagnostic or administrative utilities without authentication to local requests to aid in system recovery [2].
    3.  **Alternative Listening Ports:** Administrative interfaces may run on a different port than the main application, bound strictly to `127.0.0.1`, rendering them unreachable from the public internet but fully exposed to loopback SSRF [2].

*   **Example Payload:**
    ```http
    POST /product/stock HTTP/1.1
    Host: vulnerable-website.com
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 48

    stockApi=http://localhost/admin/delete?username=carlos
    ``` [2, 3]

### B. SSRF Attacks Against Other Back-End Systems (Intranet)
Applications often reside within private networks (intranets) alongside other backend systems that are not publicly routable [3].

*   **Private Address Spaces:** RFC 1918 ranges (such as `10.0.0.0/8`, `172.16.0.0/12`, or `192.168.0.0/16`) [3].
*   **The "Soft Underbelly" Pattern:** Because backend systems are protected by network topologies (firewalls/DMZs), they often have a weaker security posture. They frequently expose sensitive features, administrative tools, or APIs without authentication under the assumption that only trusted internal hosts can interact with them [3].
*   **Cloud Metadata Endpoints:** Cloud-hosted environments (AWS, GCP, Azure) maintain internal link-local endpoints (typically `http://169.254.169.254/`) that supply sensitive instance metadata, credentials, and configuration tokens.

*   **Example Payload:**
    ```http
    POST /product/stock HTTP/1.1
    Host: vulnerable-website.com
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 43

    stockApi=http://192.168.0.68/admin
    ``` [3]

---

## 3. Circumventing SSRF Defenses

Applications containing SSRF-susceptible features frequently implement input validation or sanitization mechanisms. These defenses can often be circumvented.

### A. Bypassing Blacklist-Based Input Filters
Blacklist filters block specific keywords, hostnames, or IP ranges (e.g., `127.0.0.1`, `localhost`, `admin`) [4].

1.  **Alternative IP Representations:**
    *   **Decimal (Dword) Encoding:** `2130706433` (equivalent to `127.0.0.1`) [4]
    *   **Octal Encoding:** `017700000001` [4]
    *   **Abbreviated/Alternative IPs:** `127.1` or `127.0.1` [4]
    *   **IPv6 Loopback:** `[::1]` or `[0:0:0:0:0:0:0:1]`

2.  **Wildcard and Spoofed DNS Resolution:**
    *   An attacker can register a domain name that resolves directly to `127.0.0.1` or a private IP [4].
    *   *Burp Collaborator Wildcards:* e.g., `spoofed.burpcollaborator.net` [4].
    *   *Public DNS Loops:* Services like `nip.io` (e.g., `127.0.0.1.nip.io`).

3.  **Obfuscation Techniques:**
    *   URL encoding individual characters or the entire host portion (e.g., `%31%32%37%2e%30%2e%30%2e%31`) [4].
    *   Mixed-case variations for protocol or path segments (e.g., `hTtP://LoCaLhOsT/AdMiN`).

4.  **Redirection Bypasses:**
    *   Providing an external, attacker-controlled URL that responds with an HTTP `3xx` redirect to the restricted internal resource [4].
    *   **Protocol Switching:** Forcing a redirect from `http:` to `https:` during redirection has been shown to successfully bypass some anti-SSRF filters [4].

### B. Bypassing Whitelist-Based Input Filters
Whitelist filters only permit inputs matching a strict pattern of allowed values, hostnames, or domains [4]. These can be bypassed by leveraging complexities in how standard URL parsers interpret characters.

1.  **Credential Embedding (`@`):**
    *   Standard URLs allow credentials before the hostname [4].
    *   **Syntax:** `https://expected-host:fakepassword@evil-host` [4]
    *   The parser may see `expected-host` and pass the filter, but the backend HTTP client connects to `evil-host` [4].

2.  **URL Fragments (`#`):**
    *   Fragments indicate client-side anchors and are not typically transmitted over the network [4].
    *   **Syntax:** `https://evil-host#expected-host` [4]
    *   If the parser reads the string from right to left or looks for the whitelist entry anywhere in the string, it sees `expected-host`. The backend HTTP client, however, truncates the request at `#` and fetches `evil-host` [4].

3.  **DNS Hierarchy Exploitation:**
    *   An attacker can register a subdomain under their own control that incorporates the whitelisted domain name [4].
    *   **Syntax:** `https://expected-host.evil-host` [4]

4.  **Discrepant URL Parsing & Double Encoding:**
    *   Discrepancies occur when the component implementing the whitelist validation parses the URL differently than the backend HTTP client that executes the request [4].
    *   Using double-URL encoding (e.g., encoding `#` to `%23` and then to `%25%32%33`) can trick the validation engine into treating the character as a literal, while the backend web server recursively decodes it and interprets it as a special control character [4].

### C. Filter Bypass via Open Redirection
If an application whitelists a specific domain or set of paths, but one of those permitted endpoints is vulnerable to **Open Redirection**, an attacker can chain the vulnerabilities [4].

1.  **Mechanics:** The SSRF validation accepts the URL because the target hostname is on the whitelist. The backend HTTP client issues the request, receives a `302 Redirect` pointing to an internal IP address, and follows the redirection [4].
2.  **Example Payload Structure:**
    ```http
    POST /product/stock HTTP/1.1
    Host: vulnerable-website.com
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 130

    stockApi=http://weliketoshop.net/product/nextProduct?currentProductId=6&path=http://192.168.0.68/admin
    ``` [4]

---

## 4. Blind SSRF Vulnerabilities

A **Blind SSRF** occurs when the application can be induced to issue a backend HTTP request to an arbitrary URL, but the response (both headers and body) is not returned in the front-end HTTP response [5].

### Detection and Exploitation

1.  **Out-of-Band (OAST) Detection:**
    *   The most reliable detection method involves triggering an HTTP or DNS request to an external system controlled by the auditor (such as a Burp Collaborator domain) [5].
    *   Monitoring the collaborator logs for incoming connections verifies the vulnerability [5].
    *   **DNS vs. HTTP Interaction:** It is common to observe a DNS lookup but no subsequent HTTP request. This indicates that outbound DNS (port 53) is allowed, but the actual HTTP connection (ports 80/443) was blocked by outbound network firewall rules [5].

2.  **Blind Network Scanning:**
    *   While attackers cannot read responses, they can blindly "sweep" the internal network space [5].
    *   They can send payloads designed to exploit known vulnerabilities on internal services. If those exploit payloads themselves contain blind out-of-band signals (e.g., trigger a DNS resolution back to the attacker upon successful exploit), the attacker can discover and compromise internal services [5].

3.  **Server-Side Client Exploit Delivery:**
    *   If an attacker can force the application to connect to an external server under their control, they can return malicious responses specifically designed to exploit client-side parsing vulnerabilities in the server’s HTTP user-agent library [5].
    *   Exploiting buffer overflows or parsing bugs in the server’s HTTP client can lead to Remote Code Execution (RCE) on the application server [5].

---

## 5. Hidden SSRF Attack Surfaces

SSRF vulnerabilities frequently exist in features where URLs are not explicitly passed as parameters.

| Attack Surface | Explanation / Payload Vector |
| :--- | :--- |
| **Partial URLs in Requests** | The application expects only a path or a hostname (e.g., `server=apiserver`). If the backend concatenates this into `https://{user_input}.internal/api/`, the attacker may be able to traverse paths or inject query parameters to redirect the endpoint [6]. |
| **URLs in Structured Data Formats** | **XML (XXE):** XML parsers may allow defining external entities that point to internal resources (e.g., `<!ENTITY xxe SYSTEM "http://169.254.169.254/">`) [6, 7].<br>**SVG Images:** SVG is an XML-based format. If users can upload SVGs, an embedded `<image href="http://localhost/admin" />` tag can trigger SSRF when the server processes or renders the image. |
| **Referer Header Processing** | Analytics and tracking scripts log the HTTP `Referer` header to map inbound user traffic [7]. If these analytics systems automatically visit incoming referer links to scrape metadata or anchor text, submitting a malicious URL in the `Referer` header can trigger an SSRF [7]. |

---

## 6. SSRF Prevention

Securing applications against SSRF requires a defense-in-depth approach that combines application-level validation with network-level segregation.

### A. Network-Level Defenses (Most Effective)
*   **Segment Traffic:** Isolate the application server from internal backend resources. If the application has no business need to access administrative subnets, block those connections at the firewall layer.
*   **Default Deny Firewalls:** Enforce egress firewall rules that block all outbound traffic except to explicitly authorized, whitelisted external domains and ports.
*   **Restrict Link-Local Access:** Block access to the cloud metadata endpoint (`169.254.169.254`) from general application containers. In modern AWS environments, transition to IMDSv2, which uses session-oriented tokens to prevent simple SSRF extraction.

### B. Application-Level Defenses
*   **Strict Whitelisting:** Validate user input against an explicit list of allowed hostnames, IP addresses, or protocols. Reject any inputs that do not match the exact pattern.
*   **Avoid Raw URL Parsing:** Do not rely on custom regular expressions or string splits for URL validation. Use established, robust URL parsing libraries native to the language framework, and ensure they resolve IP addresses to their canonical forms (handling DNS pinning/DNS rebinding defenses) before validating.
*   **Disable Unused Protocols:** Restrict the HTTP client library to only allow `http` and `https` protocols. Disable support for dangerous protocols like `file://`, `gopher://`, `dict://`, or `ftp://`.

---

## 7. URL Validation Bypass Cheat Sheet

This quick-reference sheet summarizes bypasses for common input validation configurations:

### Loopback / Localhost Equivalents
```text
127.0.0.1
localhost
127.1
127.0.1
017700000001 (Octal)
2130706433 (Decimal/Dword)
0x7f000001 (Hexadecimal)
[::1] (IPv6 Loopback)
[0:0:0:0:0:0:0:1] (IPv6 Full)
```

### Whitelist Bypass Templates
*   **Credential Bypass:** `http://allowed-domain.com@evil-domain.com`
*   **Fragment Bypass:** `http://evil-domain.com#allowed-domain.com`
*   **DNS Subdomain:** `http://allowed-domain.com.evil-domain.com`
*   **URL Encoded Fragment:** `http://evil-domain.com%23allowed-domain.com`
*   **Double Encoded Fragment:** `http://evil-domain.com%2523allowed-domain.com`

### Redirect Exploitation Pattern
1.  **Target:** `http://vulnerable-host.com/stockCheck?url=http://allowed-domain.com/redirect?to=http://192.168.0.50/admin`
2.  **Validation Engine:** Reads `allowed-domain.com`, permits the request.
3.  **HTTP Client:** Sends request, receives `302 Redirect` to `192.168.0.50/admin`, follows redirect, and executes internal SSRF.
