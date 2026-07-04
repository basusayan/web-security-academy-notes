# PortSwigger Web Security Academy: Web Cache Deception (WCD)
## Comprehensive Study Notes & Exploitation Guide

This comprehensive reference guide synthesized the entire **Web Cache Deception (WCD)** learning path from the PortSwigger Web Security Academy. This includes the fundamental architecture of web caches, advanced path parsing and delimiter discrepancies, directory traversal normalization bypasses, and mitigation strategies based on Black Hat USA 2024 research ("Gotta Cache 'em all: bending the rules of web cache exploitation").

---

## 1. Core Concepts & Architecture

### Web Cache Deception (WCD) vs. Web Cache Poisoning
Although both vulnerability classes exploit caching infrastructure, they are fundamentally distinct in their targets and execution:
*   **Web Cache Deception (WCD):** An attacker tricks a web cache into storing **sensitive, private, dynamic content** belonging to a victim. The attacker then requests the exact same URL to retrieve the victim's cached data.
*   **Web Cache Poisoning:** An attacker manipulates cache keys (using unkeyed inputs like custom HTTP headers) to inject a **malicious payload (e.g., XSS)** into a cached response. The poisoned response is then served to multiple subsequent users.

```
Web Cache Deception:
Victim ---[Request with Sensitive Data]---> Cache (Stores Response)
                                               ^
Attacker ---[Same Request URL]-----------------+ (Retrieves Stored Data)

Web Cache Poisoning:
Attacker ---[Injected Payload]---> Cache (Stores Payload)
                                      ^
Victims <---[Served Poisoned Page]----+
```

### How Web Caches Work
Web caches (such as CDNs or reverse proxies) sit between the user's browser and the origin server.
*   **Cache Miss:** If the cache does not contain a copy of the requested resource, it forwards the request to the origin server. The origin server processes the request, returns the response to the cache, and the cache evaluates its rules to determine whether to store it.
*   **Cache Hit:** If a subsequent request matches a cached resource's identifier, the cache serves the stored response directly to the user, completely bypassing the origin server.

### Cache Keys
To quickly check if a resource is already cached, the cache generates a **Cache Key** from elements of the HTTP request. 
*   **Standard Cache Key Components:** Typically includes the URL scheme, host, path, and query parameters.
*   **Unkeyed Inputs:** Elements of the request (like headers like `User-Agent` or `Cookie`) that are ignored when generating the cache key.
*   **Collision Requirement:** For a Web Cache Deception attack to succeed, the victim and the attacker must generate the exact same cache key. Since the path is always part of the cache key, path manipulation is the primary vector for WCD.

### Cache Rules
Cache rules determine what types of responses are eligible for storage and for how long. CDNs are typically configured to ignore dynamic data and cache static files to save bandwidth. Common rule types include:
1.  **Static File Extension Rules:** Target files ending in specific extensions (e.g., `.css`, `.js`, `.png`, `.ico`, `.woff2`).
2.  **Static Directory Rules:** Target paths beginning with specific static prefix paths (e.g., `/static/*`, `/assets/*`, `/resources/*`).
3.  **File Name Rules:** Target specific, universally required static filenames that rarely change (e.g., `robots.txt`, `favicon.ico`, `sitemap.xml`).

---

## 2. Attack Methodology & Workflow

Constructing a Web Cache Deception attack follows a structured testing lifecycle:

```
[Target Identification] -> [Cache Buster Setup] -> [Discrepancy Testing] -> [Exploit Delivery]
```

### Step 1: Target Identification
Search for sensitive, dynamically generated user data.
*   **Idempotency:** Focus only on safe HTTP methods: `GET`, `HEAD`, or `OPTIONS`. State-changing methods like `POST`, `PUT`, or `DELETE` are typically never cached by default.
*   **Hidden Data:** Inspect full HTTP responses in Burp Suite. Many high-value dynamic endpoints (like JSON APIs returning API keys, personal profiles, or CSRF tokens) might contain sensitive data in the raw response body that is not rendered on the UI.

### Step 2: Cache Buster Setup
When testing, you must ensure your requests do not serve a cached response from a previous test.
*   **Manual Cache Busting:** Append a unique, changing query parameter to your path on every request:
    `GET /api/user/profile?cb=12345`
*   **Automated Cache Busting:** Install the **Param Miner** Burp extension. Go to `Param Miner > Settings` and check `Add dynamic cachebuster`. Burp will automatically append a unique query string to every request.

### Step 3: Detecting Cached Responses
Inspect response headers and latency to verify if the cache stored the response:
*   **X-Cache Header:**
    *   `X-Cache: miss` - Response was fetched from the origin. If cacheable, it is now stored. Resend to verify.
    *   `X-Cache: hit` - Response was successfully served directly from the cache. **Vulnerable state confirmed.**
    *   `X-Cache: dynamic` - The origin marked it as dynamic; the cache declined to store it.
    *   `X-Cache: refresh` - The cache revalidated the outdated content with the origin.
*   **Cache-Control Header:** Look for public caching instructions:
    *   `Cache-Control: public, max-age=3600`
    *   *Warning:* Caches are often misconfigured to override origin headers, meaning a resource might be cached even if the server returned `Cache-Control: private, no-store`.
*   **Response Time:** A cached response (`hit`) typically resolves significantly faster (e.g., <10ms) compared to an origin lookup (`miss` - e.g., >100ms).

---

## 3. Exploiting Static Extension Cache Rules

This class of WCD exploits discrepancies in how the cache and the origin server interpret path parameters and map URLs to physical or logical resources.

### Path Mapping Discrepancies
URL path mapping dictates how an incoming request maps to an application resource.
*   **Traditional URL Mapping:** Maps directly to physical files on the disk:
    `http://example.com/assets/styles.css` (Accesses the physical file `styles.css`).
*   **RESTful URL Mapping:** Maps URLs logically to API endpoints and path parameters:
    `http://example.com/user/123/profile` (API endpoint `/user/profile` with ID `123`).

#### The Vulnerability Discrepancy
If an attacker appends a static extension path segment to a REST URL:
`http://vulnerable.com/user/123/profile/wcd.css`

1.  **The Origin Server (RESTful):** Parses the path logically. It routes the request to `/user/123/profile` and treats the extra segment `wcd.css` as an empty parameter or ignores it, returning the **sensitive dynamic profile** of the logged-in user.
2.  **The Cache (Traditional):** Parses the path literally. It looks at the end of the URL and sees `/wcd.css`. It matches its **Static File Extension Rule** (cache anything ending in `.css`) and caches the victim's profile.

#### Testing and Exploitation
1.  **Test Origin Mapping:** Add an arbitrary segment to the target path:
    `GET /api/user/profile/arbitrarysegment`
    *   If it still returns the same dynamic profile page, the origin abstracts paths.
2.  **Test Cache Rules:** Append a static extension to the arbitrary segment:
    `GET /api/user/profile/arbitrarysegment.js`
3.  **Check Caching:** Send the request twice. If you get `X-Cache: hit`, the path is vulnerable.
4.  **Attack Execution:** Send the malicious link `/api/user/profile/anything.css` to the victim. Once they visit it, make a request to the exact same URL to read their cached sensitive data.

---

### Delimiter Discrepancies
Delimiters separate logical components of a URL. However, parser variations cause different servers to treat characters as path separators, parameter indicators, or termination characters.

#### Matrix Variables (Java Spring)
Java Spring applications use the semicolon `;` character to denote matrix variables (key-value pairs appended directly to the path).
*   **Vulnerable URL:** `http://vulnerable.com/profile;wcd.css`
*   **Origin Interpretation (Java Spring):** Sees `;` as a delimiter. It truncates the path at `/profile` (treating `wcd.css` as a matrix variable name) and returns the **dynamic profile response**.
*   **Cache Interpretation (Standard CDN):** Does not treat `;` as a delimiter. It parses the entire path as `/profile;wcd.css`. Since it ends in `.css`, it applies the caching rule and caches the dynamic response.

#### File Format Formatter Delimiters (Ruby on Rails)
Ruby on Rails uses the period `.` character to specify formatters (e.g., returning JSON or XML).
*   **The Discrepancy:** If you request `/profile.ico`, Rails may not have an `.ico` formatter. It will fallback to its default HTML formatter and return the user's HTML profile page.
*   **The Cache:** Sees `.ico` and caches it under the "Cache universally requested icon files" rule.

#### Null Byte Delimiters (OpenLiteSpeed)
OpenLiteSpeed web servers treat the URL-encoded null byte `%00` as a path terminator.
*   **Vulnerable URL:** `http://vulnerable.com/profile%00wcd.js`
*   **Origin Interpretation:** Truncates at `%00` and processes the path as `/profile`.
*   **Cache Interpretation (Akamai / Fastly):** Processes `%00` and everything after it literally. It treats the path as `/profile%00wcd.js` and caches the dynamic response under the `.js` static extension rule.

#### Delimiter Testing Matrix
To discover what characters trigger truncation on the origin but are ignored by the cache, perform an ASCII character sweep.

| Delimiter | Encoding | Common Framework Delimiter Usage |
| :--- | :--- | :--- |
| `;` | `%3B` | Java Spring (Matrix variables) |
| `.` | `%2E` | Ruby on Rails (Formatter delimiter) |
| `?` | `%3F` | RFC standard query string delimiter (If decoded by cache but not origin) |
| `%00` | `%00` | OpenLiteSpeed (Null-byte termination) |
| `%0A` | `%0A` | Unix Newline (Parser termination) |
| `%09` | `%09` | Tab Character (Whitespace parsing termination) |

#### Delimiter Testing Steps in Burp Suite
1.  Establish a base reference with an arbitrary string: `/api/profileaaa`. Observe if it throws a 404 or redirects.
2.  Send the request to **Burp Intruder** with the payload structure: `/api/profile§character§aaa.js`.
3.  Load the ASCII character list (or URL-encoded equivalent hex list).
4.  **Crucial:** Turn off *Automated Character Encoding* in the Intruder Payload side panel so characters are sent raw/encoded precisely as intended.
5.  Analyze results: If an intruder request returns a `200 OK` (matching the profile response) and subsequent requests show `X-Cache: hit`, you have identified a viable delimiter discrepancy.

---

### Delimiter Decoding Discrepancies
Decoding discrepancies occur when one parser decodes URL characters *before* evaluating delimiters, while another parser does not.

#### Case 1: Encoded Hash Fragment (`%23` / `#`)
The browser uses `#` to denote front-end fragments and never sends it to the server. However, if sent encoded as `%23`:
*   **Origin Server:** Decodes `%23` to `#`. It treats `#` as a delimiter, truncating the path to `/profile`.
*   **Cache Server:** Does not decode `%23`. It treats the path literally as `/profile%23wcd.css` and caches the dynamic output.

#### Case 2: Decoded Query String (`%3f` / `?`)
*   **Cache Server:** Receives `/myaccount%3fwcd.css`. It applies rules to the raw encoded path first, identifying `.css` as a static file. It then decodes `%3f` to `?` and forwards the rewritten path `/myaccount?wcd.css` to the origin.
*   **Origin Server:** Receives the rewritten path `/myaccount?wcd.css`. It interprets `?` as a query delimiter, routing the request to the dynamic page `/myaccount`.

---

## 4. Exploiting Static Directory Cache Rules

Many cache rules are configured to automatically store everything within designated static directories, such as:
`^/assets/.*` | `^/static/*` | `^/images/*` | `^/scripts/*`

Attackers exploit this by combining **Path Traversal** sequences with path normalization discrepancies.

```
Expected flow:
/assets/logo.png ---> [Cache Matches "/assets/" prefix] ---> CACHED

Path Traversal Attack:
/assets/..%2fprofile ---> [Origin normalizes to /profile] ---> Returns Dynamic Profile
                        ---> [Cache reads literally /assets/..] ---> Matches static prefix rule and CACHES!
```

### Normalization Discrepancies
Normalization is the process of resolving dot-segments (`.`, `..`) and decoding percent-encoded characters in a URL path to establish a standardized canonical path. 

Discrepancies arise when either the cache or the origin server normalizes paths differently. This is typically caused by:
1.  **Encoding support:** One parser decodes URL-encoded slashes (`%2f`) or dots (`%2e`) before resolving path traversal sequences, while the other does not.
2.  **Resolution order:** One parser resolves relative dot-segments (`/../`) before passing it downstream, while the other passes it raw.

---

### Origin-Side Normalization (Exploiting `/static/..%2f` Rule)
This exploit occurs when the **origin server normalizes** the traversal sequence, but the **cache does not**.

#### The Discrepancy
*   **The Cache:** Receives `/assets/..%2fprofile`. It does not decode `%2f` or resolve dot-segments. It sees a request starting with the prefix `/assets/` and decides to cache it according to its **Static Directory Rule**.
*   **The Origin Server:** Decodes `%2f` to `/`, evaluates the path traversal `..` and resolves `/assets/../profile` to `/profile`. It serves the dynamic, private profile page of the user.

#### Detection: Origin Server Normalization
To verify if the origin server resolves encoded traversal sequences:
1.  Find a dynamic, non-cacheable endpoint (such as a POST request to `/profile` or a page with explicit no-cache headers).
2.  Prepend an arbitrary folder and an encoded dot-segment sequence:
    `GET /arbitrarydir/..%2fprofile`
3.  If the server returns the identical profile page, it has resolved the path traversal.
4.  *Note:* Try various encoding patterns if it returns a 404:
    *   `..%2f` (Single encode slash)
    *   `%2e%2e%2f` (Encode dot and slash)
    *   `%2e%2e%5c` (Backslash representation for Windows/IIS servers)
    *   `..%252f` (Double encoding)

#### Exploitation Flow
Construct a payload starting with the verified cache directory prefix, followed by the encoded path traversal sequence leading to your target endpoint:
`GET /assets/..%2fapi/user/keys`

*   **Cache:** Matches `/assets/` prefix $\rightarrow$ Caches response.
*   **Origin:** Translates `/assets/../api/user/list` $\rightarrow$ `/api/user/list` and returns sensitive dynamic API key.

---

### Cache-Side Normalization
This exploit occurs when the **cache server normalizes** the traversal sequence, but the **origin server does not**.

#### The Vulnerability Discrepancy
If an attacker sends:
`GET /profile%2f%2e%2e%2fstatic`

1.  **The Cache:** Decodes `%2f` to `/` and `%2e%2e` to `..`. It normalizes `/profile/../static` to `/static` and marks it as a static directory to be cached.
2.  **The Origin Server:** Does not decode the characters or resolve the dot-segments. It tries to interpret the raw string `/profile%2f%2e%2e%2fstatic` literally, which typically throws a `404 Not Found` error.

#### Bypassing the Origin Error (Combining Delimiters)
A pure path traversal on the cache-side is useless if it results in an origin error. To successfully exploit this, you must **couple the traversal with an origin delimiter**.

If you inject a delimiter (e.g., `;` for Java Spring) into the payload:
`GET /profile;%2f%2e%2e%2fstatic`

1.  **The Origin Server:** Treats `;` as a delimiter. It truncates the request, interpreting the path solely as `/profile`. It successfully executes and returns the dynamic, sensitive profile.
2.  **The Cache:** Ignores `;` as a delimiter. It decodes `%2f%2e%2e%2f` to `/../` and normalizes `/profile;../static` to `/static`. It matches the static directory rule and caches the response.

#### Detection & Exploitation Flow
1.  Find your target static directory (e.g., `/assets`).
2.  Append an arbitrary string to confirm caching is based on directory prefix: `GET /assets/anyfilename`. If it hits cache (`hit`), directory prefix caching is active.
3.  Inject a path traversal sequence after the directory prefix: `GET /assets/..%2fjs/script.js`.
    *   If the response is **no longer cached**, the cache normalizes path traversal sequences (interpreting it as `/js/script.js`, which does not match the `/assets` rule).
4.  Construct the complex payload combining the target dynamic endpoint, an origin-specific delimiter, and the traversal sequence ending in the static directory name:
    `GET /api/user/keys;%2f%2e%2e%2fassets`
5.  Send the payload. The origin truncates at `;` returning the API keys. The cache normalizes `/api/user/keys;../assets` to `/assets` and caches the API keys response under the static directory rule.

---

## 5. Exploiting File Name Cache Rules

Caching systems frequently target individual static files that are requested globally across all applications and change infrequently (e.g., `robots.txt`, `favicon.ico`, `index.html`).

*   **Rule Mechanism:** The cache matches the exact filename string anywhere in the URL path.
*   **The Discrepancy:** This is vulnerable if the cache server normalizes encoded traversal sequences but the origin server does not.

### Exploitation Mechanics
This exploit uses the exact same combined logic as the "Cache-Side Normalization" vulnerability, replacing the static directory prefix with a target cached filename.

#### Payload Template:
`GET /<dynamic-path><origin-delimiter>%2f%2e%2e%2f<target-static-file>`

#### Scenario: Exploiting `index.html` on Java Spring
*   **Attack Payload:** `GET /api/user/profile;%2f%2e%2e%2findex.html`
*   **Origin Server (Java Spring):** Sees `;` and truncates. Processes the request path as `/api/user/profile`. Returns the victim's private profile.
*   **Cache Server:** Does not decode `;`. It decodes the path traversal `%2f%2e%2e%2f` to `/../`. It resolves `/api/user/profile;../index.html` directly to `/index.html`. It matches the "Cache exact filename match: index.html" rule and caches the response.

---

## 6. Defensive Defeat & Remediation

Securing applications against Web Cache Deception requires a defense-in-depth approach spanning the application layer, cache configurations, and CDN armor rules.

### 1. Robust Cache-Control Headers
The absolute best defense against WCD is to explicitly instruct the caching layer to never cache dynamic content at the application layer.
*   Always configure dynamic endpoints to return:
    `Cache-Control: no-store, private`
*   Ensure that these headers are applied globally to all sensitive API endpoints, and are not omitted on application error responses (such as `500 Internal Error` or `403 Forbidden` which may still leak sensitive data).

### 2. Configure CDN to Honor Cache-Control
Ensure that your CDN reverse proxy or edge cache is strictly configured to respect and obey origin-sent `Cache-Control` directives. **Never** allow CDN rules to override `no-store` or `private` instructions.

### 3. Implement Content-Type Validation (Deception Armor)
Configure your CDN to perform strict **Content-Type validation** before caching a resource. 
*   **The Rule:** A resource should only be cached if the response's `Content-Type` matches the request path's file extension.
*   *Example:* If a request is made for `/profile/wcd.css` but the origin server returns `Content-Type: application/json` or `text/html`, the cache must refuse to store it. (e.g., Cloudflare’s *Cache Deception Armor* uses this exact methodology).

### 4. Align Path Normalization Parsers
Verify and align the URL parsing behaviors of your origin servers and edge cache servers:
*   Ensure both parsers treat delimiters (like `;`, `.`, `?`, `%00`) identically.
*   Configure both components to either consistently decode and normalize path traversal sequences (`..`) or block any incoming requests containing raw percent-encoded dots and slashes (`%2e%2e%2f`) entirely.

---

## 7. Interactive Quick Reference & Cheat Sheet

| Attack Vector | Target Tech | Payload Template | Root Discrepancy Cause |
| :--- | :--- | :--- | :--- |
| **REST Path Mapping** | Generic CDN + REST API | `/api/profile/wcd.css` | Origin treats `wcd.css` as param; Cache treats it as stylesheet file. |
| **Matrix Variables** | Java Spring | `/api/profile;wcd.css` | Origin truncates path at `;`; Cache reads full path ending in `.css`. |
| **Rails Formatter** | Ruby on Rails | `/api/profile.ico` | Origin falls back to default HTML; Cache matches static icon filename rule. |
| **Null-byte Termination** | OpenLiteSpeed | `/api/profile%00wcd.js` | Origin truncates path at `%00`; Cache reads full path ending in `.js`. |
| **Origin Normalization** | Decoded path origin | `/static/..%2fapi/profile` | Origin normalizes `/static/../profile` to `/profile`; Cache matches `/static` prefix literally. |
| **Cache Normalization** | Decoded path cache + Delimiter | `/api/profile;%2f%2e%2e%2fstatic` | Cache resolves traversal to `/static` directory; Origin truncates at `;` returning `/api/profile`. |
| **File Name Rule** | Decoded path cache + Delimiter | `/api/profile;%2f%2e%2e%2findex.html` | Cache resolves traversal to static file name `index.html`; Origin truncates at `;` returning profile. |