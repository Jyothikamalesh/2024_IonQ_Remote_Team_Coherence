## Prompt for Secure Code Remediation

### 1. Security Expert Roleplay

You are a senior cyber security expert at one of the world’s largest financial institutions, managing trillions of dollars in assets and influencing the global economy. Your code reviews and remediations directly impact the stability, trust, and security of financial markets worldwide.

---

### 2. Gamification and Threat/Reward Mechanism

- **Reward:** Earn points for each vulnerability you successfully remediate. Secure code will be recognized as best practice and promoted to the team.
- **Threat:** Any method that remains vulnerable after review will be considered a critical failure. The responsible party will face severe penalties, including loss of points and mandatory retraining.

---

### 3. Recursive Criticism and Improvement (RCI)

After generating code, you must critically review it as a security auditor. Identify any remaining weaknesses and iteratively improve the code until it is fully secure. Explain each improvement and how it addresses the vulnerability.

---

### 4. Vulnerability-Specific Details

**Vulnerability:** {VULNERABILITY_NAME}
**OWASP Content:**  
[OWASP’s recommended countermeasures and brief explanation for the vulnerability]
**Coding Essentials:**  
- **Input Validation:** [How to validate input for this vulnerability]
- **Sanitization:** [How to sanitize input for this vulnerability]
- **Secure Storage:** [How to securely store data for this vulnerability]
- **Runtime Protection:** [How to protect at runtime for this vulnerability]
**Mock Function Example (Pseudo-code):**
**Enterprise Guideline:**  
{COMPANY_SECURITY_STANDARD}

---

### 5. Instructions

- **Recognize all instances of the specified vulnerability in the code.**
- **Rewrite only the affected parts to remove the vulnerability, strictly maintaining original functionality.**
- **Apply only the four security layers above.**
- **Output the secure code with explanatory comments for each security measure applied.**
- **After each fix, explain how your change addresses the vulnerability and the impact of your improvement.**

---

### 6. Code Analysis and Remediation Section

{INSERT_CODE_TO_ANALYZE_HERE}

---

### 7. Secure Version (with Security Layer Annotations and RCI Explanation)

{INSERT_SECURE_CODE_OUTPUT_HERE}

---
## Vulnerability-Specific Details

---

### 1. Command Injection

**OWASP Content:**  
Command injection is a form of injection attack (OWASP Top 10 A03: Injection). It occurs when an application passes unsafe user-supplied data to a system shell. OWASP recommends using safe API calls that avoid invoking the shell, using strict input validation, and implementing allowlists for permitted values and commands.

**Coding Essentials:**  
- **Input Validation:** Restrict allowed characters; use allowlists for command arguments.
- **Sanitization:** Use built-in safe APIs or libraries for command execution.
- **Secure Storage:** Not directly applicable; avoid storing user input for command construction.
- **Runtime Protection:** Run commands with least privilege; use sandboxing if possible.

**Mock Function Example (Pseudo-code):**
// Vulnerable
function executeCommand(userInput)
    cmd = "ping " + userInput
    system(cmd)
end

// Secure
function executeCommand(userInput)
    if !isValid(userInput, allowlist=alphanumeric)
        throw Error("Invalid input")
    end
    cmd = ["ping", userInput]  // Use safe API with array args
    safeSystem(cmd)
end

---

### 2. Insecure Deserialization

**OWASP Content:**  
OWASP Top 10 A08: Software and Data Integrity Failures. Insecure deserialization can lead to remote code execution or privilege escalation. OWASP advises to never deserialize data from untrusted sources, use integrity checks or digital signatures, and prefer simple data formats like JSON over complex ones.

**Coding Essentials:**  
- **Input Validation:** Validate serialized data format and integrity before deserializing.
- **Sanitization:** Use safe deserialization functions; avoid deserializing untrusted data.
- **Secure Storage:** Store only trusted serialized data; log deserialization activity.
- **Runtime Protection:** Use integrity checks (e.g., digital signatures) for critical data.

**Mock Function Example (Pseudo-code):**
// Vulnerable
function deserializeData(data)
    obj = deserialize(data)  // Unsafe, may execute code
end

// Secure
function deserializeData(data)
    if !hasValidSignature(data)
        throw Error("Invalid or tampered data")
    end
    obj = safeDeserialize(data)  // Use safe, restricted deserializer
end

---

### 3. Insecure Direct Object Reference (IDOR)

**OWASP Content:**  
OWASP Top 10 A01: Broken Access Control. IDOR occurs when an application exposes a reference to an internal object. OWASP recommends implementing proper access control checks for every function that accesses a data object, using indirect references (maps), and validating user authorization for every access.

**Coding Essentials:**  
- **Input Validation:** Validate user input for object references (e.g., IDs).
- **Sanitization:** Not directly applicable.
- **Secure Storage:** Store object references securely; use indirect references (maps) if possible.
- **Runtime Protection:** Enforce access control checks for every object access.

**Mock Function Example (Pseudo-code):**
// Vulnerable
function getUserFile(userId, fileId)
    file = getFileById(fileId)  // No access control
    return file
end

// Secure
function getUserFile(userId, fileId)
    if !isOwner(userId, fileId)
        throw Error("Access denied")
    end
    file = getFileById(fileId)
    return file
end

---

### 4. Insecure Session Identifier

**OWASP Content:**  
OWASP Top 10 A07: Identification and Authentication Failures. Insecure session management can allow attackers to hijack sessions. OWASP advises to generate secure, random session identifiers, use secure cookie attributes (HttpOnly, Secure), enforce session timeouts, and protect against session fixation.

**Coding Essentials:**  
- **Input Validation:** Ensure session IDs are generated securely and not user-controlled.
- **Sanitization:** Not directly applicable.
- **Secure Storage:** Store session data securely; use HttpOnly and Secure flags for cookies.
- **Runtime Protection:** Enforce session expiration and rotation; monitor for session fixation.

**Mock Function Example (Pseudo-code):**
// Vulnerable
function createSession(userId)
    sessionId = userId  // Predictable or user-controlled
    setSession(sessionId)
end

// Secure
function createSession(userId)
    sessionId = generateSecureRandomId()
    setSecureSession(sessionId, secure=true, httpOnly=true)
end

---

### 5. Server-Side Request Forgery (SSRF)

**OWASP Content:**  
OWASP Top 10 A10: Server-Side Request Forgery. SSRF attacks allow attackers to send crafted requests from the server. OWASP recommends using allowlists for permitted domains, validating and sanitizing user input used in requests, and implementing network-level controls to restrict outbound traffic.

**Coding Essentials:**  
- **Input Validation:** Restrict user input for URLs/IPs; use allowlists for allowed domains.
- **Sanitization:** Encode or filter user input used for requests.
- **Secure Storage:** Not directly applicable.
- **Runtime Protection:** Use network-level controls (e.g., firewalls) to restrict outbound requests.

**Mock Function Example (Pseudo-code):**
// Vulnerable
function fetchUrl(userUrl)
    response = httpGet(userUrl)  // No input validation
end

// Secure
function fetchUrl(userUrl)
    if !isAllowedDomain(userUrl, allowlist=["trusted.com"])
        throw Error("Domain not allowed")
    end
    response = httpGet(userUrl)
end

---

### 6. Secrets Exposure

**OWASP Content:**  
OWASP Top 10 A02: Cryptographic Failures (previously "Sensitive Data Exposure"). OWASP advises never to hardcode secrets in code, use secure secret management tools (e.g., vaults), encrypt secrets at rest and in transit, and rotate secrets regularly.

**Coding Essentials:**  
- **Input Validation:** Not directly applicable.
- **Sanitization:** Not directly applicable.
- **Secure Storage:** Store secrets in secure vaults (e.g., AWS Secrets Manager, HashiCorp Vault).
- **Runtime Protection:** Rotate secrets regularly; avoid hardcoding secrets in code.

**Mock Function Example (Pseudo-code):**
// Vulnerable
function getApiKey()
    return "hardcoded-secret-key"
end

// Secure
function getApiKey()
    return getSecretFromVault("api-key")
end

---

### 7. SQL Injection

**OWASP Content:**  
OWASP Top 10 A03: Injection. SQL injection occurs when untrusted data is sent to an interpreter as part of a command or query. OWASP recommends using parameterized queries or prepared statements, input validation, and least privilege database accounts.

**Coding Essentials:**  
- **Input Validation:** Validate input type and length.
- **Sanitization:** Use parameterized queries or prepared statements.
- **Secure Storage:** Use least privilege for database accounts.
- **Runtime Protection:** Use WAFs and log suspicious queries.

**Mock Function Example (Pseudo-code):**
// Vulnerable
function getUser(username)
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    result = db.execute(query)
end

// Secure
function getUser(username)
    query = "SELECT * FROM users WHERE name = ?"
    result = db.executePrepared(query, [username])
end

---

### 8. Cross-Site Scripting (XSS)

**OWASP Content:**  
OWASP Top 10 A03: Injection. XSS allows attackers to inject scripts into web pages viewed by users. OWASP recommends output encoding for all untrusted data, input validation, and implementing Content Security Policy (CSP).

**Coding Essentials:**  
- **Input Validation:** Validate input for allowed characters.
- **Sanitization:** Encode output for HTML, JS, and CSS contexts.
- **Secure Storage:** Not directly applicable.
- **Runtime Protection:** Use Content Security Policy (CSP).

**Mock Function Example (Pseudo-code):**
// Vulnerable
function renderComment(comment)
    return "<div>" + comment + "</div>"
end

// Secure
function renderComment(comment)
    safeComment = htmlEncode(comment)
    return "<div>" + safeComment + "</div>"
end

---

### 9. Client-Side Request Forgery (CSRF)

**OWASP Content:**  
OWASP Top 10 A01: Broken Access Control (related to CSRF under "Authentication and Authorization"). CSRF forces users to perform unwanted actions. OWASP recommends using anti-CSRF tokens, SameSite cookie attributes, and requiring re-authentication for sensitive actions.

**Coding Essentials:**  
- **Input Validation:** Not directly applicable.
- **Sanitization:** Not directly applicable.
- **Secure Storage:** Not directly applicable.
- **Runtime Protection:** Use anti-CSRF tokens and SameSite cookie attributes.

**Mock Function Example (Pseudo-code):**
// Vulnerable
function transferMoney(amount, toAccount)
    // No CSRF protection
    db.updateBalance(amount, toAccount)
end

// Secure
function transferMoney(amount, toAccount, csrfToken)
    if !isValidCsrfToken(csrfToken)
        throw Error("Invalid CSRF token")
    end
    db.updateBalance(amount, toAccount)
end

---

### 10. XML Entities Injection (XXE)

**OWASP Content:**  
OWASP Top 10 A05: Security Misconfiguration (includes XXE). XXE attacks exploit vulnerable XML parsers. OWASP recommends disabling external entity processing in XML parsers, using simpler data formats, and validating XML schemas.

**Coding Essentials:**  
- **Input Validation:** Restrict XML input to trusted sources.
- **Sanitization:** Disable external entity processing in XML parsers.
- **Secure Storage:** Not directly applicable.
- **Runtime Protection:** Use XML parsers with XXE protection enabled.

**Mock Function Example (Pseudo-code):**
// Vulnerable
function parseXml(xmlData)
    obj = xmlParser.parse(xmlData)  // XXE enabled
end

// Secure
function parseXml(xmlData)
    parser = newXmlParser(disableExternalEntities=true)
    obj = parser.parse(xmlData)
end

---



