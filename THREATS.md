# TrustVault — Threat Model

## 1. Purpose
This document describes potential security threats to TrustVault, their possible impact, and measures intended to reduce the risks.

## 2. Assets to Protect
- User account credentials
- Uploaded documents
- Document-sharing permissions
- User and administrator accounts
- Audit logs
- Document integrity hashes
- Application configuration and database

## 3. Potential Threats and Mitigations

### Threat 1: Unauthorized Access
**Risk:** An unauthenticated or unauthorized user may attempt to access protected pages or documents.

**Mitigation:**
- Require authentication for protected routes.
- Check document ownership and sharing permissions on the server.
- Deny access when authorization checks fail.

### Threat 2: Weak or Compromised Passwords
**Risk:** An attacker may guess or obtain a user's password.

**Mitigation:**
- Store passwords using a suitable password-hashing method.
- Avoid storing plain-text passwords.
- Use strong passwords and consider login rate limiting.

### Threat 3: Unauthorized Document Download
**Risk:** A user with view-only access may attempt to download a document.

**Mitigation:**
- Enforce download permission in the server-side download route.
- Do not rely only on hiding the Download button in the interface.
- Test that unauthorized download requests are rejected.

### Threat 4: Unauthorized Document Sharing
**Risk:** A user may try to share a document they do not own or administer.

**Mitigation:**
- Verify document ownership and sharing authority on the server.
- Validate the recipient account and requested permission.
- Reject unauthorized sharing attempts.

### Threat 5: Document Tampering
**Risk:** An uploaded file may be modified or corrupted.

**Mitigation:**
- Calculate a SHA-256 hash for the stored document.
- Recalculate and compare the hash when integrity verification is required.
- Reject a document when the calculated hash does not match the stored hash.

### Threat 6: Malicious File Upload
**Risk:** A user may upload an unsafe file or a file disguised as another type.

**Mitigation:**
- Validate filenames and allowed file types.
- Apply file-size limits.
- Store files safely and avoid executing uploaded content.
- Consider malware scanning where appropriate.

### Threat 7: Session Abuse
**Risk:** An attacker may attempt to misuse a stolen or improperly managed session.

**Mitigation:**
- Protect session cookies using appropriate security settings.
- Use HTTPS in production.
- Configure session expiration and secure logout behavior.

### Threat 8: SQL Injection
**Risk:** Malicious input may attempt to alter database queries.

**Mitigation:**
- Use parameterized SQL queries.
- Avoid constructing SQL statements by concatenating untrusted input.
- Validate user-supplied values.

### Threat 9: Cross-Site Scripting (XSS)
**Risk:** Untrusted input may be rendered as executable browser content.

**Mitigation:**
- Escape user-controlled values in HTML templates.
- Avoid inserting untrusted content directly into HTML or JavaScript.
- Apply a suitable Content Security Policy where appropriate.

### Threat 10: Audit Log Tampering or Exposure
**Risk:** Unauthorized users may attempt to view or modify audit records.

**Mitigation:**
- Restrict audit-log access to authorized administrators.
- Record relevant security-sensitive events.
- Consider protecting logs against modification and deletion in production.

## 4. Residual Risks
These measures reduce risk but do not guarantee complete security. The implementation should be tested for authorization bypasses, insecure file handling, session weaknesses, and audit-log integrity.

## 5. Testing 
-  Unauthenticated users cannot access protected documents.
-  View-only users cannot download documents.
-  Users cannot access documents without permission.
-  Users cannot share documents they do not own or administer.
-  Modified documents fail integrity verification.
-  Non-admin users cannot access admin audit logs.
-  Invalid login attempts do not create authenticated sessions.

## 6. Scope
This document identifies potential threats and intended mitigations. A mitigation should be described as implemented only after it has been verified in the actual application.
