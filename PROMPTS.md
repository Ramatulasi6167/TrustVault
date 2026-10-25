# TrustVault — Project Prompts and Development Notes

## Project Goal
Develop a secure document-sharing web application that supports user authentication, document uploads, permission-based sharing, and audit logging.

## Core Requirements
1. Users should be able to register and log in.
2. Authenticated users should be able to upload and manage their documents.
3. Document owners should be able to share documents with registered users.
4. Access permissions should distinguish between viewing and downloading.
5. Server-side authorization must protect every document operation.
6. SHA-256 hashes should be used to verify document integrity.
7. Administrative audit logs should be restricted to authorized administrators.

## Development Guidelines
- Use Python and Flask for backend routes.
- Use SQLite for persistent application data.
- Use parameterized SQL queries.
- Keep authentication and authorization checks on the server.
- Do not store plain-text passwords.
- Do not expose passwords, secret keys, or sensitive document contents in logs.
- Provide clear error messages without revealing sensitive internal details.
- Test both permitted and denied access scenarios.

## Testing Scenarios
- Register a new account and log in.
- Try logging in with incorrect credentials.
- Upload a PDF and verify that it can be accessed by its owner.
- Share a document with view-only permission.
- Verify that the recipient can view the document but cannot download it.
- Grant download permission and verify that downloading works.
- Try accessing a document from an account without permission.
- Verify that non-admin users cannot access administrative audit logs.
- Modify a stored document and test the integrity check.

## Important Note
These prompts describe project requirements and testing goals. They are not proof that every feature has been implemented or security-tested.
