# TrustVault — Secure Document Sharing

## Project Overview
TrustVault is a secure document-sharing web application that allows users to upload documents, share them with other users, and manage access permissions.

The application includes authentication, role-based access control, document integrity verification, and audit logging.

## Features
- User registration and login
- Password-based authentication
- Document upload and management
- Document sharing with other users
- View-only and download permissions
- Access control for shared documents
- SHA-256 document integrity verification
- Audit logs for tracking important activities
- Admin dashboard for managing and reviewing activity

## Technology Stack
- **Language:** Python
- **Backend:** Flask
- **Database:** SQLite
- **Frontend:** HTML, CSS, JavaScript
- **Security:** Password hashing, access control, SHA-256 integrity verification

## Project Structure
```text
TrustVault/
├── app.py
├── requirements.txt
├── README.md
├── THREATS.md
├── prompts/
├── uploads/
└── trustvault.db
```

*Note: The structure above is illustrative. Actual files and folders may vary.*

## Installation and Setup

1. Open a terminal in the project directory.
2. Create and activate a virtual environment if required.
3. Install dependencies:

```bash
python -m pip install -r requirements.txt
```

4. Start the application:

```bash
python app.py
```

5. Open the local URL shown in the terminal, usually `http://127.0.0.1:5000`.

## Usage
1. Register a user account.
2. Log in using your credentials.
3. Upload a document.
4. Share the document with another registered user.
5. Assign the appropriate access permission.
6. Verify that users can perform only the actions permitted to them.
7. Review audit logs using an authorized administrator account.

## Security
TrustVault uses authentication and permission checks to protect documents. SHA-256 hashes are used to verify document integrity. Audit logs help record important application activities.

## Limitations
- The local SQLite database is separate from any deployed database unless migration is implemented.
- Browser preview depends on supported file types.
- Production deployment requires secure configuration, appropriate secret management, and HTTPS.

## Disclaimer
This project was developed as a document-sharing application for learning and hiring-challenge purposes. Security features should be tested before production use.
