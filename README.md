# PatchPilot

**Security Repair Assistant for AI-Built Websites**

Find security weaknesses in your AI-built website, understand them in plain English, and get evidence-backed guidance to fix them.

> [!IMPORTANT]
> PatchPilot helps identify potential security issues. It **cannot** guarantee complete security or make any application impossible to hack.

---

## Problem Statement

Developers, students, indie hackers, and non-security experts increasingly use AI coding tools (AI website builders, code-generation assistants, AI-powered IDEs) to build functional websites quickly. However, many of these users don't understand common security mistakes involving authentication, database access, exposed API keys, unsafe input handling, vulnerable packages, and insecure configuration.

PatchPilot bridges this gap by scanning source code, identifying supported security weaknesses, explaining them in plain language, and providing actionable guidance to fix them.

## Target Users

- **Students** building projects using AI coding tools
- **Indie hackers** launching their first web applications
- **Developers** who want a quick security review before deployment
- **Non-experts** who need actionable explanations instead of complicated security reports

## Key Features

### 🔍 Multi-Scanner Security Analysis
- **Secret Detection** — Finds hardcoded API keys, passwords, tokens, and credentials
- **Dependency Vulnerabilities** — Identifies known vulnerable npm packages
- **Static Code Analysis** — Detects injection risks, unsafe eval(), XSS patterns, and more
- **Configuration Checks** — Flags insecure CORS, missing security headers, exposed .env files
- **Framework-Specific Checks** — Express middleware, React security patterns, and more

### 📋 Evidence-Backed Reports
- Every finding includes the affected file, line number, code snippet, and scanner rule
- Severity and confidence ratings help prioritize fixes
- Findings are deduplicated and normalized across scanners

### 🔧 Remediation Workspace
- View the problematic code alongside a proposed fix
- Copy suggested fixes or download patch files
- Mark findings as fixed, accepted risk, or false positive
- Rescan to verify fixes

### 📁 Flexible Input
- Upload a ZIP archive of your project
- Submit a public GitHub repository URL
- Safe extraction with ZIP-slip and archive-bomb protections

### 📊 Scan History
- Review past scan results
- Compare findings across scans
- Export reports as JSON

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React, Vite, Tailwind CSS, React Router, Lucide Icons |
| Backend | Node.js, Express.js |
| Database | MongoDB with Mongoose |
| Scanning | Custom security scanners (secret detection, dependency analysis, static analysis, configuration checks) |
| AI (Optional) | OpenAI API for enhanced explanations (not required for core functionality) |

## Architecture

```
┌─────────────────┐     ┌──────────────────────────────────┐     ┌──────────┐
│                 │     │         Express Backend           │     │          │
│  React Frontend │────▶│                                  │────▶│ MongoDB  │
│  (Vite + TW)    │◀────│  ┌─────────┐  ┌──────────────┐  │◀────│          │
│                 │     │  │ Scanner  │  │ Remediation  │  │     └──────────┘
└─────────────────┘     │  │ Engine   │  │ Service      │  │
                        │  └─────────┘  └──────────────┘  │
                        │       │                          │
                        │  ┌────┴────────────────────┐     │
                        │  │ Scanners:               │     │
                        │  │ • Secret Detection      │     │
                        │  │ • Dependency Analysis   │     │
                        │  │ • Static Analysis       │     │
                        │  │ • Configuration Checks  │     │
                        │  │ • Project-Specific      │     │
                        │  └─────────────────────────┘     │
                        └──────────────────────────────────┘
```

## Local Setup

### Prerequisites
- Node.js 18+ 
- npm 9+
- MongoDB (local instance or MongoDB Atlas)
- Git

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/patchpilot.git
cd patchpilot

# Install all dependencies
npm run install:all

# Or install separately
cd server && npm install
cd ../client && npm install
```

### Configuration

Copy the example environment file and configure:

```bash
cp server/.env.example server/.env
```

Edit `server/.env` with your values (see Environment Variables below).

### Running Locally

```bash
# Run both frontend and backend concurrently
npm run dev

# Or run separately:
# Terminal 1 - Backend
cd server && npm run dev

# Terminal 2 - Frontend  
cd client && npm run dev
```

- Frontend: http://localhost:5173
- Backend API: http://localhost:5000

### Running Tests

```bash
npm test
# or
cd server && npm test
```

### Running a Sample Scan

A test project with intentionally vulnerable code is included at `test-project/`. You can:
1. Start PatchPilot locally
2. ZIP the test-project folder: `cd test-project && zip -r ../test-project.zip .`
3. Upload the ZIP through the PatchPilot UI
4. Review the findings

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `PORT` | No | `5000` | Backend server port |
| `MONGODB_URI` | Yes | `mongodb://localhost:27017/patchpilot` | MongoDB connection string |
| `CORS_ORIGIN` | No | `http://localhost:5173` | Allowed CORS origin |
| `UPLOAD_MAX_SIZE` | No | `52428800` (50MB) | Maximum upload file size in bytes |
| `MAX_FILES_IN_ARCHIVE` | No | `5000` | Maximum files allowed in uploaded archive |
| `MAX_DECOMPRESSED_SIZE` | No | `209715200` (200MB) | Maximum decompressed archive size |
| `NODE_ENV` | No | `development` | Environment (development/production) |
| `OPENAI_API_KEY` | No | — | OpenAI API key for AI-enhanced explanations (optional) |

> [!CAUTION]
> Never commit your `.env` file or any real credentials to Git. The `.env.example` file contains placeholder values only.

## Security Scanners

### Secret Detection
Scans source and configuration files for hardcoded secrets including AWS keys, private keys, API tokens, database credentials, and JWT secrets. Values are redacted in reports.

### Dependency Analysis  
Analyzes `package.json` and lockfiles to identify packages with known vulnerabilities. Does not execute `npm install` on untrusted projects.

### Static Code Analysis
Custom rules checking for common security anti-patterns: `eval()`, `innerHTML`, SQL injection, command injection, prototype pollution, weak cryptography, and more.

### Configuration Checks
Detects insecure configurations: committed `.env` files, permissive CORS, missing security headers, insecure cookie settings, debug mode in production.

### Framework-Specific Checks
Context-aware checks for Express.js, React, and other frameworks.

## Supported Checks

| Category | Examples |
|----------|---------|
| Secrets | AWS keys, API tokens, private keys, database credentials, JWT secrets |
| Dependencies | Known vulnerable npm packages, missing lockfiles, unsafe version ranges |
| Code Security | eval(), innerHTML, SQL injection, command injection, XSS, weak crypto |
| Configuration | Exposed .env, CORS *, missing helmet, insecure cookies, debug mode |
| Framework | Express middleware, React security patterns, input validation |

## Known Limitations

- Only analyzes JavaScript/TypeScript projects (npm ecosystem)
- Cannot scan private GitHub repositories (no auth token support in MVP)
- Static analysis only — does not execute or test the scanned application
- Cannot detect all possible vulnerabilities; findings are best-effort
- Some findings may be false positives depending on application context
- Does not replace professional security audits or penetration testing

## Deployment

### Frontend
Deploy the built frontend (`client/dist/`) to any static hosting:
- Vercel
- Netlify
- Cloudflare Pages

### Backend  
Deploy the Express backend to:
- Railway
- Render
- Fly.io
- Any Node.js hosting platform

### Database
Use MongoDB Atlas for a managed cloud database.

### Environment
Configure all environment variables on your hosting platform. Ensure CORS_ORIGIN matches your frontend deployment URL.

## Security Considerations

PatchPilot itself follows security best practices:
- Input validation on all endpoints
- ZIP-slip and archive-bomb protections
- SSRF protection for GitHub URL fetching
- Rate limiting on scan endpoints
- No execution of untrusted code
- Secrets stored in environment variables only
- CORS restricted to configured origins
- Security headers via Helmet
- Uploaded files cleaned up after processing

## License

MIT

---

**PatchPilot** — Built to help developers ship more secure software. Not a replacement for professional security review.
