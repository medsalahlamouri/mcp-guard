# MCP-Guard

**Audit MCP servers and AI-agent skills before you trust or install them.**

MCP-Guard is a local web application for security analysis of Model Context Protocol (MCP) servers, MCP configurations, and AI-agent skills. It combines static code inspection, configuration and description analysis, dependency vulnerability lookups, audit history, and change monitoring.

Its audit workflow returns one of three recommendations:

- **INSTALLER** — no blocking issue was identified by the current checks.
- **CORRIGER** — review and fix the reported issues before use.
- **REJETER** — the current risk is too high for approval.

> **Important:** an automated audit is decision support, not a security guarantee. Static analysis can produce false positives and can miss vulnerabilities. Always review the evidence and source code yourself.

## Features

- Inspect MCP tool names, descriptions, and input schemas for suspicious instructions and tool-poisoning indicators.
- Perform static analysis of Python code for selected risky patterns, including command execution, unsafe deserialization, path traversal, and suspicious network activity.
- Detect hardcoded secrets and mask detected values in reports.
- Review MCP JSON configuration files and Claude skills (SKILL.md).
- Query OSV.dev for known package vulnerabilities.
- Calculate source fingerprints and detect unexpected changes to approved servers (rug-pull monitoring).
- Keep local audit history, alerts, and user preferences.
- Import source files from GitHub.
- Optionally archive reports to Google Drive and send email notifications through SMTP.
- Use a browser-based dashboard served locally by FastAPI.

## How it works

1. Start MCP-Guard on your computer.
2. Sign in to the local web interface.
3. Submit a folder, files, or a GitHub repository for review.
4. MCP-Guard performs its configured checks without executing the submitted source code.
5. Review the findings, evidence, risk score, and recommendation.
6. Approve a server only after reviewing the audit and explicitly requesting approval.

## Project layout

~~~text
mcp-guard/
├── backend/                 # FastAPI app, Claude Agent SDK, integrations
├── frontend/                # Web dashboard
├── mcp_server/              # MCP tools, analyzers, SQLite registry
├── plugin/
│   ├── mcp-guard/            # Claude plugin and audit skills
│   └── osv-scanner/          # OSV dependency scanner plugin
├── knowledge/               # OWASP references and audit policies
├── samples/                 # Safe and intentionally unsafe test samples
├── tests/                   # Automated tests
├── docs/                    # Installation, security, features, project docs
├── data/                    # Local runtime database and generated data
├── uploads/                 # Local user-submitted audit files
├── .github/workflows/       # GitHub Actions tests
├── .env.example             # Safe configuration template
├── .gitignore               # Excludes local secrets and runtime data
├── requirements.txt         # Python dependencies
└── run.py                   # Local application entry point
~~~

Runtime data in <code>data/</code> and submitted files in <code>uploads/</code> are local application data. Their contents are intentionally excluded from version control.

## Requirements

- Windows 10/11, Linux, or macOS.
- Python **3.11 or newer** (Python 3.12 is recommended).
- Git.
- Claude Code installed and authenticated for the AI-agent features. Follow the [official Claude Code setup guide](https://docs.anthropic.com/en/docs/claude-code/setup).
- Internet access for GitHub imports and OSV.dev vulnerability lookups.

Google Drive, Gmail SMTP, and authenticated GitHub import require their own optional configuration.

## Installation

### 1. Clone the repository

~~~bash
git clone https://github.com/medsalahlamouri/mcp-guard.git
cd mcp-guard
~~~

### 2. Create and activate a virtual environment

**Windows — PowerShell**

~~~powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
~~~

If PowerShell blocks activation, use Command Prompt:

~~~bat
.venv\Scripts\activate.bat
~~~

**Linux / macOS**

~~~bash
python3 -m venv .venv
source .venv/bin/activate
~~~

### 3. Install Python dependencies

Run with the virtual environment activated:

~~~bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
~~~

### 4. Configure the environment

Create the local environment file:

**Windows — PowerShell**

~~~powershell
Copy-Item .env.example .env
notepad .env
~~~

**Linux / macOS**

~~~bash
cp .env.example .env
nano .env
~~~

Set a strong, unique local interface password:

~~~dotenv
MCPGUARD_MOT_DE_PASSE=replace-with-a-long-random-password
~~~

Keep the real value only in <code>.env</code>. Do not commit or share this file. Other integrations can remain unconfigured if you do not need them.

### 5. Install and authenticate Claude Code

Follow Anthropic's [official installation instructions](https://docs.anthropic.com/en/docs/claude-code/setup). Then open a terminal and run:

~~~bash
claude
~~~

Complete the sign-in flow when prompted. The Claude Agent SDK integration uses the local Claude Code authentication described in <code>backend/agent.py</code>; it does not require placing an Anthropic API key in this repository.

### 6. Start MCP-Guard

From the repository root, with the virtual environment activated:

~~~bash
python run.py
~~~

Open **http://127.0.0.1:8000** and sign in with the password configured in <code>.env</code>. The application binds to <code>127.0.0.1</code> by default and is intended for local use.

Stop the server with <code>Ctrl+C</code>.

## Optional integrations

Configure only the services you intend to use.

### GitHub import

Public repository import does not normally require a token. For private repositories, create a fine-grained GitHub token with minimum repository access and permissions, then set it in your local <code>.env</code>:

~~~dotenv
GITHUB_TOKEN=your_fine_grained_token
~~~

Never put a token in source code, sample files, or documentation.

### Google Drive report archive

1. Open the [Google Cloud Console](https://console.cloud.google.com/).
2. Create or select a project and enable the Google Drive API.
3. Create an OAuth client ID with application type **Desktop app**.
4. Download the OAuth client JSON to the project root as <code>credentials.json</code>.
5. Run the following command in the activated virtual environment:

~~~bash
python -m backend.autoriser_drive
~~~

6. Complete the Google consent flow in the browser. The process creates <code>token.json</code>.

Both files contain sensitive authentication material. Keep them local; they are excluded by <code>.gitignore</code>. The implementation requests the <code>drive.file</code> scope.

### Gmail SMTP notifications

For Gmail, use a Google App Password where available; do not use your normal Google account password. Configure these values in <code>.env</code>:

~~~dotenv
SMTP_HOTE=smtp.gmail.com
SMTP_PORT=465
SMTP_UTILISATEUR=your-address@gmail.com
SMTP_MOT_DE_PASSE=your-google-app-password
ALERTE_DESTINATAIRE=security-team@example.com
~~~

If SMTP is not configured, demonstration alert messages can be saved locally in <code>data/outbox/</code> instead of being sent.

## Tests

With the virtual environment activated:

~~~bash
python -m unittest discover -s tests -v
~~~

GitHub Actions also runs the test suite on pushes and pull requests.

## Troubleshooting

| Problem | What to check |
|---|---|
| Python is not found | Install Python 3.11+ and ensure it is on PATH. On Windows, try <code>py</code>. |
| Dependency installation fails | Activate <code>.venv</code>, upgrade pip, and retry. |
| Dashboard password is not configured | Set <code>MCPGUARD_MOT_DE_PASSE</code> in the root <code>.env</code>, then restart the app. |
| Claude Code is not found | Install Claude Code using Anthropic's official guide and confirm <code>claude</code> works in a new terminal. |
| Claude authentication fails | Run <code>claude</code> interactively and complete sign-in. |
| Google Drive is unavailable | Check the Drive API, Desktop OAuth client, <code>credentials.json</code>, and local consent/token setup. |
| Email is not sent | Check SMTP settings and use a Google App Password where required. |

## Security and privacy

- Never commit <code>.env</code>, OAuth credentials, access tokens, private keys, databases, uploaded files, or generated reports containing private information.
- Ignore rules do not remove files already tracked by Git.
- If a credential was ever committed, revoke or rotate it immediately. Removing it from the latest version is not sufficient; review Git history as well.
- Treat uploaded repositories, tool descriptions, configuration files, and skills as untrusted input.
- MCP-Guard is designed to analyze submitted code statically; this is not a guarantee that every input or dependency is safe.

See [docs/SECURITY.md](docs/SECURITY.md) for the security policy and incident-response checklist.

## Documentation

- [Installation guide](docs/INSTALLATION.md)
- [Repository structure](docs/STRUCTURE.md)
- [Security policy](docs/SECURITY.md)
- [Features](docs/FONCTIONNALITES.md)
- [Missions and requirements](docs/MISSIONS.md)

## License

No license file is currently provided. Unless a license is added, the project is not automatically licensed for reuse, modification, or redistribution.
