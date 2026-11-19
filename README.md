# MCP-Guard

**Security auditing for MCP servers and AI-agent skills.**

MCP-Guard is a local application that helps developers assess third-party Model Context Protocol (MCP) servers, MCP configuration files, and AI-agent skills before adding them to an AI environment.

It inspects source code and configuration, identifies suspicious patterns and known dependency vulnerabilities, and produces an audit report with evidence and a recommended decision.

**Purpose:** help developers make a more informed decision before trusting and integrating an MCP server or AI-agent skill.

## What it does

- **MCP server analysis:** inspect tool names, descriptions, input schemas, and Python source code for suspicious behavior and risky patterns.
- **Skill analysis:** review `SKILL.md` instructions for suspicious commands, hidden instructions, credential exposure, and unsafe behavior.
- **Configuration review:** inspect MCP JSON configuration files, including declared commands, arguments, environment values, and server settings.
- **Secret detection:** identify common hardcoded credentials and mask detected values in audit results.
- **Dependency checks:** query OSV.dev for publicly known vulnerabilities affecting detected packages.
- **Change monitoring:** record approved server fingerprints and detect unexpected changes in later checks.
- **Audit history:** keep local records of previous analyses, findings, and alerts.
- **Reports and notifications:** optionally archive reports in Google Drive and send notifications through Gmail SMTP.
- **GitHub import:** import repository files for analysis without requiring a local clone.

## Audit result

Each audit produces findings, evidence, a risk score, and one of three recommendations:

| Recommendation | Meaning |
|---|---|
| **INSTALLER** | No blocking issue was identified by the configured checks. Review the report before use. |
| **CORRIGER** | Issues were identified and should be addressed before integration. |
| **REJETER** | The detected risk is too high to recommend integration. |

MCP-Guard performs static analysis of submitted source files; it does not run the submitted MCP server code as part of that analysis. Results are heuristic and are not a guarantee that a component is safe.

## How it works

1. Select local files, a folder, or a GitHub repository.
2. Run an audit from the local web dashboard.
3. MCP-Guard inspects the submitted material and checks dependencies where supported.
4. Review the risk score, findings, and evidence.
5. Decide whether to reject, correct, or approve the component.
6. For approved components, use change monitoring to identify unexpected modifications.

## Project structure

~~~text
mcp-guard/
├── backend/                 # Web application, agent orchestration, integrations
├── frontend/                # Web dashboard
├── mcp_server/              # MCP tools, analyzers, local registry
├── plugin/
│   ├── mcp-guard/            # MCP-Guard Claude plugin and skills
│   └── osv-scanner/          # Dependency vulnerability lookup
├── knowledge/               # Audit criteria and reference material used by the agent
├── samples/                 # Example components for testing audits
├── tests/                   # Automated tests
├── data/                    # Local database and runtime data
├── uploads/                 # Files submitted for analysis
├── .github/workflows/       # CI test workflow
├── .env.example             # Example local configuration
├── .gitignore
├── requirements.txt
└── run.py                   # Application entry point
~~~

## Requirements

- Windows, Linux, or macOS
- Python 3.11 or newer
- Git
- Claude Code installed and authenticated for AI-agent features
- Internet access for dependency vulnerability lookups and remote repository imports

Claude Code setup: [Anthropic documentation](https://docs.anthropic.com/en/docs/claude-code/setup).

## Installation

### 1. Clone the repository

~~~bash
git clone https://github.com/medsalahlamouri/mcp-guard.git
cd mcp-guard
~~~

### 2. Create a virtual environment

**Windows — PowerShell**

~~~powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
~~~

If PowerShell activation is blocked, use Command Prompt:

~~~bat
.venv\Scripts\activate.bat
~~~

**Linux / macOS**

~~~bash
python3 -m venv .venv
source .venv/bin/activate
~~~

### 3. Install dependencies

~~~bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
~~~

### 4. Configure the application

Create a local `.env` file.

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

Set a strong local dashboard password:

~~~dotenv
MCPGUARD_MOT_DE_PASSE=choose-a-strong-unique-password
~~~

Keep the real configuration in `.env`. Do not commit this file.

### 5. Authenticate Claude Code

Install Claude Code using the [official setup guide](https://docs.anthropic.com/en/docs/claude-code/setup), then run:

~~~bash
claude
~~~

Complete the authentication flow. The AI-agent integration uses the local Claude Code authentication.

### 6. Run MCP-Guard

~~~bash
python run.py
~~~

Open **http://127.0.0.1:8000** and sign in with the password configured in `.env`.

Stop the application with `Ctrl+C`.

## Optional integrations

These integrations are optional. The application can be configured according to the services you want to use.

### GitHub

Public repositories can generally be imported without a token. For private repositories, create a fine-grained GitHub token with the minimum required permissions and add it to your local `.env`:

~~~dotenv
GITHUB_TOKEN=your_github_token
~~~

### Google Drive

To archive audit reports:

1. Enable the Google Drive API in [Google Cloud Console](https://console.cloud.google.com/).
2. Create an OAuth client of type **Desktop app**.
3. Download the client JSON to the project root as `credentials.json`.
4. Run:

~~~bash
python -m backend.autoriser_drive
~~~

5. Complete the browser authorization. The process creates `token.json`.

Keep both files private. They are excluded from Git by `.gitignore`.

### Gmail notifications

For Gmail, use a Google App Password where available, not your normal Google account password. Configure the SMTP values in `.env`:

~~~dotenv
SMTP_HOTE=smtp.gmail.com
SMTP_PORT=465
SMTP_UTILISATEUR=your-address@gmail.com
SMTP_MOT_DE_PASSE=your-google-app-password
ALERTE_DESTINATAIRE=recipient@example.com
~~~

## Run tests

~~~bash
python -m unittest discover -s tests -v
~~~

The repository also includes a GitHub Actions workflow for automated tests.

## Configuration and data

- `.env.example` is the configuration template.
- `.env` contains local settings and credentials.
- Google OAuth files (`credentials.json` and `token.json`) stay on the local machine.
- The SQLite database and uploaded audit files are local runtime data.

Never commit passwords, tokens, OAuth files, private keys, databases, or private audit data. If a credential is exposed, revoke or rotate it immediately. Removing it from the latest commit does not remove it from Git history.

## Project status

MCP-Guard is under active development. Some integrations require external accounts and credentials. Audit coverage depends on the implemented checks and supported input formats.

## License

No license is currently included. Reuse and redistribution are not automatically permitted without a license.
