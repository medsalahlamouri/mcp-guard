# MCP-Guard

**MCP-Guard** is a local security-auditing application for Model Context Protocol (MCP) servers and AI agent skills. It performs static analysis before installation and produces evidence-based recommendations: **INSTALLER**, **CORRIGER**, or **REJETER**.

## Capabilities

- Detect suspicious tool descriptions, prompt injection indicators, hardcoded secrets, unsafe code patterns, and risky MCP configuration.
- Analyze skills and MCP server code without executing the submitted code.
- Check package vulnerabilities through OSV.dev.
- Record audit history and approved-server fingerprints to detect unexpected changes ("rug pulls").
- Optionally archive reports to Google Drive and send notifications through Gmail SMTP.
- Import repositories from GitHub for analysis.

## Architecture

```text
MCP-Guard/
├── backend/          # FastAPI application, agent integration, connectors
├── frontend/         # Web interface
├── mcp_server/       # MCP tools, static analyzers, registry
├── plugin/           # MCP-Guard and OSV scanner Claude plugins
├── knowledge/        # OWASP guidance, scoring, approval policy
├── samples/          # Safe and intentionally vulnerable demonstration inputs
├── tests/            # Automated tests
├── docs/             # Functional, mission, architecture and security docs
├── data/             # Runtime database and outbox (ignored by Git)
├── uploads/           # User-submitted audit inputs (ignored by Git)
├── .env.example       # Configuration template; contains no credentials
├── .gitignore
├── requirements.txt
└── run.py
```

## Requirements

- Python 3.11 or newer
- Claude Code installed and authenticated if you use the Claude Agent SDK features
- Windows, macOS, or Linux

## Local installation

### Windows PowerShell

```powershell
git clone https://github.com/medsalahlamouri/mcp-guard.git
cd mcp-guard
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
Copy-Item .env.example .env
```

Edit the local `.env` file and set at least `MCPGUARD_MOT_DE_PASSE`. Start the application:

```powershell
python run.py
```

Open http://127.0.0.1:8000.

### Linux / macOS

```bash
git clone https://github.com/medsalahlamouri/mcp-guard.git
cd mcp-guard
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
cp .env.example .env
```

Edit `.env`, then run `python run.py`.

## Optional integrations

### Gmail notifications

Configure `SMTP_UTILISATEUR`, `SMTP_MOT_DE_PASSE`, and `ALERTE_DESTINATAIRE` in your local `.env`. For Gmail, use a Google **App Password** with 2-Step Verification enabled. Do not use or publish your normal Google account password.

### Google Drive report archive

1. Enable the Google Drive API in Google Cloud Console.
2. Create an OAuth client of type **Desktop app**.
3. Download the client JSON to the project root as `credentials.json`.
4. Run `python -m backend.autoriser_drive` and complete the consent flow.
5. Keep both `credentials.json` and the generated `token.json` local.

The project uses the `drive.file` scope described by the implementation. Review Google's current consent and verification requirements before distributing the application.

### GitHub import

Set `GITHUB_TOKEN` in the local `.env` only when needed. Prefer a fine-grained token restricted to the repositories and permissions required for importing source files.

## Tests

```bash
python -m unittest discover -s tests -v
```

GitHub Actions runs the test suite on pushes and pull requests.

## Security

**Never commit secrets or user data.** See [docs/SECURITY.md](docs/SECURITY.md) for the credential-handling policy, safe setup, and incident response checklist.

The `.gitignore` excludes local environment files, Google OAuth credentials and tokens, runtime databases, generated email, and uploaded audit inputs. This does not remove secrets that may already exist in Git history. Revoke any credential that has ever been committed, then assess whether history cleanup is required.

## Documentation

- [Security policy](docs/SECURITY.md)
- [Project structure](docs/STRUCTURE.md)
- [Features](docs/FONCTIONNALITES.md)
- [Missions and requirements](docs/MISSIONS.md)

## Limitations

Static analysis is heuristic and can produce false positives or miss vulnerabilities. An audit verdict is decision support, not a guarantee of safety. Validate findings and review changes before installing third-party MCP servers or skills.

## License

No license is currently declared. Unless a license is added, reuse and redistribution are not automatically granted.
