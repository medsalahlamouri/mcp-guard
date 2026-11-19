# Installation Guide

This guide explains how to install and run MCP-Guard on a local computer.

## 1. Prerequisites

Install the following:

- Git
- Python 3.11 or newer (Python 3.12 recommended)
- Claude Code, if you want to use the AI-agent functionality
- Internet access for package installation and online lookups

Check versions:

~~~bash
git --version
python --version
~~~

On Windows, use <code>py --version</code> if the <code>python</code> command is unavailable.

Install Claude Code using Anthropic's [official setup guide](https://docs.anthropic.com/en/docs/claude-code/setup). After installation, run <code>claude</code> and complete authentication.

## 2. Download the project

~~~bash
git clone https://github.com/medsalahlamouri/mcp-guard.git
cd mcp-guard
~~~

## 3. Create a virtual environment

### Windows PowerShell

~~~powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
~~~

If PowerShell blocks activation, use Command Prompt:

~~~bat
.venv\Scripts\activate.bat
~~~

### Linux / macOS

~~~bash
python3 -m venv .venv
source .venv/bin/activate
~~~

## 4. Install dependencies

~~~bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
~~~

## 5. Create the local configuration

**Windows PowerShell**

~~~powershell
Copy-Item .env.example .env
notepad .env
~~~

**Linux / macOS**

~~~bash
cp .env.example .env
nano .env
~~~

Set the required local dashboard password:

~~~dotenv
MCPGUARD_MOT_DE_PASSE=use-a-strong-unique-password
~~~

Do not commit <code>.env</code>. Other settings are optional until you configure their integrations.

## 6. Authenticate Claude Code

Run:

~~~bash
claude
~~~

Follow the sign-in prompts. The Claude Agent SDK integration relies on local Claude Code authentication. Do not add personal credentials to source files.

## 7. Launch the application

Ensure the virtual environment is active and the terminal is in the project root:

~~~bash
python run.py
~~~

Open **http://127.0.0.1:8000** and sign in with the password from <code>.env</code>. Stop the server with <code>Ctrl+C</code>.

## 8. Optional services

### GitHub

For private repository imports, create a fine-grained token with minimum required permissions and set <code>GITHUB_TOKEN</code> in <code>.env</code>. Public repository imports generally do not need a token.

### Google Drive

Enable the Google Drive API, create a Desktop application OAuth client, and download its JSON file as <code>credentials.json</code> in the project root. Then run:

~~~bash
python -m backend.autoriser_drive
~~~

Complete browser authorization. Keep <code>credentials.json</code> and <code>token.json</code> private.

### Gmail SMTP

Configure <code>SMTP_HOTE</code>, <code>SMTP_PORT</code>, <code>SMTP_UTILISATEUR</code>, <code>SMTP_MOT_DE_PASSE</code>, and <code>ALERTE_DESTINATAIRE</code> in <code>.env</code>. For Gmail, use an App Password where available, not your normal account password.

## 9. Verify the installation

~~~bash
python -m unittest discover -s tests -v
~~~

## 10. Common issues

- **Python command not found:** install Python 3.11+ and enable PATH integration; on Windows try <code>py</code>.
- **Module not found:** activate <code>.venv</code> and reinstall <code>requirements.txt</code>.
- **Dashboard password missing:** check that <code>.env</code> is in the project root and contains <code>MCPGUARD_MOT_DE_PASSE</code>; restart the app.
- **Claude CLI missing:** install Claude Code using Anthropic's official setup guide, then reopen the terminal.
- **Claude sign-in problem:** run <code>claude</code> interactively and complete authentication.
- **Drive or email integration fails:** verify the relevant optional credentials and service configuration.

## Security notes

- Never commit <code>.env</code>, <code>credentials.json</code>, <code>token.json</code>, API tokens, private keys, databases, or private audit data to GitHub.
- Rotate credentials immediately if they are exposed.
- <code>.gitignore</code> prevents many accidental additions, but it does not remove secrets already committed or stored in Git history.
- Audit results are heuristic and must be reviewed before approving or installing an MCP server or skill.
