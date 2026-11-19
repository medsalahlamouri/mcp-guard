# Security and secret management

## Never commit credentials

Keep all real credentials outside Git. The repository may contain templates and instructions, but must not contain:

- Google OAuth client secrets or downloaded OAuth client JSON files.
- Google access or refresh tokens.
- Gmail passwords or Google App Passwords.
- GitHub personal access tokens.
- API keys, private keys, certificates containing private material, or production connection strings.
- Local databases, email outbox contents, uploaded files, or reports containing personal data.

Use the local `.env` file for environment-specific values. Start from `.env.example`, then fill in values locally. Never paste real credentials into issues, pull requests, screenshots, documentation, or commit messages.

## Google integrations

- Use OAuth with the minimum scopes required by the feature.
- Store `credentials.json` and `token.json` locally only.
- Do not share the generated token file: it can grant access without asking for the password again.
- Revoke the OAuth grant in your Google Account if the token or client secret is exposed.

## Gmail SMTP

Use a Google App Password where supported, not the primary Google account password. Store it only in `SMTP_MOT_DE_PASSE` in the local `.env`. Revoke and replace it if exposed.

## GitHub

Use a fine-grained personal access token, restrict repository access, grant only the required permissions, and set an expiration. Store it in `GITHUB_TOKEN` locally or in the CI platform's encrypted secrets store. Never hardcode it.

## Before every commit

1. Check `git status --short`.
2. Review the staged diff with `git diff --cached`.
3. Run a secret scanner such as Gitleaks.
4. Confirm that `.env`, OAuth files, databases, outbox data, and uploads are ignored.
5. Do not rely on `.gitignore` for files that are already tracked.

## If a secret was exposed

1. Revoke or rotate the credential immediately. Deleting the visible file is not enough.
2. Review provider audit logs and account activity for unexpected access.
3. Remove the secret from the current files and prevent it from being committed again.
4. Assess whether Git history must be rewritten. History rewriting changes commit IDs and affects collaborators and forks.
5. Contact GitHub Support if cached sensitive content remains after remediation.

A private repository is not a secret store. Anyone with repository access may be able to read committed credentials.

## Scope and limitations

The ignore rules reduce accidental commits; they do not prove that the entire Git history is clean. A full history scan and provider-side credential review are required before declaring the repository free of exposed secrets.
