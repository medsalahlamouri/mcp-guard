# Repository structure

The repository is organized by application responsibility. Existing import paths are intentionally retained; moving Python packages without updating imports and tests could break the application.

| Path | Responsibility |
|---|---|
| `backend/` | FastAPI routes, Claude Agent SDK integration, Gmail/Drive/GitHub connectors |
| `frontend/` | Browser interface |
| `mcp_server/` | MCP server, analyzers, persistent registry |
| `plugin/` | Claude plugins and OSV scanner integration |
| `knowledge/` | Security reference material and audit policy |
| `samples/` | Demonstration inputs, including deliberately vulnerable examples |
| `tests/` | Automated regression tests |
| `docs/` | Project documentation |
| `data/` | Runtime database and local email outbox; generated data is not versioned |
| `uploads/` | User-submitted files; contents are not versioned |

## Configuration

- `.env.example`: safe template committed to Git.
- `.env`: local secrets and settings; ignored by Git.
- `credentials.json` and `token.json`: local Google OAuth material; ignored by Git.
- `claude_desktop_config.example.json`: example client configuration with local paths; customize locally.
