# KeySpinner 🔒

> Auto-Rotate GitHub Secrets - Detect leaked credentials and create remediation PRs

**KeySpinner** is an autonomous CLI tool that scans your GitHub repositories for leaked secrets (API keys, tokens, passwords) and automatically creates pull requests with step-by-step remediation guidance.

## What It Does

- 🔍 Scans GitHub repositories for 15+ secret types
- 🔴 Detects high/medium severity leaks
- 📋 Creates remediation PRs with rotation instructions
- 🔄 Supports organization, user, and single-repo scanning
- 📊 JSON output for CI/CD integration

## What It Doesn't Do

- **Auto-rotate credentials** (not technically possible for most providers)
- Store actual secret values (only SHA-256 hashes in memory)
- Modify code without your review (PRs must be merged manually)

## Installation

### NPM (Recommended)

```bash
npm install -g keyspinner
```

### From Source

```bash
git clone https://github.com/eylulsenakumral/keyspinner.git
cd keyspinner
npm install
npm run build
npm link
```

## GitHub Token Setup

KeySpinner requires a GitHub Personal Access Token (PAT) with `repo` scope:

1. Go to https://github.com/settings/tokens
2. Click "Generate new token (classic)"
3. Select scopes: `repo` (full control)
4. Generate and copy the token
5. Set as environment variable:

```bash
export GITHUB_TOKEN=ghp_xxx
```

## Usage

### Scan a Single Repository

```bash
keyspinner scan --repo owner/repo
```

### Scan an Organization

```bash
keyspinner scan --org myorg
```

### Scan All User Repositories

```bash
keyspinner scan --user username
```

### Create Remediation PRs

```bash
keyspinner scan --repo owner/repo --create-pr
```

### JSON Output (CI/CD)

```bash
keyspinner scan --org myorg --json --output results.json
```

## Commands

### `keyspinner scan`

Scan repositories for leaked secrets.

**Flags:**
- `-t, --token=<value>` - GitHub PAT (required, or use GITHUB_TOKEN env)
- `-o, --org=<value>` - Organization to scan
- `-r, --repo=<value>` - Single repository (owner/repo format)
- `-u, --user=<value>` - User to scan
- `-j, --json` - Output as JSON
- `--create-pr` - Create remediation PRs

### `keyspinner auth`

Verify GitHub PAT authentication.

**Flags:**
- `-t, --token=<value>` - GitHub PAT (or use GITHUB_TOKEN env)

## Supported Secret Types

| Type | Severity | Rotate? |
|------|----------|---------|
| GitHub Personal Access Token | High | Yes |
| GitHub OAuth Token | High | Yes |
| GitHub App Token | High | Yes |
| AWS Access Key ID | High | Yes |
| AWS Secret Key | High | Yes |
| Stripe Live API Key | High | Yes |
| Stripe Test Key | Medium | Yes |
| Stripe Publishable Key | Medium | Yes |
| Slack Token | High | Yes |
| Slack Webhook | Medium | Yes |
| Docker Hub Token | High | Yes |
| NPM Token | High | Yes |
| Google API Key | High | Yes |
| Google OAuth Client ID | High | Yes |
| Heroku API Key | High | Yes |

## Output Format

### Console Output

```
🔍 Scanning 3 repository(ies)...

  Scanning owner/repo1...
    🔴 Found 2 secret(s)

  Scanning owner/repo2...
    ✓ No secrets found

📊 Scan Summary:
  Total secrets found: 2
  High severity: 2
  Medium severity: 0

🔴 Action Required:
  1. Rotate all leaked credentials immediately
  2. Remove secrets from repository history
  3. Use --create-pr flag to generate remediation PRs
```

### JSON Output

```json
[
  {
    "repository": "owner/repo1",
    "secrets": [
      {
        "file": ".env",
        "line": 12,
        "type": "aws_access_key",
        "severity": "high",
        "match": "AKIAIOSFODNN7EXAMPLE",
        "description": "AWS Access Key ID",
        "rotate": true
      }
    ],
    "filesScanned": 15
  }
]
```

## Remediation PRs

When using `--create-pr`, KeySpinner:

1. Creates a new branch: `keyspinner/remediate-{timestamp}`
2. Redacts secrets in files with `[REDACTED_SECRET]`
3. Creates `KEYSPINNER_REMEDIATION.md` with rotation instructions
4. Opens a draft PR with:
   - List of all detected secrets
   - Severity levels
   - Step-by-step rotation instructions
   - Tools for history cleanup (BFG Repo-Cleaner, git-filter-repo)

## CI/CD Integration

### GitHub Actions

```yaml
name: KeySpinner Scan
on:
  push:
    branches: [main]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - run: npm install -g keyspinner
      - run: keyspinner scan --org ${{ github.repository_owner }} --json --output results.json
      - uses: actions/upload-artifact@v3
        with:
          name: scan-results
          path: results.json
```

## Troubleshooting

### "Invalid token" error

- Verify your PAT has `repo` scope
- Check token hasn't expired
- Ensure GITHUB_TOKEN env var is set correctly

### "Failed to fetch repositories"

- For org scans: Ensure your PAT has org access
- For user scans: PAT must have `repo` scope
- Rate limiting: Wait a few minutes and retry

### False Positives

KeySpinner may detect strings that look like secrets but aren't. Always:
1. Verify the detected value is actually a secret
2. Check if it's in documentation or test files
3. Use allowlists in future versions (planned feature)

### Rate Limiting

GitHub API has rate limits:
- Authenticated: 5,000 requests/hour
- KeySpinner makes ~2-3 requests per file scanned

For large orgs, consider:
1. Scanning specific repos only with `--repo`
2. Spacing out scans over time
3. Using GitHub App authentication (future feature)

## Security Model

- **No secret storage**: Only scans in memory
- **Read-only access**: Only reads repository files
- **Manual approval**: All changes via PR review
- **Transparent**: Shows exactly what was found

## Roadmap

- [ ] Allowlist patterns for false positives
- [ ] GitHub App authentication (higher rate limits)
- [ ] Multi-branch scanning
- [ ] Custom secret patterns
- [ ] Slack/Discord webhooks for alerts
- [ ] Secret expiration tracking
- [ ] Integration with secret managers (1Password, HashiCorp Vault)

## Architecture

**Majestic Monolith** - Single CLI binary, no microservices:

- TypeScript + oclif framework
- Octokit for GitHub API
- Regex-based pattern matching
- No external dependencies

## Development

```bash
# Install dependencies
npm install

# Build
npm run build

# Test locally
node bin/run.js scan --help

# Lint
npm run lint
```

## License

MIT

## Support

- GitHub Issues: https://github.com/eylulsenakumral/keyspinner/issues
- Auto Company: dev@autocompany.dev

---

**KeySpinner** is developed by Auto Company - an autonomous AI company building security tools.
