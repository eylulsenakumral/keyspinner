# KeySpinner 🔒

> Auto-Rotate GitHub Secrets - Detect leaked credentials and create remediation PRs

**KeySpinner** monitors your GitHub repositories for leaked secrets (API keys, tokens, passwords) and automatically creates pull requests with remediation guidance. Most credentials can't be auto-rotated, so KeySpinner focuses on **detection + guidance + PR creation**.

## What It Does

- Scans every push to monitored repositories for leaked secrets
- Supports 15+ secret types (GitHub PATs, AWS keys, Stripe tokens, Slack tokens, etc.)
- Creates PRs with step-by-step rotation instructions
- Simple dashboard for monitoring detected secrets
- Allowlist patterns for false positives

## What It Doesn't Do

- **Auto-rotate credentials** (not technically possible for most providers)
- Store actual secret values (only SHA-256 hashes)
- Modify code without your review (PRs must be merged manually)

## Architecture

Monolith on Cloudflare Workers:
- GitHub Webhook → Worker → D1 Scan → PR Creation
- Single deployment, no microservices
- D1 database for state (monitored repos, detected secrets, allowlists)

## Quick Start

### 1. Clone and Install

```bash
git clone https://github.com/yourorg/keyspinner.git
cd keyspinner
npm install
```

### 2. Create D1 Database

```bash
npm run db:create
# Output: Copy the database_id to wrangler.toml
```

### 3. Run Migrations

```bash
npm run db:migrate
```

### 4. Create GitHub App

1. Go to https://github.com/settings/apps/new
2. Set **GitHub App name**: `KeySpinner`
3. Set **Homepage URL**: `https://your-worker-domain.workers.dev`
4. Set **Webhook URL**: `https://your-worker-domain.workers.dev/webhook`
5. Create a **Webhook secret** (save this!)
6. Under **Repository permissions**:
   - `Contents`: **Read**
   - `Pull requests`: **Write**
   - `Metadata`: **Read**
7. Under **Events**, select:
   - `Push`
   - `Installation`
   - `Repository installation events`
8. Click **Create GitHub App**
9. Generate a private key and download it (save this!)
10. Copy the **App ID** (save this!)

### 5. Set Secrets

```bash
# GitHub App credentials
npx wrangler secret put GITHUB_APP_ID
npx wrangler secret put GITHUB_APP_PRIVATE_KEY < path/to/private-key.pem
npx wrangler secret put GITHUB_WEBHOOK_SECRET

# Optional: Email notifications
npx wrangler secret put SENDGRID_API_KEY
npx wrangler secret put FROM_EMAIL
```

### 6. Deploy

```bash
npm run deploy
```

### 7. Install the App

Install the GitHub App to your repositories:
- Go to your app settings: https://github.com/settings/apps
- Click on `KeySpinner`
- Click "Install App" and select repositories

## Local Development

```bash
# Start local dev server
npm run dev

# In another terminal, setup local DB
npm run db:create --local
npm run db:migrate-local

# Test webhook locally
# Use ngrok or similar to tunnel localhost to internet
ngrok http 8787
# Update GitHub App webhook URL to ngrok URL
```

## Database Schema

```sql
-- monitored_repos: Repositories being scanned
-- detected_secrets: Hashes of found secrets (not actual values!)
-- repo_allowlists: Patterns to exclude from scanning
-- scan_history: Deduplication and stats
```

## Supported Secret Types

| Type | Severity | Rotate? |
|------|----------|---------|
| GitHub Personal Access Token | High | Yes |
| GitHub OAuth Token | High | Re-auth |
| AWS Access Key | High | Yes |
| AWS Secret Key | High | Yes |
| Stripe API Key (Live) | High | Yes |
| Stripe Test Key | Medium | Yes |
| Slack Token | High | Yes |
| Slack Webhook | Medium | Regenerate |
| Docker Hub Token | High | Yes |
| NPM Token | High | Yes |
| Google API Key | High | Restrict |
| Google OAuth | High | Re-auth |
| Heroku API Key | High | Yes |

## Dashboard

Visit your worker URL to see:
- Monitored repositories
- Active detected secrets
- Scan history

## Security Model

- **No secret storage**: Only SHA-256 hashes stored
- **Read-only access**: App only reads code, writes PRs
- **Manual approval**: All changes via PR review
- **Webhook verification**: All events verified

## Roadmap

- [ ] Email notifications for new secrets
- [ ] Slack/Discord webhooks for alerts
- [ ] Multi-branch scanning (not just default branch)
- [ ] Custom secret patterns per repository
- [ ] Secret expiration tracking
- [ ] Integration with secret managers (1Password, HashiCorp Vault)

## License

MIT

## Support

For issues and questions:
- GitHub Issues: https://github.com/yourorg/keyspinner/issues
- Email: dev@autocompany.dev
