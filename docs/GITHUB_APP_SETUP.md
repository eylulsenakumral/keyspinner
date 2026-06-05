# GitHub App Setup Guide for KeySpinner

This guide walks you through creating the GitHub App required for KeySpinner.

## Step 1: Create a New GitHub App

1. Navigate to: https://github.com/settings/apps/new
2. Fill in the basics:

   | Field | Value |
   |-------|-------|
   | **GitHub App name** | `KeySpinner` (or your preferred name) |
   | **Homepage URL** | `https://your-worker.workers.dev` |
   | **Description** | Auto-detects leaked secrets and creates remediation PRs |

3. Under **Webhook**, check **Active**:
   - **URL**: `https://your-worker.workers.dev/webhook`
   - **Secret**: Generate and save this (you'll need it later!)

4. Under **Repository permissions**:

   | Permission | Access |
   |------------|--------|
   | Contents | Read |
   | Pull requests | Write |
   | Metadata | Read |

5. Under **Organization permissions** (optional):
   - Leave empty for user-level installation
   - Add `Contents: Read` for org-wide installation

6. Under **Events**:
   - ✅ **Push**
   - ✅ **Installation**
   - ✅ **Repository installation events** (if org-level)

7. Click **Create GitHub App**

## Step 2: Generate Private Key

1. On the app page, scroll to **Private keys**
2. Click **Generate a private key**
3. A `.pem` file will download - **save this securely!**
4. You cannot download it again

## Step 3: Note Your Credentials

From the app page, note:

- **App ID** (top of page)
- **Webhook Secret** (from Step 1)
- **Private Key** (the `.pem` file)

## Step 4: Configure Wrangler

Update your `wrangler.toml` database_id after creating D1:

```bash
npm run db:create
```

Copy the output `database_id` to your `wrangler.toml`.

## Step 5: Set Secrets

```bash
# Set the App ID
npx wrangler secret put GITHUB_APP_ID
# Paste the numeric App ID

# Set the Webhook Secret
npx wrangler secret put GITHUB_WEBHOOK_SECRET
# Paste the webhook secret

# Set the Private Key
npx wrangler secret put GITHUB_APP_PRIVATE_KEY < path/to/private-key.pem
# This reads from the downloaded .pem file
```

## Step 6: Deploy

```bash
npm run deploy
```

Copy your Worker URL from the output.

## Step 7: Update GitHub App (if needed)

If your Worker URL differs from what you set initially:
1. Go to https://github.com/settings/apps
2. Click **Edit** on your app
3. Update the **Webhook URL** to your actual Worker URL

## Step 8: Install the App

1. On your app page, click **Install App**
2. Select **All repositories** or specific repos
3. Click **Install**

## Verify Installation

1. Push a commit with a test secret to a monitored repo:
   ```
   test_secret = "ghp_test1234567890abcdef"
   ```

2. Check the dashboard at your Worker URL
3. A PR should be created within 1-2 minutes

## Troubleshooting

**No PRs created?**
- Check Worker logs: `npx wrangler tail`
- Verify webhook secret is correct
- Check installation has `Contents: Read` and `Pull requests: Write`

**Database errors?**
- Run migrations: `npm run db:migrate`
- Check `database_id` in `wrangler.toml`

**Permission denied?**
- Reinstall the app with correct permissions
- Check org settings if installing to organization
