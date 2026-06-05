/**
 * Main Cloudflare Worker entry point
 * Handles GitHub webhooks and coordinates secret scanning
 */

import { Webhooks } from '@octokit/webhooks';
import type { Octokit } from '@octokit/rest';
import { getInstallationClient, getCommitFiles, fetchFileContent } from '../lib/github';
import { findSecrets, maskSecret, hashSecret } from '../lib/secrets';
import { generatePRTitle, generatePRBody } from '../lib/pr-template';
import {
  upsertMonitoredRepo,
  wasCommitScanned,
  recordScan,
  saveDetectedSecrets,
  isSecretAllowed,
} from '../lib/db';
import type { Env, GitHubPushEvent } from '../types';

/**
 * Main worker fetch handler
 */
export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    // Health check
    if (url.pathname === '/health') {
      return Response.json({ status: 'ok', version: '1.0.0' });
    }

    // Webhook endpoint
    if (url.pathname === '/webhook' && request.method === 'POST') {
      return handleWebhook(request, env, ctx);
    }

    // Dashboard (basic for MVP)
    if (url.pathname === '/' || url.pathname === '/dashboard') {
      return handleDashboard(request, env);
    }

    return Response.json({ error: 'Not found' }, { status: 404 });
  },
};

/**
 * Handle GitHub webhook events
 */
async function handleWebhook(
  request: Request,
  env: Env,
  ctx: ExecutionContext
): Promise<Response> {
  try {
    // Verify webhook signature
    const webhooks = new Webhooks({ secret: env.GITHUB_WEBHOOK_SECRET });
    const rawBody = await request.text();
    const signature = request.headers.get('x-hub-signature-256') ?? '';

    await webhooks.verify(rawBody, signature);

    const payload = JSON.parse(rawBody) as { [key: string]: unknown };
    const eventType = request.headers.get('x-github-event') ?? 'unknown';

    // Handle different event types
    switch (eventType) {
      case 'push':
        await handlePushEvent(payload as unknown as GitHubPushEvent, env, ctx);
        break;

      case 'installation':
      case 'installation_repositories':
        await handleInstallationEvent(payload);
        break;

      default:
        console.log(`Unhandled event type: ${eventType}`);
    }

    return Response.json({ received: true });
  } catch (error) {
    console.error('Webhook error:', error);
    return Response.json({ error: 'Invalid webhook' }, { status: 400 });
  }
}

/**
 * Handle push events - trigger secret scan
 */
async function handlePushEvent(
  payload: GitHubPushEvent,
  env: Env,
  ctx: ExecutionContext
): Promise<void> {
  const { repository, installation, ref, commits } = payload;

  if (!installation) {
    console.log('No installation ID - skipping');
    return;
  }

  // Skip if no commits
  if (commits.length === 0) {
    return;
  }

  // Get or create monitored repo
  const repo = await upsertMonitoredRepo(
    env.DB,
    repository.id,
    repository.owner.login,
    repository.name,
    installation.id
  );

  // Extract branch from ref (refs/heads/main -> main)
  const branch = ref.replace('refs/heads/', '');

  // Process each commit (use latest for scanning)
  for (const commit of commits) {
    // Skip if already scanned
    if (await wasCommitScanned(env.DB, repo.id, commit.sha)) {
      console.log(`Commit ${commit.sha} already scanned`);
      continue;
    }

    // Scan the commit asynchronously
    ctx.waitUntil(
      scanCommit(repo.id, commit.sha, branch, repository.owner.login, repository.name, installation.id, env)
    );
  }
}

/**
 * Scan a commit for secrets
 */
async function scanCommit(
  repoId: number,
  commitSha: string,
  branch: string,
  owner: string,
  repoName: string,
  installationId: number,
  env: Env
): Promise<void> {
  const startTime = Date.now();

  try {
    // Get GitHub client
    const octokit = await getInstallationClient({
      appId: parseInt(env.GITHUB_APP_ID),
      privateKey: env.GITHUB_APP_PRIVATE_KEY,
      installationId,
    });

    // Get files changed in commit
    const files = await getCommitFiles(octokit, owner, repoName, commitSha);

    let filesScanned = 0;
    let secretsFound = 0;
    const detectedSecrets: Array<{
      secretType: string;
      secretValueHash: string;
      filePath: string;
      lineNumber: number;
      commitSha: string;
      commitUrl: string;
      severity: 'high' | 'medium' | 'low';
    }> = [];

    // Scan each file
    for (const file of files) {
      // Skip deleted files
      if (file.status === 'removed' || !file.sha) {
        continue;
      }

      // Skip binary/common non-code files
      if (isBinaryFile(file.path)) {
        continue;
      }

      // Check allowlist
      if (await isSecretAllowed(env.DB, repoId, file.path, '')) {
        console.log(`File ${file.path} is allowlisted - skipping`);
        continue;
      }

      try {
        // Fetch file content
        const content = await fetchFileContent(octokit, owner, repoName, file.sha!);

        // Scan for secrets
        const matches = findSecrets(content, file.path);

        if (matches.length > 0) {
          secretsFound += matches.length;

          for (const match of matches) {
            // Hash the secret value for storage (SHA-256)
            const secretHash = await hashSecret(match.match);

            detectedSecrets.push({
              secretType: match.pattern.name,
              secretValueHash: secretHash,
              filePath: file.path,
              lineNumber: match.line,
              commitSha,
              commitUrl: `https://github.com/${owner}/${repoName}/commit/${commitSha}`,
              severity: match.pattern.severity,
            });
          }
        }

        filesScanned++;
      } catch (error) {
        console.error(`Failed to scan file ${file.path}:`, error);
      }
    }

    // Save results
    await recordScan(env.DB, repoId, commitSha, branch, secretsFound, filesScanned, Date.now() - startTime);

    if (detectedSecrets.length > 0) {
      await saveDetectedSecrets(env.DB, repoId, detectedSecrets);

      // Create PR if high-severity secrets found
      const hasHighSeverity = detectedSecrets.some(s => s.severity === 'high');
      if (hasHighSeverity) {
        await createRemediationPR(
          octokit,
          owner,
          repoName,
          branch,
          commitSha,
          detectedSecrets
        );
      }
    }

    console.log(`Scan complete: ${filesScanned} files, ${secretsFound} secrets found`);
  } catch (error) {
    console.error('Scan failed:', error);
  }
}

/**
 * Create a remediation pull request
 */
async function createRemediationPR(
  octokit: Octokit,
  owner: string,
  repoName: string,
  branch: string,
  commitSha: string,
  secrets: Array<{
    secretType: string;
    secretValueHash: string;
    filePath: string;
    lineNumber: number;
    severity: 'high' | 'medium' | 'low';
  }>
): Promise<void> {
  const prData = {
    repoOwner: owner,
    repoName,
    branch,
    secrets: secrets.map((s) => ({
      type: s.secretType,
      file: s.filePath,
      line: s.lineNumber,
      masked: maskSecret(s.secretValueHash),
      severity: s.severity,
    })),
    commitSha,
    commitUrl: `https://github.com/${owner}/${repoName}/commit/${commitSha}`,
  };

  const title = generatePRTitle(secrets.length);
  const body = generatePRBody(prData);

  try {
    const { createRemediationPR } = await import('../lib/github.js');
    const pr = await createRemediationPR(octokit, owner, repoName, branch, title, body);
    console.log(`Created PR #${pr.number}: ${pr.url}`);
  } catch (error) {
    console.error('Failed to create PR:', error);
  }
}

/**
 * Handle installation events (app installed/uninstalled)
 */
async function handleInstallationEvent(payload: { [key: string]: unknown }): Promise<void> {
  const action = payload.action as string;
  const installation = payload.installation as { id: number } | undefined;

  if (action === 'created' || action === 'added') {
    console.log(`Installation ${installation?.id ?? 'unknown'} created`);
  } else if (action === 'deleted') {
    console.log(`Installation ${installation?.id ?? 'unknown'} deleted`);
  }
}

/**
 * Simple dashboard handler
 */
async function handleDashboard(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);

  // API endpoint
  if (url.pathname === '/api/repos') {
    const repos = await env.DB
      .prepare('SELECT * FROM monitored_repos WHERE enabled = 1 ORDER BY updated_at DESC')
      .all();

    return Response.json(repos.results || []);
  }

  // Simple HTML dashboard (MVP)
  const html = `
<!DOCTYPE html>
<html>
<head>
  <title>KeySpinner Dashboard</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; }
    h1 { color: #333; border-bottom: 2px solid #0366d6; padding-bottom: 10px; }
    .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }
    .stat-card { background: #f6f8fa; padding: 20px; border-radius: 8px; }
    .stat-value { font-size: 32px; font-weight: bold; color: #0366d6; }
    .stat-label { color: #586069; font-size: 14px; }
    table { width: 100%; border-collapse: collapse; margin-top: 20px; }
    th, td { padding: 12px; text-align: left; border-bottom: 1px solid #e1e4e8; }
    th { background: #f6f8fa; font-weight: 600; }
    .badge { display: inline-block; padding: 4px 8px; border-radius: 12px; font-size: 12px; font-weight: 600; }
    .badge-high { background: #d73a49; color: white; }
    .badge-medium { background: #fbca04; color: #333; }
    .badge-low { background: #6cbf6f; color: white; }
  </style>
</head>
<body>
  <h1>🔒 KeySpinner Dashboard</h1>
  <div class="stats">
    <div class="stat-card">
      <div class="stat-value" id="total-repos">-</div>
      <div class="stat-label">Monitored Repositories</div>
    </div>
    <div class="stat-card">
      <div class="stat-value" id="total-secrets">-</div>
      <div class="stat-label">Active Secrets</div>
    </div>
    <div class="stat-card">
      <div class="stat-value" id="total-scans">-</div>
      <div class="stat-label">Total Scans</div>
    </div>
  </div>
  <h2>Monitored Repositories</h2>
  <table id="repos-table">
    <thead>
      <tr>
        <th>Repository</th>
        <th>Last Scan</th>
        <th>Active Secrets</th>
        <th>Status</th>
      </tr>
    </thead>
    <tbody>
      <tr><td colspan="4">Loading...</td></tr>
    </tbody>
  </table>
  <script>
    fetch('/api/repos')
      .then(r => r.json())
      .then(repos => {
        document.getElementById('total-repos').textContent = repos.length;
        let totalSecrets = 0;
        let totalScans = 0;
        const tbody = document.querySelector('#repos-table tbody');
        tbody.innerHTML = repos.map(repo => \`
          <tr>
            <td><strong>\${repo.owner}/\${repo.repo}</strong></td>
            <td>\${new Date(repo.updated_at).toLocaleDateString()}</td>
            <td>-</td>
            <td><span class="badge" style="background: #2ea44f; color: white;">Active</span></td>
          </tr>
        \`).join('');
      });
  </script>
</body>
</html>`;

  return new Response(html, {
    headers: { 'Content-Type': 'text/html' },
  });
}

/**
 * Check if a file is binary (skip for scanning)
 */
function isBinaryFile(path: string): boolean {
  const binaryExtensions = [
    '.png', '.jpg', '.jpeg', '.gif', '.ico', '.bmp', '.webp',
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.zip', '.tar', '.gz', '.rar', '.7z',
    '.exe', '.dll', '.so', '.dylib',
    '.mp3', '.mp4', '.avi', '.mov', '.wav',
    '.ttf', '.otf', '.woff', '.woff2',
  ];
  return binaryExtensions.some((ext) => path.endsWith(ext));
}
