/**
 * GitHub API client helper functions
 */

import { Octokit } from '@octokit/rest';

export interface GitHubAuth {
  appId: number;
  privateKey: string;
  installationId: number;
}

/**
 * Get an authenticated Octokit instance for a GitHub App installation
 */
export async function getInstallationClient(auth: GitHubAuth): Promise<Octokit> {
  // Create JWT for the app
  const jwt = await createAppJWT(auth.appId, auth.privateKey);

  // Get installation token
  const appOctokit = new Octokit({ auth: jwt });
  const { data } = await appOctokit.rest.apps.createInstallationAccessToken({
    installation_id: auth.installationId,
  });

  // Return authenticated client for the installation
  return new Octokit({ auth: data.token });
}

/**
 * Create a JWT for GitHub App authentication
 * expiresIn 10 minutes (GitHub max is 10 minutes)
 */
async function createAppJWT(appId: number, privateKey: string): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iat: now - 60, // issued at (60 seconds ago for clock drift)
    exp: now + 600, // expires (10 minutes)
    iss: appId, // issuer
  };

  const header = {
    alg: 'RS256',
    typ: 'JWT',
  };

  const encoder = new TextEncoder();
  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(payload));
  const data = `${encodedHeader}.${encodedPayload}`;

  const key = await importPKCS8(privateKey);
  const signature = await crypto.subtle.sign(
    { name: 'RSASSA-PKCS1-v1_5' },
    key,
    encoder.encode(data)
  );

  return `${data}.${base64UrlEncode(new Uint8Array(signature))}`;
}

/**
 * Import a PEM private key for JWT signing
 */
async function importPKCS8(pem: string): Promise<CryptoKey> {
  // Remove PEM headers and newlines
  const b64 = pem
    .replace(/-----BEGIN PRIVATE KEY-----/g, '')
    .replace(/-----END PRIVATE KEY-----/g, '')
    .replace(/\s/g, '');

  const binary = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));

  return await crypto.subtle.importKey(
    'pkcs8',
    binary,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['sign']
  );
}

/**
 * Base64URL encode without padding
 */
function base64UrlEncode(input: string | Uint8Array): string {
  let str: string;
  if (typeof input === 'string') {
    str = btoa(input);
  } else {
    str = btoa(String.fromCharCode(...input));
  }
  return str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

/**
 * Fetch file content from a GitHub repository
 */
export async function fetchFileContent(
  octokit: Octokit,
  owner: string,
  repo: string,
  sha: string
): Promise<string> {
  const { data } = await octokit.rest.git.getBlob({
    owner,
    repo,
    file_sha: sha,
  });

  // GitHub API returns base64-encoded content
  const content = atob(data.content);
  return content;
}

/**
 * Create a pull request for secret remediation
 */
export async function createRemediationPR(
  octokit: Octokit,
  owner: string,
  repo: string,
  branch: string,
  title: string,
  body: string
): Promise<{ number: number; url: string }> {
  // First, ensure the remediation branch exists
  const remediationBranch = `keyspinner/remediate-${Date.now()}`;

  try {
    // Get the default branch reference
    const { data: ref } = await octokit.rest.git.getRef({
      owner,
      repo,
      ref: `heads/${branch}`,
    });

    // Create remediation branch
    await octokit.rest.git.createRef({
      owner,
      repo,
      ref: `refs/heads/${remediationBranch}`,
      sha: ref.object.sha,
    });

    // Create the PR
    const { data: pr } = await octokit.rest.pulls.create({
      owner,
      repo,
      title,
      body,
      head: remediationBranch,
      base: branch,
    });

    return {
      number: pr.number,
      url: pr.html_url,
    };
  } catch (error) {
    console.error('Failed to create remediation PR:', error);
    throw error;
  }
}

/**
 * Add a comment to a commit (for quick notification)
 */
export async function commentOnCommit(
  octokit: Octokit,
  owner: string,
  repo: string,
  sha: string,
  message: string
): Promise<void> {
  await octokit.rest.repos.createCommitComment({
    owner,
    repo,
    commit_sha: sha,
    body: message,
  });
}

/**
 * Get files changed in a commit
 */
export async function getCommitFiles(
  octokit: Octokit,
  owner: string,
  repo: string,
  sha: string
): Promise<Array<{ path: string; status: string; sha?: string }>> {
  const { data: commit } = await octokit.rest.repos.getCommit({
    owner,
    repo,
    ref: sha,
  });

  return (commit.files ?? []).map((f) => ({
    path: f.filename,
    status: f.status,
    ...(f.sha ? { sha: f.sha } : {}),
  }));
}
