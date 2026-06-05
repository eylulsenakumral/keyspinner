/**
 * D1 Database helper functions
 */

import {
  MonitoredRepo,
  DetectedSecret,
  RepoAllowlist,
} from '../types';

/**
 * Register or update a monitored repository
 */
export async function upsertMonitoredRepo(
  db: D1Database,
  githubRepoId: number,
  owner: string,
  repo: string,
  installationId: number
): Promise<MonitoredRepo> {
  const result = await db
    .prepare(
      `INSERT INTO monitored_repos (github_repo_id, owner, repo, installation_id)
       VALUES (?, ?, ?, ?)
       ON CONFLICT(github_repo_id) DO UPDATE SET
         installation_id = excluded.installation_id,
         updated_at = datetime('now')
       RETURNING *`
    )
    .bind(githubRepoId, owner, repo, installationId)
    .first<MonitoredRepo>();

  return result!;
}

/**
 * Get a monitored repository by GitHub repo ID
 */
export async function getMonitoredRepo(
  db: D1Database,
  githubRepoId: number
): Promise<MonitoredRepo | null> {
  return await db
    .prepare('SELECT * FROM monitored_repos WHERE github_repo_id = ? AND enabled = 1')
    .bind(githubRepoId)
    .first<MonitoredRepo>();
}

/**
 * Check if a commit has already been scanned
 */
export async function wasCommitScanned(
  db: D1Database,
  repoId: number,
  commitSha: string
): Promise<boolean> {
  const result = await db
    .prepare('SELECT 1 FROM scan_history WHERE repo_id = ? AND commit_sha = ?')
    .bind(repoId, commitSha)
    .first();

  return !!result;
}

/**
 * Record a scan in history
 */
export async function recordScan(
  db: D1Database,
  repoId: number,
  commitSha: string,
  branch: string,
  secretsFound: number,
  filesScanned: number,
  durationMs: number
): Promise<void> {
  await db
    .prepare(
      `INSERT INTO scan_history (repo_id, commit_sha, branch, secrets_found, files_scanned, scan_duration_ms)
       VALUES (?, ?, ?, ?, ?, ?)`
    )
    .bind(repoId, commitSha, branch, secretsFound, filesScanned, durationMs)
    .run();
}

/**
 * Save detected secrets (only store hash, not the actual secret)
 */
export async function saveDetectedSecrets(
  db: D1Database,
  repoId: number,
  secrets: Array<{
    secretType: string;
    secretValueHash: string;
    filePath: string;
    lineNumber: number;
    commitSha: string;
    commitUrl: string;
    severity: 'high' | 'medium' | 'low';
  }>
): Promise<void> {
  const stmt = db.prepare(
    `INSERT INTO detected_secrets (repo_id, secret_type, secret_value_hash, file_path, line_number, commit_sha, commit_url, severity)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  );

  for (const secret of secrets) {
    await stmt
      .bind(
        repoId,
        secret.secretType,
        secret.secretValueHash,
        secret.filePath,
        secret.lineNumber,
        secret.commitSha,
        secret.commitUrl,
        secret.severity
      )
      .run();
  }
}

/**
 * Check if a secret is on the allowlist
 */
export async function isSecretAllowed(
  db: D1Database,
  repoId: number,
  filePath: string,
  secretType: string
): Promise<boolean> {
  const allowlists = await db
    .prepare('SELECT pattern FROM repo_allowlists WHERE repo_id = ?')
    .bind(repoId)
    .all<RepoAllowlist>();

  for (const entry of allowlists.results) {
    // Simple pattern matching - can be enhanced with regex
    if (filePath.includes(entry.pattern) || secretType.includes(entry.pattern)) {
      return true;
    }
  }

  return false;
}

/**
 * Get active secrets for a repository
 */
export async function getActiveSecrets(
  db: D1Database,
  repoId: number
): Promise<DetectedSecret[]> {
  const result = await db
    .prepare(
      `SELECT * FROM detected_secrets
       WHERE repo_id = ? AND status = 'active'
       ORDER BY reported_at DESC`
    )
    .bind(repoId)
    .all<DetectedSecret>();

  return result.results || [];
}

/**
 * Mark a secret as resolved
 */
export async function markSecretResolved(
  db: D1Database,
  secretId: number
): Promise<void> {
  await db
    .prepare(
      `UPDATE detected_secrets
       SET status = 'rotated', resolved_at = datetime('now')
       WHERE id = ?`
    )
    .bind(secretId)
    .run();
}

/**
 * Add a pattern to the allowlist
 */
export async function addAllowlistPattern(
  db: D1Database,
  repoId: number,
  pattern: string,
  reason: string,
  addedBy: string
): Promise<void> {
  await db
    .prepare(
      `INSERT OR IGNORE INTO repo_allowlists (repo_id, pattern, reason, added_by)
       VALUES (?, ?, ?, ?)`
    )
    .bind(repoId, pattern, reason, addedBy)
    .run();
}

/**
 * Get repository stats for dashboard
 */
export async function getRepoStats(
  db: D1Database,
  repoId: number
): Promise<{
  totalScans: number;
  activeSecrets: number;
  resolvedSecrets: number;
  lastScan?: string;
}> {
  const stats = await db
    .prepare(
      `SELECT
         (SELECT COUNT(*) FROM scan_history WHERE repo_id = ?) as total_scans,
         (SELECT COUNT(*) FROM detected_secrets WHERE repo_id = ? AND status = 'active') as active_secrets,
         (SELECT COUNT(*) FROM detected_secrets WHERE repo_id = ? AND status IN ('rotated', 'false_positive')) as resolved_secrets,
         (SELECT scanned_at FROM scan_history WHERE repo_id = ? ORDER BY scanned_at DESC LIMIT 1) as last_scan`
    )
    .bind(repoId, repoId, repoId, repoId)
    .first<{
      total_scans: number;
      active_secrets: number;
      resolved_secrets: number;
      last_scan: string;
    }>();

  return {
    totalScans: stats?.total_scans ?? 0,
    activeSecrets: stats?.active_secrets ?? 0,
    resolvedSecrets: stats?.resolved_secrets ?? 0,
    ...(stats?.last_scan ? { lastScan: stats.last_scan } : {}),
  };
}
