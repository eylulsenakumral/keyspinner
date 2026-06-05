/**
 * Core types for KeySpinner
 */

export interface Env {
  // GitHub App credentials
  GITHUB_APP_ID: string;
  GITHUB_APP_PRIVATE_KEY: string;
  GITHUB_WEBHOOK_SECRET: string;

  // Database
  DB: D1Database;

  // Email (optional, for notifications)
  SENDGRID_API_KEY?: string;
  FROM_EMAIL?: string;
}

export interface MonitoredRepo {
  id: number;
  github_repo_id: number;
  owner: string;
  repo: string;
  installation_id: number;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface DetectedSecret {
  id: number;
  repo_id: number;
  secret_type: string;
  secret_value_hash: string;
  file_path: string;
  line_number: number;
  commit_sha: string;
  commit_url: string;
  severity: 'high' | 'medium' | 'low';
  status: 'active' | 'allowed' | 'rotated' | 'false_positive';
  reported_at: string;
  resolved_at?: string;
}

export interface RepoAllowlist {
  id: number;
  repo_id: number;
  pattern: string;
  reason: string;
  added_by: string;
  created_at: string;
}

export interface ScanHistory {
  id: number;
  repo_id: number;
  commit_sha: string;
  branch: string;
  scanned_at: string;
  secrets_found: number;
  files_scanned: number;
  scan_duration_ms: number;
}

export interface GitHubPushEvent {
  ref: string;
  repository: {
    id: number;
    name: string;
    full_name: string;
    owner: {
      login: string;
    };
    default_branch: string;
  };
  pusher: {
    name: string;
    email: string;
  };
  commits: Array<{
    id: string;
    sha: string;
    message: string;
    url: string;
    added: string[];
    modified: string[];
    removed: string[];
  }>;
  installation?: {
    id: number;
  };
}

export interface GitHubFileContent {
  content: string;
  encoding: string;
}

export interface PRTemplateData {
  repoOwner: string;
  repoName: string;
  branch: string;
  secrets: Array<{
    type: string;
    file: string;
    line: number;
    masked: string;
    severity: string;
  }>;
  commitSha: string;
  commitUrl: string;
}
