-- KeySpinner Database Schema for D1

-- Repositories being monitored
CREATE TABLE IF NOT EXISTS monitored_repos (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  github_repo_id INTEGER UNIQUE NOT NULL,
  owner TEXT NOT NULL,
  repo TEXT NOT NULL,
  installation_id INTEGER NOT NULL,
  enabled BOOLEAN DEFAULT 1,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_monitored_repos_github_id ON monitored_repos(github_repo_id);

-- Detected secrets (stored with hashed values only)
CREATE TABLE IF NOT EXISTS detected_secrets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  repo_id INTEGER NOT NULL REFERENCES monitored_repos(id),
  secret_type TEXT NOT NULL,
  secret_value_hash TEXT NOT NULL,
  file_path TEXT NOT NULL,
  line_number INTEGER NOT NULL,
  commit_sha TEXT NOT NULL,
  commit_url TEXT NOT NULL,
  severity TEXT NOT NULL CHECK(severity IN ('high', 'medium', 'low')),
  status TEXT DEFAULT 'active' CHECK(status IN ('active', 'allowed', 'rotated', 'false_positive')),
  reported_at TEXT DEFAULT (datetime('now')),
  resolved_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_detected_secrets_repo_id ON detected_secrets(repo_id);
CREATE INDEX IF NOT EXISTS idx_detected_secrets_status ON detected_secrets(status);
CREATE INDEX IF NOT EXISTS idx_detected_secrets_severity ON detected_secrets(severity);

-- Repository-specific allowlists
CREATE TABLE IF NOT EXISTS repo_allowlists (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  repo_id INTEGER NOT NULL REFERENCES monitored_repos(id),
  pattern TEXT NOT NULL,
  reason TEXT NOT NULL,
  added_by TEXT NOT NULL,
  created_at TEXT DEFAULT (datetime('now')),
  UNIQUE(repo_id, pattern)
);

CREATE INDEX IF NOT EXISTS idx_allowlists_repo_id ON repo_allowlists(repo_id);

-- Scan history for tracking and deduplication
CREATE TABLE IF NOT EXISTS scan_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  repo_id INTEGER NOT NULL REFERENCES monitored_repos(id),
  commit_sha TEXT NOT NULL,
  branch TEXT NOT NULL,
  scanned_at TEXT DEFAULT (datetime('now')),
  secrets_found INTEGER DEFAULT 0,
  files_scanned INTEGER DEFAULT 0,
  scan_duration_ms INTEGER,
  UNIQUE(repo_id, commit_sha)
);

CREATE INDEX IF NOT EXISTS idx_scan_history_repo_commit ON scan_history(repo_id, commit_sha);
CREATE INDEX IF NOT EXISTS idx_scan_history_scanned_at ON scan_history(scanned_at);
