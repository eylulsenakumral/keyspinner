/**
 * Secret detection patterns
 * Based on common secret types and their regex signatures
 */

export interface SecretPattern {
  name: string
  type: string
  severity: 'high' | 'medium' | 'low'
  pattern: RegExp
  description: string
  rotate: boolean
}

export const SECRET_PATTERNS: SecretPattern[] = [
  {
    name: 'GitHub Personal Access Token',
    type: 'github_pat',
    severity: 'high',
    pattern: /ghp_[a-zA-Z0-9]{36}/g,
    description: 'GitHub Personal Access Token (classic)',
    rotate: true,
  },
  {
    name: 'GitHub OAuth Token',
    type: 'github_oauth',
    severity: 'high',
    pattern: /gho_[a-zA-Z0-9]{36}/g,
    description: 'GitHub OAuth Token',
    rotate: true,
  },
  {
    name: 'GitHub App Token',
    type: 'github_app',
    severity: 'high',
    pattern: /(ghu|ghs|ghr)_[a-zA-Z0-9]{36}/g,
    description: 'GitHub App/User/Server Token',
    rotate: true,
  },
  {
    name: 'AWS Access Key ID',
    type: 'aws_access_key',
    severity: 'high',
    pattern: /AKIA[0-9A-Z]{16}/g,
    description: 'AWS Access Key ID',
    rotate: true,
  },
  {
    name: 'AWS Secret Key',
    type: 'aws_secret_key',
    severity: 'high',
    pattern: /aws_secret_access_key\s*=\s*["\']?[A-Za-z0-9/+=]{40}["\']?/gi,
    description: 'AWS Secret Access Key',
    rotate: true,
  },
  {
    name: 'Stripe Live API Key',
    type: 'stripe_live',
    severity: 'high',
    pattern: /sk_live_[a-zA-Z0-9]{24,}/g,
    description: 'Stripe Live API Key',
    rotate: true,
  },
  {
    name: 'Stripe Test Key',
    type: 'stripe_test',
    severity: 'medium',
    pattern: /sk_test_[a-zA-Z0-9]{24,}/g,
    description: 'Stripe Test API Key',
    rotate: true,
  },
  {
    name: 'Stripe Publishable Key',
    type: 'stripe_publishable',
    severity: 'medium',
    pattern: /pk_(live|test)_[a-zA-Z0-9]{24,}/g,
    description: 'Stripe Publishable Key',
    rotate: true,
  },
  {
    name: 'Slack Token',
    type: 'slack_token',
    severity: 'high',
    pattern: /xox[pbar]-[0-9]{8,13}-[0-9]{8,13}-[a-zA-Z0-9]{20,32}/gi,
    description: 'Slack Bot/User Token',
    rotate: true,
  },
  {
    name: 'Slack Webhook',
    type: 'slack_webhook',
    severity: 'medium',
    pattern: /hooks\.slack\.com\/services\/[A-Z0-9]{9,11}\/[A-Z0-9]{9,11}\/[a-zA-Z0-9]{24}/gi,
    description: 'Slack Incoming Webhook',
    rotate: true,
  },
  {
    name: 'Docker Hub Token',
    type: 'docker_hub',
    severity: 'high',
    pattern: /dckr_[a-zA-Z0-9]{64,}/g,
    description: 'Docker Hub Access Token',
    rotate: true,
  },
  {
    name: 'NPM Token',
    type: 'npm_token',
    severity: 'high',
    pattern: /npm_[a-zA-Z0-9_-]{36}/g,
    description: 'NPM Access Token',
    rotate: true,
  },
  {
    name: 'Google API Key',
    type: 'google_api_key',
    severity: 'high',
    pattern: /AIza[0-9A-Za-z\\-_]{35}/g,
    description: 'Google API Key',
    rotate: true,
  },
  {
    name: 'Google OAuth',
    type: 'google_oauth',
    severity: 'high',
    pattern: /[0-9]+-[a-zA-Z0-9_-]{32}\.apps\.googleusercontent\.com/g,
    description: 'Google OAuth Client ID',
    rotate: true,
  },
  {
    name: 'Heroku API Key',
    type: 'heroku_api_key',
    severity: 'high',
    pattern: /heroku_[a-zA-Z0-9]{26,}/g,
    description: 'Heroku API Key',
    rotate: true,
  },
]

export interface SecretMatch {
  file: string
  line: number
  type: string
  severity: 'high' | 'medium' | 'low'
  match: string
  description: string
  rotate: boolean
}

/**
 * Scan content for secrets
 */
export function scanForSecrets(content: string, filename: string): SecretMatch[] {
  const matches: SecretMatch[] = []
  const lines = content.split('\n')

  for (const pattern of SECRET_PATTERNS) {
    for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
      const line = lines[lineIndex]
      pattern.pattern.lastIndex = 0 // Reset regex

      const match = pattern.pattern.exec(line)
      if (match) {
        matches.push({
          file: filename,
          line: lineIndex + 1,
          type: pattern.type,
          severity: pattern.severity,
          match: match[0],
          description: pattern.description,
          rotate: pattern.rotate,
        })
      }
    }
  }

  return matches
}

/**
 * Check if a file should be skipped
 */
export function shouldSkipFile(path: string): boolean {
  const skipPatterns = [
    /node_modules/,
    /\.git/,
    /dist/,
    /build/,
    /coverage/,
    /\.min\.js$/,
    /\.min\.css$/,
    /package-lock\.json/,
    /yarn\.lock/,
    /pnpm-lock\.yaml/,
    /\.log$/,
  ]

  return skipPatterns.some(pattern => pattern.test(path))
}

/**
 * Common file extensions that might contain secrets
 */
export const SECRET_FILE_EXTENSIONS = [
  '.js',
  '.ts',
  '.jsx',
  '.tsx',
  '.py',
  '.rb',
  '.go',
  '.java',
  '.php',
  '.sh',
  '.bash',
  '.yml',
  '.yaml',
  '.json',
  '.env',
  '.example',
  '.config',
  '.conf',
  '.ini',
  '.toml',
  '.md',
  '.txt',
]
