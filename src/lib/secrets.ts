/**
 * Secret detection patterns - Port of top 10 Gitleaks rules
 * Focused on high-impact, low-false-positive patterns
 */

export interface SecretPattern {
  id: string;
  name: string;
  description: string;
  regex: RegExp;
  severity: 'high' | 'medium' | 'low';
  entropy?: boolean;
  minEntropy?: number;
}

export const SECRET_PATTERNS: SecretPattern[] = [
  {
    id: 'github-pat',
    name: 'GitHub Personal Access Token',
    description: 'GitHub Personal Access Token (classic and fine-grained)',
    regex: /github_pat_[a-zA-Z0-9_]{82}/gi,
    severity: 'high',
  },
  {
    id: 'github-oauth',
    name: 'GitHub OAuth Access Token',
    description: 'GitHub OAuth Token',
    regex: /gho_[a-zA-Z0-9]{36}/gi,
    severity: 'high',
  },
  {
    id: 'github-app-token',
    name: 'GitHub App Token',
    description: 'GitHub App Installation Token',
    regex: /ghu_[a-zA-Z0-9]{36}/gi,
    severity: 'high',
  },
  {
    id: 'github-refresh-token',
    name: 'GitHub Refresh Token',
    description: 'GitHub Server-to Server Refresh Token',
    regex: /ghr_[a-zA-Z0-9]{36}/gi,
    severity: 'high',
  },
  {
    id: 'aws-access-key',
    name: 'AWS Access Key ID',
    description: 'AWS Access Key ID',
    regex: /(?:A3T[A-Z0-9]|AKIA|ASIA)[A-Z0-9]{16}/gi,
    severity: 'high',
  },
  {
    id: 'aws-secret',
    name: 'AWS Secret Access Key',
    description: 'AWS Secret Access Key (high entropy)',
    regex: /(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])/gi,
    severity: 'high',
    entropy: true,
    minEntropy: 3.5,
  },
  {
    id: 'stripe-api-key',
    name: 'Stripe API Key',
    description: 'Stripe Publishable or Secret API Key',
    regex: /(?:pk|sk)_live_[a-zA-Z0-9]{24,99}/gi,
    severity: 'high',
  },
  {
    id: 'stripe-test-key',
    name: 'Stripe Test Key',
    description: 'Stripe Test API Key (medium severity)',
    regex: /(?:pk|sk)_test_[a-zA-Z0-9]{24,99}/gi,
    severity: 'medium',
  },
  {
    id: 'slack-token',
    name: 'Slack Token',
    description: 'Slack Bot Token, User Token, or Webhook',
    regex: /xox[baprs]-[a-zA-Z0-9-]{10,150}/gi,
    severity: 'high',
  },
  {
    id: 'slack-webhook',
    name: 'Slack Webhook',
    description: 'Slack Incoming Webhook URL',
    regex: /https:\/\/hooks\.slack\.com\/services\/[A-Z0-9]{9,11}\/[A-Z0-9]{9,11}\/[a-zA-Z0-9]{24}/gi,
    severity: 'medium',
  },
  {
    id: 'dockerhub-token',
    name: 'Docker Hub Token',
    description: 'Docker Hub Personal Access Token',
    regex: /dckr_[a-zA-Z0-9_-]{32,}/gi,
    severity: 'high',
  },
  {
    id: 'npm-token',
    name: 'NPM Access Token',
    description: 'NPM Access Token',
    regex: /npm_[a-zA-Z0-9_-]{36}/gi,
    severity: 'high',
  },
  {
    id: 'google-api-key',
    name: 'Google API Key',
    description: 'Google Cloud API Key',
    regex: /AIza[A-Za-z0-9_\-]{35}/gi,
    severity: 'high',
  },
  {
    id: 'google-oauth',
    name: 'Google OAuth Token',
    description: 'Google OAuth Access Token',
    regex: /ya29\.[a-zA-Z0-9_\-]{50,200}/gi,
    severity: 'high',
  },
  {
    id: 'heroku-api-key',
    name: 'Heroku API Key',
    description: 'Heroku API Key',
    regex: /heroku_[a-zA-Z0-9]{8}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{12}/gi,
    severity: 'high',
  },
];

/**
 * Calculate Shannon entropy of a string
 * Higher entropy = more random = likely a secret
 */
export function calculateEntropy(str: string): number {
  const chars = new Map<string, number>();
  for (const char of str) {
    chars.set(char, (chars.get(char) || 0) + 1);
  }

  let entropy = 0;
  for (const count of chars.values()) {
    const p = count / str.length;
    entropy -= p * Math.log2(p);
  }

  return entropy;
}

/**
 * Check if a match passes entropy threshold (if pattern requires it)
 */
export function passesEntropyCheck(match: string, pattern: SecretPattern): boolean {
  if (!pattern.entropy || pattern.minEntropy === undefined) {
    return true;
  }
  return calculateEntropy(match) >= pattern.minEntropy;
}

/**
 * Find all secrets in a file content
 */
export interface SecretMatch {
  pattern: SecretPattern;
  match: string;
  line: number;
  column: number;
  entropy?: number;
}

export function findSecrets(content: string, filename: string): SecretMatch[] {
  const matches: SecretMatch[] = [];
  const lines = content.split('\n');

  // Skip common non-secret files
  if (/\.(lock|sum|txt|md|log)$/.test(filename)) {
    return matches;
  }

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;

    for (const pattern of SECRET_PATTERNS) {
      const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
      let match;

      while ((match = regex.exec(line)) !== null) {
        const matchedText = match[0]!;

        // Check entropy if required
        if (pattern.entropy && pattern.minEntropy) {
          const entropy = calculateEntropy(matchedText);
          if (entropy < pattern.minEntropy) {
            continue;
          }
          matches.push({
            pattern,
            match: matchedText,
            line: i + 1,
            column: (match.index ?? 0) + 1,
            entropy,
          });
        } else {
          matches.push({
            pattern,
            match: matchedText,
            line: i + 1,
            column: (match.index ?? 0) + 1,
          });
        }
      }
    }
  }

  return matches;
}

/**
 * Mask a secret for display (show first 4 and last 4 chars)
 */
export function maskSecret(secret: string): string {
  if (secret.length <= 8) return '****';
  return `${secret.slice(0, 4)}...${secret.slice(-4)}`;
}

/**
 * Hash a secret value for storage (SHA-256)
 */
export async function hashSecret(secret: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(secret);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
}
