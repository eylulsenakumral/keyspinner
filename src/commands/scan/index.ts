import {Command, Flags} from '@oclif/core'
import {Octokit} from '@octokit/rest'
import {
  scanForSecrets,
  shouldSkipFile,
  SECRET_FILE_EXTENSIONS,
  SecretMatch,
} from '../../lib/patterns.js'

interface Repository {
  owner: string
  name: string
  fullName: string
  private: boolean
}

interface ScanResult {
  repository: string
  secrets: SecretMatch[]
  filesScanned: number
}

export default class Scan extends Command {
  static description = 'Scan GitHub repositories for leaked secrets'

  static examples = [
    `<%= config.bin %> <%= command.id %> --token ghp_xxx --org myorg
Scanning 10 repositories for myorg...
🔴 Found 3 secrets in repo1:
  - AWS Access Key ID at .env:12 (high)
  - GitHub PAT at config.js:45 (high)
  - Stripe API Key at stripe.json:8 (high)
`,
    `<%= config.bin %> <%= command.id %> --token ghp_xxx --repo username/repo
Scanning username/repo...
🔴 Found 1 secret:
  - NPM Token at package.json:3 (high)
`,
  ]

  static flags = {
    token: Flags.string({
      char: 't',
      description: 'GitHub Personal Access Token',
      env: 'GITHUB_TOKEN',
      required: true,
    }),
    org: Flags.string({
      char: 'o',
      description: 'Organization to scan',
    }),
    repo: Flags.string({
      char: 'r',
      description: 'Single repository to scan (format: owner/repo)',
    }),
    user: Flags.string({
      char: 'u',
      description: 'User to scan (scans all repos)',
    }),
    json: Flags.boolean({
      char: 'j',
      description: 'Output results as JSON',
      default: false,
    }),
    'create-pr': Flags.boolean({
      description: 'Create remediation PR for found secrets',
      default: false,
    }),
  }

  async run(): Promise<void> {
    const {flags} = await this.parse(Scan)

    const octokit = new Octokit({auth: flags.token})

    let repositories: Repository[] = []

    if (flags.repo) {
      const [owner, name] = flags.repo.split('/')
      if (!owner || !name) {
        this.error('Invalid repo format. Use owner/repo')
      }
      try {
        const {data} = await octokit.rest.repos.get({owner, repo: name})
        repositories = [
          {
            owner: data.owner.login,
            name: data.name,
            fullName: data.full_name,
            private: data.private,
          },
        ]
      } catch (error) {
        this.error(`Failed to fetch repo: ${error}`)
      }
    } else if (flags.org) {
      this.log(`Fetching repositories for organization: ${flags.org}`)
      repositories = await this.fetchOrgRepositories(octokit, flags.org)
    } else if (flags.user) {
      this.log(`Fetching repositories for user: ${flags.user}`)
      repositories = await this.fetchUserRepositories(octokit, flags.user)
    } else {
      this.error('Please specify --org, --user, or --repo')
    }

    this.log(`\n🔍 Scanning ${repositories.length} repository(ies)...\n`)

    const results: ScanResult[] = []

    for (const repo of repositories) {
      this.log(`  Scanning ${repo.fullName}...`)
      const result = await this.scanRepository(octokit, repo)
      results.push(result)

      if (result.secrets.length > 0) {
        this.log(`    🔴 Found ${result.secrets.length} secret(s)\n`)
      } else {
        this.log(`    ✓ No secrets found\n`)
      }
    }

    if (flags.json) {
      this.log(JSON.stringify(results, null, 2))
      return
    }

    // Summary
    const totalSecrets = results.reduce((sum, r) => sum + r.secrets.length, 0)
    const highSeverity = results.reduce(
      (sum, r) => sum + r.secrets.filter(s => s.severity === 'high').length,
      0,
    )
    const mediumSeverity = results.reduce(
      (sum, r) => sum + r.secrets.filter(s => s.severity === 'medium').length,
      0,
    )

    this.log(`\n📊 Scan Summary:`)
    this.log(`  Total secrets found: ${totalSecrets}`)
    this.log(`  High severity: ${highSeverity}`)
    this.log(`  Medium severity: ${mediumSeverity}`)

    if (totalSecrets > 0) {
      this.log(`\n🔴 Action Required:`)
      this.log(`  1. Rotate all leaked credentials immediately`)
      this.log(`  2. Remove secrets from repository history (BFG Repo-Cleaner or git-filter-repo)`)
      this.log(`  3. Use --create-pr flag to generate remediation PRs`)

      if (flags['create-pr']) {
        this.log(`\n🔄 Creating remediation PRs...`)
        await this.createRemediationPRs(octokit, results)
      }
    } else {
      this.log(`\n✅ No secrets detected. Good job!`)
    }
  }

  private async fetchOrgRepositories(octokit: Octokit, org: string): Promise<Repository[]> {
    const repositories: Repository[] = []
    let page = 1

    try {
      while (true) {
        const {data} = await octokit.rest.repos.listForOrg({
          org,
          per_page: 100,
          page,
          type: 'all',
        })

        for (const repo of data) {
          repositories.push({
            owner: repo.owner.login,
            name: repo.name,
            fullName: repo.full_name,
            private: repo.private,
          })
        }

        if (data.length < 100) break
        page++
      }
    } catch (error) {
      this.error(`Failed to fetch org repositories: ${error}`)
    }

    return repositories
  }

  private async fetchUserRepositories(octokit: Octokit, user: string): Promise<Repository[]> {
    const repositories: Repository[] = []
    let page = 1

    try {
      while (true) {
        const {data} = await octokit.rest.repos.listForAuthenticatedUser({
          per_page: 100,
          page,
        })

        for (const repo of data) {
          if (repo.owner.login === user || !user) {
            repositories.push({
              owner: repo.owner.login,
              name: repo.name,
              fullName: repo.full_name,
              private: repo.private,
            })
          }
        }

        if (data.length < 100) break
        page++
      }
    } catch (error) {
      this.error(`Failed to fetch user repositories: ${error}`)
    }

    return repositories
  }

  private async scanRepository(octokit: Octokit, repo: Repository): Promise<ScanResult> {
    const secrets: SecretMatch[] = []
    let filesScanned = 0

    try {
      // Get default branch
      const {data: repoData} = await octokit.rest.repos.get({
        owner: repo.owner,
        repo: repo.name,
      })
      const defaultBranch = repoData.default_branch

      // Get repository tree
      const {data: treeData} = await octokit.rest.git.getTree({
        owner: repo.owner,
        repo: repo.name,
        tree_sha: defaultBranch,
        recursive: 'true',
      })

      if (!treeData.tree) {
        return {repository: repo.fullName, secrets, filesScanned}
      }

      // Filter files to scan
      const filesToScan = treeData.tree.filter(item => {
        if (item.type !== 'blob') return false
        if (shouldSkipFile(item.path)) return false
        return SECRET_FILE_EXTENSIONS.some(ext => item.path.endsWith(ext))
      })

      // Scan each file
      for (const file of filesToScan) {
        try {
          const {data: fileData} = await octokit.rest.repos.getContent({
            owner: repo.owner,
            repo: repo.name,
            path: file.path,
            ref: defaultBranch,
          })

          if ('content' in fileData && fileData.content) {
            const content = Buffer.from(fileData.content, 'base64').toString('utf-8')
            const matches = scanForSecrets(content, file.path)
            secrets.push(...matches)
            filesScanned++
          }
        } catch (error) {
          // Skip files that can't be read
          continue
        }
      }
    } catch (error) {
      this.error(`Failed to scan repository ${repo.fullName}: ${error}`)
    }

    return {repository: repo.fullName, secrets, filesScanned}
  }

  private async createRemediationPRs(octokit: Octokit, results: ScanResult[]): Promise<void> {
    for (const result of results) {
      if (result.secrets.length === 0) continue

      const [owner, repo] = result.repository.split('/')
      const branchName = `keyspinner/remediate-${Date.now()}`

      try {
        // Create remediation branch
        const {data: refData} = await octokit.rest.git.getRef({
          owner,
          repo,
          ref: 'heads/main',
        })

        await octokit.rest.git.createRef({
          owner,
          repo,
          ref: `refs/heads/${branchName}`,
          sha: refData.object.sha,
        })

        // Create remediation file
        const remediationContent = this.generateRemediationContent(result)
        const commits: {path: string; content: string}[] = [
          {path: 'KEYSPINNER_REMEDIATION.md', content: remediationContent},
        ]

        // For each secret, create a redacted version
        for (const secret of result.secrets) {
          try {
            const {data: fileData} = await octokit.rest.repos.getContent({
              owner,
              repo,
              path: secret.file,
              ref: branchName,
            })

            if ('content' in fileData && fileData.content) {
              const content = Buffer.from(fileData.content, 'base64').toString('utf-8')
              const redacted = content.replace(
                secret.match,
                '[REDACTED_SECRET]',
              )

              commits.push({
                path: secret.file,
                content: redacted,
              })
            }
          } catch {
            continue
          }
        }

        // Create commits
        let lastCommitSha = refData.object.sha
        for (const commit of commits) {
          const {data: commitData} = await octokit.rest.repos.createOrUpdateFileContents({
            owner,
            repo,
            path: commit.path,
            message: `KeySpinner: Remediate leaked secret in ${commit.path}`,
            content: Buffer.from(commit.content).toString('base64'),
            sha: lastCommitSha === refData.object.sha ? undefined : lastCommitSha,
            branch: branchName,
          })
          lastCommitSha = commitData.commit.sha || lastCommitSha
        }

        // Create PR
        const {data: prData} = await octokit.rest.pulls.create({
          owner,
          repo,
          title: '🔒 Security: Remediate leaked secrets detected by KeySpinner',
          head: branchName,
          base: 'main',
          body: `## 🔒 KeySpinner Remediation

KeySpinner detected **${result.secrets.length}** leaked secret(s) in this repository.

### 🚨 High Severity Secrets
${result.secrets.filter(s => s.severity === 'high').map(s => `- \`${s.match}\` in \`${s.file}:${s.line}\``).join('\n')}

### ⚠️ Medium Severity Secrets
${result.secrets.filter(s => s.severity === 'medium').map(s => `- \`${s.match}\` in \`${s.file}:${s.line}\``).join('\n')}

### 📋 Action Items
1. **Rotate all leaked credentials immediately**
2. **Review and merge this PR** after rotation
3. **Update all references** to use new credentials
4. **Check repository history** - secrets may still exist in past commits

### 🛠️ Tools for History Cleanup
- [BFG Repo-Cleaner](https://rtyley.github.io/bfg-repo-cleaner/)
- [git-filter-repo](https://github.com/newren/git-filter-repo)

### ℹ️ About KeySpinner
KeySpinner is an autonomous security tool that detects leaked GitHub secrets.
For more information: https://github.com/eylulsenakumral/keyspinner`,
        labels: ['security', 'automated-pr'],
        draft: true,
      })

        this.log(`  ✓ Created PR #${prData.number} for ${result.repository}`)
      } catch (error) {
        this.log(`  ✗ Failed to create PR for ${result.repository}: ${error}`)
      }
    }
  }

  private generateRemediationContent(result: ScanResult): string {
    const lines: string[] = []

    lines.push('# 🔒 KeySpinner Remediation Report')
    lines.push('')
    lines.push(`**Repository:** ${result.repository}`)
    lines.push(`**Date:** ${new Date().toISOString()}`)
    lines.push(`**Secrets Found:** ${result.secrets.length}`)
    lines.push('')
    lines.push('---')
    lines.push('')
    lines.push('## 🚨 Detected Secrets')
    lines.push('')

    for (const secret of result.secrets) {
      lines.push(`### ${secret.description}`)
      lines.push('')
      lines.push(`- **File:** \`${secret.file}:${secret.line}\``)
      lines.push(`- **Severity:** ${secret.severity.toUpperCase()}`)
      lines.push(`- **Leaked Value:** \`${secret.match}\``)
      lines.push(`- **Can Rotate:** ${secret.rotate ? 'Yes' : 'No'}`)
      lines.push('')
      lines.push('#### Rotation Instructions:')
      lines.push('')
      lines.push(this.getRotationInstructions(secret.type))
      lines.push('')
      lines.push('---')
      lines.push('')
    }

    lines.push('## 📋 Next Steps')
    lines.push('')
    lines.push('1. Rotate ALL leaked credentials immediately')
    lines.push('2. Remove secrets from git history:')
    lines.push('   ```bash')
    lines.push('   # Using BFG Repo-Cleaner')
    lines.push('   bfg --delete-files SECRET_FILE.txt')
    lines.push('   git reflog expire --expire=now --all')
    lines.push('   git gc --prune=now --aggressive')
    lines.push('   ```')
    lines.push('3. Update application code with new credentials')
    lines.push('4. Force push to remote (WARNING: This rewrites history)')
    lines.push('5. Review and merge this PR')
    lines.push('')
    lines.push('## ℹ️ About KeySpinner')
    lines.push('')
    lines.push('KeySpinner is an autonomous AI security tool developed by Auto Company.')
    lines.push('GitHub: https://github.com/eylulsenakumral/keyspinner')

    return lines.join('\n')
  }

  private getRotationInstructions(type: string): string {
    const instructions: Record<string, string> = {
      github_pat: '1. Go to https://github.com/settings/tokens\n2. Revoke the leaked token\n3. Generate a new token with minimum required scopes\n4. Update your application with the new token',
      github_oauth: '1. Go to https://github.com/settings/connections\n2. Revoke the leaked authorization\n3. Re-authorize your application',
      aws_access_key: '1. Log into AWS IAM Console\n2. Navigate to Users > Security Credentials\n3. Delete the leaked access key\n4. Create a new access key\n5. Update your application credentials',
      aws_secret_key: '1. This is usually paired with an access key\n2. Rotate both the access key and secret key together\n3. Follow AWS key rotation best practices',
      stripe_live: '1. Log into Stripe Dashboard\n2. Navigate to Developers > API keys\n3. Roll the leaked key\n4. Update your application with the new key',
      stripe_test: '1. Log into Stripe Dashboard (Test mode)\n2. Navigate to Developers > API keys\n3. Roll the test key\n4. Update your application with the new key',
      slack_token: '1. Log into Slack App settings\n2. Navigate to OAuth & Permissions\n3. Reset the bot token\n4. Update your application with the new token',
      slack_webhook: '1. Log into Slack App settings\n2. Navigate to Incoming Webhooks\n3. Delete the leaked webhook\n4. Create a new webhook URL\n5. Update your application',
      npm_token: '1. Log into npmjs.com\n2. Go to Access Tokens\n3. Delete the leaked token\n4. Generate a new token\n5. Update your .npmrc',
      google_api_key: '1. Go to Google Cloud Console\n2. Navigate to APIs & Services > Credentials\n3. Delete the leaked API key\n4. Create a new API key with restrictions\n5. Update your application',
      google_oauth: '1. Go to Google Cloud Console\n2. Navigate to APIs & Services > OAuth 2.0\n3. Delete the leaked client ID\n4. Create a new OAuth client\n5. Update your application',
      heroku_api_key: '1. Log into Heroku Dashboard\n2. Go to Account Settings > API Key\n3. Reveal and revoke the leaked key\n4. Generate a new key\n5. Update your application',
      docker_hub: '1. Log into Docker Hub\n2. Go to Account Settings > Security\n3. Revoke the leaked access token\n4. Generate a new token\n5. Update your docker login',
    }

    return instructions[type] || '1. Log into the service provider dashboard\n2. Navigate to security/credentials section\n3. Revoke the leaked credential\n4. Generate a new credential\n5. Update your application'
  }
}
