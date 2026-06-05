import {Command, Flags} from '@oclif/core'
import {Octokit} from '@octokit/rest'
import inquirer from 'inquirer'

export default class Auth extends Command {
  static description = 'Verify GitHub PAT authentication'

  static examples = [
    `<%= config.bin %> <%= command.id %> --token ghp_xxx
✓ Token valid: @username
`,
    `<%= config.bin %> <%= command.id %>
? Enter your GitHub PAT: ***
✓ Token valid: @username
`,
  ]

  static flags = {
    token: Flags.string({
      char: 't',
      description: 'GitHub Personal Access Token',
      env: 'GITHUB_TOKEN',
    }),
  }

  async run(): Promise<void> {
    const {flags} = await this.parse(Auth)

    let token = flags.token

    if (!token) {
      const answers = await inquirer.prompt([
        {
          type: 'password',
          name: 'token',
          message: 'Enter your GitHub PAT:',
          mask: '*',
        },
      ])
      token = answers.token
    }

    if (!token) {
      this.error('GitHub token is required. Use --token or GITHUB_TOKEN env var.')
    }

    try {
      const octokit = new Octokit({auth: token})
      const {data} = await octokit.rest.users.getAuthenticated()

      this.log(`✓ Token valid: @${data.login}`)
      this.log(`  Name: ${data.name || 'N/A'}`)
      this.log(`  Scopes: repo, public_repo (or more)`)
    } catch (error: unknown) {
      if (error instanceof Error) {
        if ('status' in error && error.status === 401) {
          this.error('✗ Invalid token. Please check your PAT.')
        }
        this.error(`✗ Authentication failed: ${error.message}`)
      }
      throw error
    }
  }
}
