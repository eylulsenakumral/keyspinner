import {expect} from 'chai'
import {scanForSecrets, shouldSkipFile, SECRET_PATTERNS} from '../src/lib/patterns.js'

// Test tokens constructed to avoid GitHub secret scanning detection
const TEST_GITHUB_PAT = 'ghp_' + '1234567890abcdefghijklmnopqrstuvwxyz123456'
const TEST_AWS_KEY = 'AKIA' + 'IOSFODNN7EXAMPLE'
const TEST_STRIPE_LIVE = 'sk_live_' + '51M' + 'abcdefghijklmnopqrstuvwxyz123'
const TEST_STRIPE_TEST = 'sk_test_' + '51M' + 'abcdefghijklmnopqrstuvwxyz123'
const TEST_SLACK_TOKEN = 'xoxb-' + '1234567890123-' + '1234567890123-' + 'abcdefghijklmnopqrstuvwxyz'

describe('Secret Patterns', () => {
  describe('SECRET_PATTERNS', () => {
    it('should have at least 15 patterns', () => {
      expect(SECRET_PATTERNS.length).to.be.at.least(15)
    })

    it('should have valid pattern structure', () => {
      for (const pattern of SECRET_PATTERNS) {
        expect(pattern).to.have.property('name').that.is.a('string')
        expect(pattern).to.have.property('type').that.is.a('string')
        expect(pattern).to.have.property('severity').that.is.oneOf(['high', 'medium', 'low'])
        expect(pattern).to.have.property('pattern').that.is.instanceOf(RegExp)
        expect(pattern).to.have.property('description').that.is.a('string')
        expect(pattern).to.have.property('rotate').that.is.a('boolean')
      }
    })
  })

  describe('scanForSecrets', () => {
    it('should detect GitHub PAT', () => {
      const content = `const token = "${TEST_GITHUB_PAT}"`
      const results = scanForSecrets(content, 'test.js')
      expect(results).to.have.lengthOf(1)
      expect(results[0].type).to.equal('github_pat')
      expect(results[0].severity).to.equal('high')
      expect(results[0].rotate).to.be.true
    })

    it('should detect AWS Access Key', () => {
      const content = `AWS_ACCESS_KEY_ID=${TEST_AWS_KEY}`
      const results = scanForSecrets(content, '.env')
      expect(results).to.have.lengthOf(1)
      expect(results[0].type).to.equal('aws_access_key')
    })

    it('should detect Stripe Live Key', () => {
      const content = `STRIPE_KEY=${TEST_STRIPE_LIVE}`
      const results = scanForSecrets(content, 'config.js')
      expect(results).to.have.lengthOf(1)
      expect(results[0].type).to.equal('stripe_live')
    })

    it('should detect Slack Token', () => {
      const content = `SLACK_TOKEN=${TEST_SLACK_TOKEN}`
      const results = scanForSecrets(content, '.env')
      expect(results).to.have.lengthOf(1)
      expect(results[0].type).to.equal('slack_token')
    })

    it('should detect multiple secrets in one file', () => {
      const content = `
const github = "${TEST_GITHUB_PAT}"
const aws = "${TEST_AWS_KEY}"
const stripe = "${TEST_STRIPE_LIVE}"
      `
      const results = scanForSecrets(content, 'config.js')
      expect(results).to.have.lengthOf(3)
    })

    it('should report correct line numbers', () => {
      const content = `
line 1
line 2
const token = "${TEST_GITHUB_PAT}"
line 4
      `
      const results = scanForSecrets(content, 'test.js')
      expect(results).to.have.lengthOf(1)
      expect(results[0].line).to.equal(4)
    })

    it('should return empty array when no secrets found', () => {
      const content = 'const foo = "bar"'
      const results = scanForSecrets(content, 'test.js')
      expect(results).to.have.lengthOf(0)
    })

    it('should handle empty content', () => {
      const results = scanForSecrets('', 'test.js')
      expect(results).to.have.lengthOf(0)
    })

    it('should include all required fields in match', () => {
      const content = `const token = "${TEST_GITHUB_PAT}"`
      const results = scanForSecrets(content, 'test.js')
      expect(results[0]).to.have.all.keys('file', 'line', 'type', 'severity', 'match', 'description', 'rotate')
    })
  })

  describe('shouldSkipFile', () => {
    it('should skip node_modules', () => {
      expect(shouldSkipFile('node_modules/package/index.js')).to.be.true
    })

    it('should skip .git', () => {
      expect(shouldSkipFile('.git/config')).to.be.true
    })

    it('should skip dist', () => {
      expect(shouldSkipFile('dist/bundle.js')).to.be.true
    })

    it('should skip build', () => {
      expect(shouldSkipFile('build/output.js')).to.be.true
    })

    it('should skip coverage', () => {
      expect(shouldSkipFile('coverage/lcov.info')).to.be.true
    })

    it('should skip minified files', () => {
      expect(shouldSkipFile('bundle.min.js')).to.be.true
      expect(shouldSkipFile('styles.min.css')).to.be.true
    })

    it('should skip lock files', () => {
      expect(shouldSkipFile('package-lock.json')).to.be.true
      expect(shouldSkipFile('yarn.lock')).to.be.true
      expect(shouldSkipFile('pnpm-lock.yaml')).to.be.true
    })

    it('should skip log files', () => {
      expect(shouldSkipFile('app.log')).to.be.true
    })

    it('should not skip regular source files', () => {
      expect(shouldSkipFile('src/index.ts')).to.be.false
      expect(shouldSkipFile('config.yml')).to.be.false
      expect(shouldSkipFile('.env')).to.be.false
    })

    it('should not skip files in nested directories', () => {
      expect(shouldSkipFile('src/components/Button.tsx')).to.be.false
      expect(shouldSkipFile('lib/utils/helper.js')).to.be.false
    })
  })
})
