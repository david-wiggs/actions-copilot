#!/usr/bin/env npx tsx

/**
 * Manual LLM Integration Test Script
 * 
 * This script allows you to test the actual LLM integration with real API calls.
 * You can test different workflows and see how the LLM responds.
 * 
 * Usage:
 *   npm run test:llm-manual
 *   npm run test:llm-manual -- --workflow=fixtures/malicious-workflow.yml
 *   npm run test:llm-manual -- --api=openai
 */

// Load environment variables from .env file
import * as dotenv from 'dotenv';
dotenv.config();

import { CopilotService } from '../src/services/copilot-service';
import { ConfigService } from '../src/services/config-service';
import { AppConfig } from '../src/types';
import * as fs from 'fs';
import * as path from 'path';

// Parse command line arguments
const args = process.argv.slice(2);
const getArg = (name: string) => {
  const arg = args.find(a => a.startsWith(`--${name}=`));
  return arg ? arg.split('=')[1] : null;
};

const workflowFile = getArg('workflow') || 'fixtures/good-workflow.yml';
const apiType = getArg('api') || determineApiType();

// Determine API type based on environment variables
function determineApiType(): string {
  const apiUrl = process.env.LLM_API_URL || '';
  if (apiUrl.includes('openai.com')) return 'openai';
  if (apiUrl.includes('anthropic.com')) return 'anthropic';
  if (apiUrl.includes('azure.com')) return 'azure';
  return 'copilot';
}

async function main() {
  console.log('🤖 LLM Integration Test - Live API Call\n');
  
  // Configuration for different API providers
  const configs: Record<string, AppConfig> = {
    copilot: {
      llm: {
        apiUrl: process.env.LLM_API_URL || 'https://api.githubcopilot.com/chat/completions',
        apiKey: process.env.LLM_API_KEY || process.env.COPILOT_API_KEY || process.env.GITHUB_TOKEN || '',
        model: process.env.LLM_MODEL || 'gpt-4',
        maxTokens: parseInt(process.env.LLM_MAX_TOKENS || '2048'),
        temperature: parseFloat(process.env.LLM_TEMPERATURE || '0.1')
      },
      protectionRules: {
        enabledEnvironments: ['production', 'staging'],
        blockedKeywords: ['curl', 'wget', 'nc', 'netcat', 'sudo', 'rm -rf', 'ssh'],
        allowedActions: ['actions/checkout@v4', 'actions/setup-node@v4', 'actions/upload-artifact@v3'],
        blockOnMaliciousDetection: true
      }
    },
    openai: {
      llm: {
        apiUrl: process.env.LLM_API_URL || 'https://api.openai.com/v1/chat/completions',
        apiKey: process.env.OPENAI_API_KEY || process.env.LLM_API_KEY || '',
        model: process.env.LLM_MODEL || 'gpt-4',
        maxTokens: parseInt(process.env.LLM_MAX_TOKENS || '2048'),
        temperature: parseFloat(process.env.LLM_TEMPERATURE || '0.1')
      },
      protectionRules: {
        enabledEnvironments: ['production', 'staging'],
        blockedKeywords: ['curl', 'wget', 'nc', 'netcat', 'sudo', 'rm -rf', 'ssh'],
        allowedActions: ['actions/checkout@v4', 'actions/setup-node@v4', 'actions/upload-artifact@v3'],
        blockOnMaliciousDetection: true
      }
    },
    anthropic: {
      llm: {
        apiUrl: 'https://api.anthropic.com/v1/messages',
        apiKey: process.env.ANTHROPIC_API_KEY || '',
        model: 'claude-3-sonnet-20240229',
        maxTokens: 2048,
        temperature: 0.1
      },
      protectionRules: {
        enabledEnvironments: ['production', 'staging'],
        blockedKeywords: ['curl', 'wget', 'nc', 'netcat', 'sudo', 'rm -rf', 'ssh'],
        allowedActions: ['actions/checkout@v4', 'actions/setup-node@v4', 'actions/upload-artifact@v3'],
        blockOnMaliciousDetection: true
      }
    }
  };

  const config = configs[apiType];
  if (!config) {
    console.error(`❌ Unknown API type: ${apiType}`);
    console.log('Available APIs: copilot, openai, anthropic');
    process.exit(1);
  }

  if (!config.llm.apiKey) {
    console.error(`❌ API key not found for ${apiType}`);
    console.log(`Please set the appropriate environment variable:`);
    console.log(`  - GitHub Copilot: COPILOT_API_KEY or GITHUB_TOKEN`);
    console.log(`  - OpenAI: OPENAI_API_KEY or LLM_API_KEY`);
    console.log(`  - Anthropic: ANTHROPIC_API_KEY`);
    process.exit(1);
  }

  // Load workflow file
  let workflowPath: string;
  if (workflowFile.startsWith('fixtures/')) {
    workflowPath = path.join(__dirname, '..', '__tests__', workflowFile);
  } else {
    workflowPath = path.resolve(workflowFile);
  }

  if (!fs.existsSync(workflowPath)) {
    console.error(`❌ Workflow file not found: ${workflowPath}`);
    console.log('Available fixtures:');
    const fixturesDir = path.join(__dirname, '..', '__tests__', 'fixtures');
    const fixtures = fs.readdirSync(fixturesDir).filter(f => f.endsWith('.yml'));
    fixtures.forEach(f => console.log(`  - fixtures/${f}`));
    process.exit(1);
  }

  const workflowContent = fs.readFileSync(workflowPath, 'utf8');

  console.log(`📋 Testing workflow: ${path.basename(workflowPath)}`);
  console.log(`🔗 API: ${apiType} (${config.llm.apiUrl})`);
  console.log(`🤖 Model: ${config.llm.model}\n`);

  console.log('📄 Workflow Content:');
  console.log('─'.repeat(50));
  console.log(workflowContent);
  console.log('─'.repeat(50));
  console.log();

  // Create service and analyze
  const configService = new ConfigService();
  const copilotService = new CopilotService(configService);

  console.log('🔄 Sending to LLM for analysis...\n');
  
  try {
    const startTime = Date.now();
    const analysis = await copilotService.analyzeWorkflow(workflowContent, config);
    const duration = Date.now() - startTime;

    console.log('✅ Analysis Complete!');
    console.log(`⏱️  Duration: ${duration}ms\n`);

    // Display results
    console.log('📊 LLM Analysis Results:');
    console.log('═'.repeat(50));
    console.log(`🚨 Malicious: ${analysis.isMalicious ? '❌ YES' : '✅ NO'}`);
    console.log(`📈 Confidence: ${analysis.confidence}%`);
    console.log(`💡 Recommendation: ${getRecommendationEmoji(analysis.recommendation)} ${analysis.recommendation.toUpperCase()}`);
    console.log();

    if (analysis.detectedThreats.length > 0) {
      console.log('⚠️  Detected Threats:');
      analysis.detectedThreats.forEach((threat, i) => {
        console.log(`   ${i + 1}. ${threat}`);
      });
      console.log();
    }

    console.log('💭 LLM Reasoning:');
    console.log(analysis.reasoning);
    console.log();

    // Display configuration context
    console.log('⚙️  Configuration Used:');
    console.log(`   🚫 Blocked Keywords: ${config.protectionRules.blockedKeywords.join(', ')}`);
    console.log(`   ✅ Allowed Actions: ${config.protectionRules.allowedActions.join(', ')}`);
    console.log(`   🔒 Protected Environments: ${config.protectionRules.enabledEnvironments.join(', ')}`);

  } catch (error) {
    console.error('❌ Error during analysis:');
    console.error(error);
    
    if (error instanceof Error) {
      if (error.message.includes('401') || error.message.includes('Unauthorized')) {
        console.log('\n💡 This looks like an authentication error.');
        console.log('Make sure your API key is valid and has the necessary permissions.');
      } else if (error.message.includes('429') || error.message.includes('rate limit')) {
        console.log('\n💡 Rate limit exceeded. Try again in a few minutes.');
      } else if (error.message.includes('ENOTFOUND') || error.message.includes('network')) {
        console.log('\n💡 Network error. Check your internet connection.');
      }
    }
  }
}

function getRecommendationEmoji(recommendation: string): string {
  switch (recommendation) {
    case 'allow': return '✅';
    case 'block': return '🚫';
    case 'review': return '⚠️';
    default: return '❓';
  }
}

// Handle script interruption
process.on('SIGINT', () => {
  console.log('\n👋 Test interrupted by user');
  process.exit(0);
});

// Run the test
main().catch(error => {
  console.error('💥 Fatal error:', error);
  process.exit(1);
});