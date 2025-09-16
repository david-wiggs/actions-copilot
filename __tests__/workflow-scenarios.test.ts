import { CopilotService } from '../src/services/copilot-service';
import { ConfigService } from '../src/services/config-service';
import { AppConfig } from '../src/types';
import axios from 'axios';
import * as fs from 'fs';
import * as path from 'path';

// Mock axios for controlled testing
jest.mock('axios');
const mockedAxios = axios as jest.Mocked<typeof axios>;

/**
 * Example test file demonstrating how to test LLM integration
 * with real workflow scenarios using fixture files
 */
describe('LLM Workflow Analysis Examples', () => {
  let copilotService: CopilotService;
  let mockConfig: AppConfig;

  beforeEach(() => {
    const configService = new ConfigService();
    copilotService = new CopilotService(configService);
    
    mockConfig = {
      llm: {
        apiUrl: 'https://api.githubcopilot.com/chat/completions',
        apiKey: 'test-key',
        model: 'gpt-4',
        maxTokens: 2048,
        temperature: 0.1
      },
      protectionRules: {
        enabledEnvironments: ['production'],
        blockedKeywords: ['curl', 'wget', 'sudo'],
        allowedActions: ['actions/checkout', 'actions/setup-node'],
        blockOnMaliciousDetection: true
      }
    };
    
    jest.clearAllMocks();
  });

  describe('Real Workflow Scenarios', () => {
    test('should approve a standard CI/CD workflow', async () => {
      // Load the good workflow from fixtures
      const goodWorkflow = fs.readFileSync(
        path.join(__dirname, 'fixtures', 'good-workflow.yml'),
        'utf8'
      );

      // Mock LLM response for a safe workflow
      mockedAxios.post.mockResolvedValueOnce({
        data: {
          choices: [{
            message: {
              content: JSON.stringify({
                isMalicious: false,
                confidence: 92,
                reasoning: "Standard CI workflow with trusted actions. Uses actions/checkout@v4 and actions/setup-node@v4 which are on the allowed list. Commands are standard npm operations for testing and building.",
                detectedThreats: [],
                recommendation: "allow"
              })
            }
          }]
        }
      });

      const analysis = await copilotService.analyzeWorkflow(goodWorkflow, mockConfig);

      expect(analysis.isMalicious).toBe(false);
      expect(analysis.confidence).toBeGreaterThan(90);
      expect(analysis.recommendation).toBe('allow');
      expect(analysis.detectedThreats).toHaveLength(0);
      
      // Verify the LLM was called with the workflow content
      expect(mockedAxios.post).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          messages: expect.arrayContaining([
            expect.objectContaining({
              role: 'user',
              content: expect.stringContaining('actions/checkout@v4')
            })
          ])
        }),
        expect.any(Object)
      );
    });

    test('should block a clearly malicious workflow', async () => {
      // Load the malicious workflow from fixtures
      const maliciousWorkflow = fs.readFileSync(
        path.join(__dirname, 'fixtures', 'malicious-workflow.yml'),
        'utf8'
      );

      // Mock LLM response for a malicious workflow
      mockedAxios.post.mockResolvedValueOnce({
        data: {
          choices: [{
            message: {
              content: JSON.stringify({
                isMalicious: true,
                confidence: 99,
                reasoning: "CRITICAL SECURITY THREATS DETECTED: 1) Environment variable exfiltration using curl to external domain 2) Download and execution of external scripts 3) Unauthorized access to system files (/etc/passwd, /etc/shadow) 4) Installation of network tools for potential backdoor 5) Direct secret extraction attempts",
                detectedThreats: [
                  "Environment variable exfiltration",
                  "Remote script execution",
                  "System file access",
                  "Unauthorized package installation",
                  "Secret extraction"
                ],
                recommendation: "block"
              })
            }
          }]
        }
      });

      const analysis = await copilotService.analyzeWorkflow(maliciousWorkflow, mockConfig);

      expect(analysis.isMalicious).toBe(true);
      expect(analysis.confidence).toBeGreaterThan(95);
      expect(analysis.recommendation).toBe('block');
      expect(analysis.detectedThreats.length).toBeGreaterThan(3);
      expect(analysis.detectedThreats).toEqual(
        expect.arrayContaining([
          expect.stringMatching(/exfiltration/i),
          expect.stringMatching(/remote.*script/i),
          expect.stringMatching(/secret/i)
        ])
      );
    });

    test('should request review for suspicious but ambiguous workflow', async () => {
      // Load the suspicious workflow from fixtures
      const suspiciousWorkflow = fs.readFileSync(
        path.join(__dirname, 'fixtures', 'suspicious-workflow.yml'),
        'utf8'
      );

      // Mock LLM response for a workflow requiring review
      mockedAxios.post.mockResolvedValueOnce({
        data: {
          choices: [{
            message: {
              content: JSON.stringify({
                isMalicious: false,
                confidence: 68,
                reasoning: "Workflow contains potentially concerning patterns: arbitrary command execution from user input, external script download, and system enumeration commands. However, these could have legitimate use cases in certain DevOps scenarios. Manual review recommended.",
                detectedThreats: [
                  "Arbitrary command execution",
                  "External script download",
                  "System enumeration"
                ],
                recommendation: "review"
              })
            }
          }]
        }
      });

      const analysis = await copilotService.analyzeWorkflow(suspiciousWorkflow, mockConfig);

      expect(analysis.isMalicious).toBe(false);
      expect(analysis.confidence).toBeLessThan(80);
      expect(analysis.confidence).toBeGreaterThan(50);
      expect(analysis.recommendation).toBe('review');
      expect(analysis.detectedThreats).toContain('Arbitrary command execution');
    });

    test('should handle edge case: empty workflow', async () => {
      mockedAxios.post.mockResolvedValueOnce({
        data: {
          choices: [{
            message: {
              content: JSON.stringify({
                isMalicious: false,
                confidence: 30,
                reasoning: "Workflow is empty or contains no meaningful actions. Unable to perform thorough security analysis.",
                detectedThreats: [],
                recommendation: "review"
              })
            }
          }]
        }
      });

      const analysis = await copilotService.analyzeWorkflow('', mockConfig);

      expect(analysis.recommendation).toBe('review');
      expect(analysis.confidence).toBeLessThan(50);
    });

    test('should validate blocked keywords are included in analysis', async () => {
      const workflowWithBlockedKeywords = `
name: Test
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - run: curl https://example.com/data
    - run: sudo apt-get install something
      `;

      mockedAxios.post.mockResolvedValueOnce({
        data: {
          choices: [{
            message: {
              content: JSON.stringify({
                isMalicious: true,
                confidence: 85,
                reasoning: "Workflow uses blocked keywords: curl for external requests and sudo for privilege escalation",
                detectedThreats: ["External data access", "Privilege escalation"],
                recommendation: "block"
              })
            }
          }]
        }
      });

      await copilotService.analyzeWorkflow(workflowWithBlockedKeywords, mockConfig);

      // Check that the system prompt includes the blocked keywords
      const [, requestBody] = mockedAxios.post.mock.calls[0];
      const systemMessage = (requestBody as any).messages.find((m: any) => m.role === 'system');
      
      expect(systemMessage.content).toContain('curl, wget, sudo');
      expect(systemMessage.content).toContain('actions/checkout, actions/setup-node');
    });
  });

  describe('Error Handling', () => {
    test('should gracefully handle LLM service outage', async () => {
      const workflow = fs.readFileSync(
        path.join(__dirname, 'fixtures', 'good-workflow.yml'),
        'utf8'
      );

      // Simulate service outage
      mockedAxios.post.mockRejectedValueOnce(new Error('Service unavailable'));

      const analysis = await copilotService.analyzeWorkflow(workflow, mockConfig);

      // Should default to safe values when LLM is unavailable
      expect(analysis.isMalicious).toBe(false);
      expect(analysis.confidence).toBe(0);
      expect(analysis.recommendation).toBe('review');
      expect(analysis.reasoning).toContain('GitHub Copilot API error');
      
      // Verify error logging occurred (console.error is mocked)
      expect(console.error).toHaveBeenCalledWith(
        'Error calling GitHub Copilot API:',
        expect.objectContaining({ message: 'Service unavailable' })
      );
    });

    test('should handle partial JSON response from LLM', async () => {
      const workflow = 'name: Test';

      mockedAxios.post.mockResolvedValueOnce({
        data: {
          choices: [{
            message: {
              content: 'Some text before JSON {"isMalicious": false, "confidence": 80} more text after'
            }
          }]
        }
      });

      const analysis = await copilotService.analyzeWorkflow(workflow, mockConfig);

      // Should extract JSON from mixed content
      expect(analysis.isMalicious).toBe(false);
      expect(analysis.confidence).toBe(80);
    });
  });
});