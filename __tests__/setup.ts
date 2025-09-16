// Test setup and utilities
import { jest } from '@jest/globals';

// Setup environment variables for testing
process.env.NODE_ENV = 'test';
process.env.GITHUB_TOKEN = 'test-github-token';
process.env.COPILOT_API_KEY = 'test-copilot-key';

// Mock console methods to reduce noise in tests
const originalConsole = global.console;

beforeEach(() => {
  // Mock console.error to suppress expected error messages during tests
  global.console = {
    ...originalConsole,
    error: jest.fn(), // Suppress error logs in tests
    warn: jest.fn(),  // Suppress warning logs in tests
  };
});

afterEach(() => {
  // Restore original console after each test
  global.console = originalConsole;
});