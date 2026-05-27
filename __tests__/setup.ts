// Test setup and utilities
import { jest } from '@jest/globals';

// Setup environment variables for testing — only set defaults if not already provided
// (preserves real values when running live tests with actual credentials)
process.env.NODE_ENV = 'test';
process.env.GITHUB_TOKEN = process.env.GITHUB_TOKEN || 'test-github-token';
// Note: COPILOT_API_KEY is intentionally not defaulted here so that live tests
// can fall through to GITHUB_TOKEN without being shadowed by a fake test value.

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