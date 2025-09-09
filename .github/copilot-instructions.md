<!-- Use this file to provide workspace-specific custom instructions to Copilot. For more details, visit https://code.visualstudio.com/docs/copilot/copilot-customization#_use-a-githubcopilotinstructionsmd-file -->

# Actions Copilot - Development Guide

This is a Probot GitHub App that provides environment protection using GitHub Copilot's AI to analyze GitHub Actions workflows for security threats.

## Project Checklist

- [x] Project setup complete with TypeScript and Probot framework
- [x] GitHub Copilot integration service implemented with API endpoints
- [x] Environment protection handler created for deployment protection rules
- [x] Configuration service supports both environment variables and repository-specific settings
- [x] Comprehensive documentation and examples provided
- [x] Project compiles successfully and development server available

## Development Status

The project is ready for use! To get started:

1. Configure your GitHub App credentials in `.env`
2. Set up your GitHub token for Copilot API access
3. Install the GitHub App on your repository
4. Configure environment protection rules

## Key Features Implemented

- **GitHub Copilot Security Analysis**: Uses GitHub Copilot API to analyze workflow content
- **Environment Protection**: Protects specified environments from malicious deployments  
- **Flexible Configuration**: Supports environment variables and per-repository config
- **Comprehensive Logging**: Detailed security audit trail
- **Alternative AI Providers**: Compatible with OpenAI, Anthropic, Azure OpenAI as alternatives
