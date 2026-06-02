<!-- Use this file to provide workspace-specific custom instructions to Copilot. For more details, visit https://code.visualstudio.com/docs/copilot/copilot-customization#_use-a-githubcopilotinstructionsmd-file -->

# Actions Copilot - Development Guide

This is a Probot GitHub App that uses a local LLM (Ollama) to protect GitHub environments from malicious workflow deployments.

## Key Architecture

- **LLM Service** (`src/services/copilot-service.ts`): OpenAI-compatible API client, defaults to local Ollama
- **Dependency Service** (`src/services/dependency-service.ts`): Resolves action dependency trees, scans for lifecycle script risks via lockfile + npm registry
- **Environment Protection Handler** (`src/handlers/environment-protection.ts`): Orchestrates analysis on `deployment_protection_rule.requested` events
- **Config Service** (`src/services/config-service.ts`): Env vars + per-repo `.github/actions-copilot-config.json`

## Key Features

- **Local LLM Security Analysis**: Uses Ollama (no external API calls by default)
- **Dependency-Aware Analysis**: Resolves full action dependency tree including transitive composite actions
- **npm Lifecycle Script Detection**: Scans package-lock.json and npm registry for dependencies with install hooks (supply-chain attack indicator)
- **Environment Protection**: Protects specified environments from malicious deployments
- **Flexible Configuration**: Supports environment variables and per-repository config
