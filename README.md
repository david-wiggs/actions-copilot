# Actions Copilot

A Probot GitHub App that uses a local LLM (Ollama) to protect GitHub environments from malicious workflow deployments. This bot analyzes GitHub Actions workflows before deployment and uses AI capabilities to detect potentially malicious activities — all running locally without sending data to external APIs.

## Features

- **Local LLM-Powered Security Analysis**: Uses Ollama (local LLM) to analyze workflow content with advanced understanding of GitHub Actions patterns — no data leaves your machine
- **Environment Protection**: Protects specific environments (production, staging, etc.) from malicious deployments
- **Dependency-Aware Analysis**: Resolves the full dependency tree of actions referenced in workflows (including transitive composite action dependencies), inspired by [jessehouwing/actions-dependency-submission](https://github.com/jessehouwing/actions-dependency-submission)
- **npm Lifecycle Script Detection**: Scans `package-lock.json` and the npm registry for dependencies with install hooks (`preinstall`/`postinstall`) — the primary entry point for supply-chain attacks like the [RedHat Cloud Services compromise](https://www.stepsecurity.io/blog/multiple-redhat-cloud-services-npm-packages-compromised)
- **Supply Chain Risk Detection**: Flags unpinned action references, unapproved organizations, typosquatting, and Docker images from untrusted registries
- **Configurable Rules**: Supports both environment variables and repository-specific configuration
- **Flexible Responses**: Can approve, reject, or request manual review based on analysis confidence
- **Comprehensive Logging**: Detailed logging for security audit trails

## How It Works

1. **Webhook Reception**: Listens for `deployment_protection_rule.requested` events
2. **Environment Check**: Verifies if the target environment is protected
3. **Workflow Analysis**: Fetches and analyzes the workflow content using the local LLM (Ollama)
4. **Dependency Resolution**: Resolves the full action dependency tree (direct + transitive) and evaluates supply chain policies
5. **Lifecycle Script Scan**: If the workflow runs `npm install`, checks `package-lock.json` and the npm registry for dependencies with install hooks
6. **Security Decision**: Makes approval/rejection decisions based on LLM analysis combined with dependency context
7. **Response**: Responds to GitHub with the protection rule decision

## Installation

### Prerequisites

- Node.js 18 or higher
- [Ollama](https://ollama.ai) installed and running locally
- A model pulled (e.g., `ollama pull mistral:7b`)
- A GitHub App with the following permissions:
  - Repository permissions:
    - Actions: Read
    - Contents: Read
    - Metadata: Read
  - Subscribe to events:
    - Deployment protection rule

### Setup

1. **Clone and Install**:
   ```bash
   git clone <your-repo>
   cd actions-copilot
   npm install
   ```

2. **Configure Environment**:
   ```bash
   cp .env.example .env
   # Edit .env with your configuration (defaults to local Ollama)
   ```

3. **Build the Project**:
   ```bash
   npm run build
   ```

4. **Start Ollama** (if not already running):
   ```bash
   ollama serve
   ```

5. **Start the Bot**:
   ```bash
   npm start
   ```

   For development:
   ```bash
   npm run dev
   ```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `LLM_API_URL` | LLM API endpoint URL (OpenAI-compatible) | `http://localhost:11434/v1/chat/completions` |
| `LLM_API_KEY` | API key (use `ollama` for local Ollama) | `ollama` |
| `LLM_MODEL` | Model to use for analysis | `mistral:7b` |
| `LLM_MAX_TOKENS` | Maximum tokens for LLM response | `1000` |
| `LLM_TEMPERATURE` | Temperature for LLM analysis | `0.2` |
| `PROTECTED_ENVIRONMENTS` | Comma-separated list of protected environments | `production,staging` |
| `BLOCK_ON_MALICIOUS` | Whether to block on malicious detection | `true` |
| `ALLOWED_ACTIONS` | Comma-separated list of allowed GitHub Actions | Empty |
| `BLOCKED_KEYWORDS` | Comma-separated list of blocked keywords | `rm -rf,curl,wget,download` |
| `DEPENDENCY_ANALYSIS_ENABLED` | Enable dependency-aware analysis | `true` |
| `DEPENDENCY_RESOLVE_TRANSITIVE` | Resolve transitive action dependencies | `true` |
| `DEPENDENCY_REQUIRE_SHA_PIN` | Flag actions not pinned to SHA | `false` |
| `DEPENDENCY_APPROVED_ORGS` | Comma-separated approved action organizations | (empty) |
| `DEPENDENCY_BLOCKED_ACTIONS` | Comma-separated blocked actions | (empty) |
| `DEPENDENCY_BLOCK_ON_VIOLATION` | Block on dependency policy violations | `false` |
| `DEPENDENCY_MIN_SEVERITY` | Minimum violation severity to block | `high` |

### Repository Configuration

You can also configure the bot per repository by creating `.github/actions-copilot-config.json`:

```json
{
  "llm": {
    "apiUrl": "http://localhost:11434/v1/chat/completions",
    "model": "mistral:7b",
    "maxTokens": 1000,
    "temperature": 0.2
  },
  "protectionRules": {
    "enabledEnvironments": ["production"],
    "blockOnMaliciousDetection": true,
    "allowedActions": ["actions/checkout", "actions/setup-node"],
    "blockedKeywords": ["rm -rf", "curl", "sudo"]
  },
  "dependencyAnalysis": {
    "enabled": true,
    "resolveTransitive": true,
    "requireShaPin": true,
    "approvedOrganizations": ["actions", "github", "my-org"],
    "blockedActions": [],
    "blockOnPolicyViolation": true,
    "minimumViolationSeverity": "high"
  }
}
```

## AI Provider Configuration

### Ollama (Default — Local)

Install and start Ollama, then pull a model:
```bash
# Install: https://ollama.ai
ollama pull mistral:7b
ollama serve
```

Configuration:
```bash
LLM_API_URL=http://localhost:11434/v1/chat/completions
LLM_API_KEY=ollama
LLM_MODEL=mistral:7b
```

Other recommended models: `llama3.2`, `codellama`, `deepseek-coder`.

### Alternative: LM Studio (Local)
```bash
LLM_API_URL=http://localhost:1234/v1/chat/completions
LLM_API_KEY=lm-studio
LLM_MODEL=<model-name-from-lm-studio>
```

### Alternative: OpenAI
```bash
LLM_API_URL=https://api.openai.com/v1/chat/completions
LLM_API_KEY=sk-...
LLM_MODEL=gpt-4
```

### Alternative: Azure OpenAI
```bash
LLM_API_URL=https://your-resource.openai.azure.com/openai/deployments/your-deployment/chat/completions?api-version=2023-12-01-preview
LLM_API_KEY=your-azure-key
LLM_MODEL=gpt-4
```

## Security Considerations

- **Local-First**: By default, all workflow analysis happens locally via Ollama — no data is sent to external services
- **API Key Security**: If using remote providers, store API keys securely and rotate them regularly
- **Rate Limiting**: Local Ollama has no rate limits; remote providers may
- **Fallback Behavior**: The bot defaults to blocking deployments if LLM analysis fails
- **Audit Logging**: All decisions are logged for security audit purposes

## GitHub App Setup

1. **Create a GitHub App** in your organization settings
2. **Set Webhook URL** to your bot's endpoint
3. **Configure Permissions**:
   - Repository permissions: Actions (Read), Contents (Read), Metadata (Read)
   - Subscribe to events: Deployment protection rule
4. **Install the App** on repositories where you want protection

## Development

### Project Structure

```
src/
├── handlers/
│   └── environment-protection.ts    # Main webhook handler
├── services/
│   ├── config-service.ts            # Configuration management
│   ├── copilot-service.ts           # LLM API integration (Ollama / OpenAI-compatible)
│   └── dependency-service.ts        # Action dependency resolution, lifecycle script detection
├── types/
│   └── index.ts                     # TypeScript type definitions
└── index.ts                         # Main application entry point
```

### Testing

```bash
npm test
```

### Building

```bash
npm run build
```

## Docker Deployment

Actions Copilot can be easily deployed as a Docker container.

### Quick Start

1. **Build and run with Docker Compose** (easiest):
   ```bash
   # Copy environment template
   cp .env.example .env
   # Edit .env with your GitHub App credentials
   
   # Start the container
   npm run docker:up
   ```

2. **Or build and run manually**:
   ```bash
   npm run docker:build
   npm run docker:run
   ```

### Configuration

1. **Environment file**: Copy `.env.example` to `.env` and fill in your values
   - Set `PORT=8080` if you want to use a different port (default is 3000)
2. **Private key**: Place your GitHub App private key as `private-key.pem` in the project root
3. **GitHub App**: Configure your app to point webhooks to your container (e.g., `https://your-domain.com:8080/api/github/webhooks`)

### Docker Commands

| Command | Description |
|---------|-------------|
| `npm run docker:build` | Build the Docker image |
| `npm run docker:run` | Run container with .env file |
| `npm run docker:up` | Start with Docker Compose |
| `npm run docker:down` | Stop Docker Compose |

### What you need:
- Ollama installed and running with a model pulled
- `.env` file with your GitHub App configuration
- `private-key.pem` file (your GitHub App's private key)
- Docker and Docker Compose installed

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

MIT License - see LICENSE file for details.

## Support

For issues and questions:
- Create an issue in this repository
- Check the logs for detailed error information
- Verify your LLM API configuration and quotas
