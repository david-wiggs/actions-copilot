# Actions Copilot

A Probot GitHub App that uses GitHub Copilot to protect GitHub environments from malicious workflow deployments. This bot analyzes GitHub Actions workflows before deployment and uses GitHub Copilot's AI capabilities to detect potentially malicious activities.

## Features

- **GitHub Copilot-Powered Security Analysis**: Uses GitHub Copilot API to analyze workflow content with advanced understanding of GitHub Actions patterns
- **Environment Protection**: Protects specific environments (production, staging, etc.) from malicious deployments
- **Configurable Rules**: Supports both environment variables and repository-specific configuration
- **Flexible Responses**: Can approve, reject, or request manual review based on analysis confidence
- **Comprehensive Logging**: Detailed logging for security audit trails

## How It Works

1. **Webhook Reception**: Listens for `deployment_protection_rule.requested` events
2. **Environment Check**: Verifies if the target environment is protected
3. **Workflow Analysis**: Fetches and analyzes the workflow content using GitHub Copilot
4. **Security Decision**: Makes approval/rejection decisions based on Copilot analysis
5. **Response**: Responds to GitHub with the protection rule decision

## Installation

### Prerequisites

- Node.js 18 or higher
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
   # Edit .env with your configuration
   ```

3. **Build the Project**:
   ```bash
   npm run build
   ```

4. **Start the Bot**:
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
| `LLM_API_URL` | GitHub Copilot API endpoint URL | `https://api.githubcopilot.com/chat/completions` |
| `LLM_API_KEY` | GitHub token for Copilot API access | Required |
| `LLM_MODEL` | Model to use for analysis | `gpt-4o` |
| `LLM_MAX_TOKENS` | Maximum tokens for Copilot response | `1000` |
| `LLM_TEMPERATURE` | Temperature for Copilot analysis | `0.2` |
| `PROTECTED_ENVIRONMENTS` | Comma-separated list of protected environments | `production,staging` |
| `BLOCK_ON_MALICIOUS` | Whether to block on malicious detection | `true` |
| `ALLOWED_ACTIONS` | Comma-separated list of allowed GitHub Actions | Empty |
| `BLOCKED_KEYWORDS` | Comma-separated list of blocked keywords | `rm -rf,curl,wget,download` |

### Repository Configuration

You can also configure the bot per repository by creating `.github/actions-copilot-config.json`:

```json
{
  "llm": {
    "apiUrl": "https://api.githubcopilot.com/chat/completions",
    "model": "gpt-4o",
    "maxTokens": 1000,
    "temperature": 0.2
  },
  "protectionRules": {
    "enabledEnvironments": ["production"],
    "blockOnMaliciousDetection": true,
    "allowedActions": ["actions/checkout", "actions/setup-node"],
    "blockedKeywords": ["rm -rf", "curl", "sudo"]
  }
}
```

## AI Provider Configuration

### GitHub Copilot (Default)
```bash
LLM_API_URL=https://api.githubcopilot.com/chat/completions
LLM_API_KEY=your_github_token_here
LLM_MODEL=gpt-4o
```

### Alternative: OpenAI
```bash
LLM_API_URL=https://api.openai.com/v1/chat/completions
LLM_API_KEY=sk-...
LLM_MODEL=gpt-4
```

### Alternative: Anthropic Claude
```bash
LLM_API_URL=https://api.anthropic.com/v1/messages
LLM_API_KEY=sk-ant-...
LLM_MODEL=claude-3-sonnet-20240229
```

### Alternative: Azure OpenAI
```bash
LLM_API_URL=https://your-resource.openai.azure.com/openai/deployments/your-deployment/chat/completions?api-version=2023-12-01-preview
LLM_API_KEY=your-azure-key
LLM_MODEL=gpt-4
```

## Security Considerations

- **API Key Security**: Store LLM API keys securely and rotate them regularly
- **Rate Limiting**: Be aware of LLM API rate limits for high-volume repositories
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
│   ├── config-service.ts           # Configuration management
│   └── llm-service.ts              # LLM API integration
├── types/
│   └── index.ts                    # TypeScript type definitions
└── index.ts                        # Main application entry point
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
