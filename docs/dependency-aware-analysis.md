# Dependency-Aware Analysis Enhancement

## Overview

This enhancement integrates **dependency-aware analysis** into actions-copilot, inspired by [jessehouwing/actions-dependency-submission](https://github.com/jessehouwing/actions-dependency-submission). Instead of only analyzing workflow YAML text, actions-copilot now resolves the complete dependency tree of GitHub Actions referenced in workflows — including transitive dependencies from composite actions — and includes this context in the AI security analysis.

## Motivation

### The Supply Chain Problem

A workflow might reference `trusted-org/deploy-action@v2`, which itself calls `unknown-org/shady-helper@main` as a composite action dependency — completely invisible to surface-level text analysis.

Recent supply chain attacks have demonstrated that:
- Popular actions can be hijacked via tag rewriting
- Composite actions introduce transitive dependencies not visible in the workflow file
- Actions pinned to mutable refs (`@main`, `@v1`) can change without notice
- Typosquatting (e.g., `actons/checkout` vs `actions/checkout`) goes undetected

### The Solution

By resolving the full dependency tree before AI analysis, actions-copilot can now:

1. **Surface hidden transitive dependencies** from composite actions
2. **Detect unpinned (mutable) references** that pose supply chain risk
3. **Enforce organization allowlists** for both direct and transitive action dependencies
4. **Identify Docker image dependencies** from workflow containers and services
5. **Cross-reference against GitHub Advisory Database** for known vulnerabilities
6. **Detect typosquatting** by flagging actions from unapproved organizations

## Architecture

```
deployment_protection_rule.requested
         │
         ▼
  Fetch workflow content
         │
         ├──────────────────────────────┐
         ▼                              ▼
  Resolve dependency tree        Surface-level analysis
  (DependencyService)            (existing workflow text)
         │                              │
         ▼                              │
  Generate dependency manifest          │
  - Direct: actions/checkout@v4         │
  - Transitive: some-org/helper@abc123  │
  - Docker: node:18-alpine             │
         │                              │
         ├──────────────────────────────┘
         ▼
  Combined AI analysis with full context
  - Workflow text + complete dependency list
  - Known-vulnerable dependencies (advisory DB)
  - Unpinned / mutable references
  - Actions from untrusted orgs
         │
         ▼
  Approve / Review / Reject
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DEPENDENCY_ANALYSIS_ENABLED` | Enable dependency-aware analysis | `true` |
| `DEPENDENCY_RESOLVE_TRANSITIVE` | Resolve transitive dependencies from composite actions | `true` |
| `DEPENDENCY_REQUIRE_SHA_PIN` | Flag actions not pinned to a full SHA commit | `false` |
| `DEPENDENCY_APPROVED_ORGS` | Comma-separated list of approved action organizations | (empty) |
| `DEPENDENCY_BLOCKED_ACTIONS` | Comma-separated list of explicitly blocked actions | (empty) |
| `DEPENDENCY_APPROVED_REGISTRIES` | Comma-separated list of approved Docker registries | (empty) |
| `DEPENDENCY_BLOCK_ON_VIOLATION` | Block deployments with policy violations | `false` |
| `DEPENDENCY_MIN_SEVERITY` | Minimum violation severity to block on | `high` |

### Repository Configuration (`.github/actions-copilot-config.json`)

```json
{
  "llm": {
    "model": "gpt-4o",
    "maxTokens": 2000,
    "temperature": 0.2
  },
  "protectionRules": {
    "enabledEnvironments": ["production", "staging"],
    "blockOnMaliciousDetection": true,
    "allowedActions": ["actions/checkout", "actions/setup-node"],
    "blockedKeywords": ["rm -rf", "curl", "sudo"]
  },
  "dependencyAnalysis": {
    "enabled": true,
    "resolveTransitive": true,
    "requireShaPin": true,
    "approvedOrganizations": ["actions", "github", "my-org"],
    "blockedActions": ["known-malicious/evil-action"],
    "approvedRegistries": ["hub.docker.com", "ghcr.io"],
    "blockOnPolicyViolation": true,
    "minimumViolationSeverity": "high"
  }
}
```

## Examples

### Example 1: Detecting Unpinned Actions (Supply Chain Risk)

**Workflow:**
```yaml
name: Deploy
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production
    steps:
      - uses: actions/checkout@v4           # ⚠️ Mutable tag
      - uses: actions/setup-node@v4         # ⚠️ Mutable tag
      - uses: my-org/deploy-action@main     # ⚠️ Branch reference
      - run: npm run deploy
```

**Dependency Analysis Output (included in LLM prompt):**
```
## Resolved Dependencies (including transitive)
Total actions: 3 (3 direct, 0 transitive)

### Direct Action Dependencies
- pkg:github/actions/checkout@v4 (mutable ref ⚠)
- pkg:github/actions/setup-node@v4 (mutable ref ⚠)
- pkg:github/my-org/deploy-action@main (mutable ref ⚠)

### Policy Violations
- [MEDIUM] Action actions/checkout@v4 uses a mutable tag/branch reference instead of a SHA commit pin
  Recommendation: Pin to a specific SHA: actions/checkout@<full-sha>
- [MEDIUM] Action actions/setup-node@v4 uses a mutable tag/branch reference instead of a SHA commit pin
  Recommendation: Pin to a specific SHA: actions/setup-node@<full-sha>
- [MEDIUM] Action my-org/deploy-action@main uses a mutable tag/branch reference instead of a SHA commit pin
  Recommendation: Pin to a specific SHA: my-org/deploy-action@<full-sha>
```

**Recommended fix:**
```yaml
steps:
  - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29  # v4
  - uses: actions/setup-node@60edb5dd545a775178f52524783378180af0d1f8  # v4
  - uses: my-org/deploy-action@8f3a2b1c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a  # main
```

### Example 2: Transitive Dependency from Untrusted Source

**Workflow:**
```yaml
name: Build
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    environment: staging
    steps:
      - uses: actions/checkout@v4
      - uses: popular-org/build-action@v2  # This is a composite action
```

**What actions-copilot discovers:**

`popular-org/build-action@v2` is a composite action whose `action.yml` contains:
```yaml
runs:
  using: composite
  steps:
    - uses: actions/setup-node@v4
    - uses: sketchy-person/minify-tool@main  # Hidden transitive dependency!
```

**Dependency Analysis Output:**
```
## Resolved Dependencies (including transitive)
Total actions: 4 (2 direct, 2 transitive)

### Direct Action Dependencies
- pkg:github/actions/checkout@v4 (mutable ref ⚠)
- pkg:github/popular-org/build-action@v2 (mutable ref ⚠)

### Transitive Action Dependencies
- pkg:github/actions/setup-node@v4 (via popular-org/build-action@v2)
- pkg:github/sketchy-person/minify-tool@main (via popular-org/build-action@v2)

### Policy Violations
- [HIGH] Action sketchy-person/minify-tool@main is from organization 'sketchy-person' which is not on the approved list
  Recommendation: Use an action from an approved org: actions, github, my-org
- [MEDIUM] Action sketchy-person/minify-tool@main uses a mutable tag/branch reference instead of a SHA commit pin
  Recommendation: Pin to a specific SHA: sketchy-person/minify-tool@<full-sha>
```

**Result:** Deployment blocked due to high-severity policy violation (unapproved organization for transitive dependency).

### Example 3: Typosquatting Detection

**Workflow:**
```yaml
name: CI
on: pull_request
jobs:
  test:
    runs-on: ubuntu-latest
    environment: development
    steps:
      - uses: actons/checkout@v4          # ← Typo! 'actons' not 'actions'
      - uses: actions/setup-node@v4
      - run: npm test
```

**Dependency Analysis Output:**
```
## Resolved Dependencies (including transitive)
Total actions: 2 (2 direct, 0 transitive)

### Direct Action Dependencies
- pkg:github/actons/checkout@v4 (mutable ref ⚠)
- pkg:github/actions/setup-node@v4 (mutable ref ⚠)

### Policy Violations
- [HIGH] Action actons/checkout@v4 is from organization 'actons' which is not on the approved list
  Recommendation: Use an action from an approved org: actions, github, my-org
```

**Result:** The typosquatted `actons/checkout` is flagged because `actons` is not in the approved organizations list — catching what could be a supply chain attack.

### Example 4: Docker Image from Untrusted Registry

**Workflow:**
```yaml
name: Integration Tests
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    environment: staging
    container:
      image: suspicious-registry.io/org/custom-runner:latest
    services:
      db:
        image: postgres:15
    steps:
      - uses: actions/checkout@v4
      - run: npm test
```

**Dependency Analysis Output:**
```
## Resolved Dependencies (including transitive)
Total actions: 1 (1 direct, 0 transitive)

### Direct Action Dependencies
- pkg:github/actions/checkout@v4 (mutable ref ⚠)

### Docker Image Dependencies
- suspicious-registry.io/org/custom-runner:latest (container, unpinned ⚠)
- postgres:15 (container, unpinned ⚠)

### Policy Violations
- [MEDIUM] Docker image suspicious-registry.io/org/custom-runner:latest is from unapproved registry 'suspicious-registry.io'
  Recommendation: Use an image from an approved registry: hub.docker.com, ghcr.io
```

### Example 5: Secure Workflow (All Checks Pass)

**Workflow:**
```yaml
name: Production Deploy
on:
  push:
    branches: [main]
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production
    steps:
      - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29  # v4
      - uses: actions/setup-node@60edb5dd545a775178f52524783378180af0d1f8  # v4
      - uses: my-org/deploy-action@8f3a2b1c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a  # v2.1.0
      - run: npm ci && npm run build && npm run deploy
```

**Dependency Analysis Output:**
```
## Resolved Dependencies (including transitive)
Total actions: 3 (3 direct, 0 transitive)

### Direct Action Dependencies
- pkg:github/actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29 (SHA-pinned ✓)
- pkg:github/actions/setup-node@60edb5dd545a775178f52524783378180af0d1f8 (SHA-pinned ✓)
- pkg:github/my-org/deploy-action@8f3a2b1c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a (SHA-pinned ✓)
```

**Result:** ✅ No policy violations. All actions are SHA-pinned and from approved organizations. Deployment approved.

## Companion Workflow: Submit Action Dependencies to Dependency Graph

For repositories that want to leverage GitHub's Dependency Graph and Dependabot alerts for their action dependencies, add this companion workflow using [jessehouwing/actions-dependency-submission](https://github.com/jessehouwing/actions-dependency-submission):

```yaml
name: Submit Action Dependencies
on:
  push:
    branches: [main]
  pull_request:
  schedule:
    - cron: '0 0 * * 0'  # Weekly scan

jobs:
  submit-dependencies:
    runs-on: ubuntu-latest
    environment: development
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@v4
      - uses: jessehouwing/actions-dependency-submission@v1
        with:
          token: ${{ secrets.GITHUB_TOKEN }}
          fork-organizations: 'my-enterprise'
          detect-docker: true
          report-transitive-as-direct: false
```

This submits all action dependencies (including transitive ones) to GitHub's Dependency Graph using PURL format (`pkg:github/{owner}/{repo}@{ref}`), which enables:
- **Dependabot alerts** when a referenced action has a known vulnerability
- **Dependency Review Action** to block PRs that introduce vulnerable action deps
- **SBOM generation** that includes your CI/CD supply chain

## How It Integrates with the Security Reference Architecture

| Layer | Tool | Role |
|-------|------|------|
| **Policy enforcement** | safe-settings | Ensures environments exist with deployment protection rules |
| **Static analysis** | CodeQL | Catches missing environments and expression injection at PR time |
| **Dependency graph** | actions-dependency-submission | Makes action dependencies visible in GitHub's security features |
| **Runtime gate** | actions-copilot + dependency analysis | AI-powered evaluation with full dependency context at deployment time |

Together, these provide defense-in-depth against GitHub Actions supply chain attacks — from the moment a workflow is authored through to the instant before it executes.
