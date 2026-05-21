import { Context } from "probot";
import { AppConfig } from "../types";

export class ConfigService {
  private defaultConfig: AppConfig = {
    llm: {
      apiUrl: process.env.LLM_API_URL || "https://api.githubcopilot.com/chat/completions",
      apiKey: process.env.LLM_API_KEY || process.env.GITHUB_TOKEN || "",
      model: process.env.LLM_MODEL || "gpt-4o",
      maxTokens: parseInt(process.env.LLM_MAX_TOKENS || "1000"),
      temperature: parseFloat(process.env.LLM_TEMPERATURE || "0.2")
    },
    protectionRules: {
      enabledEnvironments: (process.env.PROTECTED_ENVIRONMENTS || "production,staging").split(","),
      blockOnMaliciousDetection: process.env.BLOCK_ON_MALICIOUS === "true",
      allowedActions: (process.env.ALLOWED_ACTIONS || "").split(",").filter(Boolean),
      blockedKeywords: (process.env.BLOCKED_KEYWORDS || "rm -rf,curl,wget,download").split(",")
    },
    dependencyAnalysis: {
      enabled: process.env.DEPENDENCY_ANALYSIS_ENABLED !== "false",
      resolveTransitive: process.env.DEPENDENCY_RESOLVE_TRANSITIVE !== "false",
      requireShaPin: process.env.DEPENDENCY_REQUIRE_SHA_PIN === "true",
      approvedOrganizations: (process.env.DEPENDENCY_APPROVED_ORGS || "").split(",").filter(Boolean),
      blockedActions: (process.env.DEPENDENCY_BLOCKED_ACTIONS || "").split(",").filter(Boolean),
      approvedRegistries: (process.env.DEPENDENCY_APPROVED_REGISTRIES || "").split(",").filter(Boolean),
      blockOnPolicyViolation: process.env.DEPENDENCY_BLOCK_ON_VIOLATION === "true",
      minimumViolationSeverity: (process.env.DEPENDENCY_MIN_SEVERITY as "critical" | "high" | "medium" | "low") || "high",
    }
  };

  async getConfig(context: Context): Promise<AppConfig> {
    try {
      // Try to load config from repository
      const repoConfig = await this.loadRepoConfig(context);
      return this.mergeConfigs(this.defaultConfig, repoConfig);
    } catch (error) {
      context.log.warn("Could not load repository config, using defaults");
      return this.defaultConfig;
    }
  }

  private mergeConfigs(base: AppConfig, override: Partial<AppConfig>): AppConfig {
    return {
      llm: { ...base.llm, ...(override.llm || {}) },
      protectionRules: { ...base.protectionRules, ...(override.protectionRules || {}) },
      dependencyAnalysis: { ...base.dependencyAnalysis, ...(override.dependencyAnalysis || {}) },
    };
  }

  private async loadRepoConfig(context: Context): Promise<Partial<AppConfig>> {
    try {
      // Check if repository exists in payload
      const repoInfo = context.repo();
      
      const { data } = await context.octokit.rest.repos.getContent({
        owner: repoInfo.owner,
        repo: repoInfo.repo,
        path: ".github/actions-copilot-config.json"
      });

      if ("content" in data) {
        const configContent = Buffer.from(data.content, "base64").toString();
        return JSON.parse(configContent);
      }
    } catch (error) {
      // Config file doesn't exist, return empty object
      return {};
    }
    return {};
  }
}
