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
    }
  };

  async getConfig(context: Context): Promise<AppConfig> {
    try {
      // Try to load config from repository
      const repoConfig = await this.loadRepoConfig(context);
      return { ...this.defaultConfig, ...repoConfig };
    } catch (error) {
      context.log.warn("Could not load repository config, using defaults");
      return this.defaultConfig;
    }
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
