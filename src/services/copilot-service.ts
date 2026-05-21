import axios from "axios";
import { LLMConfig, CopilotRequest, CopilotResponse, WorkflowAnalysis, AppConfig } from "../types";
import { ConfigService } from "./config-service";

export class CopilotService {
  constructor(private configService: ConfigService) {}

  async analyzeWorkflow(workflowContent: string, config: AppConfig, dependencyContext?: string): Promise<WorkflowAnalysis> {
    const systemPrompt = this.buildSystemPrompt(config);
    const userPrompt = this.buildUserPrompt(workflowContent, dependencyContext);

    try {
      const response = await this.callCopilot({
        model: config.llm.model,
        messages: [
          { role: "system", content: systemPrompt },
          { role: "user", content: userPrompt }
        ],
        max_tokens: config.llm.maxTokens,
        temperature: config.llm.temperature
      }, config.llm);

      return this.parseAnalysisResponse(response.choices[0].message.content);
    } catch (error) {
      console.error("Error calling GitHub Copilot API:", error);
      // Return a conservative analysis in case of error
      return {
        isMalicious: false,
        confidence: 0,
        reasoning: "Could not analyze workflow due to GitHub Copilot API error",
        detectedThreats: [],
        recommendation: "review"
      };
    }
  }

  private buildSystemPrompt(config: AppConfig): string {
    const blockedKeywords = config.protectionRules.blockedKeywords.join(", ");
    const allowedActions = config.protectionRules.allowedActions.length > 0 
      ? config.protectionRules.allowedActions.join(", ")
      : "No specific allowed actions configured";

    return `You are GitHub Copilot, a security expert analyzing GitHub Actions workflows for malicious activity.

Your task is to analyze the provided workflow and determine if it contains malicious code or patterns that could harm the repository, steal secrets, or perform unauthorized actions.

Consider these factors:
- Suspicious commands like: ${blockedKeywords}
- Unauthorized file operations (especially outside workspace)
- Network requests to unknown or suspicious domains
- Secret exfiltration attempts or environment variable dumping
- Code injection patterns in workflow inputs
- Privilege escalation attempts or sudo usage
- Unusual package installations or script downloads
- Workflow triggers that could be exploited
- Actions from untrusted sources
- Allowed actions: ${allowedActions}

Additionally, analyze the dependency context if provided:
- Actions pinned to mutable tags/branches instead of SHA commits (supply chain risk)
- Actions from unapproved or unknown organizations
- Transitive dependencies that may introduce hidden risks
- Known vulnerabilities in referenced actions
- Docker images from untrusted registries
- Typosquatting or fork confusion (e.g., 'actons/checkout' vs 'actions/checkout')

Respond ONLY with a JSON object in this exact format:
{
  "isMalicious": boolean,
  "confidence": number (0-100),
  "reasoning": "detailed explanation of findings",
  "detectedThreats": ["threat1", "threat2"],
  "recommendation": "allow" | "block" | "review"
}

Be thorough but balanced. Consider legitimate use cases while identifying genuine security risks. Focus on actual threats rather than stylistic concerns.`;
  }

  private buildUserPrompt(workflowContent: string, dependencyContext?: string): string {
    let prompt = `Please analyze this GitHub Actions workflow for security threats:

\`\`\`yaml
${workflowContent}
\`\`\``;

    if (dependencyContext) {
      prompt += `

${dependencyContext}`;
    }

    prompt += `

Provide your analysis in the specified JSON format.`;

    return prompt;
  }

  private async callCopilot(request: CopilotRequest, config: LLMConfig): Promise<CopilotResponse> {
    const authValue = "Bearer " + config.apiKey;
    const headers: Record<string, string> = {
      "authorization": authValue,
      "content-type": "application/json"
    };

    // GitHub Copilot API requires this additional header
    let apiHost: string;
    try {
      apiHost = new URL(config.apiUrl).host;
    } catch {
      apiHost = "";
    }
    const allowedCopilotHosts = [
      "api.githubcopilot.com",
      "copilot.githubcopilot.com"
    ];
    if (allowedCopilotHosts.includes(apiHost)) {
      headers["Copilot-Integration-Id"] = "copilot-chat";
    }

    const response = await axios.post(config.apiUrl, request, {
      headers,
      timeout: 30000
    });

    return response.data;
  }

  private parseAnalysisResponse(content: string): WorkflowAnalysis {
    try {
      // Extract JSON from the response if it's wrapped in other text
      const jsonMatch = content.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        const parsed = JSON.parse(jsonMatch[0]);
        return {
          isMalicious: Boolean(parsed.isMalicious),
          confidence: Math.max(0, Math.min(100, Number(parsed.confidence) || 0)),
          reasoning: String(parsed.reasoning || "No reasoning provided"),
          detectedThreats: Array.isArray(parsed.detectedThreats) ? parsed.detectedThreats : [],
          recommendation: ["allow", "block", "review"].includes(parsed.recommendation) 
            ? parsed.recommendation 
            : "review"
        };
      }
    } catch (error) {
      console.error("Error parsing GitHub Copilot response:", error);
    }

    // Fallback response if parsing fails
    return {
      isMalicious: false,
      confidence: 0,
      reasoning: "Could not parse GitHub Copilot response",
      detectedThreats: [],
      recommendation: "review"
    };
  }
}
