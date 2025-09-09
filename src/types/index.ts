export interface LLMConfig {
  apiUrl: string;
  apiKey: string;
  model: string;
  maxTokens: number;
  temperature: number;
}

export interface AppConfig {
  llm: LLMConfig;
  protectionRules: {
    enabledEnvironments: string[];
    blockOnMaliciousDetection: boolean;
    allowedActions: string[];
    blockedKeywords: string[];
  };
}

export interface CopilotRequest {
  model: string;
  messages: Array<{
    role: "system" | "user" | "assistant";
    content: string;
  }>;
  max_tokens: number;
  temperature: number;
}

export interface CopilotResponse {
  choices: Array<{
    message: {
      content: string;
    };
  }>;
}

export interface WorkflowAnalysis {
  isMalicious: boolean;
  confidence: number;
  reasoning: string;
  detectedThreats: string[];
  recommendation: "allow" | "block" | "review";
}
