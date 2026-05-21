export interface LLMConfig {
  apiUrl: string;
  apiKey: string;
  model: string;
  maxTokens: number;
  temperature: number;
}

export interface DependencyAnalysisConfig {
  enabled: boolean;
  resolveTransitive: boolean;
  requireShaPin: boolean;
  approvedOrganizations: string[];
  blockedActions: string[];
  approvedRegistries?: string[];
  blockOnPolicyViolation: boolean;
  minimumViolationSeverity: "critical" | "high" | "medium" | "low";
}

export interface AppConfig {
  llm: LLMConfig;
  protectionRules: {
    enabledEnvironments: string[];
    blockOnMaliciousDetection: boolean;
    allowedActions: string[];
    blockedKeywords: string[];
  };
  dependencyAnalysis: DependencyAnalysisConfig;
}

export interface ActionDependency {
  owner: string;
  repo: string;
  ref: string;
  uses: string;
  isTransitive: boolean;
  isLocal: boolean;
  actionPath?: string;
  sourcePath?: string;
  isPinned?: boolean;
  purl?: string;
}

export interface DockerDependency {
  registry: string;
  namespace?: string;
  image: string;
  tag?: string;
  digest?: string;
  originalReference: string;
  context: string;
  isTransitive: boolean;
}

export interface DependencyPolicyViolation {
  type: "unpinned-action" | "unapproved-org" | "blocked-action" | "unapproved-registry" | "unpinned-docker" | "known-vulnerability";
  severity: "critical" | "high" | "medium" | "low";
  package: string;
  message: string;
  recommendation: string;
}

export interface ActionDependencySnapshot {
  actionDependencies: ActionDependency[];
  dockerDependencies: DockerDependency[];
  policyViolations: DependencyPolicyViolation[];
  totalActions: number;
  directActions: number;
  transitiveActions: number;
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
