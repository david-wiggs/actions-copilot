import { Context } from "probot";
import { CopilotService } from "../services/copilot-service";
import { ConfigService } from "../services/config-service";
import { DependencyService } from "../services/dependency-service";
import { WorkflowAnalysis, DependencyPolicyViolation } from "../types";

export class EnvironmentProtectionHandler {
  constructor(
    private copilotService: CopilotService,
    private configService: ConfigService,
    private dependencyService: DependencyService
  ) {}

  async handleProtectionRule(context: Context<"deployment_protection_rule.requested">) {
    const { payload } = context;
    const deployment = payload.deployment;
    const environment = payload.environment;

    try {
      context.log.info(`Processing deployment protection rule for environment: ${environment}`);
      
      const config = await this.configService.getConfig(context);
      
      // Check if this environment is protected
      if (!environment || !config.protectionRules.enabledEnvironments.includes(environment)) {
        context.log.info(`Environment ${environment} is not protected, allowing deployment`);
        return this.approveDeployment(context);
      }

      // Get workflow content for analysis
      if (!deployment) {
        context.log.warn("No deployment found, blocking for safety");
        return this.rejectDeployment(context, "No deployment information found");
      }

      const workflowContent = await this.getWorkflowContent(context, deployment.ref);
      
      if (!workflowContent) {
        context.log.warn("No workflow content found, blocking deployment for safety");
        return this.rejectDeployment(context, "No workflow content found for analysis");
      }

      // Resolve action dependencies if enabled
      let dependencyContext: string | undefined;
      if (config.dependencyAnalysis.enabled) {
        context.log.info("Resolving action dependencies for enhanced analysis...");
        const dependencySnapshot = await this.dependencyService.resolveActionDependencies(
          context,
          workflowContent,
          config.dependencyAnalysis
        );

        // Scan for suspicious npm lifecycle scripts if the workflow runs package install
        if (this.dependencyService.workflowRunsPackageInstall(workflowContent)) {
          context.log.info("Workflow runs package install — scanning for lifecycle script risks...");
          const lifecycleViolations = await this.scanForLifecycleScriptRisks(context, deployment.ref, workflowContent);
          dependencySnapshot.policyViolations.push(...lifecycleViolations);
        }

        // Check if dependency policy violations alone should block
        if (config.dependencyAnalysis.blockOnPolicyViolation && dependencySnapshot.policyViolations.length > 0) {
          const severityOrder = ["low", "medium", "high", "critical"];
          const minIndex = severityOrder.indexOf(config.dependencyAnalysis.minimumViolationSeverity);
          const blockingViolations = dependencySnapshot.policyViolations.filter(
            v => severityOrder.indexOf(v.severity) >= minIndex
          );

          if (blockingViolations.length > 0) {
            const reasons = blockingViolations.map(v => v.message);
            context.log.warn(`Dependency policy violations detected: ${reasons.join("; ")}`);
            return this.rejectDeployment(
              context,
              `Dependency policy violations:\n${reasons.map(r => `• ${r}`).join("\n")}`
            );
          }
        }

        // Format dependency context for LLM analysis
        dependencyContext = this.dependencyService.formatDependencyContext(dependencySnapshot);
        context.log.info(
          `Dependency analysis: ${dependencySnapshot.totalActions} actions (${dependencySnapshot.directActions} direct, ${dependencySnapshot.transitiveActions} transitive), ${dependencySnapshot.policyViolations.length} policy violations`
        );
      }

      // Analyze workflow with GitHub Copilot (now with dependency context)
      const analysis = await this.copilotService.analyzeWorkflow(workflowContent, config, dependencyContext);
      
      context.log.info(`Workflow analysis complete: ${analysis.recommendation} (confidence: ${analysis.confidence})`);

      if (analysis.recommendation === "block" && config.protectionRules.blockOnMaliciousDetection) {
        return this.rejectDeployment(context, `Malicious activity detected: ${analysis.reasoning}`);
      } else if (analysis.recommendation === "review") {
        return this.requestReview(context, analysis);
      } else {
        return this.approveDeployment(context, analysis);
      }

    } catch (error) {
      context.log.error("Error processing deployment protection rule");
      return this.rejectDeployment(context, "Internal error during security analysis");
    }
  }

  private async getWorkflowContent(context: Context, ref: string): Promise<string | null> {
    try {
      // Get repository info from context
      const repoInfo = context.repo();

      const { data: workflows } = await context.octokit.rest.actions.listRepoWorkflows({
        owner: repoInfo.owner,
        repo: repoInfo.repo,
      });

      let allWorkflowContent = "";
      
      for (const workflow of workflows.workflows) {
        try {
          const { data: workflowFile } = await context.octokit.rest.repos.getContent({
            owner: repoInfo.owner,
            repo: repoInfo.repo,
            path: workflow.path,
            ref: ref,
          });

          if ("content" in workflowFile) {
            const content = Buffer.from(workflowFile.content, "base64").toString();
            allWorkflowContent += `\n\n--- Workflow: ${workflow.name} ---\n${content}`;
          }
        } catch (error) {
          context.log.warn(`Could not fetch workflow ${workflow.name}`);
        }
      }

      return allWorkflowContent || null;
    } catch (error) {
      context.log.error("Error fetching workflow content");
      return null;
    }
  }

  private async approveDeployment(context: Context<"deployment_protection_rule.requested">, analysis?: WorkflowAnalysis) {
    const comment = analysis 
      ? `✅ Deployment approved by Actions Copilot security analysis.\n\n**Analysis:** ${analysis.reasoning}\n**Confidence:** ${analysis.confidence}%`
      : "✅ Deployment approved - environment not protected";

    const deployment = context.payload.deployment;
    if (!deployment) return;

    // Get installation token from Probot's authenticated octokit
    const token = await (context.octokit.auth({ type: "installation" }) as Promise<{ token: string }>).then(auth => auth.token);

    // Use the deployment callback URL to respond to the protection rule
    await fetch(context.payload.deployment_callback_url || "", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `token ${token}`,
      },
      body: JSON.stringify({
        environment_name: context.payload.environment || "",
        state: "approved",
        comment: comment,
      }),
    });
  }

  private async rejectDeployment(context: Context<"deployment_protection_rule.requested">, reason: string) {
    const deployment = context.payload.deployment;
    if (!deployment) return;

    // Get installation token from Probot's authenticated octokit
    const token = await (context.octokit.auth({ type: "installation" }) as Promise<{ token: string }>).then(auth => auth.token);

    // Use the deployment callback URL to respond to the protection rule
    await fetch(context.payload.deployment_callback_url || "", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `token ${token}`,
      },
      body: JSON.stringify({
        environment_name: context.payload.environment || "",
        state: "rejected",
        comment: `❌ Deployment blocked by Actions Copilot security analysis.\n\n**Reason:** ${reason}`,
      }),
    });
  }

  private async requestReview(context: Context<"deployment_protection_rule.requested">, analysis: WorkflowAnalysis) {
    const comment = `⚠️ Manual review requested for deployment.\n\n**Analysis:** ${analysis.reasoning}\n**Detected Threats:** ${analysis.detectedThreats.join(", ")}\n**Confidence:** ${analysis.confidence}%\n\nPlease review the workflow and approve or reject manually.`;

    const deployment = context.payload.deployment;
    if (!deployment) return;

    // Get installation token from Probot's authenticated octokit
    const token = await (context.octokit.auth({ type: "installation" }) as Promise<{ token: string }>).then(auth => auth.token);

    // For now, we'll approve but with a warning comment
    // In a real implementation, you might want to create an issue or notification
    await fetch(context.payload.deployment_callback_url || "", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `token ${token}`,
      },
      body: JSON.stringify({
        environment_name: context.payload.environment || "",
        state: "approved",
        comment: comment,
      }),
    });
  }

  /**
   * Fetches package-lock.json from the repo and scans for dependencies
   * that declare install lifecycle scripts (preinstall/install/postinstall).
   * These are the primary entry point for supply-chain attacks.
   *
   * Uses two complementary strategies:
   * 1. Lockfile scan — fast, covers all deps including transitive (authoritative for `npm ci`)
   * 2. Registry check — queries npm for direct deps' scripts (catches stale lockfiles
   *    or `npm install` resolving to newer compromised versions)
   */
  private async scanForLifecycleScriptRisks(
    context: Context,
    ref: string,
    workflowContent: string
  ): Promise<DependencyPolicyViolation[]> {
    const repoInfo = context.repo();
    const violations: DependencyPolicyViolation[] = [];

    // Strategy 1: Lockfile scan (fast, covers transitive deps)
    try {
      const { data } = await context.octokit.rest.repos.getContent({
        owner: repoInfo.owner,
        repo: repoInfo.repo,
        path: "package-lock.json",
        ref,
      });

      if ("content" in data) {
        const lockfileContent = Buffer.from(data.content, "base64").toString();
        const lockfileViolations = this.dependencyService.scanLockfileForInstallScripts(lockfileContent);
        violations.push(...lockfileViolations);
      }
    } catch {
      context.log.debug("No package-lock.json found, skipping lockfile scan");
    }

    // Strategy 2: Registry check on direct deps (catches stale lockfiles)
    // Only needed when workflow uses `npm install` (not `npm ci` which strictly uses the lockfile)
    const usesLooseInstall = /\bnpm\s+install\b/.test(workflowContent) || /\bnpm\s+i\b/.test(workflowContent);
    if (usesLooseInstall) {
      context.log.info("Workflow uses 'npm install' (not 'npm ci') — checking registry for install scripts on direct deps...");
      try {
        const { data } = await context.octokit.rest.repos.getContent({
          owner: repoInfo.owner,
          repo: repoInfo.repo,
          path: "package.json",
          ref,
        });

        if ("content" in data) {
          const packageJsonContent = Buffer.from(data.content, "base64").toString();
          const registryViolations = await this.dependencyService.checkRegistryForInstallScripts(packageJsonContent);

          // Deduplicate — don't re-flag packages already caught by lockfile scan
          const alreadyFlagged = new Set(violations.map(v => v.package.split("@")[0]));
          for (const v of registryViolations) {
            const pkgName = v.package.split("@")[0];
            if (!alreadyFlagged.has(pkgName)) {
              violations.push(v);
            }
          }
        }
      } catch {
        context.log.debug("Could not fetch package.json for registry check");
      }
    }

    return violations;
  }
}
