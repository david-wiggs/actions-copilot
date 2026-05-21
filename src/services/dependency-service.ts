import { Context } from "probot";
import {
  ActionDependency,
  DockerDependency,
  ActionDependencySnapshot,
  DependencyAnalysisConfig,
  DependencyPolicyViolation,
} from "../types";

/**
 * Service for resolving and analyzing GitHub Actions dependencies.
 * 
 * Inspired by jessehouwing/actions-dependency-submission, this service:
 * - Parses workflow YAML to extract all `uses:` references
 * - Recursively resolves composite action dependencies (transitive)
 * - Detects Docker image dependencies
 * - Flags policy violations (unpinned refs, unapproved orgs, etc.)
 * - Cross-references against GitHub Advisory Database
 */
export class DependencyService {
  /**
   * Resolves all action dependencies from workflow content.
   * Extracts direct `uses:` references and attempts to resolve transitive
   * dependencies from composite actions.
   */
  async resolveActionDependencies(
    context: Context,
    workflowContent: string,
    config: DependencyAnalysisConfig
  ): Promise<ActionDependencySnapshot> {
    const actionDependencies: ActionDependency[] = [];
    const dockerDependencies: DockerDependency[] = [];
    const policyViolations: DependencyPolicyViolation[] = [];

    try {
      // Extract direct action dependencies from workflow content
      const directDeps = this.parseUsesStatements(workflowContent);
      actionDependencies.push(...directDeps);

      // Extract Docker dependencies
      const dockerDeps = this.parseDockerReferences(workflowContent);
      dockerDependencies.push(...dockerDeps);

      // Resolve transitive dependencies from composite actions
      if (config.resolveTransitive) {
        const transitiveDeps = await this.resolveTransitiveDependencies(
          context,
          directDeps
        );
        actionDependencies.push(...transitiveDeps);
      }

      // Evaluate policy violations
      const violations = this.evaluatePolicyViolations(
        actionDependencies,
        dockerDependencies,
        config
      );
      policyViolations.push(...violations);

      // Check for known advisories
      const advisories = await this.checkAdvisories(context, actionDependencies);
      policyViolations.push(...advisories);

    } catch (error) {
      context.log.warn("Error resolving action dependencies, continuing with partial data");
    }

    return {
      actionDependencies,
      dockerDependencies,
      policyViolations,
      totalActions: actionDependencies.length,
      directActions: actionDependencies.filter(d => !d.isTransitive).length,
      transitiveActions: actionDependencies.filter(d => d.isTransitive).length,
    };
  }

  /**
   * Parses workflow YAML content to extract all `uses:` statements.
   * Handles both step-level and job-level (reusable workflow) references.
   */
  parseUsesStatements(workflowContent: string): ActionDependency[] {
    const dependencies: ActionDependency[] = [];
    const usesRegex = /uses:\s*['"]?([^'"#\s]+)['"]?/g;
    let match;

    while ((match = usesRegex.exec(workflowContent)) !== null) {
      const usesValue = match[1].trim();
      const dep = this.parseUsesReference(usesValue);
      if (dep) {
        dependencies.push(dep);
      }
    }

    return this.deduplicateDependencies(dependencies);
  }

  /**
   * Parses a single `uses:` reference string into an ActionDependency.
   * Supports formats:
   * - owner/repo@ref
   * - owner/repo/path@ref
   * - ./local-path (local actions)
   * - docker://image:tag
   */
  private parseUsesReference(usesValue: string): ActionDependency | null {
    // Skip local actions (starts with ./)
    if (usesValue.startsWith("./") || usesValue.startsWith("../")) {
      return {
        owner: "local",
        repo: "local",
        ref: "",
        uses: usesValue,
        isTransitive: false,
        isLocal: true,
        actionPath: usesValue,
      };
    }

    // Skip docker:// references (handled separately)
    if (usesValue.startsWith("docker://")) {
      return null;
    }

    // Parse owner/repo@ref or owner/repo/path@ref
    const atIndex = usesValue.lastIndexOf("@");
    if (atIndex === -1) return null;

    const repoPath = usesValue.substring(0, atIndex);
    const ref = usesValue.substring(atIndex + 1);

    const parts = repoPath.split("/");
    if (parts.length < 2) return null;

    const owner = parts[0];
    const repo = parts[1];
    const actionPath = parts.length > 2 ? parts.slice(2).join("/") : undefined;

    return {
      owner,
      repo,
      ref,
      uses: usesValue,
      isTransitive: false,
      isLocal: false,
      actionPath,
      isPinned: this.isShaRef(ref),
      purl: `pkg:github/${owner}/${repo}@${ref}`,
    };
  }

  /**
   * Parses Docker image references from workflow content.
   * Extracts from:
   * - `docker://` step references
   * - `container:` job/service definitions
   * - `image:` in services
   */
  parseDockerReferences(workflowContent: string): DockerDependency[] {
    const dependencies: DockerDependency[] = [];

    // Match docker:// in uses statements
    const dockerUsesRegex = /uses:\s*['"]?docker:\/\/([^'"#\s]+)['"]?/g;
    let match;
    while ((match = dockerUsesRegex.exec(workflowContent)) !== null) {
      const dep = this.parseDockerImage(match[1], "step");
      if (dep) dependencies.push(dep);
    }

    // Match container: image declarations (simple form: image: value on same line)
    const imageRegex = /image:\s*['"]?([^'"#\s{]+)['"]?/g;
    while ((match = imageRegex.exec(workflowContent)) !== null) {
      const value = match[1];
      // Skip YAML keywords and variables
      if (value.startsWith("$") || value === "null" || value === "true" || value === "false") {
        continue;
      }
      // Must look like a Docker image (contains / or : or is a known base image)
      if (value.includes("/") || value.includes(":") || this.isKnownBaseImage(value)) {
        const dep = this.parseDockerImage(value, "container");
        if (dep) dependencies.push(dep);
      }
    }

    return dependencies;
  }

  /**
   * Parses a Docker image reference into a DockerDependency
   */
  private parseDockerImage(reference: string, context: string): DockerDependency | null {
    let registry = "hub.docker.com";
    let namespace: string | undefined;
    let image: string;
    let tag: string | undefined;
    let digest: string | undefined;

    let ref = reference;

    // Check for digest
    const digestIndex = ref.indexOf("@");
    if (digestIndex !== -1) {
      digest = ref.substring(digestIndex + 1);
      ref = ref.substring(0, digestIndex);
    }

    // Check for tag
    const tagIndex = ref.lastIndexOf(":");
    if (tagIndex !== -1 && !ref.substring(tagIndex).includes("/")) {
      tag = ref.substring(tagIndex + 1);
      ref = ref.substring(0, tagIndex);
    }

    const parts = ref.split("/");
    if (parts.length >= 3) {
      // registry/namespace/image
      registry = parts[0];
      namespace = parts.slice(1, -1).join("/");
      image = parts[parts.length - 1];
    } else if (parts.length === 2) {
      // Could be registry/image or namespace/image
      if (parts[0].includes(".")) {
        registry = parts[0];
        image = parts[1];
      } else {
        namespace = parts[0];
        image = parts[1];
      }
    } else {
      image = parts[0];
      namespace = "library";
    }

    return {
      registry,
      namespace,
      image,
      tag,
      digest,
      originalReference: reference,
      context,
      isTransitive: false,
    };
  }

  /**
   * Attempts to resolve transitive dependencies from composite actions.
   * Fetches the action.yml of each direct dependency and parses its `uses:` statements.
   */
  private async resolveTransitiveDependencies(
    context: Context,
    directDeps: ActionDependency[]
  ): Promise<ActionDependency[]> {
    const transitiveDeps: ActionDependency[] = [];
    const repoInfo = context.repo();

    for (const dep of directDeps) {
      if (dep.isLocal || !dep.owner || !dep.repo) continue;

      try {
        // Try to fetch action.yml from the referenced action
        const actionPath = dep.actionPath
          ? `${dep.actionPath}/action.yml`
          : "action.yml";

        const { data } = await context.octokit.rest.repos.getContent({
          owner: dep.owner,
          repo: dep.repo,
          path: actionPath,
          ref: dep.ref,
        });

        if ("content" in data) {
          const content = Buffer.from(data.content, "base64").toString();

          // Check if this is a composite action
          if (content.includes("using:") && content.includes("composite")) {
            const nestedDeps = this.parseUsesStatements(content);
            for (const nestedDep of nestedDeps) {
              if (!nestedDep.isLocal) {
                nestedDep.isTransitive = true;
                nestedDep.sourcePath = `${dep.owner}/${dep.repo}@${dep.ref}`;
                transitiveDeps.push(nestedDep);
              }
            }
          }
        }
      } catch {
        // Try action.yaml as fallback
        try {
          const actionPath = dep.actionPath
            ? `${dep.actionPath}/action.yaml`
            : "action.yaml";

          const { data } = await context.octokit.rest.repos.getContent({
            owner: dep.owner,
            repo: dep.repo,
            path: actionPath,
            ref: dep.ref,
          });

          if ("content" in data) {
            const content = Buffer.from(data.content, "base64").toString();
            if (content.includes("using:") && content.includes("composite")) {
              const nestedDeps = this.parseUsesStatements(content);
              for (const nestedDep of nestedDeps) {
                if (!nestedDep.isLocal) {
                  nestedDep.isTransitive = true;
                  nestedDep.sourcePath = `${dep.owner}/${dep.repo}@${dep.ref}`;
                  transitiveDeps.push(nestedDep);
                }
              }
            }
          }
        } catch {
          // Cannot resolve this dependency's transitive deps - skip
        }
      }
    }

    return transitiveDeps;
  }

  /**
   * Evaluates action dependencies against configured policy rules.
   */
  evaluatePolicyViolations(
    actionDeps: ActionDependency[],
    dockerDeps: DockerDependency[],
    config: DependencyAnalysisConfig
  ): DependencyPolicyViolation[] {
    const violations: DependencyPolicyViolation[] = [];

    for (const dep of actionDeps) {
      if (dep.isLocal) continue;

      // Check for unpinned references (not SHA-pinned)
      if (config.requireShaPin && !dep.isPinned) {
        violations.push({
          type: "unpinned-action",
          severity: "medium",
          package: dep.uses,
          message: `Action ${dep.uses} uses a mutable tag/branch reference instead of a SHA commit pin`,
          recommendation: `Pin to a specific SHA: ${dep.owner}/${dep.repo}@<full-sha>`,
        });
      }

      // Check for unapproved organizations
      if (config.approvedOrganizations.length > 0) {
        if (!config.approvedOrganizations.includes(dep.owner)) {
          violations.push({
            type: "unapproved-org",
            severity: "high",
            package: dep.uses,
            message: `Action ${dep.uses} is from organization '${dep.owner}' which is not on the approved list`,
            recommendation: `Use an action from an approved org: ${config.approvedOrganizations.join(", ")}`,
          });
        }
      }

      // Check for blocked actions
      if (config.blockedActions.length > 0) {
        const fullName = `${dep.owner}/${dep.repo}`;
        if (config.blockedActions.includes(fullName) || config.blockedActions.includes(dep.uses)) {
          violations.push({
            type: "blocked-action",
            severity: "critical",
            package: dep.uses,
            message: `Action ${dep.uses} is explicitly blocked by policy`,
            recommendation: "Remove this action and use an approved alternative",
          });
        }
      }
    }

    // Check Docker image policy
    for (const dep of dockerDeps) {
      if (config.approvedRegistries && config.approvedRegistries.length > 0) {
        if (!config.approvedRegistries.includes(dep.registry)) {
          violations.push({
            type: "unapproved-registry",
            severity: "medium",
            package: dep.originalReference,
            message: `Docker image ${dep.originalReference} is from unapproved registry '${dep.registry}'`,
            recommendation: `Use an image from an approved registry: ${config.approvedRegistries.join(", ")}`,
          });
        }
      }

      // Warn about images without digest pinning
      if (config.requireShaPin && !dep.digest) {
        violations.push({
          type: "unpinned-docker",
          severity: "low",
          package: dep.originalReference,
          message: `Docker image ${dep.originalReference} is not pinned to a digest`,
          recommendation: `Pin to a digest: ${dep.originalReference}@sha256:<digest>`,
        });
      }
    }

    return violations;
  }

  /**
   * Checks action dependencies against GitHub Advisory Database
   */
  private async checkAdvisories(
    context: Context,
    dependencies: ActionDependency[]
  ): Promise<DependencyPolicyViolation[]> {
    const violations: DependencyPolicyViolation[] = [];
    const repoInfo = context.repo();

    try {
      // Query vulnerability alerts for the repository
      const query = `
        query($owner: String!, $repo: String!) {
          repository(owner: $owner, name: $repo) {
            vulnerabilityAlerts(first: 50, states: [OPEN]) {
              nodes {
                securityVulnerability {
                  package {
                    name
                    ecosystem
                  }
                  severity
                  advisory {
                    ghsaId
                    description
                  }
                  vulnerableVersionRange
                  firstPatchedVersion {
                    identifier
                  }
                }
              }
            }
          }
        }
      `;

      const response: any = await context.octokit.graphql(query, {
        owner: repoInfo.owner,
        repo: repoInfo.repo,
      });

      const alertNodes = response?.repository?.vulnerabilityAlerts?.nodes || [];

      // Match advisories to actions (the ecosystem would be "ACTIONS" for GitHub Actions)
      for (const alert of alertNodes) {
        const vuln = alert.securityVulnerability;
        if (vuln.package.ecosystem === "ACTIONS") {
          const matchingDep = dependencies.find(
            d => `${d.owner}/${d.repo}` === vuln.package.name
          );
          if (matchingDep) {
            violations.push({
              type: "known-vulnerability",
              severity: vuln.severity.toLowerCase() as DependencyPolicyViolation["severity"],
              package: matchingDep.uses,
              message: `${vuln.advisory.ghsaId}: ${vuln.advisory.description}`,
              recommendation: vuln.firstPatchedVersion?.identifier
                ? `Upgrade to ${vuln.firstPatchedVersion.identifier}`
                : "Review the advisory and consider removing this action",
            });
          }
        }
      }
    } catch {
      // Advisory check failed, continue without
    }

    return violations;
  }

  /**
   * Formats the dependency snapshot as context for LLM analysis.
   */
  formatDependencyContext(snapshot: ActionDependencySnapshot): string {
    if (snapshot.totalActions === 0) {
      return "";
    }

    let output = "\n\n## Resolved Dependencies (including transitive)\n";
    output += `Total actions: ${snapshot.totalActions} (${snapshot.directActions} direct, ${snapshot.transitiveActions} transitive)\n\n`;

    // List direct dependencies
    const directDeps = snapshot.actionDependencies.filter(d => !d.isTransitive && !d.isLocal);
    if (directDeps.length > 0) {
      output += "### Direct Action Dependencies\n";
      for (const dep of directDeps) {
        const pinStatus = dep.isPinned ? "SHA-pinned ✓" : "mutable ref ⚠";
        output += `- ${dep.purl || dep.uses} (${pinStatus})\n`;
      }
      output += "\n";
    }

    // List transitive dependencies
    const transitiveDeps = snapshot.actionDependencies.filter(d => d.isTransitive);
    if (transitiveDeps.length > 0) {
      output += "### Transitive Action Dependencies\n";
      for (const dep of transitiveDeps) {
        output += `- ${dep.purl || dep.uses} (via ${dep.sourcePath || "unknown"})\n`;
      }
      output += "\n";
    }

    // List Docker dependencies
    if (snapshot.dockerDependencies.length > 0) {
      output += "### Docker Image Dependencies\n";
      for (const dep of snapshot.dockerDependencies) {
        const pinStatus = dep.digest ? "digest-pinned ✓" : "unpinned ⚠";
        output += `- ${dep.originalReference} (${dep.context}, ${pinStatus})\n`;
      }
      output += "\n";
    }

    // List policy violations
    if (snapshot.policyViolations.length > 0) {
      output += "### Policy Violations\n";
      for (const violation of snapshot.policyViolations) {
        output += `- [${violation.severity.toUpperCase()}] ${violation.message}\n`;
        output += `  Recommendation: ${violation.recommendation}\n`;
      }
      output += "\n";
    }

    return output;
  }

  /**
   * Determines if a ref string is a full SHA commit hash (pinned).
   */
  private isShaRef(ref: string): boolean {
    return /^[0-9a-f]{40}$/.test(ref);
  }

  /**
   * Checks if a string is a known Docker Hub base image
   */
  private isKnownBaseImage(name: string): boolean {
    const knownImages = [
      "alpine", "ubuntu", "debian", "centos", "node", "python",
      "golang", "rust", "ruby", "java", "nginx", "redis", "postgres",
      "mysql", "mongo", "busybox",
    ];
    return knownImages.includes(name.toLowerCase());
  }

  /**
   * Deduplicates dependencies by their `uses` value
   */
  private deduplicateDependencies(deps: ActionDependency[]): ActionDependency[] {
    const seen = new Set<string>();
    return deps.filter(dep => {
      if (seen.has(dep.uses)) return false;
      seen.add(dep.uses);
      return true;
    });
  }
}
