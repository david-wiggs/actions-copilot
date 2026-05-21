import { Probot } from "probot";
import { EnvironmentProtectionHandler } from "./handlers/environment-protection";
import { CopilotService } from "./services/copilot-service";
import { ConfigService } from "./services/config-service";
import { DependencyService } from "./services/dependency-service";

export = (app: Probot) => {
  const configService = new ConfigService();
  const copilotService = new CopilotService(configService);
  const dependencyService = new DependencyService();
  const environmentProtectionHandler = new EnvironmentProtectionHandler(copilotService, configService, dependencyService);

  // Listen for deployment protection rule requests
  app.on("deployment_protection_rule.requested", environmentProtectionHandler.handleProtectionRule.bind(environmentProtectionHandler));

  app.log.info("Actions Copilot loaded!");
};
