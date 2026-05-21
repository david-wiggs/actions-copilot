import { DependencyService } from '../src/services/dependency-service';
import { DependencyAnalysisConfig, ActionDependency, DockerDependency } from '../src/types';

describe('DependencyService', () => {
  let dependencyService: DependencyService;
  let defaultConfig: DependencyAnalysisConfig;

  beforeEach(() => {
    dependencyService = new DependencyService();
    defaultConfig = {
      enabled: true,
      resolveTransitive: true,
      requireShaPin: true,
      approvedOrganizations: ['actions', 'github', 'my-org'],
      blockedActions: ['evil-org/malware-action'],
      approvedRegistries: ['hub.docker.com', 'ghcr.io'],
      blockOnPolicyViolation: true,
      minimumViolationSeverity: 'high',
    };
  });

  describe('parseUsesStatements', () => {
    test('should parse standard action references', () => {
      const workflow = `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
      - run: npm test
      `;

      const deps = dependencyService.parseUsesStatements(workflow);
      expect(deps).toHaveLength(2);
      expect(deps[0]).toMatchObject({
        owner: 'actions',
        repo: 'checkout',
        ref: 'v4',
        uses: 'actions/checkout@v4',
        isTransitive: false,
        isLocal: false,
        isPinned: false,
      });
      expect(deps[1]).toMatchObject({
        owner: 'actions',
        repo: 'setup-node',
        ref: 'v4',
        uses: 'actions/setup-node@v4',
      });
    });

    test('should parse SHA-pinned action references', () => {
      const workflow = `
steps:
  - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29
      `;

      const deps = dependencyService.parseUsesStatements(workflow);
      expect(deps).toHaveLength(1);
      expect(deps[0].isPinned).toBe(true);
      expect(deps[0].ref).toBe('a5ac7e51b41094c92402da3b24376905380afc29');
    });

    test('should parse actions with subfolders', () => {
      const workflow = `
steps:
  - uses: github/codeql-action/init@v3
  - uses: github/codeql-action/analyze@v3
      `;

      const deps = dependencyService.parseUsesStatements(workflow);
      expect(deps).toHaveLength(2);
      expect(deps[0]).toMatchObject({
        owner: 'github',
        repo: 'codeql-action',
        actionPath: 'init',
        ref: 'v3',
      });
      expect(deps[1]).toMatchObject({
        owner: 'github',
        repo: 'codeql-action',
        actionPath: 'analyze',
        ref: 'v3',
      });
    });

    test('should handle local action references', () => {
      const workflow = `
steps:
  - uses: ./my-local-action
  - uses: ./.github/actions/deploy
      `;

      const deps = dependencyService.parseUsesStatements(workflow);
      expect(deps).toHaveLength(2);
      expect(deps[0].isLocal).toBe(true);
      expect(deps[1].isLocal).toBe(true);
    });

    test('should generate PURL for remote actions', () => {
      const workflow = `
steps:
  - uses: actions/checkout@v4
      `;

      const deps = dependencyService.parseUsesStatements(workflow);
      expect(deps[0].purl).toBe('pkg:github/actions/checkout@v4');
    });

    test('should deduplicate identical uses statements', () => {
      const workflow = `
jobs:
  job1:
    steps:
      - uses: actions/checkout@v4
  job2:
    steps:
      - uses: actions/checkout@v4
      `;

      const deps = dependencyService.parseUsesStatements(workflow);
      expect(deps).toHaveLength(1);
    });

    test('should handle reusable workflow references', () => {
      const workflow = `
jobs:
  deploy:
    uses: my-org/shared-workflows/.github/workflows/deploy.yml@main
      `;

      const deps = dependencyService.parseUsesStatements(workflow);
      expect(deps).toHaveLength(1);
      expect(deps[0]).toMatchObject({
        owner: 'my-org',
        repo: 'shared-workflows',
        ref: 'main',
        isPinned: false,
      });
    });

    test('should handle quoted uses values', () => {
      const workflow = `
steps:
  - uses: 'actions/checkout@v4'
  - uses: "actions/setup-node@v4"
      `;

      const deps = dependencyService.parseUsesStatements(workflow);
      expect(deps).toHaveLength(2);
    });
  });

  describe('parseDockerReferences', () => {
    test('should parse docker:// step references', () => {
      const workflow = `
steps:
  - uses: docker://alpine:3.18
  - uses: docker://ghcr.io/my-org/my-action:latest
      `;

      const deps = dependencyService.parseDockerReferences(workflow);
      expect(deps).toHaveLength(2);
      expect(deps[0]).toMatchObject({
        image: 'alpine',
        tag: '3.18',
        context: 'step',
      });
      expect(deps[1]).toMatchObject({
        registry: 'ghcr.io',
        image: 'my-action',
        tag: 'latest',
        context: 'step',
      });
    });

    test('should parse container image declarations', () => {
      const workflow = `
jobs:
  build:
    container:
      image: node:18-alpine
    services:
      redis:
        image: redis:7
      `;

      const deps = dependencyService.parseDockerReferences(workflow);
      expect(deps.length).toBeGreaterThanOrEqual(2);
      const nodeImg = deps.find(d => d.image === 'node');
      expect(nodeImg).toBeDefined();
      expect(nodeImg?.tag).toBe('18-alpine');
    });

    test('should detect digest-pinned images', () => {
      const workflow = `
steps:
  - uses: docker://alpine@sha256:abc123def456789
      `;

      const deps = dependencyService.parseDockerReferences(workflow);
      expect(deps).toHaveLength(1);
      expect(deps[0].digest).toBe('sha256:abc123def456789');
    });
  });

  describe('evaluatePolicyViolations', () => {
    test('should flag unpinned actions when requireShaPin is true', () => {
      const actionDeps: ActionDependency[] = [
        {
          owner: 'actions',
          repo: 'checkout',
          ref: 'v4',
          uses: 'actions/checkout@v4',
          isTransitive: false,
          isLocal: false,
          isPinned: false,
          purl: 'pkg:github/actions/checkout@v4',
        },
      ];

      const violations = dependencyService.evaluatePolicyViolations(
        actionDeps, [], defaultConfig
      );

      expect(violations.some(v => v.type === 'unpinned-action')).toBe(true);
    });

    test('should not flag SHA-pinned actions', () => {
      const actionDeps: ActionDependency[] = [
        {
          owner: 'actions',
          repo: 'checkout',
          ref: 'a5ac7e51b41094c92402da3b24376905380afc29',
          uses: 'actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29',
          isTransitive: false,
          isLocal: false,
          isPinned: true,
          purl: 'pkg:github/actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29',
        },
      ];

      const violations = dependencyService.evaluatePolicyViolations(
        actionDeps, [], defaultConfig
      );

      expect(violations.filter(v => v.type === 'unpinned-action')).toHaveLength(0);
    });

    test('should flag actions from unapproved organizations', () => {
      const actionDeps: ActionDependency[] = [
        {
          owner: 'unknown-org',
          repo: 'some-action',
          ref: 'v1',
          uses: 'unknown-org/some-action@v1',
          isTransitive: false,
          isLocal: false,
          isPinned: false,
          purl: 'pkg:github/unknown-org/some-action@v1',
        },
      ];

      const violations = dependencyService.evaluatePolicyViolations(
        actionDeps, [], defaultConfig
      );

      expect(violations.some(v => v.type === 'unapproved-org')).toBe(true);
      expect(violations.find(v => v.type === 'unapproved-org')?.severity).toBe('high');
    });

    test('should flag explicitly blocked actions', () => {
      const actionDeps: ActionDependency[] = [
        {
          owner: 'evil-org',
          repo: 'malware-action',
          ref: 'v1',
          uses: 'evil-org/malware-action@v1',
          isTransitive: false,
          isLocal: false,
          isPinned: false,
          purl: 'pkg:github/evil-org/malware-action@v1',
        },
      ];

      const violations = dependencyService.evaluatePolicyViolations(
        actionDeps, [], defaultConfig
      );

      expect(violations.some(v => v.type === 'blocked-action')).toBe(true);
      expect(violations.find(v => v.type === 'blocked-action')?.severity).toBe('critical');
    });

    test('should flag Docker images from unapproved registries', () => {
      const dockerDeps: DockerDependency[] = [
        {
          registry: 'evil-registry.io',
          namespace: 'attacker',
          image: 'backdoor',
          tag: 'latest',
          originalReference: 'evil-registry.io/attacker/backdoor:latest',
          context: 'container',
          isTransitive: false,
        },
      ];

      const violations = dependencyService.evaluatePolicyViolations(
        [], dockerDeps, defaultConfig
      );

      expect(violations.some(v => v.type === 'unapproved-registry')).toBe(true);
    });

    test('should not flag actions from approved organizations', () => {
      const actionDeps: ActionDependency[] = [
        {
          owner: 'actions',
          repo: 'checkout',
          ref: 'a5ac7e51b41094c92402da3b24376905380afc29',
          uses: 'actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29',
          isTransitive: false,
          isLocal: false,
          isPinned: true,
          purl: 'pkg:github/actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29',
        },
      ];

      const violations = dependencyService.evaluatePolicyViolations(
        actionDeps, [], defaultConfig
      );

      expect(violations).toHaveLength(0);
    });

    test('should skip local actions in policy evaluation', () => {
      const actionDeps: ActionDependency[] = [
        {
          owner: 'local',
          repo: 'local',
          ref: '',
          uses: './my-action',
          isTransitive: false,
          isLocal: true,
        },
      ];

      const violations = dependencyService.evaluatePolicyViolations(
        actionDeps, [], defaultConfig
      );

      expect(violations).toHaveLength(0);
    });
  });

  describe('formatDependencyContext', () => {
    test('should format empty snapshot as empty string', () => {
      const result = dependencyService.formatDependencyContext({
        actionDependencies: [],
        dockerDependencies: [],
        policyViolations: [],
        totalActions: 0,
        directActions: 0,
        transitiveActions: 0,
      });

      expect(result).toBe('');
    });

    test('should format snapshot with direct and transitive deps', () => {
      const result = dependencyService.formatDependencyContext({
        actionDependencies: [
          {
            owner: 'actions',
            repo: 'checkout',
            ref: 'v4',
            uses: 'actions/checkout@v4',
            isTransitive: false,
            isLocal: false,
            isPinned: false,
            purl: 'pkg:github/actions/checkout@v4',
          },
          {
            owner: 'some-org',
            repo: 'helper',
            ref: 'abc123',
            uses: 'some-org/helper@abc123',
            isTransitive: true,
            isLocal: false,
            isPinned: false,
            purl: 'pkg:github/some-org/helper@abc123',
            sourcePath: 'actions/checkout@v4',
          },
        ],
        dockerDependencies: [
          {
            registry: 'hub.docker.com',
            namespace: 'library',
            image: 'node',
            tag: '18-alpine',
            originalReference: 'node:18-alpine',
            context: 'container',
            isTransitive: false,
          },
        ],
        policyViolations: [
          {
            type: 'unpinned-action',
            severity: 'medium',
            package: 'actions/checkout@v4',
            message: 'Action actions/checkout@v4 uses a mutable tag/branch reference',
            recommendation: 'Pin to a specific SHA',
          },
        ],
        totalActions: 2,
        directActions: 1,
        transitiveActions: 1,
      });

      expect(result).toContain('Resolved Dependencies');
      expect(result).toContain('Total actions: 2');
      expect(result).toContain('1 direct');
      expect(result).toContain('1 transitive');
      expect(result).toContain('pkg:github/actions/checkout@v4');
      expect(result).toContain('pkg:github/some-org/helper@abc123');
      expect(result).toContain('node:18-alpine');
      expect(result).toContain('Policy Violations');
      expect(result).toContain('mutable tag/branch reference');
    });

    test('should include pin status indicators', () => {
      const result = dependencyService.formatDependencyContext({
        actionDependencies: [
          {
            owner: 'actions',
            repo: 'checkout',
            ref: 'a5ac7e51b41094c92402da3b24376905380afc29',
            uses: 'actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29',
            isTransitive: false,
            isLocal: false,
            isPinned: true,
            purl: 'pkg:github/actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29',
          },
        ],
        dockerDependencies: [],
        policyViolations: [],
        totalActions: 1,
        directActions: 1,
        transitiveActions: 0,
      });

      expect(result).toContain('SHA-pinned ✓');
    });
  });

  describe('supply chain attack scenarios', () => {
    test('should detect typosquatting in action names', () => {
      const workflow = `
steps:
  - uses: actons/checkout@v4
  - uses: actions/checkout@v4
      `;

      const deps = dependencyService.parseUsesStatements(workflow);
      
      // The typosquatted action will be flagged as unapproved org
      const violations = dependencyService.evaluatePolicyViolations(
        deps, [], defaultConfig
      );

      // 'actons' is not in approved orgs
      expect(violations.some(
        v => v.type === 'unapproved-org' && v.package.includes('actons')
      )).toBe(true);
    });

    test('should detect hijacked action using branch ref', () => {
      const workflow = `
steps:
  - uses: popular-org/useful-action@main
      `;

      const deps = dependencyService.parseUsesStatements(workflow);
      const violations = dependencyService.evaluatePolicyViolations(
        deps, [], defaultConfig
      );

      // Using @main is a mutable ref - supply chain risk
      expect(violations.some(v => v.type === 'unpinned-action')).toBe(true);
    });

    test('should detect transitive dependencies from untrusted sources', () => {
      const actionDeps: ActionDependency[] = [
        {
          owner: 'actions',
          repo: 'checkout',
          ref: 'v4',
          uses: 'actions/checkout@v4',
          isTransitive: false,
          isLocal: false,
          isPinned: false,
          purl: 'pkg:github/actions/checkout@v4',
        },
        {
          owner: 'unknown-sketchy-org',
          repo: 'hidden-helper',
          ref: 'main',
          uses: 'unknown-sketchy-org/hidden-helper@main',
          isTransitive: true,
          isLocal: false,
          isPinned: false,
          purl: 'pkg:github/unknown-sketchy-org/hidden-helper@main',
          sourcePath: 'actions/checkout@v4',
        },
      ];

      const violations = dependencyService.evaluatePolicyViolations(
        actionDeps, [], defaultConfig
      );

      // Transitive dep from unapproved org
      expect(violations.some(
        v => v.type === 'unapproved-org' && v.package.includes('unknown-sketchy-org')
      )).toBe(true);
    });
  });
});
