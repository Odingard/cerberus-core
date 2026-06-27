/**
 * Coverage binding in the signed delegation manifest (the receipt).
 *
 * `guardMultiAgent` signs a delegation manifest that authorizes the capability
 * surface. B4 binds the tool-coverage report in force into that signed payload,
 * so the receipt attests *what was protected* — not just the decision. These
 * tests prove the bound commitment matches the live `result.coverage`, survives
 * verification, and that a coverage gap changes the signed receipt.
 */

import { describe, it, expect } from 'vitest';
import { guardMultiAgent } from '../../src/middleware/multi-agent.js';
import { verifyGraphIntegrity } from '../../src/graph/delegation.js';
import { computeCoverageCommitment, verifyCoverageCommitment } from '../../src/engine/coverage.js';
import type { CerberusConfig } from '../../src/types/config.js';

const executors = {
  readDb: (): Promise<string> => Promise.resolve('ok'),
  sendEmail: (): Promise<string> => Promise.resolve('sent'),
};

const baseConfig: CerberusConfig = {
  alertMode: 'alert',
  multiAgent: true,
  agentType: 'orchestrator',
  trustOverrides: [{ toolName: 'readDb', trustLevel: 'trusted' }],
};

describe('guardMultiAgent — coverage bound into the signed receipt', () => {
  it('binds the live coverage report into the manifest, and it verifies', () => {
    const result = guardMultiAgent(executors, baseConfig, ['sendEmail'], 'root');
    const graph = result.getDelegationGraph();

    // The signed manifest carries a non-empty coverage commitment...
    expect(graph.coverageCommitment).toMatch(/^[0-9a-f]{64}$/);
    // ...which is exactly the commitment over the report exposed on the result...
    expect(graph.coverageCommitment).toBe(computeCoverageCommitment(result.coverage));
    // ...verifiable via the public helper...
    expect(verifyCoverageCommitment(result.coverage, graph.coverageCommitment)).toBe(true);
    // ...and the signature over (capability surface + coverage) still checks out.
    expect(verifyGraphIntegrity(graph)).toBe(true);

    result.destroy();
  });

  it('produces a different receipt when an L3 coverage gap exists', () => {
    // Same executors, but sendEmail is NOT declared outbound → it loses L3
    // exfiltration coverage. The receipt must attest that weaker posture.
    const covered = guardMultiAgent(executors, baseConfig, ['sendEmail'], 'root');
    const gap = guardMultiAgent(executors, baseConfig, [], 'root');

    expect(covered.getDelegationGraph().coverageCommitment).not.toBe(
      gap.getDelegationGraph().coverageCommitment,
    );

    covered.destroy();
    gap.destroy();
  });

  it('surfaces a declared-but-unwrapped tool in the bound receipt', () => {
    // 'sendEmial' is a typo: declared outbound but no matching executor. The
    // bound commitment must differ from the clean configuration's.
    const clean = guardMultiAgent(executors, baseConfig, ['sendEmail'], 'root');
    const typo = guardMultiAgent(executors, baseConfig, ['sendEmail', 'sendEmial'], 'root');

    expect(typo.coverage.hasUnwrappedDeclarations).toBe(true);
    expect(typo.getDelegationGraph().coverageCommitment).not.toBe(
      clean.getDelegationGraph().coverageCommitment,
    );
    // The receipt still verifies — it honestly attests the gap rather than hiding it.
    expect(verifyGraphIntegrity(typo.getDelegationGraph())).toBe(true);

    clean.destroy();
    typo.destroy();
  });
});
