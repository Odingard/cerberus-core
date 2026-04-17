/**
 * Tests for the per-turn manifest verification gate.
 *
 * Covers the five verification-failure shapes plus the happy paths:
 * no graph, valid graph, algorithm mismatch, keyId mismatch, bad
 * signature, missing verifier (WeakMap lost).
 */
import { describe, it, expect } from "vitest";

import { verifyManifestBeforeTurn } from "../../src/engine/manifest-gate.js";
import {
  createDelegationGraph,
  type DelegationGraph,
} from "../../src/graph/delegation.js";
import { Ed25519Signer, HmacSigner } from "../../src/crypto/signer.js";

function makeGraph(): { graph: DelegationGraph; signer: Ed25519Signer } {
  const signer = new Ed25519Signer();
  const graph = createDelegationGraph(
    "session-1",
    {
      agentId: "root",
      agentType: "orchestrator",
      declaredTools: ["read_email", "send_email"],
      riskState: { l1: false, l2: false, l3: false },
    },
    signer,
  );
  return { graph, signer };
}

describe("verifyManifestBeforeTurn", () => {
  it("returns null when no graph (single-agent mode)", () => {
    expect(verifyManifestBeforeTurn(undefined, "s", "turn-000")).toBeNull();
  });

  it("returns null for a freshly-signed valid graph", () => {
    const { graph } = makeGraph();
    expect(verifyManifestBeforeTurn(graph, "session-1", "turn-000")).toBeNull();
  });

  it("returns SIGNATURE_MISMATCH when the manifest is tampered", () => {
    const { graph } = makeGraph();
    // Mutate a capability surface — drop a declared tool — without
    // re-signing. The canonical payload now differs from what the
    // signature covers.
    const root = graph.nodes.get(graph.rootAgentId);
    if (!root) throw new Error("root missing");
    graph.nodes.set(graph.rootAgentId, {
      ...root,
      declaredTools: ["read_email"], // was ["read_email", "send_email"]
    });
    const result = verifyManifestBeforeTurn(graph, "session-1", "turn-001");
    expect(result).not.toBeNull();
    expect(result?.signal).toBe("MANIFEST_SIGNATURE_INVALID");
    expect(result?.reason).toBe("SIGNATURE_MISMATCH");
    expect(result?.layer).toBe("INTEGRITY");
  });

  it("returns KEY_ID_MISMATCH when an explicit verifier has a different key", () => {
    const { graph } = makeGraph();
    const otherVerifier = new Ed25519Signer();
    const result = verifyManifestBeforeTurn(
      graph,
      "session-1",
      "turn-002",
      otherVerifier,
    );
    expect(result?.reason).toBe("KEY_ID_MISMATCH");
    expect(result?.keyId).toBe(graph.keyId);
  });

  it("returns ALGORITHM_MISMATCH when verifier uses a different algorithm", () => {
    const { graph } = makeGraph();
    const hmacVerifier = new HmacSigner();
    const result = verifyManifestBeforeTurn(
      graph,
      "session-1",
      "turn-003",
      hmacVerifier,
    );
    expect(result?.reason).toBe("ALGORITHM_MISMATCH");
    expect(result?.algorithm).toBe(graph.algorithm);
  });

  it("returns VERIFIER_MISSING when the graph's verifier has been lost", () => {
    // Construct a graph object directly (no verifier registered in the
    // WeakMap). This simulates a deserialized or externally-supplied graph
    // where the caller hasn't supplied an explicit verifier.
    const orphan: DelegationGraph = {
      sessionId: "s",
      rootAgentId: "root",
      nodes: new Map([
        [
          "root",
          {
            agentId: "root",
            agentType: "orchestrator",
            declaredTools: [],
            riskState: { l1: false, l2: false, l3: false },
          },
        ],
      ]),
      edges: [],
      signature: "00",
      algorithm: "Ed25519",
      keyId: "unknown",
    };
    const result = verifyManifestBeforeTurn(orphan, "s", "turn-004");
    expect(result?.reason).toBe("VERIFIER_MISSING");
  });

  it("binds sessionId and turnId into the signal", () => {
    const { graph } = makeGraph();
    const root = graph.nodes.get(graph.rootAgentId);
    if (!root) throw new Error("root missing");
    graph.nodes.set(graph.rootAgentId, {
      ...root,
      declaredTools: [],
    });
    const result = verifyManifestBeforeTurn(graph, "session-xyz", "turn-777");
    expect(result?.sessionId).toBe("session-xyz");
    expect(result?.turnId).toBe("turn-777");
  });
});
