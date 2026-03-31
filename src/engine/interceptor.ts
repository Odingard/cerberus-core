/**
 * Interceptor — Tool call wrapper with detection pipeline.
 *
 * Wraps a single tool executor. Runs L1, L2, L3 after tool execution,
 * feeds signals to the Correlation Engine, and can block the result
 * if the action is 'interrupt'.
 */

import type { CerberusConfig } from '../types/config.js';
import type { DetectionSignal, RiskAssessment } from '../types/signals.js';
import type { ToolCallContext } from '../types/context.js';
import type { ToolExecutionOutcome } from '../types/execution.js';
import { formatBlockedToolMessage } from '../types/execution.js';
import type { DetectionSession } from './session.js';
import { recordSignal } from './session.js';
import { classifyDataSource, resolveTrustLevel } from '../layers/l1-classifier.js';
import { tagTokenProvenance } from '../layers/l2-tagger.js';
import { classifyOutboundIntent } from '../layers/l3-classifier.js';
import { checkMemoryContamination } from '../layers/l4-memory.js';
import type { MemoryToolConfig } from '../layers/l4-memory.js';
import type { ContaminationGraph } from '../graph/contamination.js';
import type { ProvenanceLedger } from '../graph/ledger.js';
import { assessRisk } from './correlation.js';
import { detectSecretsInResult } from '../classifiers/secrets-detector.js';
import { scanInjectionInResult } from '../classifiers/injection-scanner.js';
import { detectEncodingInResult } from '../classifiers/encoding-detector.js';
import { classifyOutboundDomain } from '../classifiers/domain-classifier.js';
import { checkToolCallPoisoning } from '../classifiers/mcp-scanner.js';
import { detectBehavioralDrift } from '../classifiers/drift-detector.js';
import { detectInjectionCorrelatedOutbound } from '../classifiers/outbound-correlator.js';
import { detectToolChainExfiltration } from '../classifiers/tool-chain-detector.js';
import { detectOutboundEncoding } from '../classifiers/outbound-encoding-detector.js';
import { detectSplitExfiltration } from '../classifiers/split-exfiltration-detector.js';
import { analyzeContextWindow } from './context-window.js';
import { detectCrossAgentTrifecta, detectContextContamination } from './cross-agent-correlation.js';
import { buildRiskVector } from './correlation.js';
import { updateAgentRiskState } from '../graph/delegation.js';
import { recordToolCall } from '../telemetry/otel.js';
import { collectToolResult } from './streaming.js';

/** Tool result shapes Cerberus can reconstruct into a full inspected string. */
export type ToolExecutorResult =
  | string
  | ReadableStream<Uint8Array | string>
  | AsyncIterable<string | Uint8Array>
  | Iterable<string | Uint8Array>;

/** Raw tool executor input signature before Cerberus reconstructs the result. */
export type RawToolExecutorFn = (args: Record<string, unknown>) => Promise<ToolExecutorResult>;

/** Generic wrapped tool executor function signature. */
export type ToolExecutorFn = (args: Record<string, unknown>) => Promise<string>;

/** Callback invoked with the full risk assessment after each tool call. */
export type OnFullAssessmentCallback = (assessment: RiskAssessment) => void;
/** Callback invoked with structured execution metadata after each tool call. */
export type OnExecutionOutcomeCallback = (outcome: ToolExecutionOutcome) => void;

/**
 * Create an intercepted version of a tool executor.
 *
 * The returned function has the same signature as the original executor
 * but runs the detection pipeline around it:
 * 1. Execute the tool
 * 2. Run L1 (data source classification) → Secrets Detector
 * 3. Run L2 (token provenance tagging) → Injection Scanner + Encoding Detector + MCP Scanner
 * 4. Run L3 (outbound intent classification) → Domain Classifier → Outbound Correlator
 *    → Tool Chain Detector → Outbound Encoding Detector → Split Exfiltration Detector
 * 5. Run L4 (memory contamination — optional)
 * 6. Run Behavioral Drift Detector
 * 7. Correlate signals into a risk assessment
 * 8. If action='interrupt', return a blocked message instead of the real result
 */
export function interceptToolCall(
  toolName: string,
  executor: RawToolExecutorFn,
  session: DetectionSession,
  config: CerberusConfig,
  outboundTools: readonly string[],
  onFullAssessment?: OnFullAssessmentCallback,
  onExecutionOutcome?: OnExecutionOutcomeCallback,
  memoryTools?: readonly MemoryToolConfig[],
  graph?: ContaminationGraph,
  ledger?: ProvenanceLedger,
): ToolExecutorFn {
  const trustOverrides = config.trustOverrides ?? [];
  const isOutboundTool = outboundTools.includes(toolName);

  const finalizeAssessment = (
    assessment: RiskAssessment,
    turnId: string,
    startMs: number,
    signals: readonly DetectionSignal[],
    executorRan: boolean,
    phase: ToolExecutionOutcome['phase'],
  ): ToolExecutionOutcome => {
    onFullAssessment?.(assessment);
    config.onAssessment?.({
      turnId: assessment.turnId,
      toolName,
      score: assessment.score,
      action: assessment.action,
      signals: assessment.signals.map((s) => s.signal),
    });

    const outcome: ToolExecutionOutcome = {
      turnId,
      toolName,
      action: assessment.action,
      score: assessment.score,
      blocked: assessment.action === 'interrupt',
      executorRan,
      phase,
    };
    onExecutionOutcome?.(outcome);

    if (config.opentelemetry === true) {
      recordToolCall({
        toolName,
        sessionId: session.sessionId,
        turnId,
        score: assessment.score,
        action: assessment.action,
        blocked: outcome.blocked,
        signals: signals.map((s) => s.signal),
        durationMs: Date.now() - startMs,
      });
    }

    return outcome;
  };

  const collectAllSessionSignals = (): DetectionSignal[] => {
    const allSessionSignals: DetectionSignal[] = [];
    for (const turnSignals of session.signalsByTurn.values()) {
      allSessionSignals.push(...turnSignals);
    }
    return allSessionSignals;
  };

  const correlateCrossAgentSignals = (turnId: string, signals: DetectionSignal[]): void => {
    if (config.multiAgent !== true || !session.delegationGraph || !session.currentAgentId) {
      return;
    }

    const delegationGraph = session.delegationGraph;
    const currentAgentId = session.currentAgentId;

    const currentVector = buildRiskVector(signals);
    const currentRiskState = {
      l1: currentVector.l1,
      l2: currentVector.l2,
      l3: currentVector.l3,
    };

    updateAgentRiskState(delegationGraph, currentAgentId, currentRiskState);

    const trifectaSignal = detectCrossAgentTrifecta(
      delegationGraph,
      currentAgentId,
      currentRiskState,
      turnId,
    );
    if (trifectaSignal) {
      signals.push(trifectaSignal);
      recordSignal(session, trifectaSignal);
    }

    const contaminationSignal = detectContextContamination(delegationGraph, currentAgentId, turnId);
    if (contaminationSignal) {
      signals.push(contaminationSignal);
      recordSignal(session, contaminationSignal);
    }
  };

  return async (args: Record<string, unknown>): Promise<string> => {
    // Generate turn ID
    const turnIndex = session.turnCounter;
    session.turnCounter += 1;
    const turnId = `turn-${String(turnIndex).padStart(3, '0')}`;

    // Record wall time including tool execution (used for OTel span)
    const startMs = Date.now();

    if (isOutboundTool) {
      const ctx: ToolCallContext = {
        turnId,
        sessionId: session.sessionId,
        toolName,
        toolArguments: args,
        toolResult: '',
        timestamp: Date.now(),
      };

      const signals: DetectionSignal[] = [];

      const l3Signal = classifyOutboundIntent(
        ctx,
        session,
        outboundTools,
        config.authorizedDestinations,
      );
      if (l3Signal) {
        signals.push(l3Signal);
        recordSignal(session, l3Signal);
      }

      const domainSignal = classifyOutboundDomain(ctx, session, outboundTools);
      if (domainSignal) {
        signals.push(domainSignal);
        recordSignal(session, domainSignal);
      }

      const correlatedOutboundSignal = detectInjectionCorrelatedOutbound(
        ctx,
        session,
        outboundTools,
        config.authorizedDestinations,
      );
      if (correlatedOutboundSignal) {
        signals.push(correlatedOutboundSignal);
        recordSignal(session, correlatedOutboundSignal);
      }

      const toolChainSignal = detectToolChainExfiltration(ctx, session, outboundTools);
      if (toolChainSignal) {
        signals.push(toolChainSignal);
        recordSignal(session, toolChainSignal);
      }

      const outboundEncodingSignal = detectOutboundEncoding(ctx, session, outboundTools);
      if (outboundEncodingSignal) {
        signals.push(outboundEncodingSignal);
        recordSignal(session, outboundEncodingSignal);
      }

      const splitExfilSignal = detectSplitExfiltration(
        ctx,
        session,
        outboundTools,
        config.splitExfilThresholdBytes,
      );
      if (splitExfilSignal) {
        signals.push(splitExfilSignal);
        recordSignal(session, splitExfilSignal);
      }

      const driftSignal = detectBehavioralDrift(
        ctx,
        session,
        outboundTools,
        false,
        config.authorizedDestinations,
      );
      if (driftSignal) {
        signals.push(driftSignal);
        recordSignal(session, driftSignal);
      }

      correlateCrossAgentSignals(turnId, signals);

      const assessment = assessRisk(turnId, signals, config, collectAllSessionSignals());

      if (assessment.action === 'interrupt') {
        const blockedOutcome = finalizeAssessment(
          assessment,
          turnId,
          startMs,
          signals,
          false,
          'preflight',
        );
        return formatBlockedToolMessage(blockedOutcome);
      }

      const rawResult = await executor(args);
      const result = await collectToolResult(rawResult, config);
      finalizeAssessment(assessment, turnId, startMs, signals, true, 'preflight');
      return result;
    }

    // Execute the tool
    const rawResult = await executor(args);
    const result = await collectToolResult(rawResult, config);

    // Build context for detection layers
    const ctx: ToolCallContext = {
      turnId,
      sessionId: session.sessionId,
      toolName,
      toolArguments: args,
      toolResult: result,
      timestamp: Date.now(),
    };

    // Context window check — runs BEFORE L1/L2/L3 detection
    const contextResult = analyzeContextWindow(result, turnId, config);

    // Determine which content to scan — use inspected content if overflow occurred
    const scanContent = contextResult.overflow ? contextResult.inspectedContent : result;

    // If context window manager blocked the scan entirely, skip the pipeline
    if (contextResult.blocked) {
      const signals: DetectionSignal[] = [];
      if (contextResult.signal) {
        signals.push(contextResult.signal);
        recordSignal(session, contextResult.signal);
      }

      const assessment = assessRisk(turnId, signals, config, collectAllSessionSignals());
      const outcome = finalizeAssessment(
        assessment,
        turnId,
        startMs,
        signals,
        true,
        'context-window',
      );

      if (outcome.blocked) {
        return formatBlockedToolMessage(outcome);
      }

      return result;
    }

    // Build context for detection layers — use scanned content when overflow occurred
    const scanCtx: ToolCallContext = contextResult.overflow
      ? { ...ctx, toolResult: scanContent }
      : ctx;

    // Run detection layers and collect signals
    const signals: DetectionSignal[] = [];

    // Add context overflow signal if present
    if (contextResult.signal) {
      signals.push(contextResult.signal);
      recordSignal(session, contextResult.signal);
    }

    const trustLevel = resolveTrustLevel(toolName, trustOverrides);
    const isTrusted = trustLevel === 'trusted';
    const isUntrusted = trustLevel === 'untrusted';

    // L1: Data source classification (uses scanCtx for content-aware scanning)
    const l1Signal = classifyDataSource(scanCtx, trustOverrides, session);
    if (l1Signal) {
      signals.push(l1Signal);
      recordSignal(session, l1Signal);
    }

    // L1 sub-classifier: Secrets detector (runs when L1 fires)
    const secretsSignal = detectSecretsInResult(scanCtx, session, isTrusted);
    if (secretsSignal) {
      signals.push(secretsSignal);
      recordSignal(session, secretsSignal);
    }

    // L2: Token provenance tagging
    const l2Signal = tagTokenProvenance(scanCtx, trustOverrides, session);
    if (l2Signal) {
      signals.push(l2Signal);
      recordSignal(session, l2Signal);
    }

    // L2 sub-classifiers: Injection scanner + Encoding detector (run when untrusted)
    const injectionSignal = scanInjectionInResult(scanCtx, session, isUntrusted);
    if (injectionSignal) {
      signals.push(injectionSignal);
      recordSignal(session, injectionSignal);
    }

    const encodingSignal = detectEncodingInResult(scanCtx, session, isUntrusted);
    if (encodingSignal) {
      signals.push(encodingSignal);
      recordSignal(session, encodingSignal);
    }

    // L2 sub-classifier: MCP tool poisoning (runs when toolDescriptions configured)
    if (config.toolDescriptions && config.toolDescriptions.length > 0) {
      const poisoningSignal = checkToolCallPoisoning(scanCtx, config.toolDescriptions, session);
      if (poisoningSignal) {
        signals.push(poisoningSignal);
        recordSignal(session, poisoningSignal);
      }
    }

    // L3: Outbound intent classification
    const l3Signal = classifyOutboundIntent(
      ctx,
      session,
      outboundTools,
      config.authorizedDestinations,
    );
    if (l3Signal) {
      signals.push(l3Signal);
      recordSignal(session, l3Signal);
    }

    // L3 sub-classifier: Suspicious domain classifier (runs for outbound tools)
    const domainSignal = classifyOutboundDomain(ctx, session, outboundTools);
    if (domainSignal) {
      signals.push(domainSignal);
      recordSignal(session, domainSignal);
    }

    // L3 sub-classifier: Injection-correlated outbound detector — catches summarized/transformed
    // exfiltration where PII is not verbatim in args but context has injection + privileged data
    const correlatedOutboundSignal = detectInjectionCorrelatedOutbound(
      ctx,
      session,
      outboundTools,
      config.authorizedDestinations,
    );
    if (correlatedOutboundSignal) {
      signals.push(correlatedOutboundSignal);
      recordSignal(session, correlatedOutboundSignal);
    }

    // L3 sub-classifier: Multi-hop tool chain exfiltration detector
    const toolChainSignal = detectToolChainExfiltration(ctx, session, outboundTools);
    if (toolChainSignal) {
      signals.push(toolChainSignal);
      recordSignal(session, toolChainSignal);
    }

    // L3 sub-classifier: Outbound encoding detector — catches encoded payloads in outbound args
    const outboundEncodingSignal = detectOutboundEncoding(ctx, session, outboundTools);
    if (outboundEncodingSignal) {
      signals.push(outboundEncodingSignal);
      recordSignal(session, outboundEncodingSignal);
    }

    // L3 sub-classifier: Split exfiltration detector — catches data chunked across outbound calls
    const splitExfilSignal = detectSplitExfiltration(
      ctx,
      session,
      outboundTools,
      config.splitExfilThresholdBytes,
    );
    if (splitExfilSignal) {
      signals.push(splitExfilSignal);
      recordSignal(session, splitExfilSignal);
    }

    // L4: Memory contamination detection (optional — skip if not configured)
    if (graph && ledger && memoryTools && memoryTools.length > 0) {
      const l4Signal = checkMemoryContamination(ctx, memoryTools, graph, ledger, trustLevel);
      if (l4Signal) {
        signals.push(l4Signal);
        recordSignal(session, l4Signal);
      }
    }

    // Behavioral drift detector (runs last — reads accumulated session state)
    const driftSignal = detectBehavioralDrift(
      ctx,
      session,
      outboundTools,
      isTrusted,
      config.authorizedDestinations,
    );
    if (driftSignal) {
      signals.push(driftSignal);
      recordSignal(session, driftSignal);
    }

    // Cross-agent correlation (runs after drift, before final correlation)
    correlateCrossAgentSignals(turnId, signals);

    // Correlate: vector/score from cumulative session signals, turn signals for inspection
    const assessment = assessRisk(turnId, signals, config, collectAllSessionSignals());
    const outcome = finalizeAssessment(
      assessment,
      turnId,
      startMs,
      signals,
      true,
      'post-execution',
    );

    // If action is interrupt, return blocked message
    if (outcome.blocked) {
      return formatBlockedToolMessage(outcome);
    }

    return result;
  };
}
