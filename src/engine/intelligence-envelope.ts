import type { DetectionSession } from './session.js';
import type { ToolExecutionOutcome } from '../types/execution.js';
import type {
  RiskAssessment,
  DetectionSignal,
  ExfiltrationRiskSignal,
  ContaminatedMemorySignal,
} from '../types/signals.js';
import type { IntelligenceIncidentEnvelope } from '../types/intelligence.js';

function isExfiltrationRiskSignal(signal: DetectionSignal): signal is ExfiltrationRiskSignal {
  return signal.signal === 'EXFILTRATION_RISK';
}

function isContaminatedMemorySignal(signal: DetectionSignal): signal is ContaminatedMemorySignal {
  return signal.signal === 'CONTAMINATED_MEMORY_ACTIVE';
}

/** Build the smallest stable incident envelope for the first Intelligence layer. */
export function buildIntelligenceIncidentEnvelope(
  session: DetectionSession,
  assessment: RiskAssessment,
  outcome: ToolExecutionOutcome,
): IntelligenceIncidentEnvelope {
  const exfiltrationSignal = assessment.signals.find(isExfiltrationRiskSignal);
  const memorySignals = assessment.signals.filter(isContaminatedMemorySignal);

  return {
    incidentId: `${session.sessionId}:${assessment.turnId}`,
    sessionId: session.sessionId,
    turnId: assessment.turnId,
    timestamp: assessment.timestamp,
    toolName: outcome.toolName,
    action: assessment.action,
    riskScore: assessment.score,
    riskVector: assessment.vector,
    blocked: outcome.blocked,
    executorRan: outcome.executorRan,
    phase: outcome.phase,
    signals: assessment.signals,
    trustedSources: [...session.trustedSourcesAccessed],
    untrustedSources: [...session.untrustedSources],
    accessedFields: [...session.accessedFields],
    ...(exfiltrationSignal
      ? {
          outboundDestination: exfiltrationSignal.destination,
          exfiltrationFields: exfiltrationSignal.matchedFields,
        }
      : {}),
    ...(memorySignals.length > 0
      ? {
          memoryMarkers: memorySignals.map(
            (signal) => `${signal.nodeId}:${signal.contaminationSource}`,
          ),
        }
      : {}),
    toolSequence: session.toolCallHistory.map(({ toolName, turnId }) => ({
      toolName,
      turnId,
    })),
  };
}
