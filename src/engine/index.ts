export { assessRisk, buildRiskVector, computeScore, resolveAction } from './correlation.js';

export { interceptToolCall } from './interceptor.js';
export type { ToolExecutorFn, OnFullAssessmentCallback } from './interceptor.js';

export { createSession, recordSignal, resetSession } from './session.js';
export type { DetectionSession } from './session.js';
