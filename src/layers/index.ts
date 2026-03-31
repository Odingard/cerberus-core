export {
  classifyDataSource,
  resolveTrustLevel,
  extractFieldNames,
  extractSensitiveValues,
} from './l1-classifier.js';

export type { SensitiveEntity, SensitiveEntityType } from './sensitive-entities.js';
export {
  extractSensitiveEntitiesFromText,
  extractSensitiveEntitiesFromValue,
  matchesSensitiveEntityInText,
  normalizeSensitiveEntity,
} from './sensitive-entities.js';

export { tagTokenProvenance, estimateTokenCount } from './l2-tagger.js';

export {
  classifyOutboundIntent,
  computeEntitySimilarityScore,
  isOutboundTool,
  computeSimilarityScore,
  extractDestination,
  serializeArguments,
} from './l3-classifier.js';

export {
  checkMemoryContamination,
  extractNodeId,
  defaultExtractNodeId,
  defaultExtractContent,
} from './l4-memory.js';

export type { MemoryToolConfig } from './l4-memory.js';
