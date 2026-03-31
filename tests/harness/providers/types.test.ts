/**
 * Tests for provider type definitions and canonical tool definitions.
 */

import { describe, it, expect } from 'vitest';
import { CANONICAL_TOOLS } from '../../../harness/providers/tool-defs.js';

describe('CANONICAL_TOOLS', () => {
  it('should define exactly 3 tools', () => {
    expect(CANONICAL_TOOLS).toHaveLength(3);
  });

  it('should include readPrivateData', () => {
    const tool = CANONICAL_TOOLS.find((t) => t.name === 'readPrivateData');
    expect(tool).toBeDefined();
    expect(tool!.parameters.type).toBe('object');
    expect(tool!.parameters.properties).toHaveProperty('customerId');
    expect(tool!.parameters.required).toHaveLength(0);
  });

  it('should include fetchExternalContent', () => {
    const tool = CANONICAL_TOOLS.find((t) => t.name === 'fetchExternalContent');
    expect(tool).toBeDefined();
    expect(tool!.parameters.required).toContain('url');
  });

  it('should include sendOutboundReport', () => {
    const tool = CANONICAL_TOOLS.find((t) => t.name === 'sendOutboundReport');
    expect(tool).toBeDefined();
    expect(tool!.parameters.required).toContain('recipient');
    expect(tool!.parameters.required).toContain('subject');
    expect(tool!.parameters.required).toContain('body');
  });

  it('should have descriptions for all tools', () => {
    for (const tool of CANONICAL_TOOLS) {
      expect(tool.description).toBeTruthy();
      expect(tool.description.length).toBeGreaterThan(10);
    }
  });
});
