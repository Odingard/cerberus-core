/**
 * Item 2 — instrumented trace capture: the recorder must carry self-declared
 * derivation ONLY on an instrumented recorder, and stay byte-identical to the
 * behavior-only capture otherwise.
 */

import { describe, it, expect } from 'vitest';
import { createTraceRecorder } from '../../src/middleware/trace-capture.js';

describe('trace recorder — behavior-only path is unchanged by Item 2', () => {
  it('drops declaration fields and sets no instrumented flag when not instrumented', () => {
    const rec = createTraceRecorder({ source: 'plain' });
    rec.recordRead('a');
    // A declaration is passed but the recorder is NOT instrumented: it must be ignored.
    rec.recordWrite('b', 'content-b', { declaredDeps: ['a'], availableDeps: ['a', 'x'] });
    const snap = rec.snapshot();
    expect(snap.meta.instrumented).toBeUndefined();
    const write = snap.ops.find((o) => o.op === 'write');
    expect(write).toBeDefined();
    expect(write && 'declaredDeps' in write).toBe(false);
    expect(write && 'availableDeps' in write).toBe(false);
  });
});

describe('trace recorder — instrumented path carries declared derivation', () => {
  it('records declaredDeps + availableDeps and stamps meta.instrumented', () => {
    const rec = createTraceRecorder({ source: 'agent', instrumented: true });
    rec.recordRead('fact:x');
    rec.recordWrite('note:y', 'content', {
      declaredDeps: ['fact:x'],
      availableDeps: ['fact:x', 'fact:z'],
    });
    const snap = rec.snapshot();
    expect(snap.meta.instrumented).toBe(true);
    const write = snap.ops.find((o) => o.op === 'write');
    expect(write?.op).toBe('write');
    if (write?.op === 'write') {
      expect(write.declaredDeps).toEqual(['fact:x']);
      expect(write.availableDeps).toEqual(['fact:x', 'fact:z']);
    }
  });

  it('omits declaration fields for an undeclared write even when instrumented', () => {
    const rec = createTraceRecorder({ source: 'agent', instrumented: true });
    rec.recordWrite('root', 'seed'); // no declaration → a declared root
    const write = rec.snapshot().ops.find((o) => o.op === 'write');
    expect(write && 'declaredDeps' in write).toBe(false);
    expect(write && 'availableDeps' in write).toBe(false);
  });

  it('applies the key redactor to declared and available deps', () => {
    const rec = createTraceRecorder({
      source: 'agent',
      instrumented: true,
      keyRedactor: (k) => `r(${k})`,
    });
    rec.recordWrite('w', 'c', { declaredDeps: ['a'], availableDeps: ['a', 'b'] });
    const write = rec.snapshot().ops.find((o) => o.op === 'write');
    if (write?.op === 'write') {
      expect(write.nodeId).toBe('r(w)');
      expect(write.declaredDeps).toEqual(['r(a)']);
      expect(write.availableDeps).toEqual(['r(a)', 'r(b)']);
    }
  });
});
