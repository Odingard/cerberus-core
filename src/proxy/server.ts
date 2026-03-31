/**
 * Proxy/gateway mode — createProxy()
 *
 * HTTP server that wraps any set of tool backends with Cerberus detection.
 * Agents call `POST /tool/:toolName` with `{ "args": {...} }`.
 * The proxy runs the full detection pipeline and returns either:
 *   200 { "result": "..." }          — allowed
 *   403 { "blocked": true, "message": "[Cerberus] ..." } — interrupted
 *
 * Sessions are tracked via the `X-Cerberus-Session` request header.
 * Each unique session ID maintains independent detection state so
 * cumulative scoring (L1+L2+L3 = Lethal Trifecta) works across
 * multiple HTTP requests from the same agent run. If the header is
 * missing, Cerberus creates an isolated ephemeral session and returns
 * it in the response header.
 *
 * Usage:
 *   const proxy = createProxy({
 *     port: 4000,
 *     cerberus: { alertMode: 'interrupt', threshold: 3 },
 *     tools: {
 *       readCustomerData: { target: 'http://localhost:3001/read', trustLevel: 'trusted' },
 *       fetchWebpage:     { target: 'http://localhost:3001/fetch', trustLevel: 'untrusted' },
 *       sendEmail:        { target: 'http://localhost:3001/email', outbound: true },
 *     },
 *   });
 *   await proxy.listen();
 */

import * as http from 'node:http';
import { randomUUID } from 'node:crypto';
import { guard } from '../middleware/wrap.js';
import type { GuardResult } from '../middleware/wrap.js';
import type { RawToolExecutorFn } from '../engine/interceptor.js';
import { validateCerberusConfig } from '../engine/config-validation.js';
import type { TrustOverride } from '../types/config.js';
import type { ProxyConfig, ProxyServer, ProxyToolConfig } from './types.js';

/** Build an executor that POSTs `{ args }` to `target` and returns the text response. */
function makeHttpForwarder(target: string): RawToolExecutorFn {
  return async (args: Record<string, unknown>): Promise<string> => {
    const response = await fetch(target, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ args }),
    });
    const body = await response.text();
    if (!response.ok) {
      const snippet = body.slice(0, 200);
      throw new Error(
        `[Cerberus Proxy] Upstream target ${target} responded with ${String(response.status)}${snippet.length > 0 ? `: ${snippet}` : ''}`,
      );
    }
    return body;
  };
}

/** Resolve a ProxyToolConfig into a ToolExecutorFn. */
function resolveExecutor(toolName: string, cfg: ProxyToolConfig): RawToolExecutorFn {
  if (cfg.handler && cfg.target) {
    throw new Error(
      `[Cerberus Proxy] Tool "${toolName}" cannot specify both "target" and "handler". Choose exactly one.`,
    );
  }
  if (cfg.handler) return cfg.handler;
  if (cfg.target) return makeHttpForwarder(cfg.target);
  throw new Error(
    `[Cerberus Proxy] Tool "${toolName}" must specify either "target" (URL) or "handler" (function).`,
  );
}

/** Read a Node.js IncomingMessage body to a string. */
async function readBody(req: http.IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks).toString('utf8');
}

/** Per-session state. */
interface Session {
  guard: GuardResult;
  lastUsed: number;
}

/**
 * Create a Cerberus proxy/gateway server.
 *
 * @param config - Proxy configuration
 * @returns ProxyServer handle with listen() / close()
 */
export function createProxy(config: ProxyConfig): ProxyServer {
  // ── Build executors from tool configs ──────────────────────────────────
  const baseExecutors: Record<string, RawToolExecutorFn> = {};
  const outboundTools: string[] = [];
  const toolTrustOverrides: TrustOverride[] = [];

  for (const [toolName, toolCfg] of Object.entries(config.tools)) {
    baseExecutors[toolName] = resolveExecutor(toolName, toolCfg);
    if (toolCfg.outbound === true) outboundTools.push(toolName);
    if (toolCfg.trustLevel) {
      toolTrustOverrides.push({ toolName, trustLevel: toolCfg.trustLevel });
    }
  }

  // Merge tool-level trust overrides with any from cerberus config
  const mergedCerberusConfig = {
    ...config.cerberus,
    trustOverrides: [...(config.cerberus.trustOverrides ?? []), ...toolTrustOverrides],
  };
  validateCerberusConfig(mergedCerberusConfig, { outboundTools });

  // ── Session registry ───────────────────────────────────────────────────
  const sessions = new Map<string, Session>();
  const ttl = config.sessionTtlMs ?? 1_800_000;

  function getOrCreateSession(sessionId: string): Session {
    let session = sessions.get(sessionId);
    if (!session) {
      const guardResult = guard(baseExecutors, mergedCerberusConfig, outboundTools);
      session = { guard: guardResult, lastUsed: Date.now() };
      sessions.set(sessionId, session);
    } else {
      session.lastUsed = Date.now();
    }
    return session;
  }

  // Periodically reap idle sessions
  const cleanupTimer = setInterval(() => {
    const now = Date.now();
    for (const [id, session] of sessions.entries()) {
      if (now - session.lastUsed > ttl) {
        session.guard.destroy();
        sessions.delete(id);
      }
    }
  }, 60_000);
  // Prevent the timer from keeping the process alive if server is closed
  cleanupTimer.unref();

  // ── Request handler ────────────────────────────────────────────────────
  const server = http.createServer((req: http.IncomingMessage, res: http.ServerResponse): void => {
    void handleRequest(req, res);
  });

  async function handleRequest(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    res.setHeader('Content-Type', 'application/json');

    // Health check
    if (req.method === 'GET' && req.url === '/health') {
      res.writeHead(200).end(JSON.stringify({ status: 'ok', sessions: sessions.size }));
      return;
    }

    // Auth check (bypassed for health endpoint above)
    if (config.authMiddleware && !config.authMiddleware(req)) {
      res.writeHead(401).end(JSON.stringify({ error: 'Unauthorized' }));
      return;
    }

    if (req.method !== 'POST') {
      res
        .writeHead(405)
        .end(JSON.stringify({ error: 'Method not allowed. Use POST /tool/:toolName' }));
      return;
    }

    // Route: /tool/:toolName
    const match = /^\/tool\/([^/]+)$/.exec(req.url ?? '');
    if (!match) {
      res.writeHead(404).end(JSON.stringify({ error: 'Not found. Use POST /tool/:toolName' }));
      return;
    }

    const toolName = decodeURIComponent(match[1]);

    if (!(toolName in baseExecutors)) {
      res.writeHead(404).end(JSON.stringify({ error: `Unknown tool: ${toolName}` }));
      return;
    }

    // Parse body
    let args: Record<string, unknown> = {};
    try {
      const raw = await readBody(req);
      if (raw.length > 0) {
        const parsed = JSON.parse(raw) as { args?: Record<string, unknown> };
        args = parsed.args ?? {};
      }
    } catch {
      res.writeHead(400).end(JSON.stringify({ error: 'Invalid JSON body' }));
      return;
    }

    // Resolve session. Missing headers get a fresh isolated session instead
    // of sharing a global default session across unrelated callers.
    const providedSessionId = Array.isArray(req.headers['x-cerberus-session'])
      ? req.headers['x-cerberus-session'][0]
      : req.headers['x-cerberus-session'];
    const sessionId = providedSessionId ?? `anon-${randomUUID()}`;
    res.setHeader('X-Cerberus-Session', sessionId);
    const session = getOrCreateSession(sessionId);

    // Execute through Cerberus detection pipeline
    try {
      const result = await session.guard.executors[toolName](args);
      const outcome = session.guard.getLastOutcome();

      if (outcome?.blocked === true) {
        res.setHeader('X-Cerberus-Blocked', 'true');
        res.writeHead(403).end(JSON.stringify({ blocked: true, message: result }));
      } else {
        res.writeHead(200).end(JSON.stringify({ result }));
      }
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      res.writeHead(502).end(JSON.stringify({ error: `Tool execution failed: ${message}` }));
    }
  }

  // ── Public handle ──────────────────────────────────────────────────────
  return {
    listen(): Promise<void> {
      const port = config.port ?? 4000;
      return new Promise<void>((resolve, reject) => {
        server.once('error', reject);
        server.listen(port, () => {
          server.off('error', reject);
          resolve();
        });
      });
    },

    close(): Promise<void> {
      clearInterval(cleanupTimer);
      for (const session of sessions.values()) session.guard.destroy();
      sessions.clear();
      return new Promise<void>((resolve, reject) => {
        server.close((err) => {
          if (err) reject(err);
          else resolve();
        });
      });
    },
  };
}
