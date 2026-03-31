/**
 * Proxy/gateway mode types.
 *
 * Cerberus can operate as an HTTP proxy that sits between an AI agent
 * and its tool backends. No changes to the agent's source code are needed:
 * route tool calls through the proxy and detection runs transparently.
 */

import type { IncomingMessage } from 'node:http';
import type { CerberusConfig } from '../types/config.js';
import type { RawToolExecutorFn } from '../engine/interceptor.js';

/** Configuration for a single proxied tool. */
export interface ProxyToolConfig {
  /**
   * HTTP upstream URL.
   * The proxy will POST `{ "args": {...} }` to this URL and expect a
   * plain string response body.
   * Mutually exclusive with `handler`.
   */
  readonly target?: string;

  /**
   * Local executor function (alternative to `target`).
   * Use this in tests or when the tool runs in-process.
   * Mutually exclusive with `target`.
   */
  readonly handler?: RawToolExecutorFn;

  /** Trust level for L1/L2 detection. Defaults to neutral (no override). */
  readonly trustLevel?: 'trusted' | 'untrusted';

  /**
   * Mark this tool as outbound (sends data externally).
   * Enables L3 exfiltration detection on this tool.
   * Default: false.
   */
  readonly outbound?: boolean;
}

/** Full proxy server configuration. */
export interface ProxyConfig {
  /**
   * Port to listen on.
   * Default: 4000.
   */
  readonly port?: number;

  /**
   * Cerberus detection configuration (alertMode, threshold, etc.).
   * `trustOverrides` from individual `tools` entries are merged in automatically.
   */
  readonly cerberus: CerberusConfig;

  /**
   * Tool map: toolName → ProxyToolConfig.
   * Each key becomes a route at `POST /tool/:toolName`.
   */
  readonly tools: Readonly<Record<string, ProxyToolConfig>>;

  /**
   * Session TTL in milliseconds.
   * Sessions idle beyond this duration are destroyed and GC'd.
   * Default: 1_800_000 (30 minutes).
   */
  readonly sessionTtlMs?: number;

  /**
   * Optional authentication middleware.
   * Called before every tool request. Return true to allow, false to reject (401).
   * Health checks bypass this check.
   *
   * @example
   * // Require X-Cerberus-Api-Key header
   * authMiddleware: (req) => req.headers['x-cerberus-api-key'] === process.env.API_KEY
   */
  readonly authMiddleware?: (req: IncomingMessage) => boolean;
}

/** Handle to the running proxy server. */
export interface ProxyServer {
  /** Start listening on the configured port. Resolves when bound. */
  listen(): Promise<void>;

  /** Shut down: close HTTP server, destroy all sessions. */
  close(): Promise<void>;
}
