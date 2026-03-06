/**
 * Environment-based API configuration.
 * - Local/dev: leave VITE_API_URL unset → uses relative /api/v1 (Vite proxy or same host).
 * - Production (API on different host): set VITE_API_URL=https://api.yourdomain.com at build time.
 */
const raw = typeof import.meta !== "undefined" && (import.meta as any).env?.VITE_API_URL;
const origin = typeof raw === "string" && raw.trim() ? (raw as string).replace(/\/+$/, "") : "";

/** Base URL for REST and SSE: /api/v1 (relative) or https://api.example.com/api/v1 (absolute). */
export const API_BASE = origin ? `${origin}/api/v1` : "/api/v1";

/** True when using an explicit API origin (e.g. production API on another host). */
export const isApiCrossOrigin = Boolean(origin);
