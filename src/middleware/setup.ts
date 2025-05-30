import type { Context, Next } from "hono"
import { bodyLimit } from "hono/body-limit"
import { cors } from "hono/cors"
import { etag } from "hono/etag"
import { logger } from "hono/logger"
import { requestId } from "hono/request-id"
import { secureHeaders } from "hono/secure-headers"
import { timing } from "hono/timing"

// ───────────────────────────────────────── Constants  ─────────────────────────────────────────
/**
 * Default body size limit in bytes (100MB)
 */
const DEFAULT_MAX_BODY_SIZE = 100 * 1024 * 1024

/**
 * Cache control max age for preflight requests (24 hours)
 */
const CORS_MAX_AGE_SECONDS = 86400

/**
 * Security header configuration constants
 */
const SECURITY_CONFIG = {
  X_CONTENT_TYPE_OPTIONS: "nosniff",
  ORIGIN_AGENT_CLUSTER: "?1",
  REFERRER_POLICY: "strict-origin-when-cross-origin",
} as const

/**
 * ETag configuration for optimal caching
 */
const ETAG_RETAINED_HEADERS = [
  "content-encoding",
  "content-type",
  "cache-control",
] as const

/**
 * CORS allowed methods for S3 proxy operations
 */
const CORS_ALLOWED_METHODS = [
  "GET",
  "HEAD",
  "POST",
  "PUT",
  "DELETE",
  "OPTIONS",
] as const

/**
 * CORS headers for request/response handling
 */
const CORS_HEADERS = {
  ALLOW: [
    "Content-Type",
    "Authorization",
    "Range",
    "If-None-Match",
    "If-Modified-Since",
    "Content-MD5",
    "Content-Length",
    "Cache-Control",
  ] as const,
  EXPOSE: [
    "Content-Range",
    "Accept-Ranges",
    "ETag",
    "Last-Modified",
    "X-Cache-Debug",
    "Server-Timing",
  ] as const,
}

// ───────────────────────────────────────── Middleware Functions  ─────────────────────────────────────────

/**
 * Setup secure headers middleware with S3 proxy optimized configuration
 * Provides essential security headers while allowing CDN embedding
 */
export function setupSecureHeaders() {
  return secureHeaders({
    xContentTypeOptions: SECURITY_CONFIG.X_CONTENT_TYPE_OPTIONS,
    crossOriginEmbedderPolicy: false, // Allow embedding for CDN use
    crossOriginOpenerPolicy: false, // Allow popup windows
    crossOriginResourcePolicy: "cross-origin", // Allow cross-origin resource sharing
    originAgentCluster: SECURITY_CONFIG.ORIGIN_AGENT_CLUSTER,
    referrerPolicy: SECURITY_CONFIG.REFERRER_POLICY,
    xPermittedCrossDomainPolicies: false, // Disable Flash policy files
  })
}

/**
 * Setup request ID middleware for request tracking and debugging
 * Generates unique IDs for each request to enable log correlation
 */
export function setupRequestId() {
  return requestId()
}

/**
 * Setup timing middleware for performance monitoring
 * Adds Server-Timing headers to track request processing time
 */
export function setupTiming() {
  return timing()
}

/**
 * Setup ETag middleware for efficient caching
 * Uses weak ETags with retained headers for optimal cache performance
 */
export function setupETag() {
  return etag({
    retainedHeaders: [...ETAG_RETAINED_HEADERS],
    weak: true, // Use weak ETags for better performance
  })
}

/**
 * Setup body limit middleware with configurable size limits
 * Prevents memory exhaustion from oversized request bodies
 *
 * @param maxSize - Maximum allowed body size in bytes (default: 100MB)
 * @returns Configured body limit middleware
 */
export function setupBodyLimit(maxSize = DEFAULT_MAX_BODY_SIZE) {
  return bodyLimit({
    maxSize,
    onError: (c) => {
      console.warn(`Request body exceeded limit: ${maxSize} bytes`, {
        path: c.req.path,
        method: c.req.method,
        contentLength: c.req.header("content-length"),
      })

      return c.json(
        {
          error: "Request body too large",
          maxSize,
          unit: "bytes",
        },
        413,
      )
    },
  })
}

/**
 * Parse and validate allowed origins from environment variable
 * Handles comma-separated origin lists and wildcard configuration
 *
 * @param originsConfig - Comma-separated string of allowed origins
 * @returns Array of trimmed origin strings
 */
function parseAllowedOrigins(originsConfig: string): string[] {
  return originsConfig
    .split(",")
    .map((origin: string) => origin.trim())
    .filter((origin: string) => origin.length > 0)
}

/**
 * Determine if origin should be allowed based on configuration
 * Supports wildcard (*) and explicit origin matching
 *
 * @param origin - Request origin header value
 * @param allowedOrigins - Array of allowed origin patterns
 * @returns Allowed origin string or undefined if rejected
 */
function validateOrigin(
  origin: string,
  allowedOrigins: string[],
): string | undefined {
  // Allow wildcard configuration
  if (allowedOrigins.includes("*")) {
    return "*"
  }

  // Check exact origin match
  if (allowedOrigins.includes(origin)) {
    return origin
  }

  return undefined // Reject origin
}

/**
 * Setup CORS middleware with environment-based configuration
 * Supports flexible origin configuration via environment variables
 */
export function setupCors() {
  return cors({
    origin: (origin: string | undefined, c: Context<{ Bindings: Env }>) => {
      // Allow requests without origin header (e.g., server-to-server)
      if (!origin) return "*"

      const originsConfig = c.env.CORS_ALLOW_ORIGINS ?? "*"
      const allowedOrigins = parseAllowedOrigins(originsConfig.toString())

      return validateOrigin(origin, allowedOrigins)
    },
    allowMethods: [...CORS_ALLOWED_METHODS],
    allowHeaders: [...CORS_HEADERS.ALLOW],
    exposeHeaders: [...CORS_HEADERS.EXPOSE],
    maxAge: CORS_MAX_AGE_SECONDS,
    credentials: false, // No cookies needed for S3 proxy operations
  })
}

/**
 * Setup enhanced logging middleware with structured output
 * Adds timestamps and improves log formatting for better debugging
 */
export function setupLogger() {
  return logger((str, ...rest) => {
    const timestamp = new Date().toISOString()
    console.log(`[${timestamp}] ${str}`, ...rest)
  })
}

/**
 * Environment validation middleware with lazy loading
 * Validates required environment variables before processing requests
 * Uses dynamic import to avoid circular dependencies
 */
export function environmentValidationMiddleware() {
  return async (c: Context<{ Bindings: Env }>, next: Next) => {
    try {
      // Lazy import to avoid potential circular dependencies
      const { ensureEnvironmentValidated } = await import(
        "../lib/validation.js"
      )
      ensureEnvironmentValidated(c.env)
      await next()
    } catch (error) {
      console.error("Environment validation failed:", error)
      throw error // Re-throw to trigger error handler
    }
  }
}
