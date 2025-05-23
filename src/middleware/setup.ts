import type { Context, Next } from "hono"
import { bodyLimit } from "hono/body-limit"
import { cors } from "hono/cors"
import { etag } from "hono/etag"
import { logger } from "hono/logger"
import { requestId } from "hono/request-id"
import { secureHeaders } from "hono/secure-headers"
import { timing } from "hono/timing"

/**
 * Setup secure headers middleware
 */
export function setupSecureHeaders() {
  return secureHeaders({
    xContentTypeOptions: "nosniff",
    crossOriginEmbedderPolicy: false,
    crossOriginOpenerPolicy: false,
    crossOriginResourcePolicy: "cross-origin",
    originAgentCluster: "?1", // Allow embedding for CDN use case
    referrerPolicy: "strict-origin-when-cross-origin",
    xPermittedCrossDomainPolicies: false,
  })
}

/**
 * Setup request ID middleware
 */
export function setupRequestId() {
  return requestId()
}

/**
 * Setup timing middleware for performance monitoring
 */
export function setupTiming() {
  return timing()
}

/**
 * Setup ETag middleware for better caching
 */
export function setupETag() {
  return etag({
    retainedHeaders: ["content-encoding", "content-type", "cache-control"],
    weak: true, // Use weak ETags for better performance
  })
}

/**
 * Setup body limit middleware for upload endpoints
 */
export function setupBodyLimit(maxSize = 100 * 1024 * 1024) {
  // 100MB default
  return bodyLimit({
    maxSize,
    onError: (c) => {
      return c.json({ error: "Request body too large", maxSize }, 413)
    },
  })
}

/**
 * Setup CORS middleware with environment-based configuration
 */
export function setupCors() {
  return cors({
    origin: (origin: string | undefined, c: Context<{ Bindings: Env }>) => {
      if (!origin) return "*" // Allow requests without origin header

      const allowedOrigins = (c.env.CORS_ALLOW_ORIGINS ?? "*")
        .toString()
        .split(",")
        .map((s: string) => s.trim())

      // If "*" is in the list, allow all origins
      if (allowedOrigins.includes("*")) {
        return "*"
      }

      // Check if origin is in allowed list
      if (allowedOrigins.includes(origin)) {
        return origin
      }

      return undefined // Reject origin
    },
    allowMethods: ["GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS"],
    allowHeaders: [
      "Content-Type",
      "Authorization",
      "Range",
      "If-None-Match",
      "If-Modified-Since",
      "Content-MD5",
      "Content-Length",
      "Cache-Control",
    ],
    exposeHeaders: [
      "Content-Range",
      "Accept-Ranges",
      "ETag",
      "Last-Modified",
      "X-Cache-Debug",
      "Server-Timing",
    ],
    maxAge: 86400, // 24 hours
    credentials: false, // No cookies needed for S3 proxy
  })
}

/**
 * Setup logging middleware with enhanced formatting
 */
export function setupLogger() {
  return logger((str, ...rest) => {
    // Enhanced logging with timestamp and request ID
    const timestamp = new Date().toISOString()
    console.log(`[${timestamp}] ${str}`, ...rest)
  })
}

/**
 * Enhanced metrics and context tracking middleware
 */
export function metricsMiddleware() {
  return async (c: Context, next: Next) => {
    const startTime = Date.now()

    // Initialize request context
    c.set("startTime", startTime)
    c.set("requestId", c.get("requestId") || crypto.randomUUID())

    // Increment total requests
    globalThis.__app_metrics.totalRequests++

    try {
      await next()

      // Track request completion time
      const endTime = Date.now()
      const duration = endTime - startTime
      c.set("requestDuration", duration)

      // Add performance timing header
      c.header("Server-Timing", `total;dur=${duration}`)
    } catch (error) {
      // Track errors
      globalThis.__app_metrics.totalErrors++
      throw error
    }
  }
}

/**
 * Environment validation middleware
 */
export function environmentValidationMiddleware() {
  return async (c: Context<{ Bindings: Env }>, next: Next) => {
    // Import and run validation lazily
    const { ensureEnvironmentValidated } = await import("../lib/validation.js")
    ensureEnvironmentValidated(c.env)
    await next()
  }
}
