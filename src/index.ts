import { Hono } from "hono"
import { HTTPException } from "hono/http-exception"

// Import middleware setup
import {
  environmentValidationMiddleware,
  setupBodyLimit,
  setupCors,
  setupETag,
  setupLogger,
  setupRequestId,
  setupSecureHeaders,
  setupTiming,
} from "./middleware/setup.js"

import cache from "./routes/cache.js"
import deleteRoute from "./routes/delete.js"
import files from "./routes/files.js"
// Import route handlers
import health from "./routes/health.js"
import list from "./routes/list.js"
import upload from "./routes/upload.js"

// ───────────────────────────────────────── Constants  ─────────────────────────────────────────
/**
 * Body size limits for different endpoints
 */
const BODY_LIMITS = {
  PRESIGNED_UPLOAD: 1024, // 1KB for presigned URL requests
  MULTIPART_INITIATION: 1024, // 1KB for multipart initiation
  BATCH_DELETE: 10 * 1024, // 10KB for batch delete requests
  DEFAULT_UPLOAD: 100 * 1024 * 1024, // 100MB for direct uploads
} as const

const app = new Hono<{ Bindings: Env }>()

// ───────────────────────────────────────── Global Middleware  ─────────────────────────────────────────
/**
 * Apply security headers, CORS, request tracking, and basic middleware
 * Order is important: security first, then logging and monitoring
 */
app.use("*", setupSecureHeaders())
app.use("*", setupCors())
app.use("*", setupRequestId())
app.use("*", setupTiming())

/**
 * Environment validation - fail fast if configuration is invalid
 */
app.use("*", environmentValidationMiddleware())

/**
 * Request logging - after environment validation to ensure proper setup
 */
app.use("*", setupLogger())

/**
 * Rate limiting placeholder - disabled by default
 * TODO: Implement proper rate limiting when environment types are stable
 */
app.use("*", async (_c, next) => {
  // Skip rate limiting for now to avoid environment type issues
  await next()
})

// ───────────────────────────────────────── Route-Specific Middleware  ─────────────────────────────────────────
/**
 * ETag middleware for cacheable content endpoints
 * Improves performance by enabling proper browser/CDN caching
 */
app.use("/files/*", setupETag())
app.use("/:filename{.*}", setupETag())
app.use("/list", setupETag())

/**
 * Body size limits for specific upload-related endpoints
 * Prevents oversized requests that could cause memory issues
 */
app.use("/presigned-upload", setupBodyLimit(BODY_LIMITS.PRESIGNED_UPLOAD))
app.use(
  "/:filename{.*}/uploads",
  setupBodyLimit(BODY_LIMITS.MULTIPART_INITIATION),
)
app.use("/delete", setupBodyLimit(BODY_LIMITS.BATCH_DELETE))

/**
 * Larger body limit for direct file uploads (PUT requests)
 * Applied dynamically based on request method
 */
app.use("*", async (c, next) => {
  if (c.req.method === "PUT") {
    return setupBodyLimit(BODY_LIMITS.DEFAULT_UPLOAD)(c, next)
  }
  await next()
})

// ───────────────────────────────────────── Error Handling  ─────────────────────────────────────────
/**
 * Global error handler with comprehensive logging and context
 * Provides structured error responses while protecting sensitive information
 */
app.onError((err, c) => {
  // Log error with full context for debugging
  console.error("Request error:", {
    error: err.message,
    stack: err.stack,
    path: c.req.path,
    method: c.req.method,
    userAgent: c.req.header("user-agent"),
  })

  const status = err instanceof HTTPException ? err.status : 500
  const message =
    err instanceof HTTPException ? err.message : "Internal Server Error"

  return c.json(
    {
      error: message,
      timestamp: new Date().toISOString(),
    },
    status,
  )
})

/**
 * Enhanced 404 handler with request tracking
 * Provides helpful information for debugging missing routes
 */
app.notFound((c) => {
  const requestId = c.get("requestId")
  return c.json(
    {
      error: "Not Found",
      path: c.req.path,
      requestId,
      timestamp: new Date().toISOString(),
    },
    404,
  )
})

// ───────────────────────────────────────── API Routes  ─────────────────────────────────────────
/**
 * API route group for better organization and middleware isolation
 * Groups related endpoints under a common routing structure
 */
const api = new Hono<{ Bindings: Env }>()

// Health and monitoring routes (no authentication required)
api.route("/", health)
api.route("/", cache)

// S3 operation routes
api.route("/", list)
api.route("/", upload)
api.route("/", deleteRoute)

// Mount API routes to main application
app.route("/", api)

// ───────────────────────────────────────── File Serving Routes  ─────────────────────────────────────────
/**
 * File serving routes - must be last to catch all remaining paths
 * Handles the main S3 proxy functionality for direct file access
 */
app.route("/", files)

export default app
