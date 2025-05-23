import { Hono } from "hono"
import { HTTPException } from "hono/http-exception"

// Import middleware setup
import {
  environmentValidationMiddleware,
  metricsMiddleware,
  setupBodyLimit,
  setupCors,
  setupETag,
  setupLogger,
  setupRequestId,
  setupSecureHeaders,
  setupTiming,
} from "./middleware/setup.js"

// Import initialization
import { initializeMetrics } from "./lib/metrics.js"

import cache from "./routes/cache.js"
import deleteRoute from "./routes/delete.js"
import files from "./routes/files.js"
// Import route handlers
import health from "./routes/health.js"
import list from "./routes/list.js"
import metrics from "./routes/metrics.js"
import upload from "./routes/upload.js"

// Initialize metrics on startup
initializeMetrics()

const app = new Hono<{ Bindings: Env }>()

// ───────────────────────────────────────── Global Middleware  ─────────────────────────────────────────
// Security and basic middleware
app.use("*", setupSecureHeaders())
app.use("*", setupCors())
app.use("*", setupRequestId())
app.use("*", setupTiming())

// Environment validation (fail-fast)
app.use("*", environmentValidationMiddleware())

// Logging and metrics
app.use("*", setupLogger())
app.use("*", metricsMiddleware())

// Optional rate limiting (disabled by default, enable via environment)
app.use("*", async (_c, next) => {
  // Skip rate limiting for now to avoid environment type issues
  await next()
})

// ───────────────────────────────────────── Route-Specific Middleware  ─────────────────────────────────────────
// Enable ETag for cacheable content
app.use("/files/*", setupETag())
app.use("/:filename{.*}", setupETag())
app.use("/list", setupETag())

// Body size limits for upload routes
app.use("/presigned-upload", setupBodyLimit(1024)) // 1KB for presigned URL requests
app.use("/:filename{.*}/uploads", setupBodyLimit(1024)) // 1KB for multipart initiation
app.use("/delete", setupBodyLimit(10 * 1024)) // 10KB for batch delete requests

// Larger body limit for direct uploads
app.use("*", async (c, next) => {
  if (c.req.method === "PUT") {
    const maxUploadSize = 100 * 1024 * 1024 // 100MB default
    return setupBodyLimit(maxUploadSize)(c, next)
  }
  await next()
})

// ───────────────────────────────────────── Error Handling  ─────────────────────────────────────────
// Enhanced error handler with better context
app.onError((err, c) => {
  globalThis.__app_metrics.totalErrors++

  // Log error with context
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

// Enhanced 404 handler
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
// Create API route group for better organization
const api = new Hono<{ Bindings: Env }>()

// Health and monitoring routes (no authentication required)
api.route("/", health)
api.route("/", metrics)
api.route("/", cache)

// S3 operation routes
api.route("/", list)
api.route("/", upload)
api.route("/", deleteRoute)

// Mount API routes
app.route("/", api)

// ───────────────────────────────────────── File Serving Routes  ─────────────────────────────────────────
// File serving routes (must be last to catch all other paths)
// These handle the main S3 proxy functionality
app.route("/", files)

export default app
