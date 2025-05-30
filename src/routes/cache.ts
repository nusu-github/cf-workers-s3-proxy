import { zValidator } from "@hono/zod-validator"
import { Hono } from "hono"
import type { Context } from "hono"
import { HTTPException } from "hono/http-exception"
import { z } from "zod"
import { getCacheConfig, purgeCache, warmCache } from "../lib/cache.js"
import { shouldEnforceUrlSigning, verifySignature } from "../lib/security.js"
import { ensureEnvironmentValidated } from "../lib/validation.js"

// ───────────────────────────────────────── Constants  ─────────────────────────────────────────
/**
 * Cache health test configuration
 */
const HEALTH_TEST_CONFIG = {
  KEY_PREFIX: "https://cache.internal/health-test/",
  CONTENT: "cache-test",
  CONTENT_TYPE: "text/plain",
} as const

/**
 * HTTP status codes for cache operations
 */
const HTTP_STATUS = {
  SERVICE_UNAVAILABLE: 503,
  NOT_IMPLEMENTED: 501,
  FORBIDDEN: 403,
  INTERNAL_SERVER_ERROR: 500,
} as const

// ───────────────────────────────────────── Validation Schemas  ─────────────────────────────────────────
/**
 * Schema for cache purge operations
 * Supports purging by specific keys, regex patterns, or all entries
 */
const purgeSchema = z
  .object({
    keys: z.array(z.string()).optional(),
    pattern: z.string().optional(),
    all: z.boolean().optional().default(false),
  })
  .refine((data) => data.keys || data.pattern || data.all, {
    message: "Must specify keys, pattern, or all",
  })

/**
 * Schema for cache warming operations
 * Requires at least one valid URL to warm
 */
const warmSchema = z.object({
  urls: z.array(z.string().url()).min(1, "At least one URL is required"),
})

// ───────────────────────────────────────── Type Definitions  ─────────────────────────────────────────
type PurgeOperationResult = {
  totalPurged: number
  errors: string[]
}

type CacheHealthStatus = "healthy" | "unhealthy" | "disabled"

/**
 * Cache management router for S3 proxy operations
 * Provides endpoints for cache purging, warming, statistics, and health checks
 */
const cache = new Hono<{ Bindings: Env }>()

// ───────────────────────────────────────── Helper Functions  ─────────────────────────────────────────
/**
 * Validates Bearer token authentication
 *
 * @param authHeader - Authorization header value
 * @param expectedSecret - Expected secret for comparison
 * @returns True if Bearer token is valid
 */
function isValidBearerToken(
  authHeader: string | undefined,
  expectedSecret: string,
): boolean {
  if (!authHeader) return false

  const providedSecret = authHeader.replace("Bearer ", "")
  return providedSecret === expectedSecret
}

/**
 * Validates URL signature authentication
 *
 * @param c - Hono context with environment bindings
 * @param endpoint - The endpoint being accessed
 * @throws HTTPException if URL signing is required but fails
 */
async function validateUrlSignature(
  c: Context<{ Bindings: Env }>,
  endpoint: string,
): Promise<void> {
  if (!shouldEnforceUrlSigning(c.env, endpoint)) {
    return // URL signing not required
  }

  if (!c.env.URL_SIGNING_SECRET) {
    throw new HTTPException(HTTP_STATUS.FORBIDDEN, {
      message: "Authentication required for cache operation",
    })
  }

  await verifySignature(new URL(c.req.url), c.env.URL_SIGNING_SECRET)
}

/**
 * Validates authentication for cache operations
 * Supports both Bearer token and URL signing authentication methods
 *
 * @param c - Hono context with environment bindings
 * @param endpoint - The endpoint being accessed for logging purposes
 * @throws HTTPException if authentication fails
 */
async function validateCacheAuth(
  c: Context<{ Bindings: Env }>,
  endpoint: string,
): Promise<void> {
  const purgeSecret = c.env.CACHE_PURGE_SECRET
  if (!purgeSecret) {
    throw new HTTPException(HTTP_STATUS.NOT_IMPLEMENTED, {
      message: "Cache operations are not configured",
    })
  }

  // Primary authentication: Bearer token
  const authHeader = c.req.header("authorization")
  if (isValidBearerToken(authHeader, purgeSecret)) {
    return // Authentication successful
  }

  // Fallback authentication: URL signing
  try {
    await validateUrlSignature(c, endpoint)
    return // URL signature valid
  } catch (error) {
    // Log URL signature validation failure for debugging
    console.warn("URL signature validation failed for cache operation:", {
      endpoint,
      error: error instanceof Error ? error.message : "Unknown error",
      url: c.req.url,
    })
    // Fall through to final rejection
  }

  // No valid authentication method
  console.error(
    "Cache operation authentication failed - no valid Bearer token or URL signature:",
    {
      endpoint,
      hasAuthHeader: !!c.req.header("authorization"),
      url: c.req.url,
    },
  )
  throw new HTTPException(HTTP_STATUS.FORBIDDEN, {
    message: "Invalid cache operation secret",
  })
}

/**
 * Purges cache by specific keys
 *
 * @param keys - Array of cache keys to purge
 * @returns Promise resolving to purge results
 */
async function purgeByKeys(keys: string[]): Promise<PurgeOperationResult> {
  let totalPurged = 0
  const errors: string[] = []

  for (const key of keys) {
    try {
      const result = await purgeCache(key)
      totalPurged += result.purged
      errors.push(...result.errors)
    } catch (error) {
      errors.push(
        `Failed to purge key "${key}": ${error instanceof Error ? error.message : "Unknown error"}`,
      )
    }
  }

  return { totalPurged, errors }
}

/**
 * Purges cache by regex pattern
 *
 * @param pattern - Regex pattern string
 * @returns Promise resolving to purge results
 */
async function purgeByPattern(pattern: string): Promise<PurgeOperationResult> {
  const errors: string[] = []

  try {
    const result = await purgeCache(new RegExp(pattern))
    return { totalPurged: result.purged, errors: result.errors }
  } catch (error) {
    errors.push(
      `Failed to purge pattern "${pattern}": ${error instanceof Error ? error.message : "Unknown error"}`,
    )
    return { totalPurged: 0, errors }
  }
}

/**
 * Executes cache purge operation based on the provided parameters
 * Handles purging by keys, patterns, or all entries
 *
 * @param data - Validated purge request data
 * @returns Promise resolving to operation results with counts and errors
 */
async function executePurgeOperation(
  data: z.infer<typeof purgeSchema>,
): Promise<PurgeOperationResult> {
  const { keys, pattern, all } = data

  if (all) {
    return {
      totalPurged: 0,
      errors: ["Purging all cache entries requires custom implementation"],
    }
  }

  if (keys) {
    return await purgeByKeys(keys)
  }

  if (pattern) {
    return await purgeByPattern(pattern)
  }

  // This should not happen due to schema validation
  return { totalPurged: 0, errors: ["No valid purge operation specified"] }
}

/**
 * Generates a unique test key for cache health checks
 * Includes timestamp to avoid conflicts with concurrent tests
 *
 * @returns Unique cache test key
 */
function generateHealthTestKey(): string {
  return `${HEALTH_TEST_CONFIG.KEY_PREFIX}${Date.now()}`
}

/**
 * Performs cache health check by testing basic operations
 * Tests put, get, and delete operations to verify cache functionality
 *
 * @returns Promise resolving to health status and details
 */
async function performCacheHealthTest(): Promise<{
  status: CacheHealthStatus
  message: string
  details: { apiAvailable: boolean; operationSuccessful: boolean }
}> {
  try {
    const testKey = generateHealthTestKey()
    const testResponse = new Response(HEALTH_TEST_CONFIG.CONTENT, {
      headers: { "Content-Type": HEALTH_TEST_CONFIG.CONTENT_TYPE },
    })

    const cacheInstance = caches.default

    // Test cache operations: put, get, delete
    await cacheInstance.put(testKey, testResponse.clone())
    const retrieved = await cacheInstance.match(testKey)
    await cacheInstance.delete(testKey)

    const isHealthy = retrieved !== undefined

    return {
      status: isHealthy ? "healthy" : "unhealthy",
      message: isHealthy
        ? "Cache is functioning normally"
        : "Cache operation failed",
      details: {
        apiAvailable: true,
        operationSuccessful: isHealthy,
      },
    }
  } catch (error) {
    // Log detailed error information for cache health check failure
    console.error("Cache health check failed with error:", {
      error: error instanceof Error ? error.message : "Unknown error",
      errorStack: error instanceof Error ? error.stack : undefined,
      timestamp: new Date().toISOString(),
    })

    return {
      status: "unhealthy",
      message: "Cache health check failed",
      details: {
        apiAvailable: false,
        operationSuccessful: false,
      },
    }
  }
}

// ───────────────────────────────────────── Route Handlers  ─────────────────────────────────────────
/**
 * Cache purge endpoint - POST /__cache/purge
 * Removes cached entries based on keys, patterns, or all entries
 * Requires authentication via Bearer token or URL signing
 */
cache.post("/__cache/purge", zValidator("json", purgeSchema), async (c) => {
  ensureEnvironmentValidated(c.env)
  await validateCacheAuth(c, "/__cache/purge")

  try {
    const data = c.req.valid("json")
    const { totalPurged, errors } = await executePurgeOperation(data)

    return c.json({
      success: true,
      purged: totalPurged,
      errors: errors.length > 0 ? errors : undefined,
      timestamp: new Date().toISOString(),
    })
  } catch (error) {
    console.error("Cache purge error:", error)
    throw new HTTPException(HTTP_STATUS.INTERNAL_SERVER_ERROR, {
      message: `Cache purge failed: ${error instanceof Error ? error.message : "Unknown error"}`,
    })
  }
})

/**
 * Cache warming endpoint - POST /__cache/warm
 * Pre-loads specified URLs into the cache to improve response times
 * Requires authentication via Bearer token or URL signing
 */
cache.post("/__cache/warm", zValidator("json", warmSchema), async (c) => {
  ensureEnvironmentValidated(c.env)
  await validateCacheAuth(c, "/__cache/warm")

  try {
    const { urls } = c.req.valid("json")
    const result = await warmCache(urls, c.env)

    return c.json({
      success: true,
      warmed: result.warmed,
      total: urls.length,
      errors: result.errors.length > 0 ? result.errors : undefined,
      timestamp: new Date().toISOString(),
    })
  } catch (error) {
    console.error("Cache warming error:", error)
    throw new HTTPException(HTTP_STATUS.INTERNAL_SERVER_ERROR, {
      message: `Cache warming failed: ${error instanceof Error ? error.message : "Unknown error"}`,
    })
  }
})

/**
 * Cache configuration endpoint - GET /__cache/stats
 * Returns current cache configuration and settings
 * No authentication required for read-only stats
 */
cache.get("/__cache/stats", (c) => {
  const config = getCacheConfig(c.env)

  return c.json({
    config: {
      enabled: config.enabled,
      ttlSeconds: config.ttlSeconds,
      overrideS3Headers: config.overrideS3Headers,
      minTtlSeconds: config.minTtlSeconds,
      maxTtlSeconds: config.maxTtlSeconds,
      debug: config.debug,
    },
    timestamp: new Date().toISOString(),
  })
})

/**
 * Cache health check endpoint - GET /__cache/health
 * Verifies cache functionality through test operations
 * Used by monitoring systems to check cache availability
 */
cache.get("/__cache/health", async (c) => {
  const config = getCacheConfig(c.env)

  // Check if cache is disabled
  if (!config.enabled) {
    return c.json({
      status: "disabled",
      message: "Cache is disabled",
      timestamp: new Date().toISOString(),
    })
  }

  // Perform health test
  const healthResult = await performCacheHealthTest()

  const statusCode =
    healthResult.status === "unhealthy" ? HTTP_STATUS.SERVICE_UNAVAILABLE : 200

  return c.json(
    {
      status: healthResult.status,
      message: healthResult.message,
      details: healthResult.details,
      timestamp: new Date().toISOString(),
    },
    statusCode,
  )
})

export default cache
