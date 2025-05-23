import { zValidator } from "@hono/zod-validator"
import { Hono } from "hono"
import type { Context } from "hono"
import { HTTPException } from "hono/http-exception"
import { z } from "zod"
import { getCacheConfig, purgeCache, warmCache } from "../lib/cache.js"
import { shouldEnforceUrlSigning, verifySignature } from "../lib/security.js"
import { ensureEnvironmentValidated } from "../lib/validation.js"

const cache = new Hono<{ Bindings: Env }>()

// Validation schemas
const purgeSchema = z
  .object({
    keys: z.array(z.string()).optional(),
    pattern: z.string().optional(),
    all: z.boolean().optional().default(false),
  })
  .refine((data) => data.keys || data.pattern || data.all, {
    message: "Must specify keys, pattern, or all",
  })

const warmSchema = z.object({
  urls: z.array(z.string().url()).min(1, "At least one URL is required"),
})

/**
 * Validates cache operation authentication
 */
async function validateCacheAuth(c: Context<{ Bindings: Env }>, endpoint: string): Promise<void> {
  const purgeSecret = c.env.CACHE_PURGE_SECRET
  if (!purgeSecret) {
    throw new HTTPException(501, {
      message: "Cache operations are not configured",
    })
  }

  // Check Bearer token first
  const authHeader = c.req.header("authorization")
  const providedSecret = authHeader?.replace("Bearer ", "")
  
  if (providedSecret === purgeSecret) {
    return // Authentication successful
  }

  // Fallback to URL signing
  if (shouldEnforceUrlSigning(c.env, endpoint)) {
    if (!c.env.URL_SIGNING_SECRET) {
      throw new HTTPException(403, {
        message: "Authentication required for cache operation",
      })
    }
    await verifySignature(new URL(c.req.url), c.env.URL_SIGNING_SECRET)
  } else {
    throw new HTTPException(403, {
      message: "Invalid cache operation secret",
    })
  }
}

/**
 * Executes purge operation based on request data
 */
async function executePurgeOperation(data: z.infer<typeof purgeSchema>): Promise<{ totalPurged: number; errors: string[] }> {
  const { keys, pattern, all } = data
  let totalPurged = 0
  const errors: string[] = []

  if (all) {
    errors.push("Purging all cache entries requires custom implementation")
  } else if (keys) {
    for (const key of keys) {
      const result = await purgeCache(key)
      totalPurged += result.purged
      errors.push(...result.errors)
    }
  } else if (pattern) {
    const result = await purgeCache(new RegExp(pattern))
    totalPurged += result.purged
    errors.push(...result.errors)
  }

  return { totalPurged, errors }
}

// Cache purge endpoint - POST /__cache/purge
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
    throw new HTTPException(500, {
      message: `Cache purge failed: ${error instanceof Error ? error.message : "Unknown error"}`,
    })
  }
})

// Cache warming endpoint - POST /__cache/warm
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
    throw new HTTPException(500, {
      message: `Cache warming failed: ${error instanceof Error ? error.message : "Unknown error"}`,
    })
  }
})

// Enhanced cache statistics endpoint - GET /__cache/stats
cache.get("/__cache/stats", (c) => {
  const config = getCacheConfig(c.env)
  const metricsData = globalThis.__app_metrics

  const hitRate =
    metricsData.cacheHits + metricsData.cacheMisses > 0
      ? (
          (metricsData.cacheHits /
            (metricsData.cacheHits + metricsData.cacheMisses)) *
          100
        ).toFixed(2)
      : "0.00"

  const errorRate =
    metricsData.totalRequests > 0
      ? ((metricsData.cacheErrors / metricsData.totalRequests) * 100).toFixed(2)
      : "0.00"

  return c.json({
    config: {
      enabled: config.enabled,
      ttlSeconds: config.ttlSeconds,
      overrideS3Headers: config.overrideS3Headers,
      minTtlSeconds: config.minTtlSeconds,
      maxTtlSeconds: config.maxTtlSeconds,
      debug: config.debug,
    },
    metrics: {
      cacheHits: metricsData.cacheHits,
      cacheMisses: metricsData.cacheMisses,
      cacheStores: metricsData.cacheStores,
      cacheErrors: metricsData.cacheErrors,
      cacheBytesServed: metricsData.cacheBytesServed,
      notModifiedResponses: metricsData.notModifiedResponses,
      hitRate: `${hitRate}%`,
      errorRate: `${errorRate}%`,
    },
    performance: {
      totalRequests: metricsData.totalRequests,
      totalErrors: metricsData.totalErrors,
      bytesSent: metricsData.bytesSent,
      bytesServedFromCache: metricsData.cacheBytesServed,
      cacheEfficiency:
        metricsData.bytesSent > 0
          ? `${((metricsData.cacheBytesServed / metricsData.bytesSent) * 100).toFixed(2)}%`
          : "0.00%",
    },
    timestamp: new Date().toISOString(),
  })
})

// Cache health check endpoint - GET /__cache/health
cache.get("/__cache/health", async (c) => {
  const config = getCacheConfig(c.env)

  if (!config.enabled) {
    return c.json({
      status: "disabled",
      message: "Cache is disabled",
      timestamp: new Date().toISOString(),
    })
  }

  try {
    // Test cache functionality with a simple operation
    const testKey = `cache-health-${Date.now()}`
    const testResponse = new Response("cache-test", {
      headers: { "Content-Type": "text/plain" },
    })

    const cache = caches.default
    await cache.put(testKey, testResponse.clone())
    const retrieved = await cache.match(testKey)
    await cache.delete(testKey)

    const isHealthy = retrieved !== undefined

    return c.json({
      status: isHealthy ? "healthy" : "unhealthy",
      message: isHealthy
        ? "Cache is functioning normally"
        : "Cache operation failed",
      details: {
        apiAvailable: true,
        operationSuccessful: isHealthy,
      },
      timestamp: new Date().toISOString(),
    })
  } catch (error) {
    return c.json(
      {
        status: "unhealthy",
        message: "Cache health check failed",
        error: error instanceof Error ? error.message : "Unknown error",
        timestamp: new Date().toISOString(),
      },
      503,
    )
  }
})

export default cache
