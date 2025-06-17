import { zValidator } from "@hono/zod-validator"
import { Hono } from "hono"
import type { Context } from "hono"
import { HTTPException } from "hono/http-exception"
import { z } from "zod"
import { getCacheConfig, purgeCache, warmCache } from "../lib/cache.js"
import { shouldEnforceUrlSigning, verifySignature } from "../lib/security.js"
import { ensureEnvironmentValidated } from "../lib/validation.js"

// ─────────────────────────────────────── Constants ───────────────────────────────────────
const HEALTH_TEST_CONFIG = {
  KEY_PREFIX: "https://cache.internal/health-test/",
  CONTENT: "cache-test",
  CONTENT_TYPE: "text/plain",
} as const

const HTTP_STATUS = {
  SERVICE_UNAVAILABLE: 503,
  NOT_IMPLEMENTED: 501,
  FORBIDDEN: 403,
  INTERNAL_SERVER_ERROR: 500,
} as const

// ─────────────────────────────────────── Validation Schemas ───────────────────────────────────────
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

// ─────────────────────────────────────── Type Definitions ───────────────────────────────────────
type PurgeOperationResult = {
  totalPurged: number
  errors: string[]
}

type CacheHealthStatus = "healthy" | "unhealthy" | "disabled"

type AuthResult = {
  authenticated: boolean
  method?: "bearer" | "url-signature"
}

// ─────────────────────────────────────── Auth Helper Functions ───────────────────────────────────────
function extractBearerToken(authHeader: string | undefined): string | null {
  if (!authHeader?.startsWith("Bearer ")) return null
  return authHeader.replace("Bearer ", "")
}

function validateBearerAuth(
  authHeader: string | undefined,
  secret: string,
): AuthResult {
  const token = extractBearerToken(authHeader)
  return {
    authenticated: token === secret,
    method: token ? "bearer" : undefined,
  }
}

async function validateUrlSignatureAuth(
  c: Context<{ Bindings: Env }>,
  endpoint: string,
): Promise<AuthResult> {
  if (!shouldEnforceUrlSigning(c.env, endpoint)) {
    return { authenticated: false }
  }

  if (!c.env.URL_SIGNING_SECRET) {
    return { authenticated: false }
  }

  try {
    await verifySignature(new URL(c.req.url), c.env.URL_SIGNING_SECRET)
    return { authenticated: true, method: "url-signature" }
  } catch (error) {
    console.warn("URL signature validation failed:", {
      endpoint,
      error: error instanceof Error ? error.message : "Unknown error",
    })
    return { authenticated: false }
  }
}

function throwAuthError(endpoint: string, hasAuthHeader: boolean): never {
  console.error("Cache operation authentication failed:", {
    endpoint,
    hasAuthHeader,
  })
  throw new HTTPException(HTTP_STATUS.FORBIDDEN, {
    message: "Invalid cache operation secret",
  })
}

async function validateCacheAuth(
  c: Context<{ Bindings: Env }>,
  endpoint: string,
): Promise<void> {
  if (!c.env.CACHE_PURGE_SECRET) {
    throw new HTTPException(HTTP_STATUS.NOT_IMPLEMENTED, {
      message: "Cache operations are not configured",
    })
  }

  // Try Bearer token authentication first
  const bearerResult = validateBearerAuth(
    c.req.header("authorization"),
    c.env.CACHE_PURGE_SECRET,
  )
  if (bearerResult.authenticated) return

  // Fallback to URL signature authentication
  const urlResult = await validateUrlSignatureAuth(c, endpoint)
  if (urlResult.authenticated) return

  // No valid authentication found
  throwAuthError(endpoint, !!c.req.header("authorization"))
}

// ─────────────────────────────────────── Purge Helper Functions ───────────────────────────────────────
async function purgeByKeys(keys: string[]): Promise<PurgeOperationResult> {
  let totalPurged = 0
  const errors: string[] = []

  for (const key of keys) {
    try {
      const result = await purgeCache(key)
      totalPurged += result.purged
      errors.push(...result.errors)
    } catch (error) {
      const message = error instanceof Error ? error.message : "Unknown error"
      errors.push(`Failed to purge key "${key}": ${message}`)
    }
  }

  return { totalPurged, errors }
}

async function purgeByPattern(pattern: string): Promise<PurgeOperationResult> {
  try {
    const result = await purgeCache(new RegExp(pattern))
    return { totalPurged: result.purged, errors: result.errors }
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown error"
    return {
      totalPurged: 0,
      errors: [`Failed to purge pattern "${pattern}": ${message}`],
    }
  }
}

function createPurgeAllError(): PurgeOperationResult {
  return {
    totalPurged: 0,
    errors: ["Purging all cache entries requires custom implementation"],
  }
}

async function executePurgeOperation(
  data: z.infer<typeof purgeSchema>,
): Promise<PurgeOperationResult> {
  const { keys, pattern, all } = data

  if (all) return createPurgeAllError()
  if (keys) return await purgeByKeys(keys)
  if (pattern) return await purgeByPattern(pattern)

  return { totalPurged: 0, errors: ["No valid purge operation specified"] }
}

// ─────────────────────────────────────── Health Check Helper Functions ───────────────────────────────────────
function generateHealthTestKey(): string {
  return `${HEALTH_TEST_CONFIG.KEY_PREFIX}${Date.now()}`
}

async function testCacheOperations(testKey: string): Promise<boolean> {
  const testResponse = new Response(HEALTH_TEST_CONFIG.CONTENT, {
    headers: { "Content-Type": HEALTH_TEST_CONFIG.CONTENT_TYPE },
  })

  const cacheInstance = caches.default
  await cacheInstance.put(testKey, testResponse.clone())
  const retrieved = await cacheInstance.match(testKey)
  await cacheInstance.delete(testKey)

  return retrieved !== undefined
}

function createHealthResult(
  status: CacheHealthStatus,
  message: string,
  apiAvailable: boolean,
  operationSuccessful: boolean,
) {
  return {
    status,
    message,
    details: { apiAvailable, operationSuccessful },
  }
}

async function performCacheHealthTest() {
  try {
    const testKey = generateHealthTestKey()
    const isHealthy = await testCacheOperations(testKey)

    return createHealthResult(
      isHealthy ? "healthy" : "unhealthy",
      isHealthy ? "Cache is functioning normally" : "Cache operation failed",
      true,
      isHealthy,
    )
  } catch (error) {
    console.error("Cache health check failed:", {
      error: error instanceof Error ? error.message : "Unknown error",
      timestamp: new Date().toISOString(),
    })

    return createHealthResult(
      "unhealthy",
      "Cache health check failed",
      false,
      false,
    )
  }
}

// ─────────────────────────────────────── Response Helper Functions ───────────────────────────────────────
function createSuccessResponse(
  totalPurged: number,
  errors: string[],
  operation: string,
) {
  return {
    success: true,
    [operation]: totalPurged,
    errors: errors.length > 0 ? errors : undefined,
    timestamp: new Date().toISOString(),
  }
}

function createWarmingResponse(
  warmed: number,
  total: number,
  errors: string[],
) {
  return {
    success: true,
    warmed,
    total,
    errors: errors.length > 0 ? errors : undefined,
    timestamp: new Date().toISOString(),
  }
}

function createConfigResponse(config: ReturnType<typeof getCacheConfig>) {
  return {
    config: {
      enabled: config.enabled,
      ttlSeconds: config.ttlSeconds,
      overrideS3Headers: config.overrideS3Headers,
      minTtlSeconds: config.minTtlSeconds,
      maxTtlSeconds: config.maxTtlSeconds,
      debug: config.debug,
    },
    timestamp: new Date().toISOString(),
  }
}

// ─────────────────────────────────────── Router Instance ───────────────────────────────────────
const cache = new Hono<{ Bindings: Env }>()

// ─────────────────────────────────────── Route Handlers ───────────────────────────────────────
cache.post("/__cache/purge", zValidator("json", purgeSchema), async (c) => {
  ensureEnvironmentValidated(c.env)
  await validateCacheAuth(c, "/__cache/purge")

  try {
    const data = c.req.valid("json")
    const { totalPurged, errors } = await executePurgeOperation(data)
    return c.json(createSuccessResponse(totalPurged, errors, "purged"))
  } catch (error) {
    console.error("Cache purge error:", error)
    const message = error instanceof Error ? error.message : "Unknown error"
    throw new HTTPException(HTTP_STATUS.INTERNAL_SERVER_ERROR, {
      message: `Cache purge failed: ${message}`,
    })
  }
})

cache.post("/__cache/warm", zValidator("json", warmSchema), async (c) => {
  ensureEnvironmentValidated(c.env)
  await validateCacheAuth(c, "/__cache/warm")

  try {
    const { urls } = c.req.valid("json")
    const result = await warmCache(urls, c.env)
    return c.json(
      createWarmingResponse(result.warmed, urls.length, result.errors),
    )
  } catch (error) {
    console.error("Cache warming error:", error)
    const message = error instanceof Error ? error.message : "Unknown error"
    throw new HTTPException(HTTP_STATUS.INTERNAL_SERVER_ERROR, {
      message: `Cache warming failed: ${message}`,
    })
  }
})

cache.get("/__cache/stats", (c) => {
  const config = getCacheConfig(c.env)
  return c.json(createConfigResponse(config))
})

cache.get("/__cache/health", async (c) => {
  const config = getCacheConfig(c.env)

  if (!config.enabled) {
    return c.json({
      status: "disabled",
      message: "Cache is disabled",
      timestamp: new Date().toISOString(),
    })
  }

  const healthResult = await performCacheHealthTest()
  const statusCode =
    healthResult.status === "unhealthy" ? HTTP_STATUS.SERVICE_UNAVAILABLE : 200

  return c.json(
    {
      ...healthResult,
      timestamp: new Date().toISOString(),
    },
    statusCode,
  )
})

export default cache
