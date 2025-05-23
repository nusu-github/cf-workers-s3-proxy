import type { AwsClient } from "aws4fetch"
import type { CacheConfig, CacheResult, CfProperties } from "../types/cache.js"
import { HttpMethod } from "../types/s3.js"
import { getBooleanEnv } from "./utils.js"

/**
 * Parse cache configuration from environment variables
 * Handles both JSON types (from wrangler.jsonc vars) and string types (from secrets, .dev.vars)
 */
export function getCacheConfig(env: Env): CacheConfig {
  // Helper function to handle numeric environment variables
  const getNumber = (
    value: number | string | undefined,
    defaultValue: number,
  ): number => {
    if (value === undefined || value === null) {
      return defaultValue
    }
    if (typeof value === "number") {
      return value
    }
    const parsed = Number.parseInt(value, 10)
    return Number.isNaN(parsed) ? defaultValue : parsed
  }

  return {
    enabled: getBooleanEnv(env.CACHE_ENABLED, true), // Default to true
    ttlSeconds: getNumber(env.CACHE_TTL_SECONDS, 3600), // Default 1 hour
    overrideS3Headers: getBooleanEnv(env.CACHE_OVERRIDE_S3_HEADERS, false), // Default to false
    minTtlSeconds: getNumber(env.CACHE_MIN_TTL_SECONDS, 60), // Default 1 minute
    maxTtlSeconds: getNumber(env.CACHE_MAX_TTL_SECONDS, 86400), // Default 24 hours
    debug: getBooleanEnv(env.CACHE_DEBUG, false), // Default to false
  }
}

/**
 * Enhanced cache key generation with support for cache versioning
 *
 * CRITICAL SECURITY REQUIREMENT: Signature parameters ('sig', 'exp') MUST be excluded
 * from cache keys to ensure:
 * 1. Responses to signed and unsigned requests are cached separately
 * 2. Different signatures for the same content don't create unnecessary cache misses
 * 3. Expired signatures don't serve cached content inappropriately
 * 4. Cache poisoning attacks via signature manipulation are prevented
 */
export function generateCacheKey(
  url: string,
  headers: Headers,
  version?: string,
): string {
  const urlObj = new URL(url)

  // SECURITY: Remove signature and authentication-related parameters
  // These must NEVER be part of the cache key for security reasons
  const signatureParams = ["sig", "exp"] // URL signature parameters

  // Remove additional cache-busting parameters that shouldn't affect caching
  const cacheBustingParams = ["_", "bust", "nocache", "v", "version"]

  const paramsToExclude = [...signatureParams, ...cacheBustingParams]

  for (const param of paramsToExclude) {
    urlObj.searchParams.delete(param)
  }

  // Sort remaining parameters for consistent cache keys
  urlObj.searchParams.sort()

  // Include relevant headers that affect content delivery in cache key
  const relevantHeaders = ["range", "accept-encoding"]
  const headerParts: string[] = []
  for (const header of relevantHeaders) {
    const value = headers.get(header)
    if (value) {
      headerParts.push(`${header}:${value}`)
    }
  }

  const baseKey = `${urlObj.pathname}${urlObj.search}`
  let cacheKey =
    headerParts.length > 0 ? `${baseKey}|${headerParts.join("|")}` : baseKey

  // Add cache version if provided
  if (version) {
    cacheKey = `v${version}:${cacheKey}`
  }

  return cacheKey
}

/**
 * Calculate TTL from response headers, respecting cache config constraints
 */
export function calculateTtl(response: Response, config: CacheConfig): number {
  if (config.overrideS3Headers) {
    return Math.max(
      config.minTtlSeconds,
      Math.min(config.maxTtlSeconds, config.ttlSeconds),
    )
  }

  const cacheControl = response.headers.get("cache-control")
  if (cacheControl) {
    const maxAgeMatch = cacheControl.match(/max-age=(\d+)/)
    if (maxAgeMatch?.[1]) {
      const s3Ttl = Number.parseInt(maxAgeMatch[1], 10)
      return Math.max(
        config.minTtlSeconds,
        Math.min(config.maxTtlSeconds, s3Ttl),
      )
    }
  }

  const expires = response.headers.get("expires")
  if (expires) {
    const expiryTime = new Date(expires).getTime()
    const now = Date.now()
    if (expiryTime > now) {
      const s3Ttl = Math.floor((expiryTime - now) / 1000)
      return Math.max(
        config.minTtlSeconds,
        Math.min(config.maxTtlSeconds, s3Ttl),
      )
    }
  }

  // Fallback to configured TTL with constraints
  return Math.max(
    config.minTtlSeconds,
    Math.min(config.maxTtlSeconds, config.ttlSeconds),
  )
}

/**
 * Check if response can be cached
 */
export function canCache(response: Response, method: HttpMethod): boolean {
  // Don't cache non-GET requests or error responses
  if (method !== HttpMethod.GET || !response.ok) {
    return false
  }

  // Don't cache partial content responses (206) or responses with Vary: *
  if (response.status === 206 || response.headers.get("vary") === "*") {
    return false
  }

  // Don't cache if response has no-cache directive
  const cacheControl = response.headers.get("cache-control")
  return !(
    cacheControl?.includes("no-cache") || cacheControl?.includes("no-store")
  )
}

/**
 * Enhanced conditional request handling
 */
export function handleConditionalRequest(
  request: Request,
  cachedResponse: Response,
): Response | null {
  const ifNoneMatch = request.headers.get("if-none-match")
  const ifModifiedSince = request.headers.get("if-modified-since")

  // Handle ETag-based conditional requests
  if (ifNoneMatch) {
    const etag = cachedResponse.headers.get("etag")
    if (etag && (ifNoneMatch === "*" || ifNoneMatch.includes(etag))) {
      return new Response(null, {
        status: 304,
        headers: {
          etag: etag,
          "cache-control": cachedResponse.headers.get("cache-control") || "",
          "last-modified": cachedResponse.headers.get("last-modified") || "",
        },
      })
    }
  }

  // Handle Last-Modified-based conditional requests
  if (ifModifiedSince && !ifNoneMatch) {
    const lastModified = cachedResponse.headers.get("last-modified")
    if (lastModified) {
      const ifModifiedSinceTime = new Date(ifModifiedSince).getTime()
      const lastModifiedTime = new Date(lastModified).getTime()
      if (lastModifiedTime <= ifModifiedSinceTime) {
        return new Response(null, {
          status: 304,
          headers: {
            "last-modified": lastModified,
            "cache-control": cachedResponse.headers.get("cache-control") || "",
          },
        })
      }
    }
  }

  return null
}

/**
 * Handles cache API operations and conditional requests
 */
async function handleCacheApiRequest(
  cache: Cache,
  cacheRequest: Request,
  request: Request | undefined,
  config: CacheConfig,
  cacheKey: string,
): Promise<{ response: Response; cacheResult: CacheResult } | null> {
  try {
    const cachedResponse = await cache.match(cacheRequest)
    if (!cachedResponse) return null

    // Handle conditional requests if original request is provided
    if (request) {
      const conditionalResponse = handleConditionalRequest(
        request,
        cachedResponse,
      )
      if (conditionalResponse) {
        globalThis.__app_metrics.notModifiedResponses++
        return {
          response: conditionalResponse,
          cacheResult: { hit: true, source: "cache", key: cacheKey },
        }
      }
    }

    // Update cache metrics
    globalThis.__app_metrics.cacheHits++
    const contentLength = Number(
      cachedResponse.headers.get("content-length") ?? "0",
    )
    if (contentLength > 0) {
      globalThis.__app_metrics.cacheBytesServed += contentLength
    }

    if (config.debug) {
      console.log("Cache hit from Cache API")
    }

    // Clone the response and add cache debug headers
    const response = cachedResponse.clone()
    if (config.debug) {
      response.headers.set(
        "X-Cache-Debug",
        JSON.stringify({
          hit: true,
          source: "cache-api",
          key: cacheKey,
        }),
      )
    }

    return {
      response,
      cacheResult: { hit: true, source: "cache", key: cacheKey },
    }
  } catch (cacheError) {
    console.warn("Cache API error:", cacheError)
    globalThis.__app_metrics.cacheErrors++
    return null
  }
}

/**
 * Updates metrics based on cache status and response
 */
function updateCacheMetrics(
  cfCacheStatus: string | null,
  contentLength: number,
): boolean {
  const isEdgeHit = cfCacheStatus === "HIT"

  if (isEdgeHit) {
    globalThis.__app_metrics.cacheHits++
    if (contentLength > 0) {
      globalThis.__app_metrics.cacheBytesServed += contentLength
    }
  } else {
    globalThis.__app_metrics.cacheMisses++
  }

  // Update general metrics
  if (contentLength > 0) {
    globalThis.__app_metrics.bytesSent += contentLength
  }

  return isEdgeHit
}

/**
 * Stores response in Cache API if applicable
 */
async function storeInCacheApi(
  response: Response,
  method: HttpMethod,
  cache: Cache,
  cacheRequest: Request,
  config: CacheConfig,
  isEdgeHit: boolean,
): Promise<void> {
  if (!response.ok || !canCache(response, method) || isEdgeHit) {
    return
  }

  try {
    const ttl = calculateTtl(response, config)
    const cacheResponse = response.clone()

    // Add cache headers
    cacheResponse.headers.set("Cache-Control", `max-age=${ttl}`)
    cacheResponse.headers.set("X-Cache-Stored", new Date().toISOString())

    // Store in Cache API (fire and forget)
    cache.put(cacheRequest, cacheResponse).catch((putError) => {
      console.warn("Failed to store in Cache API:", putError)
      globalThis.__app_metrics.cacheErrors++
    })

    globalThis.__app_metrics.cacheStores++
  } catch (storeError) {
    console.warn("Cache storage error:", storeError)
    globalThis.__app_metrics.cacheErrors++
  }
}

/**
 * Performs a single fetch attempt with proper error handling
 */
async function performFetchAttempt(
  signer: AwsClient,
  url: string,
  method: HttpMethod,
  headers: Headers,
  config: CacheConfig,
  cacheKey: string,
): Promise<Response> {
  const signedRequest = await signer.sign(url, {
    method,
    headers: headers,
  })

  // Use fetch with cf options for edge caching as fallback
  const fetchOptions: RequestInit & { cf?: CfProperties } = {
    method,
    headers: signedRequest.headers,
    cf: {
      // Use custom cache key
      cacheKey: cacheKey,
      // Cache everything for the calculated TTL
      cacheTtl: config.ttlSeconds,
      // Enable caching regardless of response headers
      cacheEverything: true,
    },
  }

  const res = await fetch(signedRequest.url, fetchOptions)

  // Handle range request validation
  if (method === HttpMethod.GET && headers.has("Range")) {
    if (!res.headers.has("content-range")) {
      throw new Error("Missing content-range")
    }
  }

  if (!res.ok && res.status >= 500) {
    throw new Error(`Upstream responded with server error: ${res.status}`)
  }

  return res
}

/**
 * Hybrid cache implementation using both Cache API and edge caching
 */
export async function cachedS3Fetch(
  signer: AwsClient,
  url: string,
  method: HttpMethod,
  headers: Headers,
  attempts: number,
  env: Env,
  request?: Request,
): Promise<{ response: Response; cacheResult: CacheResult }> {
  const config = getCacheConfig(env)
  const cacheKey = generateCacheKey(url, headers, env.VERSION)

  if (config.debug) {
    console.log("Cache config:", config)
    console.log(`Cache key: ${cacheKey}`)
  }

  // If caching is disabled, use original s3Fetch
  if (!config.enabled) {
    const { s3Fetch } = await import("./aws-client.js")
    const response = await s3Fetch(signer, url, method, headers, attempts)
    return {
      response,
      cacheResult: { hit: false, source: "s3", key: cacheKey },
    }
  }

  // Get cache instance
  const cache = caches.default
  const cacheRequest = new Request(cacheKey, { method: "GET" })

  // Try to get from Cache API first
  const cacheResult = await handleCacheApiRequest(
    cache,
    cacheRequest,
    request,
    config,
    cacheKey,
  )

  if (cacheResult) {
    return cacheResult
  }

  // Cache miss - fetch from S3 with hybrid caching
  let attempt = 0
  let lastErr: unknown

  while (attempt < attempts) {
    try {
      const res = await performFetchAttempt(
        signer,
        url,
        method,
        headers,
        config,
        cacheKey,
      )

      // Track cache metrics
      const cfCacheStatus = res.headers.get("cf-cache-status")
      const contentLength = Number(res.headers.get("content-length") ?? "0")
      const isEdgeHit = updateCacheMetrics(cfCacheStatus, contentLength)

      // Store in Cache API if applicable
      await storeInCacheApi(res, method, cache, cacheRequest, config, isEdgeHit)

      const finalCacheResult: CacheResult = {
        hit: isEdgeHit,
        source: isEdgeHit ? "cache" : "s3",
        key: cacheKey,
        ttl: isEdgeHit ? undefined : calculateTtl(res, config),
      }

      if (config.debug) {
        console.log("Cache result:", finalCacheResult)
        console.log(`CF-Cache-Status: ${cfCacheStatus}`)
      }

      // Clone response and add debug headers
      const response = new Response(res.body, res)
      if (config.debug) {
        response.headers.set("X-Cache-Debug", JSON.stringify(finalCacheResult))
      }

      return { response, cacheResult: finalCacheResult }
    } catch (e) {
      lastErr = e
      globalThis.__app_metrics.cacheErrors++
      const backoff = 200 * 2 ** attempt + Math.random() * 100
      await new Promise((r) => setTimeout(r, backoff))
      attempt++
    }
  }

  throw new Error(`Failed after ${attempts} attempts: ${String(lastErr)}`)
}

/**
 * Purge cache entries by pattern or specific key
 */
export async function purgeCache(
  pattern: string | RegExp,
): Promise<{ purged: number; errors: string[] }> {
  const cache = caches.default
  const errors: string[] = []
  let purged = 0

  try {
    if (typeof pattern === "string") {
      // Purge specific key
      const deleted = await cache.delete(pattern)
      if (deleted) {
        purged = 1
      }
    } else {
      // Pattern-based purging is not directly supported by Cache API
      // This would require implementing a custom cache key registry
      errors.push("Pattern-based purging requires custom implementation")
    }
  } catch (error) {
    errors.push(
      `Cache purge error: ${error instanceof Error ? error.message : "Unknown error"}`,
    )
  }

  return { purged, errors }
}

/**
 * Warm cache for frequently accessed content
 */
export async function warmCache(
  urls: string[],
  env: Env,
): Promise<{ warmed: number; errors: string[] }> {
  const config = getCacheConfig(env)
  if (!config.enabled) {
    return { warmed: 0, errors: ["Cache is disabled"] }
  }

  const errors: string[] = []
  let warmed = 0

  for (const url of urls) {
    try {
      // Create a cache warming request
      const response = await fetch(url, {
        cf: {
          cacheEverything: true,
          cacheTtl: config.ttlSeconds,
        },
      })

      if (response.ok) {
        warmed++
      } else {
        errors.push(`Failed to warm ${url}: ${response.status}`)
      }
    } catch (error) {
      errors.push(
        `Cache warming error for ${url}: ${error instanceof Error ? error.message : "Unknown error"}`,
      )
    }
  }

  return { warmed, errors }
}
