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
  const parseNumericEnvVar = (
    value: number | string | undefined,
    defaultValue: number,
  ): number => {
    if (value === undefined || value === null) {
      return defaultValue
    }
    if (typeof value === "number") {
      return value
    }
    const parsedValue = Number.parseInt(value, 10)
    return Number.isNaN(parsedValue) ? defaultValue : parsedValue
  }

  return {
    enabled: getBooleanEnv(env.CACHE_ENABLED, true), // Default to true
    ttlSeconds: parseNumericEnvVar(env.CACHE_TTL_SECONDS, 3600), // Default 1 hour
    overrideS3Headers: getBooleanEnv(env.CACHE_OVERRIDE_S3_HEADERS, false), // Default to false
    minTtlSeconds: parseNumericEnvVar(env.CACHE_MIN_TTL_SECONDS, 60), // Default 1 minute
    maxTtlSeconds: parseNumericEnvVar(env.CACHE_MAX_TTL_SECONDS, 86400), // Default 24 hours
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

  const excludedParams = [...signatureParams, ...cacheBustingParams]

  for (const paramName of excludedParams) {
    urlObj.searchParams.delete(paramName)
  }

  // Sort remaining parameters for consistent cache keys
  urlObj.searchParams.sort()

  // Include relevant headers that affect content delivery in cache key
  const relevantHeaderNames = ["range", "accept-encoding"]
  const headerParts: string[] = []

  for (const headerName of relevantHeaderNames) {
    const headerValue = headers.get(headerName)
    if (headerValue) {
      headerParts.push(`${headerName}:${headerValue}`)
    }
  }

  // Create cache URL with fixed scheme and host to ensure valid URL
  const cacheUrl = new URL("https://cache.internal")
  cacheUrl.pathname = urlObj.pathname

  // Copy cleaned search parameters
  for (const [name, value] of urlObj.searchParams) {
    cacheUrl.searchParams.set(name, value)
  }

  // Add headers as query parameter if present
  const hasRelevantHeaders = headerParts.length > 0
  if (hasRelevantHeaders) {
    const combinedHeaders = headerParts.join("|")
    cacheUrl.searchParams.set("_cache_headers", combinedHeaders)
  }

  // Add version as query parameter if provided
  if (version) {
    cacheUrl.searchParams.set("_cache_version", version)
  }

  return cacheUrl.toString()
}

/**
 * Calculate TTL from response headers, respecting cache config constraints
 */
export function calculateTtl(response: Response, config: CacheConfig): number {
  if (config.overrideS3Headers) {
    const configuredTtl = config.ttlSeconds
    const constrainedTtl = Math.max(
      config.minTtlSeconds,
      Math.min(config.maxTtlSeconds, configuredTtl),
    )
    return constrainedTtl
  }

  const cacheControlValue = response.headers.get("cache-control")
  if (cacheControlValue) {
    const maxAgeMatch = cacheControlValue.match(/max-age=(\d+)/)
    if (maxAgeMatch?.[1]) {
      const s3DefinedTtl = Number.parseInt(maxAgeMatch[1], 10)
      const constrainedS3Ttl = Math.max(
        config.minTtlSeconds,
        Math.min(config.maxTtlSeconds, s3DefinedTtl),
      )
      return constrainedS3Ttl
    }
  }

  const expiresValue = response.headers.get("expires")
  if (expiresValue) {
    const expiryTime = new Date(expiresValue).getTime()
    const currentTime = Date.now()
    const isFutureExpiry = expiryTime > currentTime

    if (isFutureExpiry) {
      const secondsUntilExpiry = Math.floor((expiryTime - currentTime) / 1000)
      const constrainedExpiryTtl = Math.max(
        config.minTtlSeconds,
        Math.min(config.maxTtlSeconds, secondsUntilExpiry),
      )
      return constrainedExpiryTtl
    }
  }

  // Fallback to configured TTL with constraints
  const fallbackTtl = Math.max(
    config.minTtlSeconds,
    Math.min(config.maxTtlSeconds, config.ttlSeconds),
  )
  return fallbackTtl
}

/**
 * Check if response can be cached
 */
export function isCacheable(response: Response, method: HttpMethod): boolean {
  // Don't cache non-GET requests or error responses
  const isGetRequest = method === HttpMethod.GET
  const isSuccessResponse = response.ok

  if (!isGetRequest || !isSuccessResponse) {
    return false
  }

  // Don't cache partial content responses (206) or responses with Vary: *
  const isPartialContent = response.status === 206
  const hasWildcardVary = response.headers.get("vary") === "*"

  if (isPartialContent || hasWildcardVary) {
    return false
  }

  // Don't cache if response has no-cache directive
  const cacheControlValue = response.headers.get("cache-control")
  const hasNoCacheDirective =
    cacheControlValue?.includes("no-cache") ||
    cacheControlValue?.includes("no-store")

  return !hasNoCacheDirective
}

/**
 * Enhanced conditional request handling
 */
export function createConditionalResponse(
  request: Request,
  cachedResponse: Response,
): Response | null {
  const clientEtag = request.headers.get("if-none-match")
  const clientModifiedSince = request.headers.get("if-modified-since")

  // Handle ETag-based conditional requests
  if (clientEtag) {
    const serverEtag = cachedResponse.headers.get("etag")
    const isEtagMatch =
      serverEtag && (clientEtag === "*" || clientEtag.includes(serverEtag))

    if (isEtagMatch) {
      return new Response(null, {
        status: 304,
        headers: {
          etag: serverEtag,
          "cache-control": cachedResponse.headers.get("cache-control") || "",
          "last-modified": cachedResponse.headers.get("last-modified") || "",
        },
      })
    }
  }

  // Handle Last-Modified-based conditional requests
  const shouldCheckModifiedSince = clientModifiedSince && !clientEtag
  if (shouldCheckModifiedSince) {
    const serverLastModified = cachedResponse.headers.get("last-modified")

    if (serverLastModified) {
      const clientTime = new Date(clientModifiedSince).getTime()
      const serverTime = new Date(serverLastModified).getTime()
      const isNotModified = serverTime <= clientTime

      if (isNotModified) {
        return new Response(null, {
          status: 304,
          headers: {
            "last-modified": serverLastModified,
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
  originalRequest: Request | undefined,
  config: CacheConfig,
  cacheKey: string,
): Promise<{ response: Response; cacheResult: CacheResult } | null> {
  try {
    const cachedResponse = await cache.match(cacheRequest)
    if (!cachedResponse) return null

    // Handle conditional requests if original request is provided
    if (originalRequest) {
      const conditionalResponse = createConditionalResponse(
        originalRequest,
        cachedResponse,
      )
      if (conditionalResponse) {
        return {
          response: conditionalResponse,
          cacheResult: { hit: true, source: "cache", key: cacheKey },
        }
      }
    }

    if (config.debug) {
      console.log("Cache hit from Cache API")
    }

    // Clone the response and add cache debug headers - use clone() to avoid body consumption issues
    const clonedResponse = cachedResponse.clone()
    if (config.debug) {
      clonedResponse.headers.set(
        "X-Cache-Debug",
        JSON.stringify({
          hit: true,
          source: "cache-api",
          key: cacheKey,
        }),
      )
    }

    return {
      response: clonedResponse,
      cacheResult: { hit: true, source: "cache", key: cacheKey },
    }
  } catch (cacheError) {
    console.warn("Cache API error:", cacheError)
    return null
  }
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
  const shouldSkipStorage =
    !response.ok || !isCacheable(response, method) || isEdgeHit

  if (shouldSkipStorage) {
    return
  }

  try {
    const calculatedTtl = calculateTtl(response, config)
    // Clone the response to avoid body consumption issues
    const responseClone = response.clone()

    // Add cache headers - create new response with modified headers to make them mutable
    const responseWithCacheHeaders = new Response(responseClone.body, {
      status: responseClone.status,
      statusText: responseClone.statusText,
      headers: new Headers(responseClone.headers),
    })
    responseWithCacheHeaders.headers.set(
      "Cache-Control",
      `max-age=${calculatedTtl}`,
    )
    responseWithCacheHeaders.headers.set(
      "X-Cache-Stored",
      new Date().toISOString(),
    )

    // Store in Cache API (fire and forget)
    cache.put(cacheRequest, responseWithCacheHeaders).catch((putError) => {
      console.warn("Failed to store in Cache API:", putError)
    })
  } catch (storeError) {
    console.warn("Cache storage error:", storeError)
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
 * Handles the case when caching is disabled
 */
async function handleCachingDisabled(
  signer: AwsClient,
  url: string,
  method: HttpMethod,
  headers: Headers,
  attempts: number,
  cacheKey: string,
): Promise<{ response: Response; cacheResult: CacheResult }> {
  const { s3Fetch } = await import("./aws-client.js")
  const response = await s3Fetch(signer, url, method, headers, attempts)
  return {
    response,
    cacheResult: { hit: false, source: "s3", key: cacheKey },
  }
}

/**
 * Creates cache result object with optional debug response
 */
function createCacheResult(
  response: Response,
  isEdgeHit: boolean,
  cacheKey: string,
  config: CacheConfig,
): { response: Response; cacheResult: CacheResult } {
  const finalCacheResult: CacheResult = {
    hit: isEdgeHit,
    source: isEdgeHit ? "cache" : "s3",
    key: cacheKey,
    ttl: isEdgeHit ? undefined : calculateTtl(response, config),
  }

  if (config.debug) {
    console.log("Cache result:", finalCacheResult)
    console.log(`CF-Cache-Status: ${response.headers.get("cf-cache-status")}`)
  }

  // Clone response and add debug headers - avoid body consumption issues
  const clonedResponse = response.clone()
  if (config.debug) {
    // Create new response with mutable headers for debug info
    const responseWithDebug = new Response(clonedResponse.body, {
      status: clonedResponse.status,
      statusText: clonedResponse.statusText,
      headers: new Headers(clonedResponse.headers),
    })
    responseWithDebug.headers.set(
      "X-Cache-Debug",
      JSON.stringify(finalCacheResult),
    )
    return { response: responseWithDebug, cacheResult: finalCacheResult }
  }

  return { response: clonedResponse, cacheResult: finalCacheResult }
}

/**
 * Performs the main fetch and cache operation loop
 */
async function performFetchWithRetry(
  signer: AwsClient,
  url: string,
  method: HttpMethod,
  headers: Headers,
  attempts: number,
  config: CacheConfig,
  cacheKey: string,
  cache: Cache,
  cacheRequest: Request,
): Promise<{ response: Response; cacheResult: CacheResult }> {
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
      const isEdgeHit = cfCacheStatus === "HIT"

      // Store in Cache API if applicable
      await storeInCacheApi(res, method, cache, cacheRequest, config, isEdgeHit)

      return createCacheResult(res, isEdgeHit, cacheKey, config)
    } catch (e) {
      lastErr = e
      const backoff = 200 * 2 ** attempt + Math.random() * 100
      await new Promise((r) => setTimeout(r, backoff))
      attempt++
    }
  }

  throw new Error(`Failed after ${attempts} attempts: ${String(lastErr)}`)
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
    return handleCachingDisabled(
      signer,
      url,
      method,
      headers,
      attempts,
      cacheKey,
    )
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
  return performFetchWithRetry(
    signer,
    url,
    method,
    headers,
    attempts,
    config,
    cacheKey,
    cache,
    cacheRequest,
  )
}

/**
 * Purge cache entries by pattern or specific key
 * Note: pattern must be a valid URL (cache key) when using string pattern
 */
export async function purgeCache(
  pattern: string | RegExp,
): Promise<{ purged: number; errors: string[] }> {
  const cache = caches.default
  const errors: string[] = []
  let purged = 0

  try {
    if (typeof pattern === "string") {
      // Purge specific key - pattern must be a valid URL cache key
      // If it's not a valid URL, attempt to create one for backwards compatibility
      let cacheKey = pattern
      try {
        new URL(pattern) // Validate it's a valid URL
      } catch {
        // If not a valid URL, try to construct one
        if (pattern.startsWith("/")) {
          cacheKey = `https://cache.internal${pattern}`
        } else {
          cacheKey = `https://cache.internal/${pattern}`
        }
      }

      const deleted = await cache.delete(cacheKey)
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
