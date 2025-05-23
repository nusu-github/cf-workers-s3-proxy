import { Hono } from "hono"
import type { Context } from "hono"
import { HTTPException } from "hono/http-exception"
import { getAwsClient, getS3BaseUrl } from "../lib/aws-client.js"
import { cachedS3Fetch, getCacheConfig } from "../lib/cache.js"
import { shouldEnforceUrlSigning, verifySignature } from "../lib/security.js"
import { int, sanitizeDownloadFilename } from "../lib/utils.js"
import { ensureEnvironmentValidated } from "../lib/validation.js"

import { HttpMethod } from "../types/s3.js"
import { filenameValidator } from "../validators/filename.js"

const files = new Hono<{ Bindings: Env }>()

/**
 * Validates URL signing for file access
 */
function validateFileAccess(
  env: Env,
  pathname: string,
  requestUrl: string,
): Promise<void> {
  if (shouldEnforceUrlSigning(env, pathname)) {
    if (!env.URL_SIGNING_SECRET) {
      throw new HTTPException(501, {
        message: "URL signing is required but not configured",
      })
    }
    return verifySignature(new URL(requestUrl), env.URL_SIGNING_SECRET)
  }
  return Promise.resolve()
}

/**
 * Builds request headers for S3 fetch
 */
function buildRequestHeaders(c: Context<{ Bindings: Env }>): Headers {
  const headers = new Headers()

  // Enhanced header handling
  const rangeHeader = c.req.header("range")
  if (rangeHeader) {
    headers.set("Range", rangeHeader)
  }

  // Forward conditional headers for cache efficiency and reduced data transfer
  const ifNoneMatch = c.req.header("if-none-match")
  const ifModifiedSince = c.req.header("if-modified-since")
  if (ifNoneMatch) {
    headers.set("If-None-Match", ifNoneMatch)
  }
  if (ifModifiedSince) {
    headers.set("If-Modified-Since", ifModifiedSince)
  }

  return headers
}

/**
 * Handles download disposition headers
 */
function handleDownloadDisposition(
  c: Context<{ Bindings: Env }>,
  method: HttpMethod,
  filename: string,
  headers: Headers,
): void {
  if (method === HttpMethod.GET) {
    if (c.req.query("download") !== undefined) {
      const defaultName = filename.split("/").pop() || "download"
      const dlName = c.req.query("download") || defaultName
      const sanitizedName = sanitizeDownloadFilename(dlName, defaultName)
      headers.set(
        "Content-Disposition",
        `attachment; filename="${sanitizedName}"`,
      )
    } else if (c.req.query("inline") !== undefined) {
      headers.set("Content-Disposition", "inline")
    }
  }
}

/**
 * Logs conditional request headers for debugging
 */
function logConditionalHeaders(
  config: ReturnType<typeof getCacheConfig>,
  ifNoneMatch: string | undefined,
  ifModifiedSince: string | undefined,
): void {
  if (config.debug) {
    const conditionalHeaders = []
    if (ifNoneMatch) conditionalHeaders.push(`If-None-Match: ${ifNoneMatch}`)
    if (ifModifiedSince)
      conditionalHeaders.push(`If-Modified-Since: ${ifModifiedSince}`)
    if (conditionalHeaders.length > 0) {
      console.log(
        `Processing conditional request with headers: ${conditionalHeaders.join(", ")}`,
      )
    }
  }
}

/**
 * Enhances response with debug headers
 */
function enhanceResponse(
  response: Response,
  config: ReturnType<typeof getCacheConfig>,
  cacheResult: Awaited<ReturnType<typeof cachedS3Fetch>>["cacheResult"],
  version: string | undefined,
): Response {
  // Check if we need to add any headers
  const needsDebugHeader = config.debug && cacheResult
  const needsVersionHeader = true // Always add version header

  if (needsDebugHeader || needsVersionHeader) {
    // Create new response with mutable headers to avoid immutable header errors
    const enhancedResponse = new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: new Headers(response.headers),
    })

    // Add headers to the new mutable response
    if (needsDebugHeader) {
      enhancedResponse.headers.set("X-Cache-Debug", JSON.stringify(cacheResult))
    }
    if (needsVersionHeader) {
      enhancedResponse.headers.set("X-Proxy-Version", version || "dev")
    }

    return enhancedResponse
  }

  return response
}

// Enhanced handler for GET requests with better Hono features
files.get("/:filename{.*}", filenameValidator, async (c) => {
  // Ensure environment is validated (fail-fast behavior)
  ensureEnvironmentValidated(c.env)

  globalThis.__app_metrics.totalRequests++

  const validatedData = c.req.valid("param") as { filename: string }
  const filename = validatedData.filename

  // Security: Enhanced URL signing enforcement
  const pathname = `/${filename}`
  await validateFileAccess(c.env, pathname, c.req.url)

  const method = c.req.raw.method as HttpMethod
  const signer = getAwsClient(c.env)
  const url = `${getS3BaseUrl(c.env)}/${filename}`

  // Build request headers
  const headers = buildRequestHeaders(c)

  // Handle download disposition
  handleDownloadDisposition(c, method, filename, headers)

  // Debug logging for conditional requests
  const config = getCacheConfig(c.env)
  const ifNoneMatch = c.req.header("if-none-match")
  const ifModifiedSince = c.req.header("if-modified-since")
  logConditionalHeaders(config, ifNoneMatch, ifModifiedSince)

  try {
    const { response, cacheResult } = await cachedS3Fetch(
      signer,
      url,
      method,
      headers,
      int(c.env.RANGE_RETRY_ATTEMPTS, "RANGE_RETRY_ATTEMPTS"),
      c.env,
      c.req.raw,
    )

    return enhanceResponse(response, config, cacheResult, c.env.VERSION)
  } catch (error) {
    console.error(`File retrieval error for ${filename}:`, error)

    if (error instanceof HTTPException) {
      throw error
    }

    throw new HTTPException(502, {
      message: `Failed to retrieve file: ${error instanceof Error ? error.message : "Unknown error"}`,
    })
  }
})

// HEAD request handler for file metadata
files.on("HEAD", "/:filename{.*}", filenameValidator, async (c) => {
  // Use the same logic as GET but with HEAD method
  return files.fetch(
    new Request(c.req.url, { method: "GET", headers: c.req.raw.headers }),
    c.env,
  )
})

export default files
