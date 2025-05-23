import { Hono } from "hono"
import { HTTPException } from "hono/http-exception"
import { getAwsClient, getS3BaseUrl } from "../lib/aws-client.js"
import { cachedS3Fetch, getCacheConfig } from "../lib/cache.js"
import { shouldEnforceUrlSigning, verifySignature } from "../lib/security.js"
import { int, sanitizeDownloadFilename } from "../lib/utils.js"
import { ensureEnvironmentValidated } from "../lib/validation.js"

import { HttpMethod } from "../types/s3.js"
import { filenameValidator } from "../validators/filename.js"

const files = new Hono<{ Bindings: Env }>()

// Enhanced handler for GET requests with better Hono features
files.get("/:filename{.*}", filenameValidator, async (c) => {
  // Ensure environment is validated (fail-fast behavior)
  ensureEnvironmentValidated(c.env)

  globalThis.__app_metrics.totalRequests++

  const validatedData = c.req.valid("param") as { filename: string }
  const filename = validatedData.filename

  // Security: Enhanced URL signing enforcement
  const pathname = `/${filename}`
  if (shouldEnforceUrlSigning(c.env, pathname) || c.env.URL_SIGNING_SECRET) {
    if (!c.env.URL_SIGNING_SECRET) {
      throw new HTTPException(501, {
        message: "URL signing is required but not configured",
      })
    }
    await verifySignature(new URL(c.req.url), c.env.URL_SIGNING_SECRET)
  }

  const method = c.req.raw.method as HttpMethod
  const signer = getAwsClient(c.env)
  const url = `${getS3BaseUrl(c.env)}/${filename}`
  const rangeHeader = c.req.header("range")
  const headers = new Headers()

  // Enhanced header handling
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

  // Debug logging for conditional requests
  const config = getCacheConfig(c.env)
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

  // Handle download disposition for GET requests
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

    // Enhanced response headers
    if (config.debug && cacheResult) {
      response.headers.set("X-Cache-Debug", JSON.stringify(cacheResult))
    }

    // Add custom headers for debugging
    response.headers.set("X-Proxy-Version", c.env.VERSION || "dev")

    return response
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
