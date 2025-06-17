import { Hono } from "hono"
import type { Context } from "hono"
import { HTTPException } from "hono/http-exception"
import { getAwsClient, getS3BaseUrl } from "../lib/aws-client.js"
import { cachedS3Fetch, getCacheConfig } from "../lib/cache.js"
import { shouldEnforceUrlSigning, verifySignature } from "../lib/security.js"
import { parseInteger, sanitizeDownloadFilename } from "../lib/utils.js"
import { ensureEnvironmentValidated } from "../lib/validation.js"

import { HttpMethod } from "../types/s3.js"
import { filenameValidator } from "../validators/filename.js"

// ─────────────────────────────────────── Constants ───────────────────────────────────────
const HTTP_STATUS = {
  NOT_IMPLEMENTED: 501,
  BAD_GATEWAY: 502,
} as const

const CONDITIONAL_HEADERS = {
  IF_NONE_MATCH: "if-none-match",
  IF_MODIFIED_SINCE: "if-modified-since",
  RANGE: "range",
} as const

// ─────────────────────────────────────── Auth Helper Functions ───────────────────────────────────────
async function enforceUrlSigning(
  env: Env,
  pathname: string,
  requestUrl: string,
): Promise<void> {
  if (!shouldEnforceUrlSigning(env, pathname)) return

  if (!env.URL_SIGNING_SECRET) {
    throw new HTTPException(HTTP_STATUS.NOT_IMPLEMENTED, {
      message: "URL signing is required but not configured",
    })
  }

  await verifySignature(new URL(requestUrl), env.URL_SIGNING_SECRET)
}

// ─────────────────────────────────────── Header Helper Functions ───────────────────────────────────────
function extractConditionalHeaders(headers: Headers) {
  return {
    ifNoneMatch: headers.get(CONDITIONAL_HEADERS.IF_NONE_MATCH),
    ifModifiedSince: headers.get(CONDITIONAL_HEADERS.IF_MODIFIED_SINCE),
    range: headers.get(CONDITIONAL_HEADERS.RANGE),
  }
}

function buildRequestHeaders(c: Context<{ Bindings: Env }>): Headers {
  const headers = new Headers()
  const { ifNoneMatch, ifModifiedSince, range } = extractConditionalHeaders(
    c.req.raw.headers,
  )

  if (range) headers.set("Range", range)
  if (ifNoneMatch) headers.set("If-None-Match", ifNoneMatch)
  if (ifModifiedSince) headers.set("If-Modified-Since", ifModifiedSince)

  return headers
}

function determineContentDisposition(
  c: Context<{ Bindings: Env }>,
  filename: string,
): string | null {
  const downloadParam = c.req.query("download")
  const inlineParam = c.req.query("inline")

  // Validate query parameters
  if (downloadParam !== undefined && typeof downloadParam !== "string") {
    return null
  }
  if (inlineParam !== undefined && typeof inlineParam !== "string") {
    return null
  }

  if (downloadParam !== undefined) {
    const defaultName = filename.split("/").pop() || "download"
    const requestedName = downloadParam || defaultName
    const sanitizedName = sanitizeDownloadFilename(requestedName, defaultName)
    // Additional escaping to prevent header injection
    const escapedName = sanitizedName.replace(/["\\\r\n]/g, "_")
    return `attachment; filename="${escapedName}"`
  }

  if (inlineParam !== undefined) {
    return "inline"
  }

  return null
}

function addContentDisposition(
  headers: Headers,
  disposition: string | null,
): void {
  if (disposition) {
    headers.set("Content-Disposition", disposition)
  }
}

// ─────────────────────────────────────── Debug Helper Functions ───────────────────────────────────────
function logConditionalRequest(
  config: ReturnType<typeof getCacheConfig>,
  conditionalHeaders: ReturnType<typeof extractConditionalHeaders>,
): void {
  if (!config.debug) return

  const { ifNoneMatch, ifModifiedSince } = conditionalHeaders
  const logEntries = []

  if (ifNoneMatch) logEntries.push(`If-None-Match: ${ifNoneMatch}`)
  if (ifModifiedSince) logEntries.push(`If-Modified-Since: ${ifModifiedSince}`)

  if (logEntries.length > 0) {
    console.log(
      `Processing conditional request with headers: ${logEntries.join(", ")}`,
    )
  }
}

function addDebugHeaders(
  response: Response,
  config: ReturnType<typeof getCacheConfig>,
  cacheResult: Awaited<ReturnType<typeof cachedS3Fetch>>["cacheResult"],
): void {
  if (config.debug && cacheResult) {
    response.headers.set("X-Cache-Debug", JSON.stringify(cacheResult))
  }
}

function addVersionHeader(response: Response, version?: string): void {
  response.headers.set("X-Proxy-Version", version || "dev")
}

// ─────────────────────────────────────── Response Helper Functions ───────────────────────────────────────
function shouldEnhanceResponse(
  config: ReturnType<typeof getCacheConfig>,
  cacheResult: Awaited<ReturnType<typeof cachedS3Fetch>>["cacheResult"],
): boolean {
  return config.debug || !!cacheResult
}

function createEnhancedResponse(
  originalResponse: Response,
  config: ReturnType<typeof getCacheConfig>,
  cacheResult: Awaited<ReturnType<typeof cachedS3Fetch>>["cacheResult"],
  version?: string,
): Response {
  const enhancedResponse = new Response(originalResponse.body, {
    status: originalResponse.status,
    statusText: originalResponse.statusText,
    headers: new Headers(originalResponse.headers),
  })

  addDebugHeaders(enhancedResponse, config, cacheResult)
  addVersionHeader(enhancedResponse, version)

  return enhancedResponse
}

function enhanceResponseIfNeeded(
  response: Response,
  config: ReturnType<typeof getCacheConfig>,
  cacheResult: Awaited<ReturnType<typeof cachedS3Fetch>>["cacheResult"],
  version?: string,
): Response {
  if (!shouldEnhanceResponse(config, cacheResult)) {
    return response
  }

  return createEnhancedResponse(response, config, cacheResult, version)
}

// ─────────────────────────────────────── Error Helper Functions ───────────────────────────────────────
function handleFileError(error: unknown, filename: string): never {
  console.error(`File retrieval error for ${filename}:`, error)

  if (error instanceof HTTPException) {
    throw error
  }

  const message = error instanceof Error ? error.message : "Unknown error"
  throw new HTTPException(HTTP_STATUS.BAD_GATEWAY, {
    message: `Failed to retrieve file: ${message}`,
  })
}

// ─────────────────────────────────────── Core File Functions ───────────────────────────────────────
async function processFileRequest(
  c: Context<{ Bindings: Env }>,
  filename: string,
  method: HttpMethod,
): Promise<Response> {
  const signer = getAwsClient(c.env)
  const url = `${getS3BaseUrl(c.env)}/${filename}`
  const config = getCacheConfig(c.env)

  // Build request headers
  const headers = buildRequestHeaders(c)
  const conditionalHeaders = extractConditionalHeaders(c.req.raw.headers)

  // Handle content disposition for GET requests
  if (method === HttpMethod.GET) {
    const disposition = determineContentDisposition(c, filename)
    addContentDisposition(headers, disposition)
  }

  // Debug logging
  logConditionalRequest(config, conditionalHeaders)

  // Execute S3 request
  const retryAttempts = parseInteger(
    c.env.RANGE_RETRY_ATTEMPTS,
    "RANGE_RETRY_ATTEMPTS",
  )
  const { response, cacheResult } = await cachedS3Fetch(
    signer,
    url,
    method,
    headers,
    retryAttempts,
    c.env,
    c.req.raw,
  )

  // Enhance response if needed
  return enhanceResponseIfNeeded(response, config, cacheResult, c.env.VERSION)
}

// ─────────────────────────────────────── Router Instance ───────────────────────────────────────
const files = new Hono<{ Bindings: Env }>()

// ─────────────────────────────────────── Route Handlers ───────────────────────────────────────
files.get("/:filename{.*}", filenameValidator, async (c) => {
  ensureEnvironmentValidated(c.env)

  const validatedData = c.req.valid("param") as { filename: string }
  const filename = validatedData.filename

  await enforceUrlSigning(c.env, `/${filename}`, c.req.url)

  try {
    // Validate method
    const method = c.req.raw.method
    if (method !== HttpMethod.GET) {
      throw new HTTPException(405, { message: "Method not allowed" })
    }
    return await processFileRequest(c, filename, method)
  } catch (error) {
    handleFileError(error, filename)
  }
})

files.on("HEAD", "/:filename{.*}", filenameValidator, async (c) => {
  ensureEnvironmentValidated(c.env)

  const validatedData = c.req.valid("param") as { filename: string }
  const filename = validatedData.filename

  await enforceUrlSigning(c.env, `/${filename}`, c.req.url)

  try {
    return await processFileRequest(c, filename, HttpMethod.HEAD)
  } catch (error) {
    handleFileError(error, filename)
  }
})

export default files
