import { zValidator } from "@hono/zod-validator"
import { Hono } from "hono"
import type { Context } from "hono"
import { HTTPException } from "hono/http-exception"
import type { ContentfulStatusCode } from "hono/utils/http-status"
import { z } from "zod"
import {
  generatePresignedUrl,
  getAwsClient,
  getS3BaseUrl,
} from "../lib/aws-client.js"
import { shouldEnforceUrlSigning, verifySignature } from "../lib/security.js"
import { ensureEnvironmentValidated } from "../lib/validation.js"
import { HttpMethod } from "../types/s3.js"
import { filenameValidator } from "../validators/filename.js"

// ─────────────────────────────────────── Constants ───────────────────────────────────────
const MULTIPART_PART_LIMITS = {
  MIN_PART_NUMBER: 1,
  MAX_PART_NUMBER: 10000,
} as const

const HTTP_STATUS = {
  BAD_REQUEST: 400,
  NOT_IMPLEMENTED: 501,
  BAD_GATEWAY: 502,
} as const

const HEADER_GROUPS = {
  CONTENT: [
    "content-type",
    "content-md5",
    "content-length",
    "content-encoding",
    "cache-control",
  ],
  SSE: [
    "x-amz-server-side-encryption",
    "x-amz-server-side-encryption-aws-kms-key-id",
    "x-amz-server-side-encryption-context",
    "x-amz-server-side-encryption-customer-algorithm",
    "x-amz-server-side-encryption-customer-key",
    "x-amz-server-side-encryption-customer-key-md5",
  ],
} as const

// ─────────────────────────────────────── Schemas ───────────────────────────────────────
const presignedUploadSchema = z.object({
  key: z.string().min(1, "Key cannot be empty"),
  expiresIn: z.number().int().min(1).max(604800).optional().default(3600),
  conditions: z
    .object({
      contentType: z.string().optional(),
      contentLength: z.number().int().min(0).optional(),
      contentMd5: z.string().optional(),
      metadata: z.record(z.string()).optional(),
    })
    .optional()
    .default({}),
})

// ─────────────────────────────────────── Router Instance ───────────────────────────────────────
const upload = new Hono<{ Bindings: Env }>()

// ─────────────────────────────────────── Helper Functions ───────────────────────────────────────
/**
 * Validates and enforces URL signing authentication
 * Consolidates the authentication logic to eliminate code duplication
 *
 * @param env - Environment configuration
 * @param pathname - Path to validate signing for
 * @param requestUrl - Full request URL for signature verification
 * @throws HTTPException if URL signing is required but not configured or invalid
 */
async function enforceUrlSigning(
  env: Env,
  pathname: string,
  requestUrl: string,
): Promise<void> {
  if (!shouldEnforceUrlSigning(env, pathname)) {
    return // URL signing not required
  }

  if (!env.URL_SIGNING_SECRET) {
    throw new HTTPException(HTTP_STATUS.NOT_IMPLEMENTED, {
      message: "URL signing is required but not configured",
    })
  }

  await verifySignature(new URL(requestUrl), env.URL_SIGNING_SECRET)
}

/**
 * Validates multipart upload part number
 *
 * @param partNumber - Part number as string
 * @returns Validated part number as integer
 * @throws HTTPException if part number is invalid
 */
function validatePartNumber(partNumber: string): number {
  const partNum = Number.parseInt(partNumber, 10)
  const isValidPartNumber =
    !Number.isNaN(partNum) &&
    partNum >= MULTIPART_PART_LIMITS.MIN_PART_NUMBER &&
    partNum <= MULTIPART_PART_LIMITS.MAX_PART_NUMBER

  if (!isValidPartNumber) {
    throw new HTTPException(HTTP_STATUS.BAD_REQUEST, {
      message: `Invalid part number. Must be between ${MULTIPART_PART_LIMITS.MIN_PART_NUMBER} and ${MULTIPART_PART_LIMITS.MAX_PART_NUMBER}`,
    })
  }

  return partNum
}

/**
 * Forwards relevant S3 headers from the incoming request
 * Organized by header groups for better maintainability
 */
function forwardS3Headers(sourceHeaders: Headers): Headers {
  const headers = new Headers()

  // Forward content headers
  for (const headerName of HEADER_GROUPS.CONTENT) {
    const value = sourceHeaders.get(headerName)
    if (value) {
      headers.set(headerName, value)
    }
  }

  // Forward SSE headers
  for (const headerName of HEADER_GROUPS.SSE) {
    const value = sourceHeaders.get(headerName)
    if (value) {
      headers.set(headerName, value)
    }
  }

  // Forward S3 metadata headers (x-amz-meta-*)
  for (const [name, value] of sourceHeaders.entries()) {
    if (name.toLowerCase().startsWith("x-amz-meta-")) {
      headers.set(name, value)
    }
  }

  // Forward S3 checksum headers (x-amz-checksum-*)
  for (const [name, value] of sourceHeaders.entries()) {
    if (name.toLowerCase().startsWith("x-amz-checksum-")) {
      headers.set(name, value)
    }
  }

  return headers
}

/**
 * Handles upload errors consistently with improved error context
 * Enhanced for better debugging and testability
 */
function handleUploadError(error: unknown, context: string): never {
  // Log error for debugging (can be mocked in tests)
  console.error(`${context}:`, error)

  if (error instanceof HTTPException) {
    throw error
  }

  if (error instanceof Error) {
    throw new HTTPException(HTTP_STATUS.BAD_GATEWAY, {
      message: `${context}: ${error.message}`,
    })
  }

  throw new HTTPException(HTTP_STATUS.BAD_GATEWAY, {
    message: `${context}: Unknown error occurred`,
  })
}

/**
 * Enhanced error handling for S3 responses with detailed error information
 */
async function handleS3ResponseError(
  response: Response,
  context: string,
): Promise<void> {
  let errorDetails = ""
  try {
    errorDetails = await response.text()
  } catch (readError) {
    console.error("Failed to read error response:", readError)
  }

  const statusMessage = `${response.status} ${response.statusText}`
  const fullMessage = `${context}: ${statusMessage}${errorDetails ? ` - ${errorDetails}` : ""}`

  throw new HTTPException(response.status as ContentfulStatusCode, {
    message: fullMessage,
  })
}

/**
 * Creates headers for multipart upload part request
 * Extracted for better testability and reusability
 */
function createPartUploadHeaders(
  contentLength: string | undefined,
  contentMd5: string | undefined,
): Headers {
  const headers = new Headers()

  if (contentLength) {
    headers.set("Content-Length", contentLength)
  }

  if (contentMd5) {
    headers.set("Content-MD5", contentMd5)
  }

  return headers
}

/**
 * Creates headers for presigned URL generation
 * Consolidates conditional header logic
 */
function createPresignedUrlHeaders(
  conditions: z.infer<typeof presignedUploadSchema>["conditions"],
): Headers {
  const headers = new Headers()

  if (conditions.contentType) {
    headers.set("Content-Type", conditions.contentType)
  }

  if (conditions.contentLength) {
    headers.set("Content-Length", conditions.contentLength.toString())
  }

  if (conditions.contentMd5) {
    headers.set("Content-MD5", conditions.contentMd5)
  }

  if (conditions.metadata) {
    for (const [metaKey, metaValue] of Object.entries(conditions.metadata)) {
      headers.set(`x-amz-meta-${metaKey}`, String(metaValue))
    }
  }

  return headers
}

/**
 * Creates headers for multipart upload initiation
 * Extracts metadata and content-type headers
 */
function createMultipartInitHeaders(sourceHeaders: Headers): Headers {
  const headers = new Headers()

  const contentType = sourceHeaders.get("content-type")
  if (contentType) {
    headers.set("Content-Type", contentType)
  }

  // Forward S3 metadata headers
  for (const [name, value] of sourceHeaders.entries()) {
    if (name.toLowerCase().startsWith("x-amz-meta-")) {
      headers.set(name, value)
    }
  }

  return headers
}

/**
 * Creates headers for multipart upload completion
 * Sets XML content type and optional content length
 */
function createMultipartCompletionHeaders(
  contentLength: string | undefined,
): Headers {
  const headers = new Headers()
  headers.set("Content-Type", "application/xml")

  if (contentLength) {
    headers.set("Content-Length", contentLength)
  }

  return headers
}

/**
 * Builds S3 URL for multipart operations
 * Centralized URL construction for consistency
 */
function buildMultipartUrl(
  baseUrl: string,
  filename: string,
  operation: "uploads" | "completion" | "abort" | "part",
  uploadId?: string,
  partNumber?: string,
): string {
  const encodedFilename = encodeURIComponent(filename)

  switch (operation) {
    case "uploads":
      return `${baseUrl}/${encodedFilename}?uploads`
    case "part":
      if (!uploadId || !partNumber) {
        throw new Error(
          "uploadId and partNumber are required for part upload operations",
        )
      }
      return `${baseUrl}/${encodedFilename}?partNumber=${encodeURIComponent(partNumber)}&uploadId=${encodeURIComponent(uploadId)}`
    case "completion":
    case "abort":
      if (!uploadId) {
        throw new Error("uploadId is required for completion/abort operations")
      }
      return `${baseUrl}/${encodedFilename}?uploadId=${encodeURIComponent(uploadId)}`
    default:
      throw new Error(`Unknown multipart operation: ${operation}`)
  }
}

/**
 * Handles multipart upload part request
 * Refactored to be more focused and testable
 */
async function handleMultipartUploadPart(
  c: Context<{ Bindings: Env }>,
  filename: string,
  partNumber: string,
  uploadId: string,
): Promise<Response> {
  const validatedPartNumber = validatePartNumber(partNumber)

  await enforceUrlSigning(c.env, `/${filename}`, c.req.url)

  const body = c.req.raw.body
  if (!body) {
    throw new HTTPException(HTTP_STATUS.BAD_REQUEST, {
      message: "Request body is required for part upload",
    })
  }

  try {
    const signer = getAwsClient(c.env)
    const baseUrl = getS3BaseUrl(c.env)
    const url = buildMultipartUrl(
      baseUrl,
      filename,
      "part",
      uploadId,
      partNumber,
    )

    const headers = createPartUploadHeaders(
      c.req.header("content-length"),
      c.req.header("content-md5"),
    )

    const signedRequest = await signer.sign(url, {
      method: HttpMethod.PUT,
      headers,
      body,
    })

    const response = await fetch(signedRequest)

    if (!response.ok) {
      await handleS3ResponseError(
        response,
        `Part ${validatedPartNumber} upload failed`,
      )
    }

    return response
  } catch (error) {
    handleUploadError(error, `Part ${validatedPartNumber} upload failed`)
  }
}

// ─────────────────────────────────────── Route Handlers ───────────────────────────────────────

// Upload file - PUT /:filename
upload.put("/:filename{.*}", filenameValidator, async (c) => {
  ensureEnvironmentValidated(c.env)

  const validatedData = c.req.valid("param") as { filename: string }
  const filename = validatedData.filename

  // Check if this is a multipart upload part request
  const partNumber = c.req.query("partNumber")
  const uploadId = c.req.query("uploadId")

  if (partNumber && uploadId) {
    return handleMultipartUploadPart(c, filename, partNumber, uploadId)
  }

  // Handle regular file upload
  await enforceUrlSigning(c.env, `/${filename}`, c.req.url)

  const body = c.req.raw.body
  if (!body) {
    throw new HTTPException(HTTP_STATUS.BAD_REQUEST, {
      message: "Request body is required for PUT uploads",
    })
  }

  const headers = forwardS3Headers(c.req.raw.headers)
  const signer = getAwsClient(c.env)
  const url = `${getS3BaseUrl(c.env)}/${filename}`

  try {
    const signedRequest = await signer.sign(url, {
      method: HttpMethod.PUT,
      headers,
      body,
    })

    const response = await fetch(signedRequest)

    if (!response.ok) {
      await handleS3ResponseError(response, "Upload failed")
    }

    return response
  } catch (error) {
    handleUploadError(error, "Upload failed")
  }
})

// Generate presigned upload URL - POST /presigned-upload
upload.post(
  "/presigned-upload",
  zValidator("json", presignedUploadSchema),
  async (c) => {
    ensureEnvironmentValidated(c.env)
    await enforceUrlSigning(c.env, "/presigned-upload", c.req.url)

    try {
      const { key, expiresIn, conditions } = c.req.valid("json")

      const signer = getAwsClient(c.env)
      const url = `${getS3BaseUrl(c.env)}/${key}`

      const headers = createPresignedUrlHeaders(conditions)
      const expirationTimestamp = Math.floor(Date.now() / 1000) + expiresIn

      const presignedUrl = await generatePresignedUrl(
        signer,
        url,
        HttpMethod.PUT,
        headers,
        expiresIn,
      )

      const response = {
        presignedUrl,
        key,
        expiresIn,
        expiresAt: new Date(expirationTimestamp * 1000).toISOString(),
        method: "PUT",
        requiredHeaders: Object.fromEntries(headers.entries()),
      }

      return c.json(response)
    } catch (error) {
      handleUploadError(error, "Failed to generate presigned URL")
    }
  },
)

// Multipart upload initiation - POST /:filename/uploads
upload.post("/:filename{.*}/uploads", filenameValidator, async (c) => {
  ensureEnvironmentValidated(c.env)

  const validatedData = c.req.valid("param") as { filename: string }
  const filename = validatedData.filename

  await enforceUrlSigning(c.env, `/${filename}/uploads`, c.req.url)

  try {
    const signer = getAwsClient(c.env)
    const baseUrl = getS3BaseUrl(c.env)
    const url = buildMultipartUrl(baseUrl, filename, "uploads")

    const headers = createMultipartInitHeaders(c.req.raw.headers)

    const signedRequest = await signer.sign(url, {
      method: HttpMethod.POST,
      headers,
    })

    const response = await fetch(signedRequest)

    if (!response.ok) {
      await handleS3ResponseError(
        response,
        "Multipart upload initiation failed",
      )
    }

    return response
  } catch (error) {
    handleUploadError(error, "Multipart upload initiation failed")
  }
})

// Complete multipart upload - POST /:filename?uploadId=
upload.post("/:filename{.*}", filenameValidator, async (c) => {
  const uploadId = c.req.query("uploadId")

  if (!uploadId) {
    throw new HTTPException(HTTP_STATUS.BAD_REQUEST, {
      message:
        "Invalid request. For multipart completion, uploadId is required",
    })
  }

  ensureEnvironmentValidated(c.env)

  const validatedData = c.req.valid("param") as { filename: string }
  const filename = validatedData.filename

  await enforceUrlSigning(c.env, `/${filename}`, c.req.url)

  const body = c.req.raw.body
  if (!body) {
    throw new HTTPException(HTTP_STATUS.BAD_REQUEST, {
      message:
        "Request body with part list is required for completing multipart upload",
    })
  }

  try {
    const signer = getAwsClient(c.env)
    const baseUrl = getS3BaseUrl(c.env)
    const url = buildMultipartUrl(baseUrl, filename, "completion", uploadId)

    const headers = createMultipartCompletionHeaders(
      c.req.header("content-length"),
    )

    const signedRequest = await signer.sign(url, {
      method: HttpMethod.POST,
      headers,
      body,
    })

    const response = await fetch(signedRequest)

    if (!response.ok) {
      await handleS3ResponseError(
        response,
        "Multipart upload completion failed",
      )
    }

    return response
  } catch (error) {
    handleUploadError(error, "Multipart upload completion failed")
  }
})

// Abort multipart upload - DELETE /:filename?uploadId=
upload.delete("/:filename{.*}", filenameValidator, async (c) => {
  const uploadId = c.req.query("uploadId")

  if (!uploadId) {
    throw new HTTPException(HTTP_STATUS.BAD_REQUEST, {
      message: "Invalid request. For multipart abort, uploadId is required",
    })
  }

  ensureEnvironmentValidated(c.env)

  const validatedData = c.req.valid("param") as { filename: string }
  const filename = validatedData.filename

  await enforceUrlSigning(c.env, `/${filename}`, c.req.url)

  try {
    const signer = getAwsClient(c.env)
    const baseUrl = getS3BaseUrl(c.env)
    const url = buildMultipartUrl(baseUrl, filename, "abort", uploadId)

    const signedRequest = await signer.sign(url, {
      method: HttpMethod.DELETE,
    })

    const response = await fetch(signedRequest)

    if (!response.ok) {
      await handleS3ResponseError(response, "Multipart upload abort failed")
    }

    return c.json({
      success: true,
      message: `Multipart upload for '${filename}' aborted successfully`,
      uploadId,
      abortedAt: new Date().toISOString(),
    })
  } catch (error) {
    handleUploadError(error, "Multipart upload abort failed")
  }
})

export default upload
