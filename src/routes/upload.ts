import { zValidator } from "@hono/zod-validator"
import { Hono } from "hono"
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

const upload = new Hono<{ Bindings: Env }>()

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

/**
 * Forwards relevant S3 headers from the incoming request
 */
function forwardS3Headers(sourceHeaders: Headers): Headers {
  const headers = new Headers()

  // Content headers
  const contentHeaders = [
    "content-type",
    "content-md5",
    "content-length",
    "content-encoding",
    "cache-control",
  ]

  for (const headerName of contentHeaders) {
    const value = sourceHeaders.get(headerName)
    if (value) {
      headers.set(headerName, value)
    }
  }

  // S3 metadata headers (x-amz-meta-*)
  for (const [name, value] of sourceHeaders.entries()) {
    if (name.toLowerCase().startsWith("x-amz-meta-")) {
      headers.set(name, value)
    }
  }

  // S3 checksum headers (x-amz-checksum-*)
  for (const [name, value] of sourceHeaders.entries()) {
    if (name.toLowerCase().startsWith("x-amz-checksum-")) {
      headers.set(name, value)
    }
  }

  // S3 server-side encryption headers
  const sseHeaders = [
    "x-amz-server-side-encryption",
    "x-amz-server-side-encryption-aws-kms-key-id",
    "x-amz-server-side-encryption-context",
    "x-amz-server-side-encryption-customer-algorithm",
    "x-amz-server-side-encryption-customer-key",
    "x-amz-server-side-encryption-customer-key-md5",
  ]

  for (const headerName of sseHeaders) {
    const value = sourceHeaders.get(headerName)
    if (value) {
      headers.set(headerName, value)
    }
  }

  return headers
}

/**
 * Validates URL signing if required and returns error if not configured
 */
function validateUrlSigning(env: Env, pathname: string): void {
  if (shouldEnforceUrlSigning(env, pathname)) {
    if (!env.URL_SIGNING_SECRET) {
      throw new HTTPException(501, {
        message: "URL signing is required but not configured",
      })
    }
  }
}

/**
 * Updates upload metrics based on content length
 */
function updateUploadMetrics(contentLength: string | null | undefined): void {
  globalThis.__app_metrics.totalUploads++
  if (contentLength) {
    const uploadSize = Number.parseInt(contentLength, 10)
    if (!Number.isNaN(uploadSize)) {
      globalThis.__app_metrics.bytesSent += uploadSize
      globalThis.__app_metrics.bytesUploaded += uploadSize
    }
  }
}

/**
 * Handles upload errors consistently
 */
function handleUploadError(error: unknown, context: string): never {
  console.error(`${context}:`, error)

  if (error instanceof HTTPException) {
    throw error
  }

  if (error instanceof Error) {
    throw new HTTPException(502, {
      message: `${context}: ${error.message}`,
    })
  }

  throw new HTTPException(502, {
    message: `${context}: Unknown error occurred`,
  })
}

// Upload file - PUT /:filename
upload.put("/:filename{.*}", filenameValidator, async (c) => {
  // Ensure environment is validated
  ensureEnvironmentValidated(c.env)

  globalThis.__app_metrics.totalRequests++

  const validatedData = c.req.valid("param") as { filename: string }
  const filename = validatedData.filename

  // Security: Enhanced URL signing enforcement for uploads
  const pathname = `/${filename}`
  validateUrlSigning(c.env, pathname)

  if (shouldEnforceUrlSigning(c.env, pathname) && c.env.URL_SIGNING_SECRET) {
    await verifySignature(new URL(c.req.url), c.env.URL_SIGNING_SECRET)
  }

  // Get the request body stream
  const body = c.req.raw.body
  if (!body) {
    throw new HTTPException(400, {
      message: "Request body is required for PUT uploads",
    })
  }

  // Forward S3-related headers
  const headers = forwardS3Headers(c.req.raw.headers)

  const signer = getAwsClient(c.env)
  const url = `${getS3BaseUrl(c.env)}/${filename}`

  try {
    // Sign the request with the body stream
    const signedRequest = await signer.sign(url, {
      method: HttpMethod.PUT,
      headers: headers,
      body: body, // Stream the body directly
    })

    // Execute the upload request
    const response = await fetch(signedRequest)

    // Track upload metrics
    const contentLength = c.req.header("content-length")
    updateUploadMetrics(contentLength)

    // Return the S3 response directly
    // This preserves all S3 headers like ETag, x-amz-version-id, etc.
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
    // Ensure environment is validated
    ensureEnvironmentValidated(c.env)

    globalThis.__app_metrics.totalRequests++

    // Security: URL signing enforcement for presigned URL generation
    validateUrlSigning(c.env, "/presigned-upload")

    if (
      shouldEnforceUrlSigning(c.env, "/presigned-upload") &&
      c.env.URL_SIGNING_SECRET
    ) {
      await verifySignature(new URL(c.req.url), c.env.URL_SIGNING_SECRET)
    }

    try {
      const { key, expiresIn, conditions } = c.req.valid("json")

      const signer = getAwsClient(c.env)
      const url = `${getS3BaseUrl(c.env)}/${key}`

      // Prepare headers for presigned URL
      const headers = new Headers()

      // Add conditional headers if specified
      if (conditions.contentType) {
        headers.set("Content-Type", conditions.contentType)
      }
      if (conditions.contentLength) {
        headers.set("Content-Length", conditions.contentLength.toString())
      }
      if (conditions.contentMd5) {
        headers.set("Content-MD5", conditions.contentMd5)
      }

      // Add S3 metadata headers if specified
      if (conditions.metadata) {
        for (const [metaKey, metaValue] of Object.entries(
          conditions.metadata,
        )) {
          headers.set(`x-amz-meta-${metaKey}`, String(metaValue))
        }
      }

      // Calculate expiration timestamp
      const expirationTimestamp = Math.floor(Date.now() / 1000) + expiresIn

      // Generate presigned URL using the helper function
      const presignedUrl = await generatePresignedUrl(
        signer,
        url,
        HttpMethod.PUT,
        headers,
        expiresIn,
      )

      const response = {
        presignedUrl: presignedUrl,
        key: key,
        expiresIn: expiresIn,
        expiresAt: new Date(expirationTimestamp * 1000).toISOString(),
        method: "PUT",
        // Include headers that must be included in the actual request
        requiredHeaders: Object.fromEntries(headers.entries()),
      }

      // Track presigned URL generation
      globalThis.__app_metrics.presignedUrlsGenerated++

      return c.json(response)
    } catch (error) {
      handleUploadError(error, "Failed to generate presigned URL")
    }
  },
)

// Multipart upload initiation - POST /:filename/uploads
upload.post("/:filename{.*}/uploads", filenameValidator, async (c) => {
  // Ensure environment is validated
  ensureEnvironmentValidated(c.env)

  globalThis.__app_metrics.totalRequests++

  const validatedData = c.req.valid("param") as { filename: string }
  const filename = validatedData.filename

  // Security: Enhanced URL signing enforcement
  const pathname = `/${filename}/uploads`
  validateUrlSigning(c.env, pathname)

  if (shouldEnforceUrlSigning(c.env, pathname) && c.env.URL_SIGNING_SECRET) {
    await verifySignature(new URL(c.req.url), c.env.URL_SIGNING_SECRET)
  }

  try {
    const signer = getAwsClient(c.env)
    const url = `${getS3BaseUrl(c.env)}/${filename}?uploads`

    // Use the simplified header forwarding for basic headers
    const headers = new Headers()

    // Forward Content-Type if provided
    const contentType = c.req.header("content-type")
    if (contentType) {
      headers.set("Content-Type", contentType)
    }

    // Forward S3 metadata headers
    for (const [name, value] of c.req.raw.headers.entries()) {
      if (name.toLowerCase().startsWith("x-amz-meta-")) {
        headers.set(name, value)
      }
    }

    // Sign and execute the multipart upload initiation request
    const signedRequest = await signer.sign(url, {
      method: HttpMethod.POST,
      headers: headers,
    })

    const response = await fetch(signedRequest)

    if (!response.ok) {
      throw new HTTPException(response.status as ContentfulStatusCode, {
        message: `Multipart upload initiation failed: ${response.statusText}`,
      })
    }

    // Return the S3 response (contains UploadId in XML format)
    return response
  } catch (error) {
    handleUploadError(error, "Multipart upload initiation failed")
  }
})

export default upload
